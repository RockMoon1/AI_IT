"""aiit-agent: runs on the endpoint being supported."""
from __future__ import annotations

import argparse
import contextlib
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .. import __version__
from ..common.bundle import pack_dir, write_bundle
from ..common.crypto import CryptoError
from ..common.net import HttpStatusError, NetError, http_json
from ..common.policy import Policy
from ..common.schema import BundleManifest, Enrollment, SignedPlan
from ..common.util import current_os, hostname, iso, new_id, os_version, read_json, safe_join, validate_id, write_json
from .collectors import FAILURE_STATUSES, collect_all, collector_table_sha256, is_elevated, selftest_rows, status_counts
from .executor import apply_plan, load_signed_plan, preflight, verify_signed_plan
from .state import AgentState

EXIT_USAGE, EXIT_NETWORK, EXIT_VERIFY, EXIT_POLICY = 2, 3, 4, 5


def _state(args: argparse.Namespace) -> AgentState:
    return AgentState(Path(args.data_dir) if args.data_dir else None)


def _require_enrolled(st: AgentState) -> None:
    if not st.is_enrolled():
        sys.exit("This endpoint is not enrolled. Run: aiit-agent enroll <console-enrollment.json>")


def _env_token() -> str | None:
    import os
    tok = os.environ.get("AIIT_SERVER_TOKEN")
    if tok:
        return tok
    f = os.environ.get("AIIT_SERVER_TOKEN_FILE")
    if f and Path(f).is_file():
        return Path(f).read_text(encoding="utf-8").strip() or None
    return None


def _auth_headers(token: str | None) -> dict[str, str]:
    token = token or _env_token()
    return {"Authorization": f"Bearer {token}"} if token else {}


# ------------------------------------------------------------------ commands

def cmd_enroll(args: argparse.Namespace) -> None:
    st = _state(args)
    try:
        enr = Enrollment.model_validate(read_json(Path(args.enrollment)))
    except (ValidationError, ValueError, OSError) as e:
        sys.exit(f"{args.enrollment} is not a valid enrollment file: {type(e).__name__}")
    if st.is_enrolled() and not args.force:
        sys.exit(f"Already enrolled with console {st.enrollment().console_id}. Use --force to re-enroll.")
    ident = st.enroll(enr)
    print(f"Enrolled. agent_id={ident.id} console_id={enr.console_id}")
    print(f"State dir: {st.root}")
    pol = st.policy()
    print(f"Policy: {st.policy_file} (mode={pol.mode}, max_risk={pol.max_risk}, digest={pol.digest()[:12]})")


def _seal_diagnostics(st: AgentState, root: Path, files: list, bundle_id: str, out: Path, *, quick: bool,
                      issue: str = "", case_id: str | None = None) -> Path:
    """Write the manifest into ``root`` (the collection directory) and seal it to the enrolled console.

    Besides the collected files the manifest records what a field tester
    needs to interpret failures: whether the agent was elevated, the policy
    digest and mode, whether the agent is a frozen executable, and which
    collector set and table produced the bundle.
    """
    ident = st.identity()
    enr = st.enrollment()
    os_name = current_os()
    pol = st.policy()
    manifest = BundleManifest(
        bundle_id=bundle_id, agent_id=ident.id, hostname=hostname(), platform=os_name,
        os_version=os_version(), collected_at=iso(), aiit_version=__version__,
        issue_description=issue, case_id=case_id, files=files, audit_head=st.audit.head(),
        elevated=is_elevated(), policy_sha256=pol.digest(), policy_mode=pol.mode,
        aiit_frozen=bool(getattr(sys, "frozen", False)), collector_set="quick" if quick else "full",
        collector_table_sha256=collector_table_sha256(os_name),
    )
    write_json(root / "manifest.json", manifest.model_dump())
    plaintext = pack_dir(root)
    write_bundle(out, plaintext, enr.console_box_pub, ident, kind="diagnostics", bundle_id=bundle_id, console_id=enr.console_id)
    return out


def _status_summary(files: list) -> str:
    return " ".join(f"{k}={v}" for k, v in status_counts(files).items())


def cmd_collect(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_enrolled(st)
    ident = st.identity()
    os_name = current_os()
    bundle_id = new_id("b-")
    out = Path(args.out) if args.out else st.outbox / f"{hostname()}-{bundle_id}.aiit"
    with tempfile.TemporaryDirectory(prefix="aiit-collect-") as tmp:
        root = Path(tmp)
        print(f"Collecting diagnostics ({os_name}, {'quick' if args.quick else 'full'})...")
        files = collect_all(root, quick=args.quick, progress=lambda n: print(f"  - {n}"), include_osquery=not args.no_osquery)
        _seal_diagnostics(st, root, files, bundle_id, out, quick=args.quick, issue=args.issue or "", case_id=args.case)
    errors = sum(1 for f in files if f.error)
    st.audit.record("collect", bundle_id=bundle_id, files=len(files), errors=errors, out=str(out), quick=args.quick,
                    statuses=status_counts(files))
    st.audit.checkpoint(ident)
    print(f"Wrote {out} ({out.stat().st_size} bytes, {len(files)} files, {errors} collector errors; {_status_summary(files)})")
    print(f"Hand this file to the console: aiit-console ingest {out.name}")
    if args.push and not _push_file(st, out, args.push, args.token):
        sys.exit(EXIT_NETWORK)


# ------------------------------------------------------------------ selftest

def _selftest_report(files: list, os_name: str, quick: bool) -> dict[str, Any]:
    """Metadata-only report of one collector run. No hostname, no command lines, no output."""
    rows = selftest_rows(files, os_name)
    counts = status_counts(files)
    return {
        "report": "aiit-agent selftest",
        "aiit_version": __version__,
        "aiit_frozen": bool(getattr(sys, "frozen", False)),
        "platform": os_name,
        "os_version": os_version(),
        "python": platform.python_version(),
        "elevated": is_elevated(),
        "collector_set": "quick" if quick else "full",
        "collector_table_sha256": collector_table_sha256(os_name),
        "generated_at": iso(),
        "total": len(rows),
        "failures": sum(counts.get(s, 0) for s in FAILURE_STATUSES),
        "summary": counts,
        "collectors": rows,
    }


def _yes_no(v: Any) -> str:
    return "unknown" if v is None else ("yes" if v else "no")


def _selftest_markdown(rep: dict[str, Any]) -> str:
    lines = [
        "## aiit-agent selftest", "",
        "| field | value |", "|---|---|",
        f"| aiit | {rep['aiit_version']} (frozen: {_yes_no(rep['aiit_frozen'])}) |",
        f"| platform | {rep['platform']}, {rep['os_version']} |",
        f"| python | {rep['python']} |",
        f"| elevated | {_yes_no(rep['elevated'])} |",
        f"| collector set | {rep['collector_set']} (table {rep['collector_table_sha256'][:12]}) |",
        f"| generated | {rep['generated_at']} |",
        "",
        f"**{rep['total']} collectors, {rep['failures']} failed**: " + ", ".join(f"{v} {k}" for k, v in rep["summary"].items()),
        "",
        "| collector | admin | status | exit | ms | bytes | stderr bytes | error class |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rep["collectors"]:
        lines.append(f"| {r['category']}/{r['name']} | {'yes' if r['requires_admin'] else ''} | {r['status']} | "
                     f"{'' if r['exit_code'] is None else r['exit_code']} | {r['duration_ms']} | {r['size']} | {r['stderr_size']} | "
                     f"{r['error_class'] or ''} |")
    return "\n".join(lines) + "\n"


def _selftest_text(rep: dict[str, Any]) -> str:
    lines = [
        f"aiit-agent {rep['aiit_version']} selftest  platform={rep['platform']}  python={rep['python']}  "
        f"elevated={_yes_no(rep['elevated'])}  frozen={_yes_no(rep['aiit_frozen'])}  set={rep['collector_set']}",
        f"os: {rep['os_version']}", "",
        f"{'collector':34} {'admin':5} {'status':12} {'exit':>5} {'ms':>7} {'bytes':>9} {'stderr':>7}  error class",
    ]
    for r in rep["collectors"]:
        lines.append(f"{r['category'] + '/' + r['name']:34} {'yes' if r['requires_admin'] else '':5} {r['status']:12} "
                     f"{'' if r['exit_code'] is None else r['exit_code']:>5} {r['duration_ms']:>7} {r['size']:>9} {r['stderr_size']:>7}  "
                     f"{r['error_class'] or ''}")
    lines.append("")
    lines.append(f"{rep['total']} collectors, {rep['failures']} failed: " + ", ".join(f"{v} {k}" for k, v in rep["summary"].items()))
    return "\n".join(lines) + "\n"


def cmd_selftest(args: argparse.Namespace) -> None:
    """Run every collector for this OS and report metadata only (for field testing and bug reports)."""
    st = _state(args)
    if args.seal:
        _require_enrolled(st)
    os_name = current_os()
    quick = not args.full
    sealed: Path | None = None
    with tempfile.TemporaryDirectory(prefix="aiit-selftest-") as tmp:
        root = Path(tmp)
        print(f"Running {'quick' if quick else 'full'} collector set for {os_name}...", file=sys.stderr)
        files = collect_all(root, quick=quick, progress=lambda n: print(f"  - {n}", file=sys.stderr), include_osquery=not args.no_osquery)
        if args.seal:
            bundle_id = new_id("b-")
            sealed = _seal_diagnostics(st, root, files, bundle_id, Path(args.seal), quick=quick, issue="aiit-agent selftest")
            st.audit.record("selftest", bundle_id=bundle_id, files=len(files), statuses=status_counts(files), out=str(sealed))
            st.audit.checkpoint(st.identity())
    rep = _selftest_report(files, os_name, quick)
    if args.json:
        print(json.dumps(rep, indent=2))
    elif args.markdown:
        print(_selftest_markdown(rep), end="")
    else:
        print(_selftest_text(rep), end="")
    if sealed:
        print(f"Sealed bundle of this run: {sealed} (hand it to the console: aiit-console ingest {sealed.name})", file=sys.stderr)
    if args.strict and rep["failures"]:
        sys.exit(1)


def _push_file(st: AgentState, path: Path, server: str, token: str | None) -> bool:
    """Upload one bundle. Returns False (after printing why and recording push_failed) instead of exiting,
    so a caller with several files can go on with the rest."""
    from ..common.bundle import read_bundle_header
    hdr = read_bundle_header(path)
    headers = _auth_headers(token)
    headers["X-AIIT-Bundle-Id"] = hdr.get("bundle_id", "")
    try:
        body = http_json("POST", server.rstrip("/") + "/v1/bundles", raw_body=path.read_bytes(), headers=headers, timeout=120, retries=3)
    except HttpStatusError as e:
        st.audit.record("push_failed", bundle_id=hdr.get("bundle_id"), server=server, status=e.status)
        print(f"Push failed for {path.name}: HTTP {e.status} {e.body_snippet[:200]}", file=sys.stderr)
        print(f"Bundle kept at {path}; carry it by USB or retry: aiit-agent push {path} --server {server}", file=sys.stderr)
        return False
    except NetError as e:
        st.audit.record("push_failed", bundle_id=hdr.get("bundle_id"), server=server, error=str(e)[:200])
        print(f"Push failed for {path.name}: {e}", file=sys.stderr)
        print(f"Bundle kept at {path}; carry it by USB or retry: aiit-agent push {path} --server {server}", file=sys.stderr)
        return False
    print(f"Pushed {path.name} to {server}: {body}")
    st.audit.record("push", bundle_id=hdr.get("bundle_id"), server=server, result=body)
    with contextlib.suppress(OSError):  # a bundle that cannot be moved to sent/ is pushed again next time (idempotent on bundle_id)
        if path.resolve().parent == st.outbox.resolve():
            st.sent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(st.sent / path.name))
    return True


def cmd_push(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_enrolled(st)
    files: list[Path] = []
    if args.outbox:
        files = sorted(p for p in st.outbox.glob("*.aiit") if p.is_file())
        if not files:
            print(f"Nothing to push in {st.outbox}")
            return
    elif args.file:
        files = [Path(args.file)]
    else:
        sys.exit("give a bundle file or --outbox")
    for f in files:
        if not f.is_file():
            sys.exit(f"no such file: {f}")
    failed = [f for f in files if not _push_file(st, f, args.server, args.token)]
    if failed:
        print(f"{len(failed)} of {len(files)} bundle(s) failed to push: {', '.join(f.name for f in failed)}", file=sys.stderr)
        sys.exit(EXIT_NETWORK)


def cmd_pull(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_enrolled(st)
    ident = st.identity()
    enr = st.enrollment()
    policy = st.policy()
    try:
        plans = http_json("GET", args.server.rstrip("/") + f"/v1/plans?agent_id={ident.id}", headers=_auth_headers(args.token), timeout=60, retries=2)
    except HttpStatusError as e:
        sys.exit(f"Pull failed: HTTP {e.status} {e.body_snippet[:200]}")
    except NetError as e:
        sys.exit(f"Pull failed: {e}")
    if not isinstance(plans, list):
        st.audit.record("pull_rejected", server=args.server, reason="response is not a list")
        sys.exit("Pull failed: the server did not return a list of plans")
    st.inbox.mkdir(parents=True, exist_ok=True)
    applied = set(st.applied_plan_ids())
    saved, skipped, rejected = 0, 0, 0
    for item in plans:
        try:
            sp = SignedPlan.model_validate(item)
        except ValidationError as e:
            rejected += 1
            st.audit.record("pull_rejected", server=args.server, reason="invalid signed plan", errors=len(e.errors()))
            continue
        pid = sp.plan.plan_id
        if pid in applied:
            skipped += 1
            continue
        problems = verify_signed_plan(sp, enr, ident.id, list(applied), max_plan_hours=policy.max_plan_hours)
        if problems:
            rejected += 1
            st.audit.record("pull_rejected", server=args.server, plan_id=pid, problems=problems)
            print(f"Rejected plan {pid}: {'; '.join(problems)}", file=sys.stderr)
            continue
        p = safe_join(st.inbox, f"{validate_id(pid, 'plan_id')}.signed.json")
        write_json(p, sp.model_dump(), private=True)
        saved += 1
        print(f"Saved {p}")
    st.audit.record("pull", server=args.server, saved=saved, skipped=skipped, rejected=rejected)
    print(f"{saved} new plan(s), {skipped} already applied, {rejected} rejected. Apply with: aiit-agent apply <file>")


def _print_plan(sp: SignedPlan, checks: list[tuple[Any, bool, str]] | None = None) -> None:
    plan = sp.plan
    print(f"\nPlan {plan.plan_id}  case={plan.case_id}  target_os={plan.target_os}  expires={plan.expires_at}")
    print(f"Approved by {sp.approved_by} at {sp.approved_at} (console {sp.signer_id})")
    print(f"Diagnosis ({plan.confidence:.0%} confidence): {plan.diagnosis}\n")
    verdicts = {s.id: (ok, reason) for s, ok, reason in (checks or [])}
    for s in plan.steps:
        flag = ", reboot" if s.requires_reboot else ""
        print(f"  [{s.id}] ({s.risk}{flag}) {s.title}")
        if s.action == "command":
            print(f"        $ {s.command}")
        else:
            print(f"        manual: {s.expected_outcome or s.rationale}")
        if s.id in verdicts and not verdicts[s.id][0]:
            print(f"        BLOCKED by local policy: {verdicts[s.id][1]}")
    if plan.notes_for_operator:
        print(f"\nNotes: {plan.notes_for_operator}")


def cmd_apply(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_enrolled(st)
    ident = st.identity()
    enr = st.enrollment()
    policy = st.policy()
    try:
        sp = load_signed_plan(Path(args.plan))
    except (ValidationError, ValueError, OSError) as e:
        sys.exit(f"{args.plan} is not a valid signed plan: {type(e).__name__}")
    applied = st.applied_plan_ids()
    replay_forced = False
    if sp.plan.plan_id in applied and args.force_replay:
        answer = input("This plan already ran on this endpoint. Type REPLAY to run it again: ")
        if answer.strip() != "REPLAY":
            sys.exit("Aborted.")
        applied = [p for p in applied if p != sp.plan.plan_id]
        replay_forced = True
    problems = verify_signed_plan(sp, enr, ident.id, applied, max_plan_hours=policy.max_plan_hours)
    if problems:
        st.audit.record("apply_refused", plan_id=sp.plan.plan_id, problems=problems)
        print("Refusing plan:\n  - " + "\n  - ".join(problems), file=sys.stderr)
        sys.exit(EXIT_VERIFY)
    if replay_forced:
        st.audit.record("apply_replay_forced", plan_id=sp.plan.plan_id)
    checks = preflight(sp, policy, current_os(), allow_reboot=args.allow_reboot)
    _print_plan(sp, checks)
    blocked = [s.id for s, ok, _ in checks if not ok and s.action == "command"]
    dry = True if args.dry_run else None
    effective = "dry_run" if (dry or policy.mode != "enforce") else "ENFORCE (commands will run)"
    print(f"\nPolicy mode: {policy.mode}, max_risk={policy.max_risk}, digest={policy.digest()[:12]}. Effective mode: {effective}")
    if blocked:
        print(f"Preflight: step(s) {', '.join(blocked)} are blocked by the local policy; nothing will be executed.")
    skip: set[str] = set()
    marker = st.applying()
    if args.resume:
        if marker and marker.get("plan_id") == sp.plan.plan_id:
            skip = set(marker.get("completed", []))
            print(f"Resuming: skipping already completed step(s) {', '.join(sorted(skip)) or 'none'}")
        else:
            print("Nothing to resume for this plan.")
    elif marker and marker.get("plan_id") == sp.plan.plan_id and effective.startswith("ENFORCE"):
        done = [str(s) for s in marker.get("completed", [])]
        note = f"An earlier enforce run of this plan was interrupted (completed step(s): {', '.join(done) or 'none'})."
        if not args.force_replay:
            st.audit.record("apply_refused", plan_id=sp.plan.plan_id, problems=["interrupted enforce run; --resume or --force-replay required"])
            print(f"{note}\nRe-run with --resume to skip the completed steps, or --force-replay to run every step again.", file=sys.stderr)
            sys.exit(EXIT_USAGE)
        answer = input(f"{note} Type REPLAY to run every step again from the first: ")
        if answer.strip() != "REPLAY":
            sys.exit("Aborted.")
        st.audit.record("apply_replay_forced", plan_id=sp.plan.plan_id, interrupted_after=done)
    if effective.startswith("ENFORCE") and not blocked and not args.yes:
        answer = input("Type APPLY to run this plan, anything else to abort: ")
        if answer.strip() != "APPLY":
            st.audit.record("apply_aborted", plan_id=sp.plan.plan_id)
            sys.exit("Aborted.")
    completed: list[str] = sorted(skip)

    def on_step(index: int, step: Any, result: Any) -> None:
        if result is None:
            st.mark_applying(sp.plan.plan_id, completed, step.id)
        else:
            if result.status in ("success", "dry_run", "manual"):
                completed.append(step.id)
            st.mark_applying(sp.plan.plan_id, completed, None)

    report = apply_plan(sp, policy, ident.id, st.audit, dry_run=dry, allow_reboot=args.allow_reboot, os_name=current_os(),
                        skip_step_ids=skip or None, on_step=on_step if effective.startswith("ENFORCE") else None)
    if report.mode == "enforce" and not blocked:
        st.mark_applied(sp.plan.plan_id)
        st.clear_applying()
    report.audit_head = st.audit.head()
    print("\nResults:")
    for r in report.results:
        line = f"  [{r.step_id}] {r.status:17} {r.title}"
        if r.reason:
            line += f"  ({r.reason})"
        if r.exit_code is not None:
            line += f"  exit={r.exit_code}"
        print(line)
    with tempfile.TemporaryDirectory(prefix="aiit-report-") as tmp:
        root = Path(tmp)
        write_json(root / "report.json", report.model_dump())
        bundle_id = new_id("r-")
        manifest = BundleManifest(
            kind="execution_report", bundle_id=bundle_id, agent_id=ident.id, hostname=hostname(), platform=current_os(),
            os_version=os_version(), collected_at=iso(), aiit_version=__version__, case_id=sp.plan.case_id, plan_id=sp.plan.plan_id,
            audit_head=st.audit.head(),
        )
        write_json(root / "manifest.json", manifest.model_dump())
        plaintext = pack_dir(root)
    out = Path(args.out) if args.out else st.outbox / f"report-{sp.plan.plan_id}-{bundle_id}.aiit"
    write_bundle(out, plaintext, enr.console_box_pub, ident, kind="execution_report", bundle_id=bundle_id, console_id=enr.console_id,
                 extra={"case_id": sp.plan.case_id, "plan_id": sp.plan.plan_id})
    st.audit.record("report_written", plan_id=sp.plan.plan_id, bundle_id=bundle_id, out=str(out))
    st.audit.checkpoint(ident)
    print(f"\nReport written: {out}\nReturn it to the console: aiit-console report {out.name}")
    if args.push and not _push_file(st, out, args.push, args.token):
        sys.exit(EXIT_NETWORK)
    if blocked and report.mode == "enforce":
        sys.exit(EXIT_POLICY)


def cmd_status(args: argparse.Namespace) -> None:
    st = _state(args)
    print(f"aiit-agent {__version__}  state={st.root}")
    if not st.is_enrolled():
        print("Not enrolled.")
        return
    ident = st.identity()
    enr = st.enrollment()
    pol = st.policy()
    print(f"agent_id={ident.id}  host={hostname()}  os={current_os()}")
    print(f"console_id={enr.console_id}  console_sign_pub={enr.console_sign_pub[:16]}...")
    print(f"policy: mode={pol.mode} max_risk={pol.max_risk} max_plan_hours={pol.max_plan_hours} deny_patterns={len(pol.deny_patterns)} "
          f"allow_patterns={len(pol.allow_patterns)} digest={pol.digest()[:16]}")
    print(f"applied plans: {len(st.applied_plan_ids())}")
    marker = st.applying()
    if marker:
        print(f"INTERRUPTED enforce run: plan {marker.get('plan_id')} (completed {len(marker.get('completed', []))} step(s)); use apply --resume")
    ok, msg = st.audit.verify(expected_pub=ident.sign_pub_hex)
    print(f"audit chain: {'OK' if ok else 'BROKEN'} ({msg})")


def cmd_policy(args: argparse.Namespace) -> None:
    st = _state(args)
    pol = st.policy()
    if args.policy_cmd == "show":
        print(json.dumps(pol.to_dict(), indent=2))
    elif args.policy_cmd == "digest":
        print(pol.digest())
    elif args.policy_cmd == "set-mode":
        pol.mode = args.value
        pol.save(st.policy_file)
        st.audit.record("policy_change", field="mode", value=args.value, digest=pol.digest())
        print(f"policy mode = {args.value}")
    elif args.policy_cmd == "set-max-risk":
        pol.max_risk = args.value
        pol.save(st.policy_file)
        st.audit.record("policy_change", field="max_risk", value=args.value, digest=pol.digest())
        print(f"policy max_risk = {args.value}")
    elif args.policy_cmd == "reset":
        Policy().save(st.policy_file)
        st.audit.record("policy_change", field="reset", value="defaults", digest=Policy().digest())
        print("policy reset to defaults")


def cmd_audit(args: argparse.Namespace) -> None:
    st = _state(args)
    pub = st.public_sign_key()
    sub = getattr(args, "audit_cmd", None) or "verify"
    if sub == "verify":
        breaks = st.audit.verify_detailed(expected_pub=pub)
        if breaks:
            print("BROKEN:")
            for b in breaks:
                print(f"  line {b.line_no} seq {b.seq}: {b.reason}")
        else:
            ok, msg = st.audit.verify(expected_pub=pub)
            print(("OK: " if ok else "BROKEN: ") + msg)
        if args.tail:
            for e in st.audit.entries()[-args.tail:]:
                print(json.dumps(e))
        if breaks:
            sys.exit(1)
    elif sub == "export":
        n = st.audit.export(args.format, Path(args.out), actions=args.action or None, since=args.since, until=args.until)
        print(f"wrote {n} entries to {args.out}")
    elif sub == "timeline":
        for e in st.audit.iter_filtered(plan_id=args.plan_id):
            print(f"{e['ts']}  {e['action']:22} {json.dumps(e.get('details', {}))[:120]}")
    elif sub == "repair-tail":
        # with the agent's key the signed checkpoint is refreshed when the splice moved its offset
        print(json.dumps(st.audit.repair_tail(identity=st.identity() if st.is_enrolled() else None), indent=2))


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aiit-agent", description="AI_IT endpoint agent")
    p.add_argument("--data-dir", help="state directory (default: AIIT_AGENT_DIR or ~/.aiit/agent)")
    p.add_argument("--debug", action="store_true", help="show tracebacks")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("enroll", help="trust a console using its public enrollment file")
    s.add_argument("enrollment")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_enroll)

    s = sub.add_parser("collect", help="collect diagnostics into an encrypted bundle")
    s.add_argument("--out", help="output .aiit path (e.g. on a USB stick)")
    s.add_argument("--issue", help="what the user reports is wrong")
    s.add_argument("--case", help="existing case id if this is a follow-up collection")
    s.add_argument("--quick", action="store_true", help="skip slow collectors")
    s.add_argument("--no-osquery", action="store_true")
    s.add_argument("--push", metavar="URL", help="also upload to a console server (LAN mode)")
    s.add_argument("--token", help="server token (prefer AIIT_SERVER_TOKEN or AIIT_SERVER_TOKEN_FILE)")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("selftest", help="run every collector for this OS and print per-collector metadata only (no content, no hostname)")
    s.add_argument("--full", action="store_true", help="run the full set instead of the quick set")
    s.add_argument("--no-osquery", action="store_true")
    fmt = s.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="machine readable report on stdout")
    fmt.add_argument("--markdown", action="store_true", help="report ready to paste into a GitHub issue")
    s.add_argument("--seal", metavar="OUT", help="also write a normal sealed bundle of the same run for the console (needs enrollment)")
    s.add_argument("--strict", action="store_true",
                   help=f"exit 1 when any collector is {', '.join(FAILURE_STATUSES)} (default: exit 0, it is a report)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("push", help="upload a bundle or report to a console server (LAN mode)")
    s.add_argument("file", nargs="?", help="a .aiit file")
    s.add_argument("--outbox", action="store_true", help="push every unsent bundle in the outbox")
    s.add_argument("--server", required=True)
    s.add_argument("--token")
    s.set_defaults(func=cmd_push)

    s = sub.add_parser("apply", help="verify and run a signed plan")
    s.add_argument("plan", help="path to <plan>.signed.json")
    s.add_argument("--dry-run", action="store_true", help="force dry run even if policy mode is enforce")
    s.add_argument("--allow-reboot", action="store_true")
    s.add_argument("--yes", action="store_true", help="skip the APPLY confirmation")
    s.add_argument("--resume", action="store_true", help="skip steps completed by an interrupted enforce run")
    s.add_argument("--force-replay", action="store_true",
                   help="run every step of a plan that already ran here, or whose enforce run was interrupted (asks for a typed confirmation)")
    s.add_argument("--out", help="report .aiit path")
    s.add_argument("--push", metavar="URL")
    s.add_argument("--token")
    s.set_defaults(func=cmd_apply)

    s = sub.add_parser("pull", help="fetch pending signed plans from a console server (LAN mode)")
    s.add_argument("server")
    s.add_argument("--token")
    s.set_defaults(func=cmd_pull)

    s = sub.add_parser("status")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("policy", help="show or change the local execution policy")
    ps = s.add_subparsers(dest="policy_cmd", required=True)
    ps.add_parser("show")
    ps.add_parser("digest")
    a = ps.add_parser("set-mode"); a.add_argument("value", choices=["dry_run", "enforce"])
    a = ps.add_parser("set-max-risk"); a.add_argument("value", choices=["read_only", "low", "medium", "high"])
    ps.add_parser("reset")
    s.set_defaults(func=cmd_policy)

    s = sub.add_parser("audit", help="verify, export or repair the local audit chain")
    s.add_argument("--tail", type=int, default=0)
    asub = s.add_subparsers(dest="audit_cmd")
    asub.add_parser("verify")
    e = asub.add_parser("export"); e.add_argument("--format", choices=["csv", "jsonl", "html"], default="csv"); e.add_argument("--out", required=True)
    e.add_argument("--action", action="append"); e.add_argument("--since"); e.add_argument("--until")
    t = asub.add_parser("timeline"); t.add_argument("plan_id")
    asub.add_parser("repair-tail")
    s.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> None:
    for stream in (sys.stdout, sys.stderr):
        # plan titles and step reasons carry whatever Unicode the console or the endpoint produced; a
        # redirected stdout on Windows (cp1252) must print '?' for it rather than die with UnicodeEncodeError
        with contextlib.suppress(AttributeError, ValueError, OSError):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if args.cmd not in ("enroll",):
        try:
            st = AgentState(Path(args.data_dir) if args.data_dir else None)
            if st.is_enrolled():
                st.audit.check_and_alert(expected_pub=st.public_sign_key())
        except Exception as e:  # pragma: no cover - the check must never block the command
            if args.debug:
                raise
            print(f"warning: audit check skipped: {type(e).__name__}", file=sys.stderr)
    try:
        args.func(args)
    except CryptoError as e:
        if args.debug:
            raise
        print(f"error: {e}", file=sys.stderr)
        sys.exit(EXIT_VERIFY)
    except NetError as e:
        if args.debug:
            raise
        print(f"network error: {e}", file=sys.stderr)
        sys.exit(EXIT_NETWORK)
    except (ValidationError, ValueError, FileNotFoundError) as e:
        if args.debug:
            raise
        print(f"error: {str(e).splitlines()[0][:300]}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


if __name__ == "__main__":  # pragma: no cover
    main()
