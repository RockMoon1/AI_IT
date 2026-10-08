"""aiit-agent: runs on the endpoint being supported."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from .. import __version__
from ..common.bundle import pack_dir, write_bundle
from ..common.schema import BundleManifest, Enrollment
from ..common.util import current_os, hostname, iso, new_id, os_version, read_json, write_json
from .collectors import collect_all
from .executor import apply_plan, load_signed_plan, verify_signed_plan
from .state import AgentState


def _state(args: argparse.Namespace) -> AgentState:
    return AgentState(Path(args.data_dir) if args.data_dir else None)


def _require_enrolled(st: AgentState) -> None:
    if not st.is_enrolled():
        sys.exit("This endpoint is not enrolled. Run: aiit-agent enroll <console-enrollment.json>")


# ------------------------------------------------------------------ commands

def cmd_enroll(args: argparse.Namespace) -> None:
    st = _state(args)
    enr = Enrollment.model_validate(read_json(Path(args.enrollment)))
    if st.is_enrolled() and not args.force:
        sys.exit(f"Already enrolled with console {st.enrollment().console_id}. Use --force to re-enroll.")
    ident = st.enroll(enr)
    print(f"Enrolled. agent_id={ident.id} console_id={enr.console_id}")
    print(f"State dir: {st.root}")
    print(f"Policy: {st.policy_file} (mode={st.policy().mode}, max_risk={st.policy().max_risk})")


def cmd_collect(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_enrolled(st)
    ident = st.identity()
    enr = st.enrollment()
    os_name = current_os()
    bundle_id = new_id("b-")
    with tempfile.TemporaryDirectory(prefix="aiit-collect-") as tmp:
        root = Path(tmp)
        print(f"Collecting diagnostics ({os_name}, {'quick' if args.quick else 'full'})...")
        files = collect_all(root, quick=args.quick, progress=lambda n: print(f"  - {n}"), include_osquery=not args.no_osquery)
        manifest = BundleManifest(
            bundle_id=bundle_id, agent_id=ident.id, hostname=hostname(), platform=os_name,
            os_version=os_version(), collected_at=iso(), aiit_version=__version__,
            issue_description=args.issue or "", case_id=args.case, files=files,
        )
        write_json(root / "manifest.json", manifest.model_dump())
        plaintext = pack_dir(root)
    out = Path(args.out) if args.out else st.outbox / f"{hostname()}-{bundle_id}.aiit"
    hdr = write_bundle(out, plaintext, enr.console_box_pub, ident, kind="diagnostics", bundle_id=bundle_id, console_id=enr.console_id)
    st.audit.record("collect", bundle_id=bundle_id, files=len(files), errors=sum(1 for f in files if f.error), out=str(out), quick=args.quick)
    print(f"Wrote {out} ({out.stat().st_size} bytes, {len(files)} files, {sum(1 for f in files if f.error)} collector errors)")
    print(f"Hand this file to the console: aiit-console ingest {out.name}")
    if args.push:
        _push(st, out, args.push, args.token, hdr)


def _push(st: AgentState, path: Path, server: str, token: str | None, hdr: dict) -> None:
    token = token or _env_token()
    req = urllib.request.Request(server.rstrip("/") + "/v1/bundles", data=path.read_bytes(), method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    req.add_header("X-AIIT-Bundle-Id", hdr["bundle_id"])
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            print(f"Pushed to {server}: {body}")
            st.audit.record("push", bundle_id=hdr["bundle_id"], server=server, result=body)
    except urllib.error.HTTPError as e:
        sys.exit(f"Push failed: HTTP {e.code} {e.read().decode('utf-8', 'replace')[:300]}")
    except urllib.error.URLError as e:
        sys.exit(f"Push failed: {e.reason}")


def _env_token() -> str | None:
    import os
    return os.environ.get("AIIT_SERVER_TOKEN")


def cmd_pull(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_enrolled(st)
    token = args.token or _env_token()
    req = urllib.request.Request(args.server.rstrip("/") + f"/v1/plans?agent_id={st.identity().id}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            plans = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        sys.exit(f"Pull failed: HTTP {e.code}")
    except urllib.error.URLError as e:
        sys.exit(f"Pull failed: {e.reason}")
    st.inbox.mkdir(parents=True, exist_ok=True)
    applied = set(st.applied_plan_ids())
    n = 0
    for sp in plans:
        pid = sp["plan"]["plan_id"]
        if pid in applied:
            continue
        p = st.inbox / f"{pid}.signed.json"
        write_json(p, sp, private=True)
        n += 1
        print(f"Saved {p}")
    print(f"{n} new plan(s). Apply with: aiit-agent apply <file>")


def _print_plan(sp) -> None:
    plan = sp.plan
    print(f"\nPlan {plan.plan_id}  case={plan.case_id}  target_os={plan.target_os}  expires={plan.expires_at}")
    print(f"Approved by {sp.approved_by} at {sp.approved_at} (console {sp.signer_id})")
    print(f"Diagnosis ({plan.confidence:.0%} confidence): {plan.diagnosis}\n")
    for s in plan.steps:
        flag = "REBOOT " if s.requires_reboot else ""
        print(f"  [{s.id}] ({s.risk}{', ' + flag if flag else ''}) {s.title}")
        if s.action == "command":
            print(f"        $ {s.command}")
        else:
            print(f"        manual: {s.expected_outcome or s.rationale}")
    if plan.notes_for_operator:
        print(f"\nNotes: {plan.notes_for_operator}")


def cmd_apply(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_enrolled(st)
    ident = st.identity()
    enr = st.enrollment()
    policy = st.policy()
    sp = load_signed_plan(Path(args.plan))
    problems = verify_signed_plan(sp, enr, ident.id, st.applied_plan_ids())
    if problems:
        st.audit.record("apply_refused", plan_id=sp.plan.plan_id, problems=problems)
        sys.exit("Refusing plan:\n  - " + "\n  - ".join(problems))
    _print_plan(sp)
    dry = True if args.dry_run else None
    effective = "dry_run" if (dry or policy.mode != "enforce") else "ENFORCE (commands will run)"
    print(f"\nPolicy mode: {policy.mode}, max_risk={policy.max_risk}. Effective mode: {effective}")
    if effective.startswith("ENFORCE") and not args.yes:
        answer = input("Type APPLY to run this plan, anything else to abort: ")
        if answer.strip() != "APPLY":
            st.audit.record("apply_aborted", plan_id=sp.plan.plan_id)
            sys.exit("Aborted.")
    report = apply_plan(sp, policy, ident.id, st.audit, dry_run=dry, allow_reboot=args.allow_reboot, os_name=current_os())
    if report.mode == "enforce":
        st.mark_applied(sp.plan.plan_id)
    print("\nResults:")
    for r in report.results:
        line = f"  [{r.step_id}] {r.status:17} {r.title}"
        if r.reason:
            line += f"  ({r.reason})"
        if r.exit_code is not None:
            line += f"  exit={r.exit_code}"
        print(line)
    # report bundle
    with tempfile.TemporaryDirectory(prefix="aiit-report-") as tmp:
        root = Path(tmp)
        write_json(root / "report.json", report.model_dump())
        bundle_id = new_id("r-")
        manifest = BundleManifest(
            kind="execution_report", bundle_id=bundle_id, agent_id=ident.id, hostname=hostname(), platform=current_os(),
            os_version=os_version(), collected_at=iso(), aiit_version=__version__, case_id=sp.plan.case_id, plan_id=sp.plan.plan_id,
        )
        write_json(root / "manifest.json", manifest.model_dump())
        plaintext = pack_dir(root)
    out = Path(args.out) if args.out else st.outbox / f"report-{sp.plan.plan_id}-{bundle_id}.aiit"
    hdr = write_bundle(out, plaintext, enr.console_box_pub, ident, kind="execution_report", bundle_id=bundle_id, console_id=enr.console_id,
                       extra={"case_id": sp.plan.case_id, "plan_id": sp.plan.plan_id})
    print(f"\nReport written: {out}\nReturn it to the console: aiit-console report {out.name}")
    if args.push:
        _push(st, out, args.push, args.token, hdr)


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
    print(f"policy: mode={pol.mode} max_risk={pol.max_risk} deny_patterns={len(pol.deny_patterns)} allow_patterns={len(pol.allow_patterns)}")
    print(f"applied plans: {len(st.applied_plan_ids())}")
    ok, msg = st.audit.verify()
    print(f"audit chain: {'OK' if ok else 'BROKEN'} ({msg})")


def cmd_policy(args: argparse.Namespace) -> None:
    st = _state(args)
    pol = st.policy()
    if args.policy_cmd == "show":
        print(json.dumps(pol.to_dict(), indent=2))
    elif args.policy_cmd == "set-mode":
        pol.mode = args.value
        pol.save(st.policy_file)
        st.audit.record("policy_change", field="mode", value=args.value)
        print(f"policy mode = {args.value}")
    elif args.policy_cmd == "set-max-risk":
        pol.max_risk = args.value
        pol.save(st.policy_file)
        st.audit.record("policy_change", field="max_risk", value=args.value)
        print(f"policy max_risk = {args.value}")
    elif args.policy_cmd == "reset":
        from ..common.policy import Policy
        Policy().save(st.policy_file)
        st.audit.record("policy_change", field="reset", value="defaults")
        print("policy reset to defaults")


def cmd_audit(args: argparse.Namespace) -> None:
    st = _state(args)
    ok, msg = st.audit.verify()
    print(("OK: " if ok else "BROKEN: ") + msg)
    if args.tail:
        for e in st.audit.entries()[-args.tail:]:
            print(json.dumps(e))
    if not ok:
        sys.exit(1)


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aiit-agent", description="AI_IT endpoint agent")
    p.add_argument("--data-dir", help="state directory (default: AIIT_AGENT_DIR or ~/.aiit/agent)")
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
    s.add_argument("--token", help="server token (or AIIT_SERVER_TOKEN)")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("apply", help="verify and run a signed plan")
    s.add_argument("plan", help="path to <plan>.signed.json")
    s.add_argument("--dry-run", action="store_true", help="force dry run even if policy mode is enforce")
    s.add_argument("--allow-reboot", action="store_true")
    s.add_argument("--yes", action="store_true", help="skip the APPLY confirmation")
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
    a = ps.add_parser("set-mode"); a.add_argument("value", choices=["dry_run", "enforce"])
    a = ps.add_parser("set-max-risk"); a.add_argument("value", choices=["read_only", "low", "medium", "high"])
    ps.add_parser("reset")
    s.set_defaults(func=cmd_policy)

    s = sub.add_parser("audit", help="verify the local audit chain")
    s.add_argument("--tail", type=int, default=0)
    s.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    main()
