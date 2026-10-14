"""aiit-console: runs on the operator machine."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from .. import __version__
from ..common.crypto import CryptoError
from ..common.net import NetError
from ..common.redact import RedactionConfig
from ..common.util import read_json
from .llm import PROVIDER_NAMES, ProviderError, ProviderRefusal, get_provider
from .planner import MAX_PLAN_HOURS_DEFAULT, approve, build_context, diagnose, format_plan, load_plan, plan_warnings
from .store import ConsoleState, default_console_dir, load_dotenv

EXIT_USAGE, EXIT_PROVIDER, EXIT_VERIFY = 2, 3, 4


def _state(args: argparse.Namespace) -> ConsoleState:
    return ConsoleState(Path(args.data_dir) if args.data_dir else None)


def _require_init(st: ConsoleState) -> None:
    if not st.is_initialized():
        sys.exit("Console not initialized. Run: aiit-console init")


def cmd_init(args: argparse.Namespace) -> None:
    st = _state(args)
    try:
        enr = st.init(label=args.label or "")
    except RuntimeError as e:
        sys.exit(str(e))
    print(f"Console initialized: {enr.console_id}")
    print(f"State dir (keep private, back up the keys): {st.root}")
    print(f"Enrollment file to copy to endpoints (public): {st.enrollment_file}")
    print(f"Put provider settings in {st.root / '.env'} (see .env.example); the console never reads .env from the current directory.")
    if not os.environ.get("AIIT_KEY_PASSPHRASE"):
        print("Note: AIIT_KEY_PASSPHRASE was not set, so private keys are stored unencrypted. Set it before init for at-rest key encryption.")
    st.audit.checkpoint(st.identity())


def cmd_enrollment(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    print(st.enrollment_file)
    print(json.dumps(read_json(st.enrollment_file), indent=2))


def cmd_ingest(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    cfg = RedactionConfig(redact_private_ips=args.redact_private_ips, extra_literals=[s for s in (args.redact or []) if s])
    try:
        case_id, manifest, case = st.ingest_bundle(Path(args.bundle), cfg)
    except FileNotFoundError as e:
        sys.exit(f"Ingest failed: {e}")
    except CryptoError as e:
        print(f"Ingest failed: {e}", file=sys.stderr)
        sys.exit(EXIT_VERIFY)
    st.audit.checkpoint(st.identity())
    if manifest.kind == "execution_report":
        print(f"Attached execution report to case {case_id}: {case['reports'][-1]}")
        return
    print(f"Case {case_id} created from {manifest.hostname} ({manifest.platform}, agent {manifest.agent_id}, trust={case['agent_trust']})")
    print(f"  files={case['files']} collector_errors={case['collector_errors']}")
    print(f"  redactions: {case['redaction_counts'] or 'none'}")
    if manifest.issue_description:
        print(f"  issue: {manifest.issue_description}")
    print(f"Next: aiit-console diagnose {case_id} --issue \"...\"")


def cmd_cases(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    cases = st.list_cases()
    if args.json:
        print(json.dumps(cases, indent=2))
        return
    for c in cases:
        print(f"{c['case_id']}  {c['created_at']}  {c['hostname']:20} {c['platform']:8} plans={len(c.get('plans', []))} "
              f"reports={len(c.get('reports', []))}  {c.get('issue_description', '')[:60]}")


def cmd_show(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    cdir = st.case_dir(args.case)
    print(json.dumps(read_json(cdir / "case.json"), indent=2))
    manifest = read_json(cdir / "raw" / "manifest.json")
    print("\nFiles:")
    for f in manifest["files"]:
        flag = f"  ERROR: {f['error']}" if f.get("error") else ""
        print(f"  {f['path']:40} {f['size']:>9}B exit={f.get('exit_code')}{flag}")


def cmd_preview(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    cdir = st.case_dir(args.case)
    if args.file:
        from ..common.util import safe_join
        print(safe_join(cdir / "redacted", args.file).read_text(encoding="utf-8", errors="replace"))
        return
    ctx, included = build_context(cdir, args.issue or "", max_chars=args.max_chars)
    print(ctx)
    print(f"\n[{len(ctx)} chars, {len(included)} files would be sent to the model]", file=sys.stderr)


def cmd_diagnose(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    name = args.provider or os.environ.get("AIIT_PROVIDER") or "ollama"
    try:
        provider = get_provider(name, model=args.model)
    except ProviderError as e:
        sys.exit(str(e))
    max_chars = args.max_chars if args.max_chars else min(150_000, getattr(provider, "max_input_chars", 150_000))
    print(f"Diagnosing {args.case} with {provider.name}/{provider.model} (prompt budget {max_chars} chars) ...")
    try:
        plan, warnings = diagnose(st, args.case, args.issue or "", provider, max_chars=max_chars, hours_valid=args.hours)
    except ProviderRefusal as e:
        print(f"Refused: {e}", file=sys.stderr)
        sys.exit(EXIT_PROVIDER)
    except ProviderError as e:
        print(f"Provider error: {e}", file=sys.stderr)
        sys.exit(EXIT_PROVIDER)
    st.audit.checkpoint(st.identity())
    print(format_plan(plan, warnings))
    print(f"\nSaved. Approve with: aiit-console approve {args.case} {plan.plan_id} --out <usb-dir>")


def cmd_plans(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    case = read_json(st.case_dir(args.case) / "case.json")
    if args.json:
        print(json.dumps(case.get("plans", []), indent=2))
        return
    for p in case.get("plans", []):
        print(f"{p['plan_id']}  {p['created_at']}  {p['provider']}/{p['model']}  steps={p['steps']} conf={p['confidence']:.0%}  "
              f"approved={p['approved']}  warnings={len(p.get('warnings', []))}")


def cmd_plan(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    cdir = st.case_dir(args.case)
    plan = load_plan(cdir, args.plan_id)
    if args.json:
        print(json.dumps(plan.model_dump(), indent=2))
        return
    print(format_plan(plan, plan_warnings(cdir, args.plan_id)))


def cmd_approve(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    cdir = st.case_dir(args.case)
    warnings = plan_warnings(cdir, args.plan_id)
    print(format_plan(load_plan(cdir, args.plan_id), warnings))
    if warnings and not args.ack_warnings and not args.yes:
        print(f"\n{len(warnings)} warning(s) above. Pass --ack-warnings to approve anyway.")
    if not args.yes:
        ans = input("\nSign this plan for the endpoint? Type APPROVE: ")
        if ans.strip() != "APPROVE":
            sys.exit("Not approved.")
    try:
        dest = approve(st, args.case, args.plan_id, operator=args.operator, out_dir=Path(args.out) if args.out else None,
                       hours_valid=args.hours, max_plan_hours=MAX_PLAN_HOURS_DEFAULT, long_lived=args.long_lived)
    except ValueError as e:
        sys.exit(str(e))
    st.audit.checkpoint(st.identity())
    print(f"Signed plan written: {dest}")
    print(f"On the endpoint: aiit-agent apply {dest.name}")


def cmd_report(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    try:
        case_id, manifest, case = st.ingest_bundle(Path(args.bundle))
    except FileNotFoundError as e:
        sys.exit(f"Report ingest failed: {e}")
    except CryptoError as e:
        print(f"Report ingest failed: {e}", file=sys.stderr)
        sys.exit(EXIT_VERIFY)
    st.audit.checkpoint(st.identity())
    if manifest.kind != "execution_report":
        sys.exit(f"That file is a {manifest.kind} bundle, not a report (it was ingested as case {case_id})")
    rep = read_json(st.case_dir(case_id) / "reports" / manifest.bundle_id / "report.json")
    print(f"Case {case_id} plan {rep['plan_id']} mode={rep['mode']} on {rep['hostname']}:")
    for r in rep["results"]:
        line = f"  [{r['step_id']}] {r['status']:17} {r['title']}"
        if r.get("exit_code") is not None:
            line += f" exit={r['exit_code']}"
        if r.get("reason"):
            line += f" ({r['reason']})"
        print(line)
        if args.verbose and (r.get("stdout") or r.get("stderr")):
            print("      stdout: " + (r.get("stdout") or "")[:2000].replace("\n", "\n              "))
            if r.get("stderr"):
                print("      stderr: " + r["stderr"][:1000].replace("\n", "\n              "))


def cmd_agents(args: argparse.Namespace) -> None:
    st = _state(args)
    _require_init(st)
    agents = st.agents()
    if args.json:
        print(json.dumps(agents, indent=2))
        return
    for aid, a in agents.items():
        head = a.get("last_audit_head") or {}
        print(f"{aid}  {a['hostname']:24} {a.get('platform', '?'):8} first_seen={a['first_seen']}  last_seen={a['last_seen']}  "
              f"key={a['sign_pub'][:16]}...  audit_seq={head.get('seq', '-')}")


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
        n = st.audit.export(args.format, Path(args.out), actions=args.action or None, case_id=args.case, since=args.since, until=args.until)
        print(f"wrote {n} entries to {args.out}")
    elif sub == "timeline":
        for e in st.audit.timeline(args.case):
            print(f"{e['ts']}  {e.get('label', e['action']):22} {json.dumps(e.get('details', {}))[:140]}")
    elif sub == "repair-tail":
        print(json.dumps(st.audit.repair_tail(), indent=2))


def cmd_serve(args: argparse.Namespace) -> None:
    from .server import make_server
    st = _state(args)
    _require_init(st)
    token = args.token or os.environ.get("AIIT_SERVER_TOKEN") or ""
    try:
        srv = make_server(st, args.host, args.port, token, args.tls_cert, args.tls_key, insecure_no_tls=args.insecure_no_tls,
                          max_concurrent=args.max_concurrent)
    except (ValueError, OSError) as e:
        sys.exit(str(e))
    scheme = "https" if args.tls_cert else "http"
    print(f"aiit-console serving on {scheme}://{args.host}:{srv.server_address[1]}  (Ctrl+C to stop)")
    if not args.tls_cert:
        print("Warning: no TLS. Payloads are encrypted anyway, but anyone on the network can see the mailbox traffic shape and replay the token.")
    st.audit.record("serve_start", host=args.host, port=srv.server_address[1], tls=bool(args.tls_cert))
    import threading
    try:
        minutes = max(1, int(os.environ.get("AIIT_AUDIT_CHECK_MINUTES", "60") or 60))
    except ValueError:
        minutes = 60
    stop = threading.Event()

    def periodic() -> None:
        while not stop.wait(minutes * 60):
            st.audit.check_and_alert(expected_pub=st.public_sign_key())

    threading.Thread(target=periodic, daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        st.audit.record("serve_stop")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aiit-console", description="AI_IT operator console")
    p.add_argument("--data-dir", help="state directory (default: AIIT_CONSOLE_DIR or ~/.aiit/console)")
    p.add_argument("--env-file", help="settings file to load (default: <data dir>/.env or AIIT_ENV_FILE)")
    p.add_argument("--debug", action="store_true", help="show tracebacks")
    p.add_argument("--version", action="version", version=f"aiit-console {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create the console identity and enrollment file"); s.add_argument("--label"); s.set_defaults(func=cmd_init)
    s = sub.add_parser("enrollment", help="print the public enrollment file"); s.set_defaults(func=cmd_enrollment)

    s = sub.add_parser("ingest", help="decrypt, verify and redact a bundle into a new case")
    s.add_argument("bundle")
    s.add_argument("--redact", action="append", metavar="TEXT", help="extra literal to pseudonymize (e.g. a patient name); repeatable")
    s.add_argument("--redact-private-ips", action="store_true")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("cases"); s.add_argument("--json", action="store_true"); s.set_defaults(func=cmd_cases)
    s = sub.add_parser("show"); s.add_argument("case"); s.set_defaults(func=cmd_show)
    s = sub.add_parser("preview", help="print exactly what would be sent to the model")
    s.add_argument("case"); s.add_argument("--file"); s.add_argument("--issue"); s.add_argument("--max-chars", type=int, default=150_000)
    s.set_defaults(func=cmd_preview)

    s = sub.add_parser("diagnose", help="ask the model for a fix plan")
    s.add_argument("case"); s.add_argument("--issue", help="what the user reports")
    s.add_argument("--provider", choices=list(PROVIDER_NAMES)); s.add_argument("--model")
    s.add_argument("--max-chars", type=int, default=0, help="prompt budget in characters (default: provider limit, at most 150000)")
    s.add_argument("--hours", type=float, default=24.0, help="plan validity")
    s.set_defaults(func=cmd_diagnose)

    s = sub.add_parser("plans"); s.add_argument("case"); s.add_argument("--json", action="store_true"); s.set_defaults(func=cmd_plans)
    s = sub.add_parser("plan"); s.add_argument("case"); s.add_argument("plan_id"); s.add_argument("--json", action="store_true"); s.set_defaults(func=cmd_plan)

    s = sub.add_parser("approve", help="sign a plan for its endpoint")
    s.add_argument("case"); s.add_argument("plan_id"); s.add_argument("--out", help="directory or file to copy the signed plan to (USB)")
    s.add_argument("--operator"); s.add_argument("--hours", type=float); s.add_argument("--long-lived", action="store_true", help="allow --hours above 72")
    s.add_argument("--ack-warnings", action="store_true"); s.add_argument("--yes", action="store_true")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("report", help="attach an execution report bundle to its case")
    s.add_argument("bundle"); s.add_argument("-v", "--verbose", action="store_true"); s.set_defaults(func=cmd_report)

    s = sub.add_parser("agents"); s.add_argument("--json", action="store_true"); s.set_defaults(func=cmd_agents)

    s = sub.add_parser("audit", help="verify, export or repair the audit chain")
    s.add_argument("--tail", type=int, default=0)
    asub = s.add_subparsers(dest="audit_cmd")
    asub.add_parser("verify")
    e = asub.add_parser("export"); e.add_argument("--format", choices=["csv", "jsonl", "html"], default="csv"); e.add_argument("--out", required=True)
    e.add_argument("--case"); e.add_argument("--action", action="append"); e.add_argument("--since"); e.add_argument("--until")
    t = asub.add_parser("timeline"); t.add_argument("case")
    asub.add_parser("repair-tail")
    s.set_defaults(func=cmd_audit)
    s = sub.add_parser("audit-verify", help="alias for: audit verify"); s.add_argument("--tail", type=int, default=0); s.set_defaults(func=cmd_audit, audit_cmd="verify")

    s = sub.add_parser("serve", help="LAN mailbox for agents")
    s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=8787)
    s.add_argument("--token"); s.add_argument("--tls-cert"); s.add_argument("--tls-key")
    s.add_argument("--insecure-no-tls", action="store_true", help="allow a non-loopback bind without TLS (trusted LAN only)")
    s.add_argument("--max-concurrent", type=int, default=32)
    s.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    root = Path(args.data_dir) if args.data_dir else default_console_dir()
    load_dotenv(explicit=Path(args.env_file) if args.env_file else None, console_dir=root)
    if args.cmd not in ("init",):
        try:
            st = ConsoleState(root)
            if st.is_initialized():
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
    except (ProviderError, NetError) as e:
        if args.debug:
            raise
        print(f"error: {e}", file=sys.stderr)
        sys.exit(EXIT_PROVIDER)
    except (ValidationError, ValueError, FileNotFoundError) as e:
        if args.debug:
            raise
        print(f"error: {str(e).splitlines()[0][:300]}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


if __name__ == "__main__":  # pragma: no cover
    main()
