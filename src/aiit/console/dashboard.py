"""Read-only local dashboard: the console state as one self-contained HTML page.

Trust boundary
--------------
* Binds to a loopback address only (``127.0.0.1`` or ``::1``); any other host
  is a ``ValueError``. There is no authentication, by design: whoever can reach
  the port is already the operator at this machine, the same person who can
  run the CLI against the same directory. ``localhost`` is refused on purpose,
  because a hosts-file entry can point it anywhere.
* Nothing writes. Only ``GET`` and ``HEAD`` are served (every other method is
  405), the audit chain is checked with ``AuditLog.verify`` and never with
  ``check_and_alert`` (which appends an entry and fires the alert sinks), and
  no file under the console directory is created or modified.
* Every value that originates in a bundle, a model answer or an operator's
  text goes through ``html.escape`` before it reaches the page. Raw collected
  files and command output (stdout, stderr) are never rendered; the page shows
  metadata, plan steps and per-step results. Where a redacted form exists (the
  hostname token, the issue text) the page shows that form.
* The page carries no script. The Content-Security-Policy allows inline styles
  and nothing else; the auto-refresh is a ``<meta http-equiv="refresh">`` tag.

The same data the CLI prints (``cases``, ``plans``, ``plan``, ``report``,
``agents``, ``audit verify``) is read through the same store and planner
helpers, so the page cannot disagree with the terminal.
"""
from __future__ import annotations

import html
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .. import __version__
from ..common.schema import RISK_ORDER, ExecutionReport, FixPlan
from ..common.util import iso, read_json, safe_join, validate_id
from .planner import load_plan
from .store import ConsoleState

LOOPBACK_HOSTS = ("127.0.0.1", "::1")
DEFAULT_PORT = 8788
REFRESH_SECONDS = 15
SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
}
STEP_STATUSES = ("success", "failed", "dry_run", "blocked_by_policy", "skipped", "manual", "timeout")

CSS = """
:root{--fg:#1b1b1b;--bg:#fff;--muted:#5f6368;--line:#d4d7dc;--zebra:#f6f7f9;--head:#eceff3;--link:#0b57d0;
--ok:#0a6b1e;--bad:#b00020;--warn:#8a5300;--info:#174ea6;--ok-bg:#e6f4ea;--bad-bg:#fce8e6;--warn-bg:#fef3dc;--info-bg:#e8f0fe;--grey-bg:#eceff1}
@media (prefers-color-scheme:dark){:root{--fg:#e6e6e6;--bg:#141618;--muted:#a0a6ad;--line:#3a3f45;--zebra:#1b1e21;--head:#23272b;--link:#8ab4f8;
--ok:#7bd88f;--bad:#ff8a80;--warn:#ffcc66;--info:#9ec1ff;--ok-bg:#163a21;--bad-bg:#4a1b1b;--warn-bg:#4a3a10;--info-bg:#1b2f4a;--grey-bg:#2b2f33}}
body{font-family:system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;margin:0;padding:18px 24px;color:var(--fg);background:var(--bg);font-size:14px}
a{color:var(--link)}h1{font-size:1.4em;margin:0 0 4px}h2{font-size:1.15em;margin:26px 0 8px}h3{font-size:1em;margin:18px 0 6px}
header{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:baseline;border-bottom:1px solid var(--line);padding-bottom:10px}
.meta{color:var(--muted)}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
table{border-collapse:collapse;width:100%;margin:6px 0 10px}th,td{border:1px solid var(--line);padding:4px 7px;text-align:left;vertical-align:top}
th{background:var(--head);font-weight:600}tbody tr:nth-child(even){background:var(--zebra)}td.num{text-align:right}
.badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:12px;font-weight:600;white-space:nowrap}
.ok{color:var(--ok);background:var(--ok-bg)}.bad{color:var(--bad);background:var(--bad-bg)}.warn{color:var(--warn);background:var(--warn-bg)}
.info{color:var(--info);background:var(--info-bg)}.grey{color:var(--muted);background:var(--grey-bg)}
.risk-read_only{color:var(--ok);background:var(--ok-bg)}.risk-low{color:var(--info);background:var(--info-bg)}
.risk-medium{color:var(--warn);background:var(--warn-bg)}.risk-high{color:var(--bad);background:var(--bad-bg)}.risk-unknown{background:var(--grey-bg)}
.st-success{color:var(--ok);background:var(--ok-bg)}.st-dry_run{color:var(--info);background:var(--info-bg)}.st-manual{color:var(--info);background:var(--info-bg)}
.st-failed,.st-timeout,.st-blocked_by_policy{color:var(--bad);background:var(--bad-bg)}.st-skipped,.st-unknown{color:var(--muted);background:var(--grey-bg)}
section.plan,section.report{border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:10px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:6px 0}dt{color:var(--muted)}dd{margin:0}
ul.warnings{margin:4px 0;padding-left:20px;color:var(--warn)}p.empty{color:var(--muted);font-style:italic}
footer{margin-top:28px;border-top:1px solid var(--line);padding-top:8px;color:var(--muted);font-size:12.5px}
"""


# --------------------------------------------------------------------------- helpers
def _t(value: Any) -> str:
    """Text for the page: str() then html.escape. Used for every dynamic value, no exceptions."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _read_json_or_none(path: Path) -> Any:
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def _risk_class(risk: Any) -> str:
    return f"risk-{risk}" if risk in RISK_ORDER else "risk-unknown"


def _status_class(status: Any) -> str:
    return f"st-{status}" if status in STEP_STATUSES else "st-unknown"


def _badge(text: Any, cls: str) -> str:
    return f'<span class="badge {cls}">{_t(text)}</span>'


def _last_activity(case: dict[str, Any]) -> str:
    stamps = [case.get("created_at")]
    for p in case.get("plans", []) or []:
        stamps += [p.get("created_at"), p.get("approved_at")]
    for r in case.get("reports", []) or []:
        stamps.append(r.get("received_at"))
    return max((str(s) for s in stamps if s), default="")


def _audit_status(state: ConsoleState) -> dict[str, Any]:
    """Chain verdict without side effects: ``verify`` only, never ``check_and_alert``."""
    ok, message = state.audit.verify(expected_pub=state.public_sign_key())
    head = state.audit.head() or {}
    signed_seq: int | None = None
    cp = _read_json_or_none(state.audit.head_path)
    if isinstance(cp, dict):
        seq = cp.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool):
            signed_seq = seq
    return {"ok": ok, "message": message, "head_seq": head.get("seq"), "head_hash": head.get("hash"), "signed_seq": signed_seq}


def _hostname_token(state: ConsoleState, case: dict[str, Any]) -> str:
    """The case's ``<HOST_...>`` token from the redacted manifest; the raw hostname stays off the page."""
    try:
        cdir = state.case_dir(str(case.get("case_id", "")))
    except (ValueError, FileNotFoundError):
        return ""
    manifest = _read_json_or_none(cdir / "redacted" / "manifest.json")
    return str(manifest.get("hostname", "")) if isinstance(manifest, dict) else ""


# --------------------------------------------------------------------------- page pieces
def _page(title: str, body: str, state: ConsoleState, audit: dict[str, Any], now: str, *, subpage: bool) -> str:
    console_id = state.console_id_or_none()
    chain = _badge(f"audit OK ({audit['message']})", "ok") if audit["ok"] else _badge(f"AUDIT BROKEN: {audit['message']}", "bad")
    head_seq = audit["head_seq"] if audit["head_seq"] is not None else "-"
    signed_seq = audit["signed_seq"] if audit["signed_seq"] is not None else "none"
    nav = '<a href="/">all cases</a>' if subpage else ""
    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="refresh" content="{REFRESH_SECONDS}">'
        f"<title>{_t(title)}</title><style>{CSS}</style></head><body>"
        "<header><h1>AI_IT console</h1>"
        f'<span class="meta">console <code>{_t(console_id or "not initialized")}</code></span>'
        f'<span>{chain}</span><span class="meta">chain head seq {_t(head_seq)} · signed checkpoint seq {_t(signed_seq)}</span>'
        f"<span>{nav}</span></header>"
        f"{body}"
        f'<footer>Rendered {_t(now)} · aiit-console {_t(__version__)} · refreshes every {REFRESH_SECONDS} s · '
        "<strong>read-only; use the CLI to act</strong></footer></body></html>\n"
    )


def _cases_table(state: ConsoleState, cases: list[dict[str, Any]]) -> str:
    if not cases:
        return '<p class="empty">No cases yet. Ingest a bundle with the CLI.</p>'
    rows = []
    for c in cases:
        cid = str(c.get("case_id", ""))
        try:
            validate_id(cid, "case_id")
            link = f'<a href="/case/{_t(cid)}"><code>{_t(cid)}</code></a>'
        except ValueError:
            link = f"<code>{_t(cid)}</code>"
        trust = str(c.get("agent_trust", ""))
        rows.append(
            "<tr>"
            f"<td>{link}</td><td>{_t(c.get('created_at'))}</td><td><code>{_t(_hostname_token(state, c))}</code></td>"
            f"<td>{_t(c.get('platform'))}</td><td><code>{_t(c.get('agent_id'))}</code></td>"
            f"<td>{_badge(trust or '?', 'ok' if trust == 'known' else 'warn')}</td>"
            f"<td class=\"num\">{_t(len(c.get('plans', []) or []))}</td><td class=\"num\">{_t(len(c.get('reports', []) or []))}</td>"
            f"<td>{_t(_last_activity(c))}</td></tr>"
        )
    return ("<table><thead><tr><th>Case</th><th>Created</th><th>Host token</th><th>Platform</th><th>Agent</th><th>Trust</th>"
            "<th>Plans</th><th>Reports</th><th>Last activity</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _agents_table(agents: dict[str, Any]) -> str:
    if not agents:
        return '<p class="empty">No agents enrolled with this console yet.</p>'
    rows = []
    for aid, a in agents.items():
        a = a if isinstance(a, dict) else {}
        head = a.get("last_audit_head") if isinstance(a.get("last_audit_head"), dict) else {}
        key = str(a.get("sign_pub", ""))[:16]
        rows.append(
            f"<tr><td><code>{_t(aid)}</code></td><td>{_t(a.get('hostname'))}</td><td>{_t(a.get('platform', '?'))}</td>"
            f"<td>{_t(a.get('first_seen'))}</td><td>{_t(a.get('last_seen'))}</td><td><code>{_t(key)}&hellip;</code></td>"
            f"<td class=\"num\">{_t(head.get('seq', '-'))}</td></tr>"
        )
    return ("<table><thead><tr><th>Agent</th><th>Hostname</th><th>Platform</th><th>First seen</th><th>Last seen</th><th>Key</th>"
            "<th>Audit seq</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def _steps_table(plan: FixPlan, warnings: list[str]) -> str:
    rows = []
    for s in plan.steps:
        step_warnings = [w for w in warnings if w.startswith(f"step {s.id} ") or w.startswith(f"duplicate step id {s.id}")]
        if s.action == "command":
            what = f"<code>{_t(s.command)}</code>"
        else:
            what = f"manual: {_t(s.expected_outcome or s.rationale)}"
        extra = []
        if s.requires_reboot:
            extra.append(_badge("reboot", "warn"))
        if s.action == "command" and s.expected_outcome:
            extra.append(f'<div class="meta">expect: {_t(s.expected_outcome)}</div>')
        if s.rollback:
            extra.append(f'<div class="meta">rollback: {_t(s.rollback)}</div>')
        for w in step_warnings:
            extra.append(f'<div class="warn">warning: {_t(w)}</div>')
        rows.append(
            f"<tr><td><code>{_t(s.id)}</code></td><td>{_badge(s.risk, _risk_class(s.risk))}</td><td>{_t(s.title)}"
            f'<div class="meta">{_t(s.rationale)}</div></td><td>{_t(s.os)}</td><td>{what}{"".join(extra)}</td></tr>'
        )
    return ("<table><thead><tr><th>Step</th><th>Risk</th><th>Title</th><th>OS</th><th>Action</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _render_plan(cdir: Path, summary: dict[str, Any]) -> str:
    pid = str(summary.get("plan_id", ""))
    approved = bool(summary.get("approved"))
    state_badge = _badge("approved and signed", "ok") if approved else _badge("not approved", "grey")
    head = f"<h3>Plan <code>{_t(pid)}</code> {state_badge}</h3>"
    try:
        plan = load_plan(cdir, pid)
    except (ValueError, OSError) as e:  # bad id, missing file or a plan that no longer validates
        return f'<section class="plan">{head}<p class="bad">plan file unreadable ({_t(type(e).__name__)})</p></section>'
    warnings = [str(w) for w in (summary.get("warnings") or [])]
    approval = (f"by {_t(summary.get('approved_by'))} at {_t(summary.get('approved_at'))}" if approved
                else "unsigned; approve it with the CLI")
    parts = [
        f'<section class="plan">{head}<dl>',
        f"<dt>Created</dt><dd>{_t(plan.created_at)}</dd><dt>Expires</dt><dd>{_t(plan.expires_at)}</dd>",
        f"<dt>Provider</dt><dd>{_t(plan.provider)}/{_t(plan.model)} (attempts: {_t(summary.get('attempts', 1))})</dd>",
        f"<dt>Confidence</dt><dd>{_t(f'{plan.confidence:.0%}')}</dd><dt>Approval</dt><dd>{approval}</dd>",
        f"<dt>Target</dt><dd><code>{_t(plan.target_agent_id)}</code> ({_t(plan.target_os)})</dd>",
        f"<dt>Issue</dt><dd>{_t(plan.issue_summary)}</dd><dt>Diagnosis</dt><dd>{_t(plan.diagnosis)}</dd>",
    ]
    if plan.alternative_causes:
        parts.append(f"<dt>Alternatives</dt><dd>{'; '.join(_t(a) for a in plan.alternative_causes)}</dd>")
    if plan.more_data_needed:
        parts.append(f"<dt>More data needed</dt><dd>{'; '.join(_t(m) for m in plan.more_data_needed)}</dd>")
    if plan.notes_for_operator:
        parts.append(f"<dt>Notes</dt><dd>{_t(plan.notes_for_operator)}</dd>")
    parts.append("</dl>")
    if warnings:
        parts.append(f"<p>{_badge(f'{len(warnings)} lint warning(s)', 'warn')}</p><ul class=\"warnings\">"
                     + "".join(f"<li>{_t(w)}</li>" for w in warnings) + "</ul>")
    parts.append(_steps_table(plan, warnings))
    parts.append("</section>")
    return "".join(parts)


def _render_report(cdir: Path, summary: dict[str, Any]) -> str:
    bid = str(summary.get("bundle_id", ""))
    head = (f"<h3>Report <code>{_t(bid)}</code> for plan <code>{_t(summary.get('plan_id'))}</code> "
            f"{_badge(summary.get('mode', '?'), 'info' if summary.get('mode') == 'dry_run' else 'warn')}</h3>"
            f'<div class="meta">received {_t(summary.get("received_at"))}</div>')
    try:
        validate_id(bid, "bundle_id")
        report = ExecutionReport.model_validate(read_json(safe_join(cdir / "reports", bid) / "report.json"))
    except (ValueError, OSError) as e:
        return f'<section class="report">{head}<p class="bad">report file unreadable ({_t(type(e).__name__)})</p></section>'
    rows = []
    for r in report.results:
        exit_code = "" if r.exit_code is None else str(r.exit_code)
        rows.append(
            f"<tr><td><code>{_t(r.step_id)}</code></td><td>{_badge(r.status, _status_class(r.status))}</td><td>{_t(r.title)}</td>"
            f"<td class=\"num\">{_t(exit_code)}</td><td>{_t(r.reason)}</td></tr>"
        )
    return (
        f'<section class="report">{head}<dl><dt>Started</dt><dd>{_t(report.started_at)}</dd><dt>Ended</dt><dd>{_t(report.ended_at)}</dd>'
        f"<dt>Policy</dt><dd>version {_t(report.policy_version)}</dd></dl>"
        "<table><thead><tr><th>Step</th><th>Status</th><th>Title</th><th>Exit</th><th>Reason</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
        '<p class="meta">Command output is not shown here; the CLI report command prints it with -v.</p></section>'
    )


# --------------------------------------------------------------------------- public renderers
def render_dashboard(state: ConsoleState) -> str:
    """The overview: audit verdict, every case, every agent. Pure read; raises nothing for ordinary store states."""
    now = iso()
    audit = _audit_status(state)
    cases = state.list_cases()
    body = (
        f"<h2>Cases ({len(cases)})</h2>{_cases_table(state, cases)}"
        f"<h2>Agents</h2>{_agents_table(state.agents())}"
    )
    return _page("AI_IT console", body, state, audit, now, subpage=False)


def render_case(state: ConsoleState, case_id: str) -> str:
    """One case with its plans (steps, risk, approval) and reports (per-step status).

    Raises ValueError for an id that is not shaped like a case id and FileNotFoundError when there is no such case.
    """
    validate_id(case_id, "case_id")
    cdir = state.case_dir(case_id)
    case = read_json(cdir / "case.json")
    if not isinstance(case, dict):
        raise FileNotFoundError(f"case {case_id} has no readable case.json")
    now = iso()
    audit = _audit_status(state)
    red_manifest = _read_json_or_none(cdir / "redacted" / "manifest.json")
    red_manifest = red_manifest if isinstance(red_manifest, dict) else {}
    trust = str(case.get("agent_trust", ""))
    counts = case.get("redaction_counts") or {}
    counts_text = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) if isinstance(counts, dict) and counts else "none"
    parts = [
        f"<h2>Case <code>{_t(case_id)}</code></h2><dl>",
        f"<dt>Created</dt><dd>{_t(case.get('created_at'))}</dd><dt>Collected</dt><dd>{_t(case.get('collected_at'))}</dd>",
        f"<dt>Host token</dt><dd><code>{_t(red_manifest.get('hostname', ''))}</code></dd>",
        f"<dt>Platform</dt><dd>{_t(case.get('platform'))} {_t(case.get('os_version'))}</dd>",
        f"<dt>Agent</dt><dd><code>{_t(case.get('agent_id'))}</code> {_badge(trust or '?', 'ok' if trust == 'known' else 'warn')}</dd>",
        f"<dt>Bundle</dt><dd><code>{_t(case.get('bundle_id'))}</code>, {_t(case.get('files', 0))} files, "
        f"{_t(case.get('collector_errors', 0))} collector errors</dd>",
        f"<dt>Redactions</dt><dd>{_t(counts_text)}</dd>",
        f"<dt>Issue (redacted)</dt><dd>{_t(red_manifest.get('issue_description', '')) or '<span class=\"meta\">none</span>'}</dd></dl>",
    ]
    plans = case.get("plans") or []
    parts.append(f"<h2>Plans ({len(plans)})</h2>")
    if not plans:
        parts.append('<p class="empty">No plans. Run diagnose with the CLI.</p>')
    for p in plans:
        parts.append(_render_plan(cdir, p if isinstance(p, dict) else {}))
    reports = sorted((r for r in (case.get("reports") or []) if isinstance(r, dict)), key=lambda r: str(r.get("received_at", "")))
    parts.append(f"<h2>Reports ({len(reports)})</h2>")
    if not reports:
        parts.append('<p class="empty">No execution reports yet.</p>')
    for r in reports:
        parts.append(_render_report(cdir, r))
    return _page(f"Case {case_id}", "".join(parts), state, audit, now, subpage=True)


def _error_page(code: int, text: str) -> str:
    return ('<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>' + _t(f"{code} {text}") + "</title></head><body>"
            f"<h1>{_t(code)}</h1><p>{_t(text)}</p></body></html>\n")


# --------------------------------------------------------------------------- server
class DashboardHandler(BaseHTTPRequestHandler):
    server_version = f"aiit-console-dashboard/{__version__}"
    sys_version = ""
    timeout = 30  # a stalled browser connection must not hold a thread forever
    state: ConsoleState

    def log_message(self, fmt: str, *args: Any) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        line = "".join(ch if ch.isprintable() else "?" for ch in (fmt % args))[:400]
        print(f"[dashboard {ts}] {self.address_string()} {line}", file=sys.stderr)

    def _send(self, code: int, body: str, extra_headers: dict[str, str] | None = None, *, head_only: bool = False) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def _route(self) -> tuple[int, str]:
        path = urlparse(self.path).path
        try:
            if path == "/":
                return 200, render_dashboard(self.state)
            if path.startswith("/case/"):
                try:
                    return 200, render_case(self.state, path[len("/case/"):])
                except (ValueError, FileNotFoundError):
                    return 404, _error_page(404, "no such case")
            return 404, _error_page(404, "not found")
        except Exception as e:  # a damaged file must not take the server down or put a traceback on the page
            self.log_message("render failed: %s", type(e).__name__)
            return 500, _error_page(500, "the page could not be rendered; see the console log")

    def do_GET(self) -> None:
        code, body = self._route()
        self._send(code, body)

    def do_HEAD(self) -> None:
        code, body = self._route()
        self._send(code, body, head_only=True)

    def _read_only(self) -> None:
        self._send(405, _error_page(405, "the dashboard is read-only; use the CLI to act"), {"Allow": "GET, HEAD"})

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _read_only


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr: tuple[str, int], handler: type):
        if ":" in addr[0]:
            self.address_family = socket.AF_INET6
        super().__init__(addr, handler)


def make_dashboard_server(state: ConsoleState, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> HTTPServer:
    """A bound, not yet serving, HTTP server for the dashboard. Loopback only: anything else is a ValueError."""
    if host not in LOOPBACK_HOSTS:
        raise ValueError(f"the dashboard has no authentication and listens on loopback only (127.0.0.1 or ::1), not {host!r}")
    handler = type("BoundDashboardHandler", (DashboardHandler,), {"state": state})
    return DashboardServer((host, port), handler)
