"""Read-only dashboard: loopback bind, routing, escaping, headers, and that a GET never touches the audit log."""
import http.client
import json
import socket
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from . import helpers
from aiit.console import dashboard as dash
from aiit.console.dashboard import make_dashboard_server, render_case, render_dashboard
from aiit.console.llm import get_provider
from aiit.console.planner import approve, diagnose

# Planted markup. If any of these reach the page unescaped, a bundle or a model answer could run script in the operator's browser.
STEP_TITLE = "Check <script>alert('step')</script> disk"
REPORT_REASON = "policy said <script>alert('reason')</script> no"
ISSUE_TEXT = "printer <script>alert('issue')</script> offline for jdoe@example.org"
HOSTNAME = "lab-pc-07<i>styled</i>"
OPERATOR = "ops<b>bold</b>"


def _populate(root: Path):
    """A console with one case, one approved dryrun plan (first step title tampered with markup) and one report."""
    state = helpers.make_console(root / "console")
    agent = helpers.agent_identity()
    bundle = helpers.seal_diagnostics(state, agent, root / "d.aiit", hostname=HOSTNAME, issue=ISSUE_TEXT,
                                      files={"sys/echo.txt": "svc ok for jdoe@example.org\n"})
    case_id, _, _ = state.ingest_bundle(bundle)
    plan, _ = diagnose(state, case_id, "mail is slow", get_provider("dryrun"), max_chars=50_000)
    plan_file = state.case_dir(case_id) / "plans" / f"{plan.plan_id}.json"
    data = json.loads(plan_file.read_text(encoding="utf-8"))
    data["steps"][0]["title"] = STEP_TITLE
    plan_file.write_text(json.dumps(data), encoding="utf-8")
    approve(state, case_id, plan.plan_id, operator=OPERATOR)
    report = helpers.seal_report(state, agent, root / "r.aiit", case_id, plan.plan_id, [
        {"step_id": "s1", "title": STEP_TITLE, "status": "failed", "exit_code": 2, "reason": REPORT_REASON},
        {"step_id": "s2", "title": "List failed units", "status": "dry_run"},
        {"step_id": "s3", "title": "Blocked one", "status": "blocked_by_policy", "reason": "deny pattern"},
    ])
    state.ingest_bundle(report)
    state.audit.checkpoint(state.identity())  # what every CLI command does after a state change
    return state, agent, case_id, plan.plan_id, data


class DashboardBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state, self.agent, self.case_id, self.plan_id, self.plan_data = _populate(self.root)
        self.srv = make_dashboard_server(self.state, "127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def get(self, path, method="GET", body=None):
        req = urllib.request.Request(self.url + path, data=body, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8"), dict(e.headers)

    def assert_security_headers(self, headers):
        for name, value in dash.SECURITY_HEADERS.items():
            self.assertEqual(headers.get(name), value, name)
        self.assertEqual(headers.get("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertTrue(headers.get("Content-Type", "").startswith("text/html"))


class OverviewTests(DashboardBase):
    def test_overview_lists_cases_agents_and_audit_state(self):
        status, body, headers = self.get("/")
        self.assertEqual(status, 200)
        self.assert_security_headers(headers)
        self.assertIn(self.case_id, body)
        self.assertIn(f'href="/case/{self.case_id}"', body)
        self.assertIn(self.agent.id, body)
        self.assertIn(self.state.console_id_or_none(), body)
        self.assertIn("audit OK", body)
        self.assertIn("entries verified", body)
        signed_seq = json.loads(self.state.audit.head_path.read_text(encoding="utf-8"))["seq"]
        self.assertIn(f"signed checkpoint seq {signed_seq}", body)
        self.assertIn(f"chain head seq {self.state.audit.head()['seq']}", body)
        self.assertIn('<meta http-equiv="refresh" content="15">', body)
        self.assertIn("read-only; use the CLI to act", body)
        self.assertIn("Rendered 20", body)
        self.assertIn('<span class="badge warn">new</span>', body)  # trust state as recorded on the case
        # the overview shows the host token from the redacted manifest, not the raw hostname
        self.assertIn("&lt;HOST_", body)
        self.assertNotIn("<i>styled</i>", body)
        self.assertNotIn("<script", body)

    def test_page_has_no_script_and_no_external_resources(self):
        for path in ("/", f"/case/{self.case_id}"):
            _, body, _ = self.get(path)
            low = body.lower()
            self.assertNotIn("<script", low, path)
            self.assertNotIn("<link", low, path)
            self.assertNotIn("src=", low, path)
            self.assertNotIn("javascript:", low, path)
            self.assertNotIn("onload", low, path)

    def test_head_and_write_methods(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.read(), b"")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        conn.close()
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            status, body, headers = self.get("/", method=method, body=b"x=1")
            self.assertEqual(status, 405, method)
            self.assertEqual(headers.get("Allow"), "GET, HEAD")
            self.assert_security_headers(headers)
            self.assertIn("read-only", body)


class CasePageTests(DashboardBase):
    def test_case_page_shows_plan_steps_and_report_results(self):
        status, body, headers = self.get(f"/case/{self.case_id}")
        self.assertEqual(status, 200)
        self.assert_security_headers(headers)
        self.assertIn(self.case_id, body)
        self.assertIn(self.plan_id, body)
        for step in self.plan_data["steps"]:
            self.assertIn(dash._t(step["title"]), body)
            if step["command"]:
                self.assertIn(f"<code>{dash._t(step['command'])}</code>", body)
        self.assertIn("approved and signed", body)
        self.assertIn(dash._t(OPERATOR), body)
        self.assertIn("risk-read_only", body)
        self.assertIn("dryrun/none", body)
        self.assertIn("st-failed", body)
        self.assertIn("st-dry_run", body)
        self.assertIn("st-blocked_by_policy", body)
        self.assertIn("deny pattern", body)
        self.assertIn("&lt;HOST_", body)
        self.assertIn("&lt;EMAIL_", body)  # the issue text is the redacted one
        self.assertNotIn("jdoe@example.org", body)
        self.assertNotIn("svc ok for", body)  # collected files are never rendered

    def test_planted_markup_is_escaped_everywhere(self):
        _, body, _ = self.get(f"/case/{self.case_id}")
        self.assertNotIn("<script", body)
        self.assertNotIn("<b>bold</b>", body)
        self.assertIn("&lt;script&gt;alert(&#x27;step&#x27;)&lt;/script&gt;", body)
        self.assertIn("&lt;script&gt;alert(&#x27;reason&#x27;)&lt;/script&gt;", body)
        self.assertIn("&lt;script&gt;alert(&#x27;issue&#x27;)&lt;/script&gt;", body)
        self.assertIn("ops&lt;b&gt;bold&lt;/b&gt;", body)
        _, over, _ = self.get("/")
        self.assertNotIn("<script", over)
        self.assertNotIn("<i>styled</i>", over)

    def test_unknown_paths_and_bad_ids_are_404(self):
        for path in ("/nope", "/index.html", "/case", "/case/", "/case/../keys/identity.json", "/case/%2e%2e/x",
                     "/case/not-an-id!", "/case/plan-ffffffffffff", f"/case/{self.case_id}/extra", f"/cases/{self.case_id}",
                     "/case/" + "a" * 300, "/v1/health", "/audit.jsonl"):
            status, body, headers = self.get(path)
            self.assertEqual(status, 404, path)
            self.assert_security_headers(headers)
            self.assertNotIn("Traceback", body)
        # a query string is ignored, not a reason to 404
        self.assertEqual(self.get(f"/case/{self.case_id}?x=1")[0], 200)

    def test_render_case_raises_for_bad_or_missing_ids(self):
        with self.assertRaises(ValueError):
            render_case(self.state, "../etc")
        with self.assertRaises(FileNotFoundError):
            render_case(self.state, "case-ffffffffffff")

    def test_damaged_plan_or_report_file_is_reported_not_raised(self):
        cdir = self.state.case_dir(self.case_id)
        (cdir / "plans" / f"{self.plan_id}.json").write_text("{not json", encoding="utf-8")
        report_dir = next(p for p in (cdir / "reports").iterdir() if p.is_dir())
        (report_dir / "report.json").unlink()
        status, body, _ = self.get(f"/case/{self.case_id}")
        self.assertEqual(status, 200)
        self.assertIn("plan file unreadable", body)
        self.assertIn("report file unreadable", body)
        self.assertNotIn("Traceback", body)


class ReadOnlyTests(DashboardBase):
    def test_get_never_changes_the_audit_log_or_the_checkpoint(self):
        log_before = self.state.audit.path.read_bytes()
        head_before = self.state.audit.head_path.read_bytes()
        n_before = len(self.state.audit.entries())
        for _ in range(3):
            self.assertEqual(self.get("/")[0], 200)
            self.assertEqual(self.get(f"/case/{self.case_id}")[0], 200)
            self.assertEqual(self.get("/nope")[0], 404)
            self.assertEqual(self.get("/", method="POST", body=b"act=approve")[0], 405)
        self.assertEqual(self.state.audit.path.read_bytes(), log_before)
        self.assertEqual(self.state.audit.head_path.read_bytes(), head_before)
        self.assertEqual(len(self.state.audit.entries()), n_before)
        self.assertEqual(sorted(self.state.inbox.glob("*")) if self.state.inbox.exists() else [], [])

    def test_broken_chain_is_shown_without_appending_an_entry(self):
        # check_and_alert would append audit_chain_broken; the dashboard must only verify and display
        helpers.tamper_audit_line(self.state.audit.path, 1, lambda e: e["details"].update({"files": 99}))
        size_before = self.state.audit.path.stat().st_size
        status, body, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("AUDIT BROKEN", body)
        self.assertNotIn("audit OK", body)
        self.assertEqual(self.state.audit.path.stat().st_size, size_before)
        self.assertNotIn(b"audit_chain_broken", self.state.audit.path.read_bytes())


class BindTests(unittest.TestCase):
    def test_non_loopback_hosts_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            state = helpers.make_console(Path(d))
            for host in ("0.0.0.0", "10.1.2.3", "::", "localhost", "", "127.0.0.2", "127.0.0.1 "):
                with self.assertRaises(ValueError, msg=host):
                    make_dashboard_server(state, host, 0)
            srv = make_dashboard_server(state, "127.0.0.1", 0)
            self.assertEqual(srv.server_address[0], "127.0.0.1")
            srv.server_close()

    def test_ipv6_loopback_is_accepted(self):
        if not socket.has_ipv6:
            self.skipTest("no IPv6 support")
        with tempfile.TemporaryDirectory() as d:
            state = helpers.make_console(Path(d))
            try:
                srv = make_dashboard_server(state, "::1", 0)
            except OSError as e:  # the runner has IPv6 compiled in but no ::1 interface
                self.skipTest(f"::1 not bindable here: {e}")
            try:
                self.assertEqual(srv.server_address[0], "::1")
            finally:
                srv.server_close()

    def test_render_on_an_empty_console(self):
        with tempfile.TemporaryDirectory() as d:
            state = helpers.make_console(Path(d))
            page = render_dashboard(state)
            self.assertTrue(page.startswith("<!DOCTYPE html>"))
            self.assertIn("No cases yet", page)
            self.assertIn("No agents", page)
            self.assertIn("signed checkpoint seq none", page)
            self.assertIn(state.console_id_or_none(), page)
            self.assertNotIn("<script", page)


if __name__ == "__main__":
    unittest.main()
