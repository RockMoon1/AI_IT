"""Full offline loop: init -> enroll -> collect -> ingest -> diagnose -> approve -> apply -> report, plus LAN mode."""
import json
import os
import tempfile
import threading
import unittest
import unittest.mock as mock
import urllib.request
from pathlib import Path

from aiit.agent import cli as agent_cli
from aiit.agent import collectors
from aiit.agent.collectors import Collector, collect_all
from aiit.common.schema import SignedPlan
from aiit.common.util import current_os, read_json
from aiit.console import cli as console_cli
from aiit.console.server import make_server
from aiit.console.store import ConsoleState

TOKEN = "unit-test-token-0123456789abcdef"


def fake_collectors(os_name: str) -> list[Collector]:
    return [
        Collector("echo_ok", "sys", ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'svc ok user@example.org 11.22.33.44'"] if os.name == "nt" else ["sh", "-c", "echo 'svc ok user@example.org 11.22.33.44'"], "txt", 120),  # PowerShell cold start on a loaded runner is slow
        Collector("missing_tool", "logs", ["definitely-not-a-real-command-xyz"], "txt", 5),
    ]


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.cdir, self.adir, self.usb = root / "console", root / "agent", root / "usb"
        self.usb.mkdir()
        self.patch = mock.patch.object(collectors, "collectors_for", fake_collectors)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def console(self, *argv: str) -> None:
        console_cli.main(["--data-dir", str(self.cdir), *argv])

    def agent(self, *argv: str) -> None:
        agent_cli.main(["--data-dir", str(self.adir), *argv])

    def test_sneakernet_loop(self):
        self.console("init", "--label", "test")
        enr = self.cdir / "enrollment" / "console-enrollment.json"
        self.assertTrue(enr.exists())
        self.assertNotIn("sign.key", enr.read_text())
        self.agent("enroll", str(enr))
        bundle = self.usb / "case.aiit"
        self.agent("collect", "--issue", "printer offline for jdoe@example.org", "--out", str(bundle), "--no-osquery", "--quick")
        self.assertTrue(bundle.exists())
        self.assertNotIn(b"jdoe@example.org", bundle.read_bytes())   # encrypted at rest on the stick

        self.console("ingest", str(bundle))
        st = ConsoleState(self.cdir)
        cases = st.list_cases()
        self.assertEqual(len(cases), 1)
        case = cases[0]
        case_id = case["case_id"]
        self.assertEqual(case["agent_trust"], "new")
        self.assertEqual(case["collector_errors"], 1)
        redacted = (self.cdir / "cases" / case_id / "redacted" / "sys" / "echo_ok.txt").read_text()
        self.assertNotIn("user@example.org", redacted)
        self.assertNotIn("11.22.33.44", redacted)
        self.assertIn("<EMAIL_", redacted)
        m = read_json(self.cdir / "cases" / case_id / "redacted" / "manifest.json")
        self.assertIn("<EMAIL_", m["issue_description"])
        self.assertTrue(m["hostname"].startswith("<HOST_"))

        self.console("diagnose", case_id, "--provider", "dryrun", "--issue", "printer offline")
        plans = read_json(self.cdir / "cases" / case_id / "case.json")["plans"]
        self.assertEqual(len(plans), 1)
        plan_id = plans[0]["plan_id"]
        self.console("approve", case_id, plan_id, "--yes", "--out", str(self.usb))
        signed = self.usb / f"{plan_id}.signed.json"
        sp = SignedPlan.model_validate(read_json(signed))
        self.assertEqual(sp.plan.target_os, current_os())

        # dry run by default, no confirmation needed
        report = self.usb / "report.aiit"
        self.agent("apply", str(signed), "--out", str(report))
        self.assertTrue(report.exists())
        self.console("report", str(report))
        case = read_json(self.cdir / "cases" / case_id / "case.json")
        self.assertEqual(case["reports"][0]["mode"], "dry_run")
        self.assertIn("dry_run", case["reports"][0]["summary"])

        # enforce mode runs the read-only checks and marks the plan applied
        self.agent("policy", "set-mode", "enforce")
        report2 = self.usb / "report2.aiit"
        self.agent("apply", str(signed), "--yes", "--out", str(report2))
        self.console("report", str(report2), "-v")
        case = read_json(self.cdir / "cases" / case_id / "case.json")
        self.assertEqual(case["reports"][1]["mode"], "enforce")
        with self.assertRaises(SystemExit):          # replay refused
            self.agent("apply", str(signed), "--yes")

        # tampered plan refused
        bad = read_json(signed)
        bad["plan"]["steps"][0]["command"] = "echo tampered"
        (self.usb / "bad.signed.json").write_text(json.dumps(bad))
        with self.assertRaises(SystemExit):
            self.agent("apply", str(self.usb / "bad.signed.json"), "--yes")

        # a second diagnose sees the previous report in its context
        self.console("diagnose", case_id, "--provider", "dryrun")
        from aiit.console.planner import build_context
        ctx, _ = build_context(self.cdir / "cases" / case_id)
        self.assertIn("Previous execution report", ctx)

        self.console("audit-verify")
        self.agent("audit")
        self.agent("status")
        self.console("cases")
        self.console("show", case_id)
        self.console("agents")
        self.console("plans", case_id)

    def test_lan_mode(self):
        self.console("init")
        self.agent("enroll", str(self.cdir / "enrollment" / "console-enrollment.json"))
        st = ConsoleState(self.cdir)
        srv = make_server(st, "127.0.0.1", 0, TOKEN)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            with self.assertRaises(SystemExit):     # wrong token
                self.agent("collect", "--out", str(self.usb / "x.aiit"), "--no-osquery", "--push", url, "--token", "wrong-token-wrong-token")
            self.agent("collect", "--issue", "lan test", "--out", str(self.usb / "y.aiit"), "--no-osquery", "--push", url, "--token", TOKEN)
            case = st.list_cases()[0]
            self.console("diagnose", case["case_id"], "--provider", "dryrun")
            plan_id = read_json(self.cdir / "cases" / case["case_id"] / "case.json")["plans"][0]["plan_id"]
            self.console("approve", case["case_id"], plan_id, "--yes")
            self.agent("pull", url, "--token", TOKEN)
            pulled = list((self.adir / "inbox").glob("*.signed.json"))
            self.assertEqual(len(pulled), 1)
            self.agent("apply", str(pulled[0]), "--push", url, "--token", TOKEN)
            case = read_json(self.cdir / "cases" / case["case_id"] / "case.json")
            self.assertEqual(len(case["reports"]), 1)
            req = urllib.request.Request(url + "/v1/health")
            req.add_header("Authorization", f"Bearer {TOKEN}")
            self.assertTrue(json.loads(urllib.request.urlopen(req).read())["ok"])
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertTrue(st.audit.verify()[0])


class RealCollectorSmokeTest(unittest.TestCase):
    """Runs the real quick collectors for this OS; only checks that every collector produced a file."""

    def test_quick_collectors_produce_files(self):
        with tempfile.TemporaryDirectory() as d:
            entries = collect_all(Path(d), quick=True, include_osquery=False)
            self.assertGreater(len(entries), 5)
            for e in entries:
                self.assertTrue((Path(d) / e.path).exists(), e.path)
                self.assertEqual(len(e.sha256), 64)
            ok = [e for e in entries if e.error is None and (e.exit_code in (0, None))]
            self.assertGreater(len(ok), 3, [(e.path, e.error, e.exit_code) for e in entries])


if __name__ == "__main__":
    unittest.main()
