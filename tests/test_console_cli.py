"""Console CLI branches not covered by the end-to-end loop."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from . import helpers
from aiit.console import cli as console_cli
from aiit.console.store import ConsoleState, load_dotenv


class ConsoleCliBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cdir = self.root / "console"
        self.console("init", "--label", "t")
        self.state = ConsoleState(self.cdir)
        self.agent = helpers.agent_identity()

    def tearDown(self):
        self.tmp.cleanup()

    def console(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            console_cli.main(["--data-dir", str(self.cdir), *argv])
        return out.getvalue() + err.getvalue()

    def console_exit(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            console_cli.main(["--data-dir", str(self.cdir), *argv])
        code = cm.exception.code
        text = out.getvalue() + err.getvalue() + (code if isinstance(code, str) else "")
        return code, text

    def ingest(self, **kw):
        p = helpers.seal_diagnostics(self.state, self.agent, self.root / f"b{len(self.state.list_cases())}.aiit", **kw)
        self.console("ingest", str(p))
        return self.state.list_cases()[-1]["case_id"]


class BasicCommandTests(ConsoleCliBase):
    def test_init_twice_and_enrollment(self):
        code, out = self.console_exit("init")
        self.assertIn("already initialized", out)
        out = self.console("enrollment")
        self.assertIn("console_sign_pub", out)

    def test_ingest_errors(self):
        code, out = self.console_exit("ingest", str(self.root / "missing.aiit"))
        self.assertIn("Ingest failed", out)
        garbage = self.root / "g.aiit"
        garbage.write_bytes(b"nope")
        code, out = self.console_exit("ingest", str(garbage))
        self.assertEqual(code, 4)

    def test_cases_plans_plan_json_and_preview(self):
        case_id = self.ingest(files={"sys/echo.txt": "alice@example.org was here"}, issue="slow")
        cases = json.loads(self.console("cases", "--json"))
        self.assertEqual(cases[0]["case_id"], case_id)
        self.console("diagnose", case_id, "--provider", "dryrun", "--issue", "mail from bob@example.org")
        plans = json.loads(self.console("plans", case_id, "--json"))
        plan_id = plans[0]["plan_id"]
        plan = json.loads(self.console("plan", case_id, plan_id, "--json"))
        self.assertEqual(plan["plan_id"], plan_id)
        preview = self.console("preview", case_id, "--issue", "bob@example.org again")
        self.assertNotIn("bob@example.org", preview)
        self.assertIn("<EMAIL_", preview)
        self.assertIn("AIIT-DATA-", preview)
        self.assertNotIn("alice@example.org", self.console("preview", case_id, "--file", "sys/echo.txt"))
        code, out = self.console_exit("preview", case_id, "--file", "../raw/sys/echo.txt")
        self.assertEqual(code, 2)
        code, out = self.console_exit("plan", case_id, "plan-ffffffffffff")
        self.assertEqual(code, 2)

    def test_approve_hours_cap_and_warnings(self):
        case_id = self.ingest()
        self.console("diagnose", case_id, "--provider", "dryrun")
        plan_id = json.loads(self.console("plans", case_id, "--json"))[0]["plan_id"]
        code, out = self.console_exit("approve", case_id, plan_id, "--yes", "--hours", "100")
        self.assertIn("--long-lived", out)
        out = self.console("approve", case_id, plan_id, "--yes", "--hours", "100", "--long-lived", "--out", str(self.root / "usb"))
        self.assertIn("Signed plan written", out)
        self.assertTrue((self.root / "usb" / f"{plan_id}.signed.json").exists())
        with mock.patch("builtins.input", return_value="no"):
            code, out = self.console_exit("approve", case_id, plan_id)
        self.assertIn("Not approved", out)

    def test_report_via_ingest_and_agents(self):
        case_id = self.ingest()
        p = helpers.seal_report(self.state, self.agent, self.root / "r.aiit", case_id, "plan-000000000001", [{"step_id": "s1", "title": "t", "status": "success", "exit_code": 0}])
        out = self.console("ingest", str(p))
        self.assertIn("Attached execution report", out)
        out = self.console("report", str(p), "-v")
        self.assertIn("[s1] success", out)
        agents = json.loads(self.console("agents", "--json"))
        self.assertIn(self.agent.id, agents)
        self.assertIn(self.agent.id, self.console("agents"))

    def test_audit_subcommands_and_alias(self):
        case_id = self.ingest()
        self.assertIn("OK", self.console("audit"))
        self.assertIn("OK", self.console("audit-verify"))
        for fmt in ("csv", "jsonl", "html"):
            out_path = self.root / f"audit.{fmt}"
            self.assertIn("wrote", self.console("audit", "export", "--format", fmt, "--out", str(out_path), "--case", case_id))
            self.assertTrue(out_path.exists())
        self.assertIn("ingest", self.console("audit", "timeline", case_id))
        self.console("audit", "repair-tail")

    def test_serve_refuses_non_loopback_without_tls(self):
        code, out = self.console_exit("serve", "--host", "10.1.2.3", "--port", "0", "--token", "unit-test-token-0123456789abcdef")
        self.assertIn("without TLS", out)
        code, out = self.console_exit("serve", "--host", "127.0.0.1", "--port", "0", "--token", "short")
        self.assertIn("at least 16", out)


class DotenvTests(unittest.TestCase):
    def test_loads_console_env_not_cwd(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "console").mkdir()
            env = root / "console" / ".env"
            env.write_text("AIIT_TEST_DOTENV=from-console\nAIIT_CONSOLE_DIR=/should/be/ignored\n")
            if os.name != "nt":
                os.chmod(env, 0o600)
            cwd_env = root / ".env"
            cwd_env.write_text("AIIT_TEST_DOTENV=from-cwd\n")
            old = os.getcwd()
            os.chdir(root)
            try:
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("AIIT_TEST_DOTENV", None)
                    os.environ.pop("AIIT_CONSOLE_DIR", None)
                    err = io.StringIO()
                    with redirect_stderr(err):
                        loaded = load_dotenv(console_dir=root / "console")
                    self.assertEqual(loaded, env)
                    self.assertEqual(os.environ.get("AIIT_TEST_DOTENV"), "from-console")
                    self.assertNotIn("AIIT_CONSOLE_DIR", os.environ)
                    self.assertIn("was not loaded", err.getvalue())
            finally:
                os.chdir(old)

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_world_writable_env_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / ".env"
            env.write_text("AIIT_TEST_DOTENV2=x\n")
            os.chmod(env, 0o666)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AIIT_TEST_DOTENV2", None)
                err = io.StringIO()
                with redirect_stderr(err):
                    loaded = load_dotenv(explicit=env)
                self.assertIsNone(loaded)
                self.assertNotIn("AIIT_TEST_DOTENV2", os.environ)
                self.assertIn("world-writable", err.getvalue())


if __name__ == "__main__":
    unittest.main()
