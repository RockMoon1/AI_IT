"""Console CLI branches not covered by the end-to-end loop."""
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from pathlib import Path

from . import helpers
from aiit.common.util import iso, parse_iso, read_json, utcnow
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

    def diagnose(self, case_id, *extra):
        """Run a dryrun diagnose and return the new plan id."""
        self.console("diagnose", case_id, "--provider", "dryrun", *extra)
        return json.loads(self.console("plans", case_id, "--json"))[-1]["plan_id"]

    def set_warnings(self, case_id, plan_id, warnings):
        """Store lint warnings for a plan exactly where cmd_approve reads them (case.json)."""
        cj = self.state.case_dir(case_id) / "case.json"
        case = read_json(cj)
        for p in case["plans"]:
            if p["plan_id"] == plan_id:
                p["warnings"] = list(warnings)
        cj.write_text(json.dumps(case), encoding="utf-8")

    def redate_plan(self, case_id, plan_id, created_at, expires_at):
        pj = self.state.case_dir(case_id) / "plans" / f"{plan_id}.json"
        plan = read_json(pj)
        plan["created_at"], plan["expires_at"] = created_at, expires_at
        pj.write_text(json.dumps(plan), encoding="utf-8")

    def signed_plan(self, case_id, plan_id):
        return read_json(self.state.case_dir(case_id) / "plans" / f"{plan_id}.signed.json")["plan"]

    def _cp_seq(self):
        """seq recorded in the console's signed audit checkpoint."""
        return read_json(self.state.audit.head_path)["seq"]


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

    def test_approve_hours_cap_and_redating(self):
        case_id = self.ingest()
        plan_id = self.diagnose(case_id)
        code, out = self.console_exit("approve", case_id, plan_id, "--yes", "--hours", "100")
        self.assertIn("--long-lived", out)
        out = self.console("approve", case_id, plan_id, "--yes", "--hours", "100", "--long-lived", "--out", str(self.root / "usb"))
        self.assertIn("Signed plan written", out)
        self.assertTrue((self.root / "usb" / f"{plan_id}.signed.json").exists())
        with mock.patch("builtins.input", return_value="no"):
            code, out = self.console_exit("approve", case_id, plan_id)
        self.assertIn("Not approved", out)
        # A plan diagnosed 50 h ago: without --hours it has expired and is not signed; with --hours 24
        # it is re-dated from now on BOTH stamps, because the agent measures expires_at - created_at.
        old = utcnow() - timedelta(hours=50)
        self.redate_plan(case_id, plan_id, iso(old), iso(old + timedelta(hours=24)))
        code, out = self.console_exit("approve", case_id, plan_id, "--yes")
        self.assertIn("expired", out)
        self.assertIn("Signed plan written", self.console("approve", case_id, plan_id, "--yes", "--hours", "24"))
        signed = self.signed_plan(case_id, plan_id)
        created, expires = parse_iso(signed["created_at"]), parse_iso(signed["expires_at"])
        self.assertLess(abs((utcnow() - created).total_seconds()), 120)
        self.assertEqual((expires - created).total_seconds(), 24 * 3600)
        # The lifetime about to be signed is checked even when --hours is omitted.
        now = utcnow()
        self.redate_plan(case_id, plan_id, iso(now), iso(now + timedelta(hours=100)))
        code, out = self.console_exit("approve", case_id, plan_id, "--yes")
        self.assertIn("lifetime 100 h exceeds 72", out)
        self.assertIn("Signed plan written", self.console("approve", case_id, plan_id, "--yes", "--long-lived"))
        self.assertEqual(parse_iso(self.signed_plan(case_id, plan_id)["expires_at"]), (now + timedelta(hours=100)).replace(microsecond=0))

    def test_ack_warnings_is_a_hard_gate(self):
        case_id = self.ingest()
        plan_id = self.diagnose(case_id)
        self.set_warnings(case_id, plan_id, ["step s1 targets windows but the endpoint is linux"])
        signed = self.state.case_dir(case_id) / "plans" / f"{plan_id}.signed.json"
        # --yes alone (the scripted form) must not sign a plan that carries lint warnings ...
        code, out = self.console_exit("approve", case_id, plan_id, "--yes")
        self.assertIn("--ack-warnings", out)
        self.assertNotIn("Signed plan written", out)
        self.assertFalse(signed.exists())
        # ... and neither does typing APPROVE: the prompt is never even shown
        with mock.patch("builtins.input", return_value="APPROVE") as inp:
            code, out = self.console_exit("approve", case_id, plan_id)
        inp.assert_not_called()
        self.assertIn("--ack-warnings", out)
        self.assertFalse(signed.exists())
        self.assertFalse(json.loads(self.console("plans", case_id, "--json"))[0]["approved"])
        self.assertNotIn("plan_approved", [e["action"] for e in self.state.audit.entries()])
        out = self.console("approve", case_id, plan_id, "--yes", "--ack-warnings")
        self.assertIn("Signed plan written", out)
        self.assertTrue(signed.exists())
        self.assertTrue(json.loads(self.console("plans", case_id, "--json"))[0]["approved"])

    def test_diagnose_applies_the_lifetime_cap(self):
        case_id = self.ingest()
        code, out = self.console_exit("diagnose", case_id, "--provider", "dryrun", "--hours", "100")
        self.assertIn("--long-lived", out)
        self.assertEqual(json.loads(self.console("plans", case_id, "--json")), [])
        self.assertNotIn("llm_request", [e["action"] for e in self.state.audit.entries()])  # refused before any model call
        code, out = self.console_exit("diagnose", case_id, "--provider", "dryrun", "--hours", "0")
        self.assertIn("must be positive", out)
        plan_id = self.diagnose(case_id, "--hours", "100", "--long-lived")
        plan = json.loads(self.console("plan", case_id, plan_id, "--json"))
        self.assertEqual((parse_iso(plan["expires_at"]) - parse_iso(plan["created_at"])).total_seconds(), 100 * 3600)
        plan = json.loads(self.console("plan", case_id, self.diagnose(case_id), "--json"))
        self.assertEqual((parse_iso(plan["expires_at"]) - parse_iso(plan["created_at"])).total_seconds(), 24 * 3600)

    def test_each_state_change_moves_the_signed_checkpoint(self):
        last = 0

        def assert_checkpointed(what):
            nonlocal last
            head = self.state.audit.head()
            cp = read_json(self.state.audit.head_path)
            self.assertEqual((cp["seq"], cp["hash"]), (head["seq"], head["hash"]), what)
            self.assertEqual(cp["signer_id"], self.state.console_id_or_none(), what)
            self.assertGreater(cp["seq"], last, what)
            last = cp["seq"]

        assert_checkpointed("init")
        case_id = self.ingest()
        assert_checkpointed("ingest")
        plan_id = self.diagnose(case_id)
        assert_checkpointed("diagnose")
        self.console("approve", case_id, plan_id, "--yes")
        assert_checkpointed("approve")
        p = helpers.seal_report(self.state, self.agent, self.root / "r.aiit", case_id, plan_id, [{"step_id": "s1", "title": "t", "status": "success", "exit_code": 0}])
        self.console("report", str(p))
        assert_checkpointed("report")
        self.assertEqual(self._cp_seq(), last)

    def test_unencodable_output_does_not_abort_the_command(self):
        # On Windows a redirected stdout is the ANSI code page; U+FFFD (from a collector decoded with
        # errors="replace") and arrows are not encodable there. The CLI must reconfigure whatever
        # sys.stdout is at call time instead of dying with UnicodeEncodeError (a ValueError, exit 2).
        case_id = self.ingest(files={"sys/echo.txt": "bad byte � here → end\n"})
        raw = io.BytesIO()
        narrow = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", write_through=True)
        with mock.patch("sys.stdout", narrow), redirect_stderr(io.StringIO()):
            console_cli.main(["--data-dir", str(self.cdir), "preview", case_id, "--file", "sys/echo.txt"])
            narrow.flush()
            self.assertEqual(narrow.errors, "replace")
            self.assertIn(b"bad byte ? here ? end", raw.getvalue())
        self.assertIsNot(sys.stdout, narrow)  # the patch restored the real stream

    def test_missing_env_file_is_a_usage_error(self):
        missing = self.root / "consol.env"  # a typo of console.env must not run the command without settings
        code, out = self.console_exit("--env-file", str(missing), "cases")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", out)
        self.assertIn("consol.env", out)
        with mock.patch.dict(os.environ, {"AIIT_ENV_FILE": str(missing)}):
            code, out = self.console_exit("cases")
        self.assertEqual(code, 2)
        self.assertIn("AIIT_ENV_FILE", out)
        code, out = self.console_exit("--env-file", str(self.root), "cases")  # a directory is not a settings file
        self.assertEqual(code, 2)

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
        def result_json(text):  # the JSON result; stderr (the start-up chain banner) is captured after it
            return json.loads(text[text.index("{"):text.rindex("}") + 1])

        self.assertFalse(result_json(self.console("audit", "repair-tail"))["repaired"])
        # a torn trailing write (power loss mid-append) is repaired and the signed checkpoint is refreshed
        with open(self.state.audit.path, "ab") as f:
            f.write(b'{"seq": 999, "action": "torn')
        res = result_json(self.console("audit", "repair-tail"))
        self.assertTrue(res["repaired"])
        self.assertFalse(res["checkpoint_offset_stale"])
        self.assertTrue(self.state.audit.corrupt_path.exists())
        self.assertTrue(self.console("audit").startswith("OK: "))

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

    def test_dotenv_precedence_and_existing_env_wins(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "c").mkdir()
            files = {}
            for name, val in (("c/.env", "datadir"), ("envfile.env", "envfile"), ("explicit.env", "explicit")):
                p = root / name
                p.write_text(f'AIIT_TEST_PREC="{val}"\nAIIT_TEST_KEEP=\'from-{val}\'\n# comment\nnot a pair\n=novalue\n', encoding="utf-8")
                if os.name != "nt":
                    os.chmod(p, 0o600)
                files[name] = p
            with mock.patch.dict(os.environ, {}, clear=False), redirect_stderr(io.StringIO()):
                for k in ("AIIT_TEST_PREC", "AIIT_TEST_KEEP", "AIIT_ENV_FILE"):
                    os.environ.pop(k, None)
                # 1. nothing named: <console_dir>/.env, with quotes stripped from values
                self.assertEqual(load_dotenv(console_dir=root / "c"), files["c/.env"])
                self.assertEqual(os.environ["AIIT_TEST_PREC"], "datadir")
                self.assertEqual(os.environ["AIIT_TEST_KEEP"], "from-datadir")
                # 2. AIIT_ENV_FILE replaces the data-dir file (it is not read in addition)
                os.environ.pop("AIIT_TEST_PREC")
                os.environ["AIIT_ENV_FILE"] = str(files["envfile.env"])
                self.assertEqual(load_dotenv(console_dir=root / "c"), files["envfile.env"])
                self.assertEqual(os.environ["AIIT_TEST_PREC"], "envfile")
                # 3. --env-file beats AIIT_ENV_FILE
                os.environ.pop("AIIT_TEST_PREC")
                self.assertEqual(load_dotenv(explicit=files["explicit.env"], console_dir=root / "c"), files["explicit.env"])
                self.assertEqual(os.environ["AIIT_TEST_PREC"], "explicit")
                # 4. a variable already in the process environment is never overridden by a file
                self.assertEqual(os.environ["AIIT_TEST_KEEP"], "from-datadir")
                os.environ["AIIT_TEST_PREC"] = "preset"
                load_dotenv(explicit=files["explicit.env"], console_dir=root / "c")
                self.assertEqual(os.environ["AIIT_TEST_PREC"], "preset")

    def test_missing_explicit_env_file_raises(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            default = root / ".env"
            default.write_text("AIIT_TEST_DOTENV3=x\n", encoding="utf-8")
            if os.name != "nt":
                os.chmod(default, 0o600)
            with mock.patch.dict(os.environ, {}, clear=False), redirect_stderr(io.StringIO()):
                os.environ.pop("AIIT_TEST_DOTENV3", None)
                os.environ.pop("AIIT_ENV_FILE", None)
                with self.assertRaises(FileNotFoundError) as cm:
                    load_dotenv(explicit=root / "typo.env", console_dir=root)
                self.assertIn("typo.env", str(cm.exception))
                os.environ["AIIT_ENV_FILE"] = str(root / "typo2.env")
                with self.assertRaises(FileNotFoundError) as cm:
                    load_dotenv(console_dir=root)
                self.assertIn("AIIT_ENV_FILE", str(cm.exception))
                self.assertNotIn("AIIT_TEST_DOTENV3", os.environ)  # and no silent fallback to the data-dir file
                os.environ.pop("AIIT_ENV_FILE")
                self.assertIsNone(load_dotenv(console_dir=root / "nowhere"))  # the default file stays optional

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_world_or_group_writable_env_is_refused(self):
        for who, octal, needle in (("world", "666", "world-writable"), ("group", "660", "group- or world-writable")):
            with self.subTest(who), tempfile.TemporaryDirectory() as d:
                env = Path(d) / ".env"
                env.write_text("AIIT_TEST_DOTENV2=x\n")
                os.chmod(env, int(octal, 8))  # deliberately permissive: this is the hostile input under test
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("AIIT_TEST_DOTENV2", None)
                    err = io.StringIO()
                    with redirect_stderr(err):
                        loaded = load_dotenv(explicit=env)
                    self.assertIsNone(loaded)
                    self.assertNotIn("AIIT_TEST_DOTENV2", os.environ)
                    self.assertIn(needle, err.getvalue())


if __name__ == "__main__":
    unittest.main()


class ProviderGateAndFallbackTests(ConsoleCliBase):
    """D1: hosted providers need an explicit opt-in; a fallback may only move towards more privacy."""

    def _fake_anthropic(self):
        from tests.test_planner_providers import _fake_anthropic
        mod, calls = _fake_anthropic()
        for patcher in (mock.patch.dict(sys.modules, {"anthropic": mod}),
                        mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-" + "x" * 24})):
            patcher.start()
            self.addCleanup(patcher.stop)
        return calls

    def test_hosted_provider_is_refused_without_opt_in(self):
        case_id = self.ingest()
        calls = self._fake_anthropic()
        os.environ.pop("AIIT_ALLOW_HOSTED", None)
        code, out = self.console_exit("diagnose", case_id, "--provider", "anthropic")
        self.assertIn("--allow-hosted", out)
        self.assertIn("api.anthropic.com", out)
        self.assertEqual(calls["beta"] + calls["plain"], 0, "no request may leave the machine before the opt-in")
        self.assertEqual(json.loads(self.console("plans", case_id, "--json")), [])

    def test_hosted_provider_runs_with_flag_or_env(self):
        case_id = self.ingest()
        calls = self._fake_anthropic()
        self.console("diagnose", case_id, "--provider", "anthropic", "--allow-hosted")
        first = calls["beta"] + calls["plain"]
        self.assertGreater(first, 0)
        with mock.patch.dict(os.environ, {"AIIT_ALLOW_HOSTED": "1"}):
            self.console("diagnose", case_id, "--provider", "anthropic")
        self.assertGreater(calls["beta"] + calls["plain"], first)
        self.assertEqual(len(json.loads(self.console("plans", case_id, "--json"))), 2)

    def test_fallback_must_be_at_least_as_private(self):
        case_id = self.ingest()
        code, out = self.console_exit("diagnose", case_id, "--provider", "dryrun", "--fallback", "ollama")
        self.assertIn("less private", out)
        self.assertEqual(json.loads(self.console("plans", case_id, "--json")), [])

    def test_fallback_to_dryrun_after_a_provider_failure_is_audited(self):
        case_id = self.ingest()
        srv = helpers.FakeHTTP().start()
        self.addCleanup(srv.stop)
        srv.queue(500, {"error": "boom"}).queue(500, {"error": "boom"}).queue(500, {"error": "boom"})
        with mock.patch("aiit.common.net._sleep", lambda s: None), \
             mock.patch.dict(os.environ, {"AIIT_OLLAMA_URL": srv.url, "AIIT_PLAN_REPAIRS": "0"}):
            out = self.console("diagnose", case_id, "--provider", "ollama", "--fallback", "dryrun")
        self.assertIn("falling back to dryrun", out)
        self.assertIn("fallback provider dryrun", out)
        plans = json.loads(self.console("plans", case_id, "--json"))
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0]["provider"], "dryrun")
        actions = [e["action"] for e in self.state.audit.entries()]
        self.assertIn("llm_fallback", actions)
        fb = [e for e in self.state.audit.entries() if e["action"] == "llm_fallback"][0]["details"]
        self.assertEqual((fb["from_provider"], fb["to_provider"]), ("ollama", "dryrun"))

    def test_provider_failure_without_fallback_hints_at_one(self):
        case_id = self.ingest()
        srv = helpers.FakeHTTP().start()
        self.addCleanup(srv.stop)
        for _ in range(4):
            srv.queue(500, {"error": "boom"})
        with mock.patch("aiit.common.net._sleep", lambda s: None), \
             mock.patch.dict(os.environ, {"AIIT_OLLAMA_URL": srv.url, "AIIT_PLAN_REPAIRS": "0"}):
            code, out = self.console_exit("diagnose", case_id, "--provider", "ollama")
        self.assertEqual(code, 3)
        self.assertIn("--fallback dryrun", out)


class OutputAndErrorSurfaceTests(ConsoleCliBase):
    """D3/D4: machine-readable output on request, one coloured line (never a traceback) on failure."""

    def test_report_json_and_no_color(self):
        case_id = self.ingest()
        plan_id = self.diagnose(case_id)
        self.console("approve", case_id, plan_id, "--yes")
        plan = self.signed_plan(case_id, plan_id)
        results = [{"step_id": s["id"], "title": s["title"], "command": s.get("command"), "status": "dry_run", "reason": "policy mode is dry_run"}
                   for s in plan["steps"]]
        rp = helpers.seal_report(self.state, self.agent, self.root / "r.aiit", case_id, plan_id, results)
        out = self.console("--no-color", "report", str(rp), "--json")
        data = json.loads(out[out.index("{"):])
        self.assertEqual(data["case_id"], case_id)
        self.assertEqual(data["plan_id"], plan_id)
        self.assertEqual({r["status"] for r in data["results"]}, {"dry_run"})
        self.assertNotIn("\x1b[", out)

    def test_interrupt_and_eof_map_to_exit_codes(self):
        with mock.patch.object(console_cli, "cmd_cases", side_effect=KeyboardInterrupt):
            code, out = self.console_exit("cases")
        self.assertEqual(code, 130)
        self.assertIn("interrupted", out)
        with mock.patch.object(console_cli, "cmd_cases", side_effect=EOFError):
            code, out = self.console_exit("cases")
        self.assertEqual(code, 2)
        self.assertIn("stdin", out)

    def test_os_and_tar_errors_are_one_line_with_a_hint(self):
        import tarfile
        with mock.patch.object(console_cli, "cmd_cases", side_effect=tarfile.ReadError("truncated")):
            code, out = self.console_exit("cases")
        self.assertEqual(code, 4)
        self.assertIn("damaged", out)
        self.assertNotIn("Traceback", out)
        with mock.patch.object(console_cli, "cmd_cases", side_effect=OSError(28, "No space left on device")):
            code, out = self.console_exit("cases")
        self.assertEqual(code, 1)
        self.assertIn("No space left", out)
        self.assertIn("hint:", out)

    def test_debug_re_raises(self):
        with mock.patch.object(console_cli, "cmd_cases", side_effect=OSError(5, "io")):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), self.assertRaises(OSError):
                console_cli.main(["--data-dir", str(self.cdir), "--debug", "cases"])


class DashboardCommandTests(ConsoleCliBase):
    def test_dashboard_refuses_non_loopback_and_audits_a_run(self):
        code, out = self.console_exit("dashboard", "--host", "0.0.0.0", "--port", "0")
        self.assertIn("127.0.0.1", out)
        from aiit.console import dashboard
        with mock.patch.object(dashboard.DashboardServer, "serve_forever", side_effect=KeyboardInterrupt):
            out = self.console("dashboard", "--port", "0")
        self.assertIn("read-only", out)
        self.assertIn("http://127.0.0.1:", out)
        actions = [e["action"] for e in self.state.audit.entries()]
        self.assertIn("dashboard_start", actions)
        self.assertEqual(actions[-1], "dashboard_stop")
