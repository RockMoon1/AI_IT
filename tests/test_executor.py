import glob
import os
import sys
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from . import helpers
from aiit.common.audit import AuditLog
from aiit.common.crypto import Identity, sign_object
from aiit.common.policy import Policy
from aiit.common.schema import Enrollment, FixPlan, PlanStep, SignedPlan
from aiit.common.util import current_os, in_hours, iso, utcnow
from aiit.agent.executor import apply_plan, preflight, run_step, verify_signed_plan
from aiit.agent.procs import run_capped, scrubbed_env


def make_plan(agent_id: str, steps: list[PlanStep], hours: float = 1.0) -> FixPlan:
    return FixPlan(
        issue_summary="i", diagnosis="d", confidence=0.5, steps=steps, plan_id="plan-000000000001", case_id="case-000000000001",
        target_agent_id=agent_id, target_os=current_os(), created_at=iso(), expires_at=in_hours(hours), provider="dryrun", model="none",
    )


def sign(console: Identity, plan: FixPlan) -> SignedPlan:
    return SignedPlan(plan=plan, signer_id=console.id, signer_pub=console.sign_pub_hex, approved_by="tester", approved_at=iso(),
                      signature=sign_object(console, plan.model_dump()))


def _sleeper_alive(token: str) -> bool:
    """True when any /proc entry has `token` in its cmdline (Linux only)."""
    for cmdline in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            with open(cmdline, "rb") as f:
                if token.encode("utf-8") in f.read():
                    return True
        except OSError:
            continue
    return False


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.console = Identity.generate("console-aaaaaaaaaaaa", with_box=True)
        self.enr = Enrollment(console_id="console-aaaaaaaaaaaa", console_sign_pub=self.console.sign_pub_hex, console_box_pub=self.console.box_pub_hex, created_at=iso())
        self.step = PlanStep(id="s1", title="t", rationale="r", action="command", command="echo hi", risk="read_only")

    def test_good_plan_passes(self):
        sp = sign(self.console, make_plan("agent-000000000001", [self.step]))
        self.assertEqual(verify_signed_plan(sp, self.enr, "agent-000000000001", []), [])

    def test_refusals(self):
        sp = sign(self.console, make_plan("agent-000000000001", [self.step]))
        self.assertTrue(any("targets agent" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000002", [])))
        self.assertTrue(any("already applied" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000001", ["plan-000000000001"])))
        other = Identity.generate("console-bbbbbbbbbbbb", with_box=True)
        sp2 = sign(other, make_plan("agent-000000000001", [self.step]))
        self.assertTrue(any("not signed by the enrolled console" in p for p in verify_signed_plan(sp2, self.enr, "agent-000000000001", [])))
        tampered = sp.model_copy(deep=True)
        tampered.plan.steps[0].command = "echo evil"
        self.assertTrue(any("signature is invalid" in p for p in verify_signed_plan(tampered, self.enr, "agent-000000000001", [])))
        expired = make_plan("agent-000000000001", [self.step])
        expired.expires_at = (utcnow() - timedelta(hours=1)).isoformat(timespec="seconds")
        self.assertTrue(any("expired" in p for p in verify_signed_plan(sign(self.console, expired), self.enr, "agent-000000000001", [])))

    def test_plan_lifetime_too_long_refused(self):
        sp = sign(self.console, make_plan("agent-000000000001", [self.step], hours=100))
        self.assertTrue(any("lifetime too long" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000001", [])))
        # A shorter lifetime still passes, and the ceiling is configurable.
        self.assertEqual(verify_signed_plan(sp, self.enr, "agent-000000000001", [], max_plan_hours=200), [])

    def test_created_at_in_the_future_refused(self):
        plan = make_plan("agent-000000000001", [self.step])
        plan.created_at = (utcnow() + timedelta(hours=1)).isoformat(timespec="seconds")
        plan.expires_at = (utcnow() + timedelta(hours=1, minutes=30)).isoformat(timespec="seconds")
        sp = sign(self.console, plan)
        self.assertTrue(any("created_at is in the future" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000001", [])))


class ScrubbedEnvTests(unittest.TestCase):
    def test_scrubbed_env_drops_secrets(self):
        with mock.patch.dict(os.environ, {"AIIT_KEY_PASSPHRASE": "x", "AIIT_SERVER_TOKEN": "y",
                                          "MY_API_KEY": "z", "SOME_SECRET": "s", "DB_PASSWORD": "p"}):
            env = scrubbed_env()
        for name in ("AIIT_KEY_PASSPHRASE", "AIIT_SERVER_TOKEN", "MY_API_KEY", "SOME_SECRET", "DB_PASSWORD"):
            self.assertNotIn(name, env)
        self.assertEqual(env["NoDefaultCurrentDirectoryInExePath"], "1")
        self.assertIn("PATH", env)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.console = Identity.generate("console-aaaaaaaaaaaa", with_box=True)
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl", actor_id="agent-000000000001")

    def tearDown(self):
        self.tmp.cleanup()

    def _enforce(self) -> Policy:
        pol = Policy()
        pol.mode = "enforce"
        return pol

    def test_dry_run_default_runs_nothing(self):
        steps = [PlanStep(id="s1", title="echo", rationale="r", action="command", command=helpers.echo_cmd("hi"), risk="read_only"),
                 PlanStep(id="s2", title="manual", rationale="r", action="manual", risk="high")]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, Policy(), "agent-000000000001", self.audit)
        self.assertEqual(report.mode, "dry_run")
        self.assertEqual([r.status for r in report.results], ["dry_run", "manual"])
        self.assertTrue(self.audit.verify()[0])

    def test_enforce_halts_on_failure(self):
        steps = [
            PlanStep(id="s1", title="echo", rationale="r", action="command", command=helpers.echo_cmd("hello-world"), risk="read_only"),
            PlanStep(id="s2", title="fails", rationale="r", action="command", command=helpers.fail_cmd(3), risk="low"),
            PlanStep(id="s3", title="skipped", rationale="r", action="command", command=helpers.echo_cmd("never"), risk="low"),
        ]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.mode, "enforce")
        self.assertEqual([r.status for r in report.results], ["success", "failed", "skipped"])
        self.assertIn("hello-world", report.results[0].stdout)
        self.assertEqual(report.results[1].exit_code, 3)
        # explicit dry_run flag wins even in enforce mode
        report2 = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit, dry_run=True)
        self.assertEqual(report2.mode, "dry_run")
        self.assertEqual([r.status for r in report2.results], ["dry_run", "dry_run", "dry_run"])
        self.assertTrue(self.audit.verify()[0])

    def test_timeout(self):
        steps = [PlanStep(id="s1", title="slow", rationale="r", action="command", command=helpers.sleep_cmd(20), risk="read_only", timeout_seconds=5)]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.results[0].status, "timeout")

    def test_env_step_scrubs_secrets(self):
        cmd = "Get-ChildItem Env: | ForEach-Object { $_.Name }" if os.name == "nt" else "env"
        step = PlanStep(id="s1", title="env", rationale="r", action="command", command=cmd, risk="read_only")
        sp = sign(self.console, make_plan("agent-000000000001", [step]))
        with mock.patch.dict(os.environ, {"AIIT_KEY_PASSPHRASE": "x", "AIIT_SERVER_TOKEN": "y", "MY_API_KEY": "z"}):
            report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.results[0].status, "success")
        out = report.results[0].stdout
        for name in ("AIIT_KEY_PASSPHRASE", "AIIT_SERVER_TOKEN", "MY_API_KEY"):
            self.assertNotIn(name, out)

    def test_timeout_kills_grandchild(self):
        token = "31337"
        if os.name == "nt":
            cmd = "Start-Process -NoNewWindow -FilePath powershell -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 31337'"
        else:
            cmd = "sleep 31337 & wait"
        step = PlanStep(id="s1", title="grandchild", rationale="r", action="command", command=cmd, risk="read_only", timeout_seconds=5)
        sp = sign(self.console, make_plan("agent-000000000001", [step]))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.results[0].status, "timeout")
        if os.name != "nt" and os.path.isdir("/proc"):
            time.sleep(0.5)
            self.assertFalse(_sleeper_alive(token), "a sleeping grandchild survived the timeout kill")

    def test_preflight_blocks_whole_plan(self):
        steps = [
            PlanStep(id="s1", title="one", rationale="r", action="command", command=helpers.echo_cmd("one"), risk="read_only"),
            PlanStep(id="s2", title="two", rationale="r", action="command", command=helpers.echo_cmd("two"), risk="read_only"),
            PlanStep(id="s3", title="denied", rationale="r", action="command", command="rm -rf /", risk="low"),
            PlanStep(id="s4", title="four", rationale="r", action="command", command=helpers.echo_cmd("four"), risk="read_only"),
        ]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        statuses = [r.status for r in report.results]
        self.assertEqual(statuses, ["skipped", "skipped", "blocked_by_policy", "skipped"])
        self.assertTrue(all(s in ("skipped", "blocked_by_policy") for s in statuses))
        # no command actually ran: nothing produced any stdout
        self.assertTrue(all(r.stdout == "" for r in report.results))
        self.assertEqual(report.results[0].reason, "preflight: step s3 blocked")
        text = self.audit.path.read_text(encoding="utf-8")
        self.assertIn("apply_preflight_failed", text)
        self.assertNotIn("apply_start", text)
        self.assertTrue(self.audit.verify()[0])

    def test_skip_step_ids_and_on_step_callback(self):
        steps = [
            PlanStep(id="s1", title="one", rationale="r", action="command", command=helpers.echo_cmd("one"), risk="read_only"),
            PlanStep(id="s2", title="two", rationale="r", action="command", command=helpers.echo_cmd("two"), risk="read_only"),
            PlanStep(id="s3", title="three", rationale="r", action="command", command=helpers.echo_cmd("three"), risk="read_only"),
        ]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        calls: list[tuple[int, str, bool]] = []

        def on_step(index, step, result):
            calls.append((index, step.id, result is None))

        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit,
                            skip_step_ids={"s1"}, on_step=on_step)
        statuses = [r.status for r in report.results]
        self.assertEqual(statuses, ["skipped", "success", "success"])
        self.assertEqual(report.results[0].reason, "completed in an earlier run")
        # on_step fires before (result None) and after for the two executed steps only
        self.assertEqual(calls, [(1, "s2", True), (1, "s2", False), (2, "s3", True), (2, "s3", False)])


class RunCappedTests(unittest.TestCase):
    def test_output_cap_honoured(self):
        code = "import sys; sys.stdout.write('a' * (1024 * 1024))"
        pr = run_capped([sys.executable, "-c", code], 30, cap=20_000)
        self.assertEqual(pr.exit_code, 0)
        self.assertFalse(pr.timed_out)
        self.assertIn("truncated", pr.stdout)
        self.assertLess(len(pr.stdout), 20_000 + 100)
        self.assertGreaterEqual(len(pr.stdout), 20_000)


class WindowsShellTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "PowerShell stdin round-trip is Windows only")
    def test_windows_quote_roundtrip(self):
        q_single = "'"
        q_double = '"'
        expected = "a" + q_single + "b" + q_double + "c"
        # Write-Output "a'b`"c" prints  a'b"c  . The backtick escapes the inner
        # double quote; the single quote is literal inside a double-quoted string.
        cmd = "Write-Output " + q_double + "a" + q_single + "b`" + q_double + "c" + q_double
        step = PlanStep(id="s1", title="quotes", rationale="r", action="command", command=cmd, risk="read_only")
        result = run_step(step, "windows")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.stdout.strip(), expected)


if __name__ == "__main__":
    unittest.main()
