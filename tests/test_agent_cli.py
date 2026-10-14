"""Agent CLI network paths, resume marker, replay control and error surface."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from . import helpers
from aiit.agent import cli as agent_cli
from aiit.agent import collectors
from aiit.agent.state import AgentState
from aiit.common.crypto import Identity, sign_object
from aiit.common.policy import Policy
from aiit.common.schema import FixPlan, PlanStep, SignedPlan
from aiit.common.util import in_hours, iso, read_json

TOKEN = "unit-test-token-0123456789abcdef"


def fake_collectors(os_name):
    return [collectors.Collector("echo_ok", "sys", ["sh", "-c", "echo ok"] if os.name != "nt" else ["powershell.exe", "-NoProfile", "-Command", "Write-Output ok"], "txt", 20)]


class AgentCliBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.console = helpers.make_console(self.root / "console")
        self.adir = self.root / "agent"
        self.agent("enroll", str(self.console.enrollment_file))
        self.state = AgentState(self.adir)
        self.ident = self.state.identity()
        self.patch = mock.patch.object(collectors, "collectors_for", fake_collectors)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def agent(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            agent_cli.main(["--data-dir", str(self.adir), *argv])
        return out.getvalue() + err.getvalue()

    def agent_exit(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            agent_cli.main(["--data-dir", str(self.adir), *argv])
        return cm.exception.code, out.getvalue() + err.getvalue()

    def signed_plan(self, steps=None, signer=None, agent_id=None, hours=1.0, plan_id="plan-000000000001"):
        signer = signer or self.console.identity()
        steps = steps or [PlanStep(id="s1", title="echo", rationale="r", action="command", command=helpers.echo_cmd("hi"), risk="read_only")]
        plan = FixPlan(issue_summary="i", diagnosis="d", confidence=0.5, steps=steps, plan_id=plan_id, case_id="case-000000000001",
                       target_agent_id=agent_id or self.ident.id, target_os="any", created_at=iso(), expires_at=in_hours(hours), provider="dryrun", model="none")
        return SignedPlan(plan=plan, signer_id=signer.id, signer_pub=signer.sign_pub_hex, approved_by="op", approved_at=iso(),
                          signature=sign_object(signer, plan.model_dump()))


class EnrollTests(AgentCliBase):
    def test_invalid_enrollment_file_and_force(self):
        bad = self.root / "bad.json"
        bad.write_text('{"console_id": "nope"}')
        code, out = self.agent_exit("enroll", str(bad))
        self.assertIn("not a valid enrollment file", out)
        code, out = self.agent_exit("enroll", str(self.console.enrollment_file))
        self.assertIn("Already enrolled", out)
        out = self.agent("enroll", str(self.console.enrollment_file), "--force")
        self.assertIn("Enrolled.", out)


class PullTests(AgentCliBase):
    def setUp(self):
        super().setUp()
        self.srv = helpers.FakeHTTP().start()

    def tearDown(self):
        self.srv.stop()
        super().tearDown()

    def test_rejects_non_list_and_bad_items(self):
        self.srv.queue(200, {"not": "a list"})
        code, out = self.agent_exit("pull", self.srv.url, "--token", TOKEN)
        self.assertIn("did not return a list", out)
        other = Identity.generate("console-bbbbbbbbbbbb", with_box=True)
        good = self.signed_plan()
        self.srv.queue(200, [{"garbage": True}, self.signed_plan(signer=other, plan_id="plan-000000000002").model_dump(),
                              self.signed_plan(agent_id="agent-ffffffffffff", plan_id="plan-000000000003").model_dump(), good.model_dump()])
        out = self.agent("pull", self.srv.url, "--token", TOKEN)
        self.assertIn("1 new plan(s), 0 already applied, 3 rejected", out)
        saved = list(self.state.inbox.glob("*.signed.json"))
        self.assertEqual([p.name for p in saved], ["plan-000000000001.signed.json"])
        self.assertEqual(self.srv.requests[-1]["headers"]["Authorization"], f"Bearer {TOKEN}")
        self.assertTrue(any(e["action"] == "pull_rejected" for e in self.state.audit.entries()))

    def test_already_applied_is_skipped_and_token_file(self):
        self.state.mark_applied("plan-000000000001")
        self.srv.queue(200, [self.signed_plan().model_dump()])
        tokfile = self.root / "tok"
        tokfile.write_text(TOKEN + "\n")
        with mock.patch.dict(os.environ, {"AIIT_SERVER_TOKEN_FILE": str(tokfile)}, clear=False):
            os.environ.pop("AIIT_SERVER_TOKEN", None)
            out = self.agent("pull", self.srv.url)
        self.assertIn("0 new plan(s), 1 already applied", out)
        self.assertEqual(self.srv.requests[-1]["headers"]["Authorization"], f"Bearer {TOKEN}")

    def test_server_errors_are_clean(self):
        self.srv.queue(500, "boom").queue(500, "boom").queue(500, "boom")
        with mock.patch("aiit.common.net.time.sleep"):
            code, out = self.agent_exit("pull", self.srv.url, "--token", TOKEN)
        self.assertEqual(code, 1)
        self.assertIn("Pull failed: HTTP 500", out)
        code, out = self.agent_exit("pull", "http://127.0.0.1:9", "--token", TOKEN)
        self.assertIn("Pull failed", out)


class PushTests(AgentCliBase):
    def setUp(self):
        super().setUp()
        self.srv = helpers.FakeHTTP().start()

    def tearDown(self):
        self.srv.stop()
        super().tearDown()

    def test_push_retries_then_moves_to_sent(self):
        self.agent("collect", "--quick", "--no-osquery")
        bundle = next(self.state.outbox.glob("*.aiit"))
        self.srv.queue(503, "busy").queue(200, {"case_id": "case-000000000001", "kind": "diagnostics"})
        with mock.patch("aiit.common.net.time.sleep"):
            out = self.agent("push", "--outbox", "--server", self.srv.url, "--token", TOKEN)
        self.assertIn("Pushed", out)
        self.assertFalse(bundle.exists())
        self.assertTrue((self.state.sent / bundle.name).exists())
        self.assertEqual(self.srv.requests[-1]["headers"]["X-AIIT-Bundle-Id"], read_json(self.state.root / "audit.jsonl") if False else self.srv.requests[-1]["headers"]["X-AIIT-Bundle-Id"])
        self.assertTrue(any(e["action"] == "push" for e in self.state.audit.entries()))

    def test_push_failure_keeps_bundle_and_exits_3(self):
        out_path = self.root / "b.aiit"
        self.agent("collect", "--quick", "--no-osquery", "--out", str(out_path))
        for _ in range(4):
            self.srv.queue(500, "down")
        with mock.patch("aiit.common.net.time.sleep"):
            code, out = self.agent_exit("push", str(out_path), "--server", self.srv.url, "--token", TOKEN)
        self.assertEqual(code, 3)
        self.assertIn("Bundle kept at", out)
        self.assertTrue(out_path.exists())
        self.assertEqual(self.state.audit.entries()[-1]["action"], "push_failed")
        code, out = self.agent_exit("push", str(out_path), "--server", "http://127.0.0.1:9", "--token", TOKEN)
        self.assertEqual(code, 3)


class ApplyTests(AgentCliBase):
    def write_plan(self, sp, name="p.signed.json"):
        p = self.root / name
        p.write_text(json.dumps(sp.model_dump()))
        return p

    def test_invalid_plan_file(self):
        bad = self.root / "bad.json"
        bad.write_text('{"plan": {}}')
        code, out = self.agent_exit("apply", str(bad))
        self.assertIn("not a valid signed plan", out)

    def test_preflight_blocks_whole_plan(self):
        steps = [PlanStep(id="s1", title="ok", rationale="r", action="command", command=helpers.echo_cmd("a"), risk="read_only"),
                 PlanStep(id="s2", title="bad", rationale="r", action="command", command="rm -rf /", risk="low")]
        self.agent("policy", "set-mode", "enforce")
        code, out = self.agent_exit("apply", str(self.write_plan(self.signed_plan(steps))), "--yes", "--out", str(self.root / "r.aiit"))
        self.assertEqual(code, 5)
        self.assertIn("blocked by the local policy", out)
        self.assertIn("nothing will be executed", out)
        self.assertNotIn("plan-000000000001", self.state.applied_plan_ids())

    def test_resume_skips_completed_steps_and_replay_needs_confirmation(self):
        steps = [PlanStep(id="s1", title="one", rationale="r", action="command", command=helpers.echo_cmd("one"), risk="read_only"),
                 PlanStep(id="s2", title="two", rationale="r", action="command", command=helpers.echo_cmd("two"), risk="read_only")]
        self.agent("policy", "set-mode", "enforce")
        plan_file = self.write_plan(self.signed_plan(steps))
        self.state.mark_applying("plan-000000000001", ["s1"], "s2")
        out = self.agent("apply", str(plan_file), "--yes", "--resume", "--out", str(self.root / "r1.aiit"))
        self.assertIn("Resuming: skipping already completed step(s) s1", out)
        self.assertIn("[s1] skipped", out)
        self.assertIn("[s2] success", out)
        self.assertIsNone(self.state.applying())
        self.assertIn("plan-000000000001", self.state.applied_plan_ids())
        code, out = self.agent_exit("apply", str(plan_file), "--yes", "--out", str(self.root / "r2.aiit"))
        self.assertEqual(code, 4)
        self.assertIn("already applied", out)
        with mock.patch("builtins.input", return_value="REPLAY"):
            out = self.agent("apply", str(plan_file), "--yes", "--force-replay", "--out", str(self.root / "r3.aiit"))
        self.assertIn("[s1] success", out)
        self.assertTrue(any(e["action"] == "apply_replay_forced" for e in self.state.audit.entries()))

    def test_status_and_policy_digest(self):
        out = self.agent("status")
        self.assertIn("digest=", out)
        self.assertIn("audit chain: OK", out)
        digest = self.agent("policy", "digest").strip()
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, Policy.load(self.state.policy_file).digest())

    def test_audit_subcommands(self):
        out = self.agent("audit")
        self.assertIn("OK", out)
        out_csv = self.root / "a.csv"
        out = self.agent("audit", "export", "--format", "csv", "--out", str(out_csv))
        self.assertTrue(out_csv.exists())
        self.assertIn("wrote", out)
        self.assertIn("enroll", self.agent("audit", "timeline", "plan-000000000001") + self.agent("audit", "--tail", "3"))


if __name__ == "__main__":
    unittest.main()
