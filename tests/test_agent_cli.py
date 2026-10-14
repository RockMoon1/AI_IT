"""Agent CLI network paths, resume marker, replay control and error surface."""
import io
import json
import os
import tempfile
import unittest
import unittest.mock as mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from . import helpers
from aiit.agent import cli as agent_cli
from aiit.agent import collectors
from aiit.agent import executor
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
        code = cm.exception.code
        text = out.getvalue() + err.getvalue() + (code if isinstance(code, str) else "")
        return code, text

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
        self.assertEqual(self.srv.requests[-1]["headers"]["authorization"], f"Bearer {TOKEN}")
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
        self.assertEqual(self.srv.requests[-1]["headers"]["authorization"], f"Bearer {TOKEN}")

    def test_server_errors_are_clean(self):
        self.srv.queue(500, "boom").queue(500, "boom").queue(500, "boom")
        with mock.patch("aiit.common.net._sleep"):
            code, out = self.agent_exit("pull", self.srv.url, "--token", TOKEN)
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
        with mock.patch("aiit.common.net._sleep"):
            out = self.agent("push", "--outbox", "--server", self.srv.url, "--token", TOKEN)
        self.assertIn("Pushed", out)
        self.assertFalse(bundle.exists())
        self.assertTrue((self.state.sent / bundle.name).exists())
        self.assertTrue(self.srv.requests[-1]["headers"]["x-aiit-bundle-id"].startswith("b-"))
        self.assertTrue(any(e["action"] == "push" for e in self.state.audit.entries()))

    def test_push_failure_keeps_bundle_and_exits_3(self):
        out_path = self.root / "b.aiit"
        self.agent("collect", "--quick", "--no-osquery", "--out", str(out_path))
        for _ in range(4):
            self.srv.queue(500, "down")
        with mock.patch("aiit.common.net._sleep"):
            code, out = self.agent_exit("push", str(out_path), "--server", self.srv.url, "--token", TOKEN)
        self.assertEqual(code, 3)
        self.assertIn("Bundle kept at", out)
        self.assertTrue(out_path.exists())
        self.assertEqual(self.state.audit.entries()[-1]["action"], "push_failed")
        code, out = self.agent_exit("push", str(out_path), "--server", "http://127.0.0.1:9", "--token", TOKEN)
        self.assertEqual(code, 3)

    def test_push_outbox_continues_after_a_failed_bundle(self):
        self.agent("collect", "--quick", "--no-osquery")
        self.agent("collect", "--quick", "--no-osquery")
        first, second = sorted(p for p in self.state.outbox.glob("*.aiit"))  # pushed in name order
        self.srv.queue(422, {"error": "sealed for another console"}).queue(200, {"case_id": "case-000000000001", "kind": "diagnostics"})
        code, out = self.agent_exit("push", "--outbox", "--server", self.srv.url, "--token", TOKEN)
        self.assertEqual(code, 3)
        self.assertIn(f"Push failed for {first.name}: HTTP 422", out)
        self.assertIn(f"Pushed {second.name}", out)
        self.assertIn(f"1 of 2 bundle(s) failed to push: {first.name}", out)
        self.assertTrue(first.exists())  # kept for the next attempt
        self.assertFalse(second.exists())
        self.assertTrue((self.state.sent / second.name).exists())
        self.assertEqual(len(self.srv.requests), 2)
        actions = [e["action"] for e in self.state.audit.entries()]
        self.assertEqual(actions[-2:], ["push_failed", "push"])
        # the next run only has the failed one left and succeeds
        self.srv.queue(200, {"case_id": "case-000000000001", "kind": "diagnostics"})
        out = self.agent("push", "--outbox", "--server", self.srv.url, "--token", TOKEN)
        self.assertIn(f"Pushed {first.name}", out)
        self.assertEqual(sorted(p.name for p in self.state.sent.glob("*.aiit")), sorted([first.name, second.name]))

    def test_collect_push_failure_exits_3_after_writing_the_bundle(self):
        self.srv.queue(500, "down").queue(500, "down").queue(500, "down").queue(500, "down")
        with mock.patch("aiit.common.net._sleep"):
            code, out = self.agent_exit("collect", "--quick", "--no-osquery", "--push", self.srv.url, "--token", TOKEN)
        self.assertEqual(code, 3)
        self.assertIn("Wrote ", out)
        self.assertIn("Push failed for", out)
        self.assertEqual(len(list(self.state.outbox.glob("*.aiit"))), 1)


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

    def test_interrupted_run_is_refused_without_resume_or_force_replay(self):
        steps = [PlanStep(id="s1", title="one", rationale="r", action="command", command=helpers.echo_cmd("one"), risk="read_only"),
                 PlanStep(id="s2", title="two", rationale="r", action="command", command=helpers.echo_cmd("two"), risk="read_only")]
        self.agent("policy", "set-mode", "enforce")
        plan_file = self.write_plan(self.signed_plan(steps))
        self.state.mark_applying("plan-000000000001", ["s1"], "s2")
        before = len(self.state.audit.entries())
        code, out = self.agent_exit("apply", str(plan_file), "--yes", "--out", str(self.root / "r1.aiit"))
        self.assertEqual(code, 2)
        self.assertIn("interrupted (completed step(s): s1)", out)
        self.assertIn("--resume", out)
        self.assertIn("--force-replay", out)
        marker = self.state.applying()  # untouched: the evidence of the first run survives the refusal
        self.assertEqual((marker["plan_id"], marker["completed"], marker["current"]), ("plan-000000000001", ["s1"], "s2"))
        self.assertNotIn("plan-000000000001", self.state.applied_plan_ids())
        self.assertFalse((self.root / "r1.aiit").exists())
        new = self.state.audit.entries()[before:]
        self.assertEqual([e["action"] for e in new], ["apply_refused"])
        self.assertIn("interrupted enforce run", new[0]["details"]["problems"][0])
        # a dry run of the same plan is harmless and still allowed
        out = self.agent("apply", str(plan_file), "--dry-run", "--out", str(self.root / "r2.aiit"))
        self.assertIn("[s1] dry_run", out)
        self.assertIsNotNone(self.state.applying())
        # --force-replay asks for REPLAY; anything else aborts without running a step
        with mock.patch("builtins.input", return_value="no") as ask:
            code, out = self.agent_exit("apply", str(plan_file), "--yes", "--force-replay", "--out", str(self.root / "r3.aiit"))
        self.assertEqual(code, "Aborted.")
        self.assertIn("Type REPLAY", ask.call_args.args[0])
        self.assertNotIn("step_run", [e["action"] for e in self.state.audit.entries()])
        self.assertIsNotNone(self.state.applying())
        with mock.patch("builtins.input", return_value="REPLAY"):
            out = self.agent("apply", str(plan_file), "--yes", "--force-replay", "--out", str(self.root / "r4.aiit"))
        self.assertIn("[s1] success", out)
        self.assertIn("[s2] success", out)
        self.assertIsNone(self.state.applying())
        self.assertIn("plan-000000000001", self.state.applied_plan_ids())
        forced = [e for e in self.state.audit.entries() if e["action"] == "apply_replay_forced"]
        self.assertEqual(forced[-1]["details"]["interrupted_after"], ["s1"])

    def test_marker_is_written_ahead_of_each_step_during_an_enforce_run(self):
        steps = [PlanStep(id="s1", title="one", rationale="r", action="command", command=helpers.echo_cmd("one"), risk="read_only"),
                 PlanStep(id="s2", title="two", rationale="r", action="command", command=helpers.echo_cmd("two"), risk="read_only")]
        self.agent("policy", "set-mode", "enforce")
        plan_file = self.write_plan(self.signed_plan(steps))
        seen = {}
        real = executor.run_step

        def spy(step, os_name):
            seen[step.id] = self.state.applying()
            return real(step, os_name)

        with mock.patch.object(executor, "run_step", side_effect=spy):
            out = self.agent("apply", str(plan_file), "--yes", "--out", str(self.root / "r.aiit"))
        self.assertIn("[s2] success", out)
        self.assertEqual(sorted(seen), ["s1", "s2"])
        self.assertEqual({k: seen["s1"][k] for k in ("plan_id", "completed", "current")},
                         {"plan_id": "plan-000000000001", "completed": [], "current": "s1"})
        self.assertEqual({k: seen["s2"][k] for k in ("plan_id", "completed", "current")},
                         {"plan_id": "plan-000000000001", "completed": ["s1"], "current": "s2"})
        self.assertIsNone(self.state.applying())  # cleared once the plan completed
        # no marker in dry-run mode: nothing runs, nothing to resume
        self.agent("policy", "set-mode", "dry_run")
        plan2 = self.write_plan(self.signed_plan(steps, plan_id="plan-000000000002"), "p2.signed.json")
        with mock.patch.object(executor, "run_step", side_effect=AssertionError("dry run must not execute")):
            out = self.agent("apply", str(plan2), "--out", str(self.root / "r2.aiit"))
        self.assertIn("[s1] dry_run", out)
        self.assertIsNone(self.state.applying())

    def test_policy_max_plan_hours_is_enforced_on_apply_and_pull(self):
        long_plan = self.signed_plan(hours=100)
        plan_file = self.write_plan(long_plan)
        code, out = self.agent_exit("apply", str(plan_file), "--yes", "--out", str(self.root / "r.aiit"))
        self.assertEqual(code, 4)
        self.assertIn("lifetime too long", out)
        self.assertEqual(self.state.audit.entries()[-1]["action"], "apply_refused")
        srv = helpers.FakeHTTP().start()
        try:
            srv.queue(200, [long_plan.model_dump()])
            out = self.agent("pull", srv.url, "--token", TOKEN)
            self.assertIn("Rejected plan plan-000000000001: plan lifetime too long", out)
            self.assertIn("0 new plan(s), 0 already applied, 1 rejected", out)
            self.assertEqual(list(self.state.inbox.glob("*.signed.json")), [])
            pol = Policy.load(self.state.policy_file)
            pol.max_plan_hours = 200
            pol.save(self.state.policy_file)
            srv.queue(200, [long_plan.model_dump()])
            out = self.agent("pull", srv.url, "--token", TOKEN)
            self.assertIn("1 new plan(s), 0 already applied, 0 rejected", out)
            self.assertEqual([p.name for p in self.state.inbox.glob("*.signed.json")], ["plan-000000000001.signed.json"])
        finally:
            srv.stop()
        out = self.agent("apply", str(plan_file), "--yes", "--out", str(self.root / "r.aiit"))
        self.assertIn("[s1] dry_run", out)
        self.assertIn("Report written", out)

    def test_typed_prompts_abort_cleanly(self):
        self.agent("policy", "set-mode", "enforce")
        plan_file = self.write_plan(self.signed_plan())
        with mock.patch("builtins.input", return_value="yes please") as ask:
            code, out = self.agent_exit("apply", str(plan_file), "--out", str(self.root / "r.aiit"))
        self.assertEqual(code, "Aborted.")
        self.assertIn("Type APPLY", ask.call_args.args[0])
        self.assertEqual(self.state.audit.entries()[-1]["action"], "apply_aborted")
        self.assertNotIn("plan-000000000001", self.state.applied_plan_ids())
        self.assertFalse((self.root / "r.aiit").exists())
        # a plan that already ran: --force-replay without the typed REPLAY aborts before anything is verified or run
        self.state.mark_applied("plan-000000000001")
        with mock.patch("builtins.input", return_value="") as ask:
            code, out = self.agent_exit("apply", str(plan_file), "--yes", "--force-replay", "--out", str(self.root / "r.aiit"))
        self.assertEqual(code, "Aborted.")
        self.assertIn("Type REPLAY", ask.call_args.args[0])
        self.assertNotIn("apply_replay_forced", [e["action"] for e in self.state.audit.entries()])
        self.assertNotIn("step_run", [e["action"] for e in self.state.audit.entries()])

    def test_start_up_check_alerts_on_tampered_chain(self):
        helpers.tamper_audit_line(self.state.audit.path, 0, lambda e: e["details"].__setitem__("console_id", "console-ffffffffffff"))
        n = len(self.state.audit.entries())
        with mock.patch.dict(os.environ, {"AIIT_ALERT_CMD": "", "AIIT_ALERT_WEBHOOK": "", "AIIT_ALERT_SYSLOG": ""}):
            out = self.agent("status")
        self.assertIn("AUDIT CHAIN BROKEN", out)
        self.assertIn("hash mismatch at entry 1", out)
        self.assertIn("audit chain: BROKEN", out)
        entries = self.state.audit.entries()
        self.assertEqual(len(entries), n + 1)
        self.assertEqual(entries[-1]["action"], "audit_chain_broken")
        self.assertEqual(entries[-1]["details"]["line_no"], 1)
        # every command checks, but the same break is recorded once
        with mock.patch.dict(os.environ, {"AIIT_ALERT_CMD": "", "AIIT_ALERT_WEBHOOK": "", "AIIT_ALERT_SYSLOG": ""}):
            out = self.agent("policy", "digest")
        self.assertIn("AUDIT CHAIN BROKEN", out)
        self.assertEqual(len(self.state.audit.entries()), n + 1)
        code, out = self.agent_exit("audit")
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("BROKEN:\n  line 1 seq 1: hash mismatch at entry 1"), out)

    def test_repair_tail_refreshes_the_signed_checkpoint(self):
        path = self.state.audit.path
        with open(path, "ab") as f:
            f.write(b'{"seq": 2, "ts": ')
        out = self.agent("status")  # start-up check records the torn line
        self.assertIn("AUDIT CHAIN BROKEN", out)
        self.state.audit.record("something_else")
        self.state.audit.checkpoint(self.ident)
        out = self.agent("audit", "repair-tail")  # JSON on stdout; the start-up banner (torn line) on stderr after it
        result = json.JSONDecoder().raw_decode(out[out.index("{"):])[0]
        self.assertEqual(result["method"], "spliced")
        self.assertTrue(result["checkpoint_resigned"])
        self.assertFalse(result["checkpoint_offset_stale"])
        head = read_json(self.state.audit.head_path)
        self.assertEqual((head["seq"], head["offset"]), (self.state.audit.head()["seq"], path.stat().st_size))
        self.assertEqual(head["signer_pub"], self.ident.sign_pub_hex)
        out = self.agent("status")
        self.assertNotIn("AUDIT CHAIN BROKEN", out)
        self.assertIn("audit chain: OK", out)
        self.assertTrue(self.agent("audit").startswith("OK: "))

    def test_output_streams_tolerate_unencodable_text(self):
        """A plan title with characters a cp1252 console cannot show must print as '?' rather than crash."""
        steps = [PlanStep(id="s1", title="fix \u2192 printer \ufffd queue", rationale="r", action="command",
                          command=helpers.echo_cmd("hi"), risk="read_only")]
        plan_file = self.write_plan(self.signed_plan(steps))
        out = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict", write_through=True)
        err = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict", write_through=True)
        with redirect_stdout(out), redirect_stderr(err):
            agent_cli.main(["--data-dir", str(self.adir), "apply", str(plan_file), "--out", str(self.root / "r.aiit")])
        out.flush()
        text = out.buffer.getvalue().decode("ascii")
        self.assertIn("fix ? printer ? queue", text)
        self.assertIn("[s1] dry_run", text)
        self.assertEqual(out.errors, "replace")
        self.assertEqual(err.errors, "replace")

    def test_status_and_policy_digest(self):
        out = self.agent("status")
        self.assertIn("digest=", out)
        self.assertIn("audit chain: OK", out)
        digest = self.agent("policy", "digest").strip()
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, Policy.load(self.state.policy_file).digest())

    def test_audit_subcommands(self):
        out = self.agent("audit")
        self.assertTrue(out.startswith("OK: "), out)
        self.assertRegex(out, r"^OK: \d+ entries verified\n$")
        self.assertEqual(self.agent("audit", "verify"), out)
        self.state.audit.record("step_run", plan_id="plan-000000000001", step_id="s1", status="success")
        self.state.audit.record("report_written", plan_id="plan-000000000002", bundle_id="r-000000000002")
        out_csv = self.root / "a.csv"
        out = self.agent("audit", "export", "--format", "csv", "--out", str(out_csv))
        self.assertTrue(out_csv.exists())
        self.assertIn(f"wrote {len(self.state.audit.entries())} entries to {out_csv}", out)
        tl = self.agent("audit", "timeline", "plan-000000000001")
        self.assertIn("step_run", tl)
        self.assertIn('"plan_id": "plan-000000000001"', tl)
        self.assertNotIn("enroll", tl)
        self.assertNotIn("report_written", tl)
        self.assertEqual(self.agent("audit", "timeline", "plan-000000000009"), "")
        tail = self.agent("audit", "--tail", "2").splitlines()
        self.assertEqual(tail[0], "OK: 3 entries verified")
        self.assertEqual([json.loads(line)["action"] for line in tail[1:]], ["step_run", "report_written"])


if __name__ == "__main__":
    unittest.main()
