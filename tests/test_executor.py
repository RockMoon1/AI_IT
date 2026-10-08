import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from . import helpers
from aiit.common.audit import AuditLog
from aiit.common.crypto import Identity, sign_object
from aiit.common.policy import Policy
from aiit.common.schema import Enrollment, FixPlan, PlanStep, SignedPlan
from aiit.common.util import current_os, in_hours, iso, utcnow
from aiit.agent.executor import apply_plan, verify_signed_plan


def make_plan(agent_id: str, steps: list[PlanStep], hours: float = 1.0) -> FixPlan:
    return FixPlan(
        issue_summary="i", diagnosis="d", confidence=0.5, steps=steps, plan_id="plan-1", case_id="case-1",
        target_agent_id=agent_id, target_os=current_os(), created_at=iso(), expires_at=in_hours(hours), provider="dryrun", model="none",
    )


def sign(console: Identity, plan: FixPlan) -> SignedPlan:
    return SignedPlan(plan=plan, signer_id=console.id, signer_pub=console.sign_pub_hex, approved_by="tester", approved_at=iso(),
                      signature=sign_object(console, plan.model_dump()))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.console = Identity.generate("console-A", with_box=True)
        self.enr = Enrollment(console_id="console-A", console_sign_pub=self.console.sign_pub_hex, console_box_pub=self.console.box_pub_hex, created_at=iso())
        self.step = PlanStep(id="s1", title="t", rationale="r", action="command", command="echo hi", risk="read_only")

    def test_good_plan_passes(self):
        sp = sign(self.console, make_plan("agent-1", [self.step]))
        self.assertEqual(verify_signed_plan(sp, self.enr, "agent-1", []), [])

    def test_refusals(self):
        sp = sign(self.console, make_plan("agent-1", [self.step]))
        self.assertTrue(any("targets agent" in p for p in verify_signed_plan(sp, self.enr, "agent-2", [])))
        self.assertTrue(any("already applied" in p for p in verify_signed_plan(sp, self.enr, "agent-1", ["plan-1"])))
        other = Identity.generate("console-B", with_box=True)
        sp2 = sign(other, make_plan("agent-1", [self.step]))
        self.assertTrue(any("not signed by the enrolled console" in p for p in verify_signed_plan(sp2, self.enr, "agent-1", [])))
        tampered = sp.model_copy(deep=True)
        tampered.plan.steps[0].command = "echo evil"
        self.assertTrue(any("signature is invalid" in p for p in verify_signed_plan(tampered, self.enr, "agent-1", [])))
        expired = make_plan("agent-1", [self.step])
        expired.expires_at = (utcnow() - timedelta(hours=1)).isoformat(timespec="seconds")
        self.assertTrue(any("expired" in p for p in verify_signed_plan(sign(self.console, expired), self.enr, "agent-1", [])))


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.console = Identity.generate("console-A", with_box=True)
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl", actor_id="agent-1")

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_default_runs_nothing(self):
        steps = [PlanStep(id="s1", title="echo", rationale="r", action="command", command=helpers.echo_cmd("hi"), risk="read_only"),
                 PlanStep(id="s2", title="manual", rationale="r", action="manual", risk="high")]
        sp = sign(self.console, make_plan("agent-1", steps))
        report = apply_plan(sp, Policy(), "agent-1", self.audit)
        self.assertEqual(report.mode, "dry_run")
        self.assertEqual([r.status for r in report.results], ["dry_run", "manual"])
        self.assertTrue(self.audit.verify()[0])

    def test_enforce_runs_blocks_and_halts(self):
        steps = [
            PlanStep(id="s1", title="echo", rationale="r", action="command", command=helpers.echo_cmd("hello-world"), risk="read_only"),
            PlanStep(id="s2", title="too risky", rationale="r", action="command", command=helpers.echo_cmd("x"), risk="high"),
            PlanStep(id="s3", title="denied", rationale="r", action="command", command="rm -rf /", risk="low"),
            PlanStep(id="s4", title="fails", rationale="r", action="command", command=helpers.fail_cmd(3), risk="low"),
            PlanStep(id="s5", title="skipped", rationale="r", action="command", command=helpers.echo_cmd("never"), risk="low"),
        ]
        sp = sign(self.console, make_plan("agent-1", steps))
        pol = Policy()
        pol.mode = "enforce"
        report = apply_plan(sp, pol, "agent-1", self.audit)
        self.assertEqual(report.mode, "enforce")
        statuses = [r.status for r in report.results]
        self.assertEqual(statuses, ["success", "blocked_by_policy", "blocked_by_policy", "failed", "skipped"])
        self.assertIn("hello-world", report.results[0].stdout)
        self.assertEqual(report.results[3].exit_code, 3)
        # explicit dry_run flag wins even in enforce mode
        report2 = apply_plan(sp, pol, "agent-1", self.audit, dry_run=True)
        self.assertEqual(report2.mode, "dry_run")
        self.assertTrue(self.audit.verify()[0])

    def test_timeout(self):
        steps = [PlanStep(id="s1", title="slow", rationale="r", action="command", command=helpers.sleep_cmd(20), risk="read_only", timeout_seconds=5)]
        sp = sign(self.console, make_plan("agent-1", steps))
        pol = Policy()
        pol.mode = "enforce"
        report = apply_plan(sp, pol, "agent-1", self.audit)
        self.assertEqual(report.results[0].status, "timeout")


if __name__ == "__main__":
    unittest.main()
