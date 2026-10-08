import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from . import helpers  # noqa: F401
from aiit.common.audit import AuditLog
from aiit.common.schema import FixPlanDraft, PlanStep, plan_json_schema


class AuditTests(unittest.TestCase):
    def test_chain_verify_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl", actor_id="console-1")
            self.assertEqual(log.verify(), (True, "0 entries verified"))
            log.record("init")
            log.record("ingest", case_id="c1", files=3)
            log.record("plan_approved", plan_id="p1")
            ok, msg = log.verify()
            self.assertTrue(ok, msg)
            self.assertEqual(msg, "3 entries verified")
            lines = (Path(d) / "audit.jsonl").read_text().splitlines()
            e = json.loads(lines[1])
            e["details"]["files"] = 99
            lines[1] = json.dumps(e, sort_keys=True)
            (Path(d) / "audit.jsonl").write_text("\n".join(lines) + "\n")
            ok, msg = log.verify()
            self.assertFalse(ok)
            self.assertIn("entry 2", msg)
            lines = (Path(d) / "audit.jsonl").read_text().splitlines()
            del lines[1]
            (Path(d) / "audit.jsonl").write_text("\n".join(lines) + "\n")
            self.assertFalse(log.verify()[0])


class SchemaTests(unittest.TestCase):
    def test_command_required_for_command_steps(self):
        with self.assertRaises(ValidationError):
            PlanStep(id="s1", title="t", rationale="r", action="command", risk="low")
        PlanStep(id="s1", title="t", rationale="r", action="manual", risk="low")
        with self.assertRaises(ValidationError):
            PlanStep(id="s1", title="t", rationale="r", action="command", command="x", risk="low", timeout_seconds=1)

    def test_draft_schema_is_json_schema(self):
        schema = plan_json_schema()
        self.assertEqual(schema["type"], "object")
        self.assertIn("steps", schema["properties"])
        with self.assertRaises(ValidationError):
            FixPlanDraft(issue_summary="x", diagnosis="y", confidence=1.5, steps=[])


if __name__ == "__main__":
    unittest.main()
