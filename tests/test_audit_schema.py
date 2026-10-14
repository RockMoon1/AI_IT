import unittest

from pydantic import ValidationError

from aiit.common.schema import FixPlanDraft, PlanStep, plan_json_schema


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
