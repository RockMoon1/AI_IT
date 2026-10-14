import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from . import helpers
from aiit.common.schema import FixPlanDraft
from aiit.console.llm import ProviderError, ProviderOutputError, ProviderRefusal, get_provider
from aiit.console.llm.base import LLMProvider
from aiit.console.llm.ollama import OllamaProvider
from aiit.console.planner import PRIORITY, _rank, build_context, diagnose, lint_plan

VALID_PLAN = {"issue_summary": "x", "diagnosis": "y", "confidence": 0.7, "steps": [
    {"id": "s1", "title": "t", "rationale": "r", "action": "command", "os": "linux", "command": "df -h", "risk": "read_only"}]}


class DryRunProviderTests(unittest.TestCase):
    def test_dryrun_plans_validate_for_every_os(self):
        p = get_provider("dryrun")
        for os_name in ("windows", "linux", "macos"):
            raw, usage = p.complete_json("sys", "user", {}, {"target_os": os_name, "issue": "slow"})
            draft = FixPlanDraft.model_validate(raw)
            self.assertTrue(all(s.risk == "read_only" for s in draft.steps))
            self.assertEqual(draft.steps[-1].action, "manual")
            self.assertEqual(usage["provider"], "dryrun")

    def test_unknown_provider(self):
        with self.assertRaises(ProviderError):
            get_provider("nope")


class OllamaProviderTests(unittest.TestCase):
    def setUp(self):
        self.srv = helpers.FakeHTTP().start()

    def tearDown(self):
        self.srv.stop()

    def reply(self, content, **extra):
        return {"model": "fake:1b", "message": {"role": "assistant", "content": content}, "prompt_eval_count": 10, "eval_count": 5,
                "total_duration": 2_000_000, **extra}

    def test_structured_output_roundtrip(self):
        self.srv.queue(200, self.reply(json.dumps(VALID_PLAN)))
        p = OllamaProvider(url=self.srv.url, model="fake:1b")
        raw, usage = p.complete_json("sys", "usr", {"type": "object"}, {})
        self.assertEqual(raw["confidence"], 0.7)
        self.assertEqual(usage["prompt_tokens"], 10)
        self.assertFalse(usage["hosted"])
        body = json.loads(self.srv.requests[-1]["body"])
        self.assertEqual(body["format"], {"type": "object"})
        self.assertFalse(body["stream"])

    def test_fenced_output_is_accepted_and_garbage_is_output_error(self):
        self.srv.queue(200, self.reply("```json\n" + json.dumps(VALID_PLAN) + "\n```"))
        p = OllamaProvider(url=self.srv.url, model="fake")
        self.assertEqual(p.complete_json("s", "u", {}, {})[0]["confidence"], 0.7)
        self.srv.queue(200, self.reply("not json"))
        with self.assertRaises(ProviderOutputError) as cm:
            p.complete_json("s", "u", {}, {})
        self.assertEqual(cm.exception.raw_text, "not json")

    def test_404_hint_and_format_degrade(self):
        self.srv.queue(404, {"error": "model 'fake' not found"})
        with self.assertRaises(ProviderError) as cm:
            OllamaProvider(url=self.srv.url, model="fake").complete_json("s", "u", {}, {})
        self.assertIn("ollama pull fake", str(cm.exception))
        self.srv.queue(400, {"error": "invalid format: unsupported"}).queue(200, self.reply(json.dumps(VALID_PLAN)))
        raw, usage = OllamaProvider(url=self.srv.url, model="fake").complete_json("s", "u", {"type": "object"}, {})
        self.assertTrue(usage["format_degraded"])
        self.assertEqual(json.loads(self.srv.requests[-1]["body"])["format"], "json")

    def test_timeout_and_unreachable_are_provider_errors(self):
        self.srv.queue(200, self.reply("{}"), delay=1.5)
        with mock.patch("aiit.common.net._sleep"):
            with self.assertRaises(ProviderError) as cm:
                OllamaProvider(url=self.srv.url, model="fake", timeout=0.3).complete_json("s", "u", {}, {})
        self.assertIn("timeout", str(cm.exception).lower())
        with mock.patch("aiit.common.net._sleep"):
            with self.assertRaises(ProviderError):
                OllamaProvider(url="http://127.0.0.1:9", model="fake", timeout=2).complete_json("s", "u", {}, {})

    def test_context_truncation_flag(self):
        self.srv.queue(200, self.reply(json.dumps(VALID_PLAN), prompt_eval_count=32768))
        p = OllamaProvider(url=self.srv.url, model="fake")
        self.assertTrue(p.complete_json("s", "u", {}, {})[1]["context_truncated"])


def _fake_anthropic(stop_reason="end_turn", text=None, beta_raises=False, category=None):
    """Build a stand-in `anthropic` module with the exception classes and client shape the provider uses."""
    mod = types.ModuleType("anthropic")

    class APIStatusError(Exception):
        def __init__(self, message="err", status_code=500):
            super().__init__(message)
            self.message, self.status_code = message, status_code

    class BadRequestError(APIStatusError):
        pass

    class AuthenticationError(APIStatusError):
        pass

    class RateLimitError(APIStatusError):
        pass

    class APIConnectionError(Exception):
        pass

    calls = {"beta": 0, "plain": 0, "kwargs": None, "client": None}

    class Response:
        def __init__(self):
            self.stop_reason = stop_reason
            self.stop_details = types.SimpleNamespace(category=category) if category else None
            self.content = [types.SimpleNamespace(type="text", text=text if text is not None else json.dumps(VALID_PLAN))]
            self.usage = types.SimpleNamespace(input_tokens=11, output_tokens=7, cache_read_input_tokens=0, cache_creation_input_tokens=0)
            self.model = "claude-opus-5-5"

    class Messages:
        def __init__(self, beta):
            self.beta = beta

        def create(self, **kwargs):
            calls["kwargs"] = kwargs
            if self.beta:
                calls["beta"] += 1
                if beta_raises:
                    raise BadRequestError("beta not available", 400)
            else:
                calls["plain"] += 1
            return Response()

    class Anthropic:
        def __init__(self, **kw):
            calls["client"] = kw
            self.messages = Messages(beta=False)
            self.beta = types.SimpleNamespace(messages=Messages(beta=True))

    mod.Anthropic, mod.APIStatusError, mod.BadRequestError = Anthropic, APIStatusError, BadRequestError
    mod.AuthenticationError, mod.RateLimitError, mod.APIConnectionError = AuthenticationError, RateLimitError, APIConnectionError
    return mod, calls


class AnthropicProviderTests(unittest.TestCase):
    def provider(self, env=None, **fake_kw):
        mod, calls = _fake_anthropic(**fake_kw)
        patches = [mock.patch.dict(sys.modules, {"anthropic": mod}), mock.patch.dict(os.environ, env or {}, clear=False)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for key in ("AIIT_HIPAA_MODE", "AIIT_ANTHROPIC_FALLBACKS", "AIIT_LLM_TIMEOUT", "AIIT_LLM_MAX_RETRIES"):
            if key not in (env or {}):
                os.environ.pop(key, None)
        return get_provider("anthropic"), calls

    def test_missing_sdk_is_a_clear_error(self):
        with mock.patch.dict(sys.modules, {"anthropic": None}):
            with self.assertRaises(ProviderError):
                get_provider("anthropic")

    def test_success_uses_beta_fallbacks_by_default(self):
        p, calls = self.provider()
        self.assertEqual(p.model, "claude-opus-5-5")
        raw, usage = p.complete_json("sys", "usr", {"type": "object"}, {})
        self.assertEqual(raw["confidence"], 0.7)
        self.assertEqual((calls["beta"], calls["plain"]), (1, 0))
        self.assertEqual(calls["kwargs"]["output_config"]["format"]["schema"], {"type": "object"})
        self.assertEqual(calls["kwargs"]["output_config"]["effort"], "high")
        self.assertTrue(usage["fallbacks_enabled"])
        self.assertTrue(usage["hosted"])

    def test_beta_400_degrades_once(self):
        p, calls = self.provider(beta_raises=True)
        raw, usage = p.complete_json("s", "u", {}, {})
        self.assertEqual((calls["beta"], calls["plain"]), (1, 1))
        self.assertTrue(usage["fallbacks_degraded"])

    def test_hipaa_mode_disables_beta(self):
        p, calls = self.provider(env={"AIIT_HIPAA_MODE": "1", "AIIT_LLM_TIMEOUT": "42", "AIIT_LLM_MAX_RETRIES": "5"})
        self.assertFalse(p.fallbacks)
        p.complete_json("s", "u", {}, {})
        self.assertEqual((calls["beta"], calls["plain"]), (0, 1))
        self.assertEqual(calls["client"], {"max_retries": 5, "timeout": 42.0})

    def test_refusal_and_truncation(self):
        p, _ = self.provider(stop_reason="refusal", category="cyber")
        with self.assertRaises(ProviderRefusal) as cm:
            p.complete_json("s", "u", {}, {})
        self.assertIn("cyber", str(cm.exception))
        p, _ = self.provider(stop_reason="max_tokens")
        with self.assertRaises(ProviderError):
            p.complete_json("s", "u", {}, {})
        p, _ = self.provider(text="not json at all")
        with self.assertRaises(ProviderOutputError):
            p.complete_json("s", "u", {}, {})


class ScriptedProvider(LLMProvider):
    name = "scripted"
    model = "fake"

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.prompts = []

    def complete_json(self, system, user, schema, meta):
        self.prompts.append(user)
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            raise out
        return out, {"provider": self.name, "model": self.model, "input_tokens": 3, "output_tokens": 2}


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = helpers.make_console(self.root / "console")
        self.agent = helpers.agent_identity()
        p = helpers.seal_diagnostics(self.state, self.agent, self.root / "b.aiit",
                                     files={"logs/journal_errors.txt": "x" * 5000, "sys/lsusb.txt": "y" * 5000, "sys/empty.txt": ""})
        self.case_id, _, _ = self.state.ingest_bundle(p)
        self.cdir = self.state.cases_dir / self.case_id

    def tearDown(self):
        self.tmp.cleanup()

    def test_priority_budget_and_fences(self):
        self.assertLess(_rank("sys/failed_units.txt"), _rank("sys/lsusb.txt"))
        self.assertEqual(_rank("zzz.txt"), len(PRIORITY))
        ctx, included = build_context(self.cdir, "operator jdoe@example.org says boom", max_chars=7000, delimiter="abc123")
        self.assertEqual(included, ["logs/journal_errors.txt"])
        self.assertNotIn("jdoe@example.org", ctx)
        self.assertIn("<EMAIL_", ctx)
        self.assertIn("Data delimiter for this request: AIIT-DATA-abc123", ctx)
        self.assertEqual(ctx.count("<<<AIIT-DATA-abc123"), 1)
        self.assertEqual(ctx.count("AIIT-DATA-abc123>>>"), 1)
        ctx2, included2 = build_context(self.cdir, "", max_chars=50_000)
        self.assertEqual(included2, ["logs/journal_errors.txt", "sys/lsusb.txt"])

    def test_repair_loop_recovers_and_audits(self):
        bad = {"issue_summary": "x", "diagnosis": "y", "confidence": 2.5, "steps": []}
        provider = ScriptedProvider([bad, ProviderOutputError("garbage", raw_text="{{{"), VALID_PLAN])
        with mock.patch.dict(os.environ, {"AIIT_PLAN_REPAIRS": "2"}):
            plan, warnings = diagnose(self.state, self.case_id, "it is slow", provider)
        self.assertEqual(plan.confidence, 0.7)
        self.assertEqual(len(provider.prompts), 3)
        self.assertIn("Your previous answer was rejected", provider.prompts[1])
        self.assertIn("schema violation at confidence", provider.prompts[1])
        self.assertIn("could not be parsed", provider.prompts[2])
        actions = [e["action"] for e in self.state.audit.entries()]
        self.assertIn("llm_invalid_plan", actions)
        self.assertIn("llm_output_error", actions)
        self.assertEqual(actions.count("llm_repair"), 2)
        created = [e for e in self.state.audit.entries() if e["action"] == "plan_created"][-1]
        self.assertEqual(created["details"]["attempts"], 3)
        invalid = [e for e in self.state.audit.entries() if e["action"] == "llm_invalid_plan"][-1]
        self.assertNotIn("2.5", json.dumps(invalid))

    def test_repair_exhausted_saves_rejected_output(self):
        provider = ScriptedProvider([ProviderOutputError("garbage", raw_text="nope"), ProviderOutputError("garbage", raw_text="nope2")])
        with mock.patch.dict(os.environ, {"AIIT_PLAN_REPAIRS": "1"}):
            with self.assertRaises(ProviderError) as cm:
                diagnose(self.state, self.case_id, "", provider)
        self.assertIn("rejected output is saved", str(cm.exception))
        self.assertTrue(list((self.cdir / "plans").glob("rejected-*.json")))
        self.assertEqual([p for p in (self.cdir / "plans").glob("plan-*.json")], [])

    def test_refusal_is_not_repaired(self):
        provider = ScriptedProvider([ProviderRefusal("no"), VALID_PLAN])
        with self.assertRaises(ProviderRefusal):
            diagnose(self.state, self.case_id, "", provider)
        self.assertEqual(len(provider.prompts), 1)

    def test_lint_warnings(self):
        draft = FixPlanDraft.model_validate({"issue_summary": "x", "diagnosis": "y", "confidence": 0.5, "steps": [
            {"id": "s1", "title": "t", "rationale": "r", "action": "command", "os": "windows", "command": "Get-Service", "risk": "read_only"},
            {"id": "s1", "title": "t", "rationale": "r", "action": "command", "os": "any", "command": "rm -rf /", "risk": "low"}]})
        w = lint_plan(draft, "linux")
        self.assertTrue(any("targets windows" in x for x in w))
        self.assertTrue(any("duplicate step id" in x for x in w))
        self.assertTrue(any("no rollback" in x for x in w))
        self.assertTrue(any("blocked by the default policy" in x for x in w))


if __name__ == "__main__":
    unittest.main()
