"""OpenAICompatProvider against a scripted HTTP server: request shape, the format ladder, error mapping, key hygiene."""
import json
import os
import unittest
import unittest.mock as mock

from . import helpers
from aiit.console.llm import OPENAI_COMPAT_NAMES, PROVIDER_NAMES, ProviderError, ProviderOutputError, ProviderRefusal, get_provider
from aiit.console.llm.openai_compat import FORMAT_MODES, PRESETS, OpenAICompatProvider, strict_schema
from aiit.console.planner import plan_json_schema

# helpers.scrub_env drops AIIT_* and ANTHROPIC_API_KEY; a developer's own OpenAI keys must not reach these tests either
for _name in ("OPENAI_API_KEY", "AZURE_OPENAI_API_KEY"):
    os.environ.pop(_name, None)

VALID_PLAN = {"issue_summary": "x", "diagnosis": "y", "confidence": 0.7, "steps": [
    {"id": "s1", "title": "t", "rationale": "r", "action": "command", "os": "linux", "command": "df -h", "risk": "read_only"}]}
# built by concatenation so nothing in this file looks like a credential
KEY = "sk-" + "unit-" + "k" * 24
OTHER_KEY = "sk-" + "other-" + "o" * 24


def chat_reply(content=None, *, finish="stop", refusal=None, model="fake-model", usage=True):
    message = {"role": "assistant", "content": json.dumps(VALID_PLAN) if content is None else content}
    if refusal is not None:
        message["refusal"] = refusal
    body = {"id": "chatcmpl-1", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}]}
    if usage:
        body["usage"] = {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19,
                         "prompt_tokens_details": {"cached_tokens": 3}, "completion_tokens_details": {"reasoning_tokens": 2}}
    return body


def api_error(message, code=None):
    return {"error": {"message": message, "type": "invalid_request_error", "param": None, "code": code}}


class ServerCase(unittest.TestCase):
    # one scripted server per class: every FakeHTTP.stop() waits out the 0.5 s serve_forever poll
    @classmethod
    def setUpClass(cls):
        cls.srv = helpers.FakeHTTP().start()
        cls.base = cls.srv.url + "/v1"

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def setUp(self):
        self.srv.replies.clear()
        self.srv.requests.clear()
        # no sleeping between retries, and a clean environment for every test
        sleeper = mock.patch("aiit.common.net._sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for name in ("OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "AIIT_OPENAI_API_KEY", "AIIT_OPENAI_BASE_URL", "AIIT_OPENAI_MODEL",
                     "AIIT_AZURE_OPENAI_DEPLOYMENT", "AIIT_AZURE_OPENAI_API_VERSION", "AIIT_LLM_TIMEOUT", "AIIT_LLM_MAX_RETRIES"):
            os.environ.pop(name, None)

    def openai(self, **kw):
        kw.setdefault("api_key", KEY)
        return OpenAICompatProvider("openai", base_url=self.base, max_retries=0, **kw)

    def compat(self, **kw):
        return OpenAICompatProvider("openai-compat", base_url=self.base, max_retries=0, **kw)

    def azure(self, **kw):
        kw.setdefault("api_key", KEY)
        kw.setdefault("deployment", "dep1")
        kw.setdefault("api_version", "2024-10-21")
        kw.setdefault("base_url", self.srv.url)
        return OpenAICompatProvider("azure-openai", max_retries=0, **kw)

    def last_body(self):
        return json.loads(self.srv.requests[-1]["body"])


class RequestShapeTests(ServerCase):
    def test_json_schema_happy_path(self):
        self.srv.queue(200, chat_reply())
        p = self.openai(model="gpt-test")
        raw, usage = p.complete_json("sys", "usr", {"type": "object", "properties": {"a": {"type": "string", "default": "x"}}}, {"issue": "local only"})
        self.assertEqual(raw["confidence"], 0.7)
        req = self.srv.requests[-1]
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["authorization"], "Bearer " + KEY)
        self.assertNotIn("api-key", req["headers"])
        body = json.loads(req["body"])
        self.assertEqual(body["model"], "gpt-test")
        self.assertEqual([m["role"] for m in body["messages"]], ["system", "user"])
        self.assertEqual(body["messages"][0]["content"], "sys")
        self.assertEqual(body["messages"][1]["content"], "usr")
        self.assertNotIn("local only", req["body"].decode())  # meta is local-only
        rf = body["response_format"]
        self.assertEqual(rf["type"], "json_schema")
        self.assertTrue(rf["json_schema"]["strict"])
        self.assertEqual(rf["json_schema"]["name"], "fix_plan")
        self.assertEqual(rf["json_schema"]["schema"], {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": False})
        self.assertNotIn(KEY, req["body"].decode())
        self.assertNotIn(KEY, json.dumps(usage))
        self.assertNotIn(KEY, repr(p))
        self.assertEqual(usage["provider"], "openai")
        self.assertEqual(usage["flavor"], "openai")
        self.assertEqual(usage["model"], "fake-model")
        self.assertEqual(usage["endpoint_host"], "127.0.0.1")
        self.assertTrue(usage["hosted"])
        self.assertEqual(usage["format_mode"], "json_schema")
        self.assertFalse(usage["format_degraded"])
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["total_tokens"]), (12, 7, 19))
        self.assertEqual((usage["cached_input_tokens"], usage["reasoning_tokens"]), (3, 2))
        self.assertEqual(usage["finish_reason"], "stop")

    def test_missing_usage_and_part_list_content_are_tolerated(self):
        parts = [{"type": "text", "text": "```json\n" + json.dumps(VALID_PLAN)}, {"type": "text", "text": "\n```"}]
        self.srv.queue(200, chat_reply(content=parts, usage=False))
        raw, usage = self.compat().complete_json("s", "u", {}, {})
        self.assertEqual(raw["confidence"], 0.7)
        self.assertIsNone(usage["input_tokens"])
        self.assertIsNone(usage["cached_input_tokens"])

    def test_compat_without_model_omits_the_field_and_reports_the_servers(self):
        self.srv.queue(200, chat_reply(model="served-model"))
        p = self.compat()
        self.assertEqual(p.model, "")
        _, usage = p.complete_json("s", "u", {}, {})
        self.assertNotIn("model", self.last_body())
        self.assertEqual(usage["model"], "served-model")

    def test_azure_url_and_header_shape(self):
        self.srv.queue(200, chat_reply())
        p = self.azure()
        self.assertTrue(p.hosted)
        self.assertEqual(p.model, "dep1")  # no AIIT_OPENAI_MODEL: the deployment names the model
        _, usage = p.complete_json("s", "u", {"type": "object"}, {})
        req = self.srv.requests[-1]
        self.assertEqual(req["path"], "/openai/deployments/dep1/chat/completions?api-version=2024-10-21")
        self.assertEqual(req["headers"]["api-key"], KEY)
        self.assertNotIn("authorization", req["headers"])
        self.assertNotIn(KEY, req["body"].decode())
        self.assertNotIn(KEY, json.dumps(usage))
        self.assertEqual(usage["deployment"], "dep1")
        self.assertEqual(usage["flavor"], "azure")
        self.assertTrue(usage["hosted"])
        # a base URL that already ends in /openai, and a deployment name that needs quoting
        p = self.azure(base_url=self.srv.url + "/openai/", deployment="my dep", api_version="2025-01-01-preview")
        self.srv.queue(200, chat_reply())
        p.complete_json("s", "u", {}, {})
        self.assertEqual(self.srv.requests[-1]["path"], "/openai/deployments/my%20dep/chat/completions?api-version=2025-01-01-preview")

    def test_loopback_compat_server_works_with_no_key(self):
        self.srv.queue(200, chat_reply())
        p = self.compat()
        self.assertFalse(p.hosted)
        self.assertEqual(p.endpoint_host, "127.0.0.1")
        raw, usage = p.complete_json("s", "u", {}, {})
        self.assertEqual(raw["confidence"], 0.7)
        headers = self.srv.requests[-1]["headers"]
        self.assertNotIn("authorization", headers)
        self.assertNotIn("api-key", headers)
        self.assertFalse(usage["hosted"])
        # a key, when given, is a bearer header and nothing else
        self.srv.queue(200, chat_reply())
        self.compat(api_key=KEY).complete_json("s", "u", {}, {})
        self.assertEqual(self.srv.requests[-1]["headers"]["authorization"], "Bearer " + KEY)
        self.assertNotIn(KEY, self.srv.requests[-1]["body"].decode())


class FormatLadderTests(ServerCase):
    REJECT_SCHEMA = api_error("Invalid parameter: 'response_format' of type 'json_schema' is not supported with this model.")
    REJECT_OBJECT = api_error("response_format unsupported", code="unsupported_value")

    def test_degrades_to_json_object(self):
        self.srv.queue(400, self.REJECT_SCHEMA).queue(200, chat_reply())
        raw, usage = self.openai().complete_json("sys", "usr", {"type": "object"}, {})
        self.assertEqual(raw["confidence"], 0.7)
        self.assertEqual(len(self.srv.requests), 2)
        body = self.last_body()
        self.assertEqual(body["response_format"], {"type": "json_object"})
        # json_object mode is refused upstream unless the prompt mentions JSON, so the ask is added when it is missing
        self.assertTrue(body["messages"][0]["content"].endswith("Respond with a single JSON object and nothing else."))
        self.assertEqual(usage["format_mode"], "json_object")
        self.assertTrue(usage["format_degraded"])

    def test_degrades_to_none_then_gives_up(self):
        self.srv.queue(400, self.REJECT_SCHEMA).queue(400, self.REJECT_OBJECT).queue(200, chat_reply())
        _, usage = self.compat().complete_json("Answer in JSON.", "u", {"type": "object"}, {})
        self.assertEqual(len(self.srv.requests), 3)
        self.assertNotIn("response_format", self.last_body())
        self.assertEqual(self.last_body()["messages"][0]["content"], "Answer in JSON.")  # already asks for JSON: unchanged
        self.assertEqual(usage["format_mode"], "none")
        self.assertTrue(usage["format_degraded"])
        self.srv.requests.clear()
        self.srv.queue(400, self.REJECT_SCHEMA).queue(400, self.REJECT_OBJECT).queue(400, api_error("still bad: schema"))
        with self.assertRaises(ProviderError) as cm:
            self.compat().complete_json("s", "u", {}, {})
        self.assertNotIsInstance(cm.exception, (ProviderRefusal, ProviderOutputError))
        self.assertIn("HTTP 400", str(cm.exception))
        self.assertIn("still bad", str(cm.exception))
        self.assertEqual(len(self.srv.requests), 3)

    def test_unrelated_400_is_not_retried_down_the_ladder(self):
        self.srv.queue(400, api_error("Invalid 'messages[1].content': string too long."))
        with self.assertRaises(ProviderError) as cm:
            self.openai().complete_json("s", "u", {}, {})
        self.assertEqual(len(self.srv.requests), 1)
        self.assertIn("string too long", str(cm.exception))

    def test_ladder_starts_at_the_configured_mode(self):
        self.srv.queue(200, chat_reply())
        _, usage = self.compat(format_mode="json_object").complete_json("s", "u", {}, {})
        self.assertEqual(self.last_body()["response_format"], {"type": "json_object"})
        self.assertEqual(usage["format_mode"], "json_object")
        self.assertFalse(usage["format_degraded"])
        self.srv.queue(200, chat_reply())
        self.compat(format_mode="none").complete_json("s", "u", {}, {})
        self.assertNotIn("response_format", self.last_body())
        with self.assertRaises(ProviderError):
            self.compat(format_mode="yaml")
        self.assertEqual(FORMAT_MODES, ("json_schema", "json_object", "none"))


class ReplyMappingTests(ServerCase):
    def test_length_is_a_provider_error(self):
        self.srv.queue(200, chat_reply(content='{"issue_summary": "cut', finish="length"))
        with self.assertRaises(ProviderError) as cm:
            self.openai().complete_json("s", "u", {}, {})
        self.assertNotIsInstance(cm.exception, (ProviderRefusal, ProviderOutputError))
        self.assertIn("cut off", str(cm.exception))

    def test_refusal_and_content_filter_are_refusals_without_echoing_the_text(self):
        self.srv.queue(200, chat_reply(content=None, refusal="I will not help with SECRETWORD"))
        with self.assertRaises(ProviderRefusal) as cm:
            self.openai().complete_json("s", "u", {}, {})
        self.assertNotIn("SECRETWORD", str(cm.exception))
        self.srv.queue(200, chat_reply(content="", finish="content_filter"))
        with self.assertRaises(ProviderRefusal):
            self.azure().complete_json("s", "u", {}, {})
        # Azure filters the prompt itself with a 400 whose code is content_filter: a refusal, not a ladder step
        self.srv.queue(400, api_error("The response was filtered due to the prompt triggering the content management policy.", code="content_filter"))
        with self.assertRaises(ProviderRefusal):
            self.azure().complete_json("s", "u", {}, {})
        self.assertEqual(len(self.srv.requests), 3)

    def test_garbage_is_output_error_with_raw_text(self):
        self.srv.queue(200, chat_reply(content="Sure! Here is what I think, no braces at all"))
        with self.assertRaises(ProviderOutputError) as cm:
            self.compat().complete_json("s", "u", {}, {})
        self.assertEqual(cm.exception.raw_text, "Sure! Here is what I think, no braces at all")
        self.srv.queue(200, chat_reply(content="[1, 2]"))
        with self.assertRaises(ProviderOutputError):
            self.compat().complete_json("s", "u", {}, {})

    def test_reply_without_choices(self):
        self.srv.queue(200, {"detail": "Not Found"})
        with self.assertRaises(ProviderError) as cm:
            self.compat().complete_json("s", "u", {}, {})
        self.assertNotIsInstance(cm.exception, ProviderOutputError)
        self.assertIn("chat completions endpoint", str(cm.exception))


class ErrorHintTests(ServerCase):
    def test_401_points_at_the_key(self):
        self.srv.queue(401, api_error("Incorrect API key provided", code="invalid_api_key"))
        with self.assertRaises(ProviderError) as cm:
            self.openai().complete_json("s", "u", {}, {})
        msg = str(cm.exception)
        self.assertIn("HTTP 401", msg)
        self.assertIn("OPENAI_API_KEY", msg)
        self.assertNotIn(KEY, msg)
        self.srv.queue(401, api_error("Access denied due to invalid subscription key"))
        with self.assertRaises(ProviderError) as cm:
            self.azure().complete_json("s", "u", {}, {})
        self.assertIn("AZURE_OPENAI_API_KEY", str(cm.exception))
        self.srv.queue(401, "unauthorized")
        with self.assertRaises(ProviderError) as cm:
            self.compat().complete_json("s", "u", {}, {})
        self.assertIn("wants a key", str(cm.exception))
        self.srv.queue(403, api_error("project does not have access to model"))
        with self.assertRaises(ProviderError) as cm:
            self.openai().complete_json("s", "u", {}, {})
        self.assertIn("HTTP 403", str(cm.exception))

    def test_404_points_at_base_url_and_model(self):
        self.srv.queue(404, api_error("The model 'nope' does not exist", code="model_not_found"))
        with self.assertRaises(ProviderError) as cm:
            self.openai(model="nope").complete_json("s", "u", {}, {})
        msg = str(cm.exception)
        self.assertIn("AIIT_OPENAI_BASE_URL", msg)
        self.assertIn("AIIT_OPENAI_MODEL='nope'", msg)
        self.assertIn("does not exist", msg)
        self.srv.queue(404, api_error("The API deployment for this resource does not exist", code="DeploymentNotFound"))
        with self.assertRaises(ProviderError) as cm:
            self.azure().complete_json("s", "u", {}, {})
        self.assertIn("AIIT_AZURE_OPENAI_DEPLOYMENT", str(cm.exception))
        self.assertIn("'dep1'", str(cm.exception))

    def test_429_and_5xx(self):
        self.srv.queue(429, api_error("Rate limit reached"))
        with self.assertRaises(ProviderError) as cm:
            self.openai().complete_json("s", "u", {}, {})
        self.assertIn("rate limited", str(cm.exception))
        self.srv.queue(502, "<html>bad gateway</html>")
        with self.assertRaises(ProviderError) as cm:
            self.compat().complete_json("s", "u", {}, {})
        self.assertIn("HTTP 502", str(cm.exception))
        self.assertNotIsInstance(cm.exception, (ProviderRefusal, ProviderOutputError))

    def test_connection_refused_on_a_local_url_asks_whether_the_server_runs(self):
        with self.assertRaises(ProviderError) as cm:
            OpenAICompatProvider("vllm", base_url="http://127.0.0.1:9/v1", max_retries=0, timeout=2).complete_json("s", "u", {}, {})
        self.assertIn("vllm serve", str(cm.exception))
        with self.assertRaises(ProviderError) as cm:
            OpenAICompatProvider("openai-compat", base_url="http://127.0.0.1:9/v1", max_retries=0, timeout=2).complete_json("s", "u", {}, {})
        self.assertIn("running", str(cm.exception))
        self.assertIn("127.0.0.1:9", str(cm.exception))

    def test_timeout_is_a_provider_error(self):
        self.srv.queue(200, chat_reply(), delay=1.5)
        with self.assertRaises(ProviderError) as cm:
            self.compat(timeout=0.3).complete_json("s", "u", {}, {})
        self.assertIn("timeout 0.3s", str(cm.exception))
        self.assertEqual(len(self.srv.requests), 1)

    def test_missing_key_for_a_hosted_flavor_sends_nothing(self):
        with self.assertRaises(ProviderError) as cm:
            self.openai(api_key="").complete_json("s", "u", {}, {})
        self.assertIn("OPENAI_API_KEY", str(cm.exception))
        with self.assertRaises(ProviderError) as cm:
            self.azure(api_key="").complete_json("s", "u", {}, {})
        self.assertIn("AZURE_OPENAI_API_KEY", str(cm.exception))
        self.assertEqual(self.srv.requests, [])


class ConfigTests(ServerCase):
    def test_hosted_flag_per_flavor(self):
        self.assertTrue(OpenAICompatProvider("openai", api_key=KEY).hosted)
        self.assertEqual(OpenAICompatProvider("openai", api_key=KEY).endpoint_host, "api.openai.com")
        self.assertTrue(self.openai().hosted)  # openai flavor through a loopback proxy still leaves the machine
        self.assertTrue(self.azure().hosted)
        self.assertFalse(self.compat().hosted)
        self.assertFalse(OpenAICompatProvider("openai-compat", base_url="http://10.0.0.5:8000/v1").hosted)
        self.assertFalse(OpenAICompatProvider("openai-compat", base_url="http://gpu-box.local:8000/v1").hosted)
        public = OpenAICompatProvider("openai-compat", base_url="https://8.8.8.8/v1")
        self.assertTrue(public.hosted)
        self.assertEqual(public.endpoint_host, "8.8.8.8")
        for alias, port in (("llamacpp", 8080), ("vllm", 8000), ("lmstudio", 1234)):
            p = OpenAICompatProvider(alias)
            self.assertEqual((p.flavor, p.base_url, p.hosted, p.name), ("compat", f"http://127.0.0.1:{port}/v1", False, alias))

    def test_env_driven_config(self):
        env = {"AIIT_OPENAI_BASE_URL": self.base, "AIIT_OPENAI_MODEL": "env-model", "AIIT_OPENAI_API_KEY": KEY, "OPENAI_API_KEY": OTHER_KEY,
               "AIIT_LLM_TIMEOUT": "42", "AIIT_LLM_MAX_RETRIES": "0", "AIIT_AZURE_OPENAI_DEPLOYMENT": "env-dep",
               "AIIT_AZURE_OPENAI_API_VERSION": "2024-06-01"}
        with mock.patch.dict(os.environ, env):
            p = get_provider("openai")
            self.assertIsInstance(p, OpenAICompatProvider)
            self.assertEqual((p.base_url, p.model, p.timeout, p.max_retries), (self.base, "env-model", 42.0, 0))
            self.srv.queue(200, chat_reply())
            p.complete_json("s", "u", {}, {})
            self.assertEqual(self.srv.requests[-1]["headers"]["authorization"], "Bearer " + KEY)  # AIIT_OPENAI_API_KEY wins
            a = get_provider("azure-openai")
            self.assertEqual((a.flavor, a.deployment, a.api_version, a.model), ("azure", "env-dep", "2024-06-01", "env-model"))
            self.srv.queue(200, chat_reply())
            a.complete_json("s", "u", {}, {})
            self.assertEqual(self.srv.requests[-1]["headers"]["api-key"], KEY)
            self.assertEqual(self.srv.requests[-1]["path"], "/v1/openai/deployments/env-dep/chat/completions?api-version=2024-06-01")
            c = get_provider("openai-compat", model="cli-model")
            self.assertEqual((c.flavor, c.model, c.hosted), ("compat", "cli-model", False))  # a CLI --model beats the env
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": OTHER_KEY, "AIIT_OPENAI_BASE_URL": self.base}):
            self.srv.queue(200, chat_reply())
            get_provider("openai").complete_json("s", "u", {}, {})
            self.assertEqual(self.srv.requests[-1]["headers"]["authorization"], "Bearer " + OTHER_KEY)
            self.srv.queue(200, chat_reply())
            get_provider("llamacpp").complete_json("s", "u", {}, {})  # the env base URL overrides the alias default
            self.assertEqual(self.srv.requests[-1]["path"], "/v1/chat/completions")
        with mock.patch.dict(os.environ, {"AZURE_OPENAI_API_KEY": OTHER_KEY, "AIIT_OPENAI_BASE_URL": self.srv.url, "AIIT_AZURE_OPENAI_DEPLOYMENT": "d"}):
            self.srv.queue(200, chat_reply())
            get_provider("azure-openai").complete_json("s", "u", {}, {})
            self.assertEqual(self.srv.requests[-1]["headers"]["api-key"], OTHER_KEY)
        self.assertEqual(get_provider("openai").model, "gpt-5")
        self.assertEqual(get_provider("openai").timeout, 600.0)

    def test_missing_settings_are_clear_errors(self):
        with self.assertRaises(ProviderError) as cm:
            get_provider("openai-compat")
        self.assertIn("AIIT_OPENAI_BASE_URL", str(cm.exception))
        with self.assertRaises(ProviderError) as cm:
            get_provider("azure-openai")
        self.assertIn("AIIT_OPENAI_BASE_URL", str(cm.exception))
        with self.assertRaises(ProviderError) as cm:
            OpenAICompatProvider("azure-openai", base_url="https://r.openai.azure.com")
        self.assertIn("AIIT_AZURE_OPENAI_DEPLOYMENT", str(cm.exception))
        for bad in ("ftp://x/v1", "127.0.0.1:8080/v1", "http:///v1"):
            with self.assertRaises(ProviderError):
                OpenAICompatProvider("openai-compat", base_url=bad)
        with self.assertRaises(ProviderError):
            OpenAICompatProvider("not-a-preset")

    def test_registry(self):
        self.assertEqual(set(OPENAI_COMPAT_NAMES), set(PRESETS))
        for name in OPENAI_COMPAT_NAMES:
            self.assertIn(name, PROVIDER_NAMES)
        self.assertEqual(PROVIDER_NAMES[:3], ("dryrun", "ollama", "anthropic"))
        for name, flavor in (("openai", "openai"), ("llamacpp", "compat"), ("vllm", "compat"), ("lmstudio", "compat")):
            p = get_provider(name)
            self.assertIsInstance(p, OpenAICompatProvider)
            self.assertEqual((p.name, p.flavor), (name, flavor))
        self.assertEqual(get_provider("OpenAI").name, "openai")


class StrictSchemaTests(unittest.TestCase):
    def test_real_plan_schema_becomes_strict_without_touching_the_original(self):
        original = plan_json_schema()
        before = json.dumps(original, sort_keys=True)
        strict = strict_schema(original)
        self.assertEqual(json.dumps(original, sort_keys=True), before)

        def check(node):
            if isinstance(node, list):
                for x in node:
                    check(x)
                return
            if not isinstance(node, dict):
                return
            self.assertNotIn("default", node)
            if "properties" in node:
                self.assertIs(node["additionalProperties"], False)
                self.assertEqual(node["required"], list(node["properties"]))
                for sub in node["properties"].values():
                    check(sub)
            for key, value in node.items():
                if key != "properties":
                    check(value)

        check(strict)
        step = strict["$defs"]["PlanStep"]
        self.assertIn("rollback", step["required"])
        self.assertEqual(step["properties"]["rollback"]["anyOf"], [{"type": "string"}, {"type": "null"}])  # null still allowed
        self.assertEqual(step["properties"]["os"]["enum"], ["windows", "linux", "macos", "any"])
        self.assertEqual(strict["properties"]["steps"]["items"], {"$ref": "#/$defs/PlanStep"})
        self.assertEqual(strict["properties"]["confidence"]["minimum"], 0.0)

    def test_property_names_are_not_keywords(self):
        schema = {"type": "object", "properties": {"default": {"type": "string", "default": "x"}, "properties": {"type": "object"}},
                  "$defs": {"default": {"type": "integer", "examples": [1]}}}
        strict = strict_schema(schema)
        self.assertEqual(strict["properties"]["default"], {"type": "string"})
        self.assertEqual(strict["properties"]["properties"], {"type": "object", "additionalProperties": False})
        self.assertEqual(strict["$defs"]["default"], {"type": "integer"})
        self.assertEqual(strict["required"], ["default", "properties"])
        self.assertEqual(strict_schema({}), {})


if __name__ == "__main__":
    unittest.main()
