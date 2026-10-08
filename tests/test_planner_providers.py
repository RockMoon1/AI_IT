import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from . import helpers  # noqa: F401
from aiit.common.schema import FixPlanDraft
from aiit.console.llm import ProviderError, get_provider
from aiit.console.llm.ollama import OllamaProvider
from aiit.console.planner import PRIORITY, _rank, build_context


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


class FakeOllama(BaseHTTPRequestHandler):
    reply: dict = {}
    seen: list = []

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n))
        FakeOllama.seen.append(body)
        out = json.dumps(FakeOllama.reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class OllamaProviderTests(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), FakeOllama)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_structured_output_roundtrip(self):
        plan = {"issue_summary": "x", "diagnosis": "y", "confidence": 0.7, "steps": [
            {"id": "s1", "title": "t", "rationale": "r", "action": "command", "os": "linux", "command": "df -h", "risk": "read_only"}]}
        FakeOllama.reply = {"model": "fake:1b", "message": {"role": "assistant", "content": json.dumps(plan)}, "prompt_eval_count": 10, "eval_count": 5, "total_duration": 2_000_000}
        p = OllamaProvider(url=self.url, model="fake:1b")
        raw, usage = p.complete_json("sys", "usr", {"type": "object"}, {})
        self.assertEqual(raw["confidence"], 0.7)
        self.assertEqual(usage["prompt_tokens"], 10)
        self.assertEqual(FakeOllama.seen[-1]["format"], {"type": "object"})
        self.assertFalse(FakeOllama.seen[-1]["stream"])

    def test_non_json_output_is_an_error(self):
        FakeOllama.reply = {"model": "fake", "message": {"content": "not json"}}
        with self.assertRaises(ProviderError):
            OllamaProvider(url=self.url, model="fake").complete_json("s", "u", {}, {})

    def test_unreachable(self):
        with self.assertRaises(ProviderError):
            OllamaProvider(url="http://127.0.0.1:9", model="fake", timeout=2).complete_json("s", "u", {}, {})


class AnthropicProviderTests(unittest.TestCase):
    def test_missing_sdk_is_a_clear_error(self):
        try:
            import anthropic  # noqa: F401
        except ImportError:
            with self.assertRaises(ProviderError):
                get_provider("anthropic")
        else:
            p = get_provider("anthropic")
            self.assertEqual(p.model, "claude-opus-5-5")


class ContextTests(unittest.TestCase):
    def test_priority_and_budget(self):
        self.assertLess(_rank("sys/failed_units.txt"), _rank("sys/lsusb.txt"))
        self.assertEqual(_rank("zzz.txt"), len(PRIORITY))
        with tempfile.TemporaryDirectory() as d:
            cdir = Path(d)
            (cdir / "redacted").mkdir()
            (cdir / "case.json").write_text(json.dumps({"case_id": "case-1"}))
            files = []
            for name, size in [("sys/lsusb.txt", 5000), ("logs/journal_errors.txt", 5000), ("sys/empty.txt", 0)]:
                p = cdir / "redacted" / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x" * size)
                files.append({"path": name, "sha256": "", "size": size, "collector": name, "exit_code": 0})
            manifest = {"platform": "linux", "os_version": "v", "hostname": "<HOST_1>", "collected_at": "t", "issue_description": "boom", "files": files}
            (cdir / "redacted" / "manifest.json").write_text(json.dumps(manifest))
            ctx, included = build_context(cdir, "op issue", max_chars=7000)
            self.assertEqual(included, ["logs/journal_errors.txt"])   # higher priority wins the budget
            self.assertIn("op issue", ctx)
            self.assertIn("boom", ctx)
            self.assertLessEqual(len(ctx), 7000 + 200)
            ctx2, included2 = build_context(cdir, "", max_chars=50_000)
            self.assertEqual(included2, ["logs/journal_errors.txt", "sys/lsusb.txt"])


if __name__ == "__main__":
    unittest.main()
