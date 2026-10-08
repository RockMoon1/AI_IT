"""Local model via Ollama's HTTP API (structured output through the `format` field)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .base import LLMProvider, ProviderError


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, url: str | None = None, model: str | None = None, timeout: int = 600, **_: Any):
        self.url = (url or os.environ.get("AIIT_OLLAMA_URL") or "http://127.0.0.1:11434").rstrip("/")
        self.model = model or os.environ.get("AIIT_OLLAMA_MODEL") or "qwen2.5:14b"
        self.timeout = timeout

    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": schema,
            "options": {"temperature": 0.2, "num_ctx": int(os.environ.get("AIIT_OLLAMA_NUM_CTX", "32768"))},
        }
        req = urllib.request.Request(self.url + "/api/chat", data=json.dumps(body).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise ProviderError(f"Ollama HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}") from e
        except urllib.error.URLError as e:
            raise ProviderError(f"Cannot reach Ollama at {self.url}: {e.reason}. Is `ollama serve` running?") from e
        content = (data.get("message") or {}).get("content", "")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as e:
            raise ProviderError(f"Ollama returned non-JSON output ({e}); try a larger model or lower num_ctx pressure") from e
        usage = {
            "provider": self.name, "model": data.get("model", self.model),
            "prompt_tokens": data.get("prompt_eval_count"), "output_tokens": data.get("eval_count"),
            "total_duration_ms": int((data.get("total_duration") or 0) / 1e6),
        }
        return parsed, usage
