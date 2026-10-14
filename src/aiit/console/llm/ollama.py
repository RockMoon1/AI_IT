"""Local model via Ollama's HTTP API (structured output through the `format` field)."""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

from ...common.net import HttpStatusError, NetError, http_json, is_loopback_or_private
from .base import LLMProvider, ProviderError, parse_json_text


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, url: str | None = None, model: str | None = None, timeout: float | None = None, **_: Any):
        self.url = (url or os.environ.get("AIIT_OLLAMA_URL") or "http://127.0.0.1:11434").rstrip("/")
        self.model = model or os.environ.get("AIIT_OLLAMA_MODEL") or "qwen2.5:14b"
        self.timeout = timeout if timeout is not None else _env_float("AIIT_OLLAMA_TIMEOUT", _env_float("AIIT_LLM_TIMEOUT", 600.0))
        self.num_ctx = int(os.environ.get("AIIT_OLLAMA_NUM_CTX", "32768") or 32768)
        self.endpoint_host = urlsplit(self.url).hostname or "local"
        self.hosted = not is_loopback_or_private(self.url)
        # a rough character budget so the prompt fits the context window (about 3.5 chars per token)
        self.max_input_chars = max(20_000, int(self.num_ctx * 3.5) - 8_000)

    def _chat(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            return http_json("POST", self.url + "/api/chat", body=body, timeout=self.timeout, retries=1)
        except HttpStatusError as e:
            if e.status == 404:
                raise ProviderError(f"Ollama has no model {self.model!r}; run: ollama pull {self.model}") from e
            raise ProviderError(f"Ollama returned HTTP {e.status}: {e.body_snippet[:200]}") from e
        except NetError as e:
            raise ProviderError(f"cannot talk to Ollama at {self.url}: {e}. Is `ollama serve` running? (timeout {self.timeout:g}s)") from e

    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": schema,
            "options": {"temperature": 0.2, "num_ctx": self.num_ctx},
        }
        degraded = False
        try:
            data = self._chat(body)
        except ProviderError as e:
            cause = e.__cause__
            if isinstance(cause, HttpStatusError) and cause.status == 400 and "format" in cause.body_snippet.lower():
                body["format"] = "json"
                degraded = True
                data = self._chat(body)
            else:
                raise
        content = (data.get("message") or {}).get("content", "")
        parsed = parse_json_text(content)
        prompt_tokens = data.get("prompt_eval_count")
        usage = {
            "provider": self.name, "model": data.get("model", self.model),
            "prompt_tokens": prompt_tokens, "output_tokens": data.get("eval_count"),
            "total_duration_ms": int((data.get("total_duration") or 0) / 1e6),
            "format_degraded": degraded, "hosted": self.hosted,
            "context_truncated": bool(prompt_tokens and prompt_tokens >= self.num_ctx - 256),
        }
        return parsed, usage
