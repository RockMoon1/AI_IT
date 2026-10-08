"""Claude via the official `anthropic` SDK.

Only use this with PHI-bearing bundles when your organization has a signed
BAA and a HIPAA-ready org (docs/compliance/hipaa.md section 5). The API key
is read by the SDK from ANTHROPIC_API_KEY; it is never written to disk by AI_IT.
"""
from __future__ import annotations

import json
import os
from typing import Any

from .base import LLMProvider, ProviderError, ProviderRefusal

DEFAULT_MODEL = "claude-opus-5-5"


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str | None = None, effort: str | None = None, fallbacks: bool | None = None, max_tokens: int = 16000, **_: Any):
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise ProviderError("the `anthropic` package is not installed: pip install 'aiit[anthropic]'") from e
        self.model = model or os.environ.get("AIIT_ANTHROPIC_MODEL") or DEFAULT_MODEL
        self.effort = effort or os.environ.get("AIIT_ANTHROPIC_EFFORT") or "high"
        env_fb = os.environ.get("AIIT_ANTHROPIC_FALLBACKS", "1")
        self.fallbacks = fallbacks if fallbacks is not None else env_fb not in ("0", "false", "no")
        self.max_tokens = max_tokens

    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        import anthropic

        client = anthropic.Anthropic()
        kwargs: dict[str, Any] = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        )
        try:
            if self.fallbacks:
                # Server-side refusal fallback (Claude API only): if a safety classifier declines,
                # the request is re-run on a fallback model inside the same call.
                response = client.beta.messages.create(
                    betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs
                )
            else:
                response = client.messages.create(**kwargs)
        except anthropic.AuthenticationError as e:
            raise ProviderError("Anthropic authentication failed: set ANTHROPIC_API_KEY in .env") from e
        except anthropic.RateLimitError as e:
            raise ProviderError("Anthropic rate limit hit; retry shortly") from e
        except anthropic.APIStatusError as e:
            raise ProviderError(f"Anthropic API error {e.status_code}: {e.message}") from e
        except anthropic.APIConnectionError as e:
            raise ProviderError(f"Cannot reach the Anthropic API: {e}") from e

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise ProviderRefusal(f"the model declined this request (category={category}); review the redacted bundle and retry with a narrower prompt")
        if response.stop_reason == "max_tokens":
            raise ProviderError("output was cut off at max_tokens; raise max_tokens or reduce --max-chars")
        text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), None)
        if text is None:
            raise ProviderError("no text block in the model response")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ProviderError(f"model returned invalid JSON: {e}") from e
        u = response.usage
        usage = {
            "provider": self.name, "model": getattr(response, "model", self.model), "effort": self.effort,
            "input_tokens": getattr(u, "input_tokens", None), "output_tokens": getattr(u, "output_tokens", None),
            "cache_read_input_tokens": getattr(u, "cache_read_input_tokens", None),
            "cache_creation_input_tokens": getattr(u, "cache_creation_input_tokens", None),
            "fallbacks_enabled": self.fallbacks,
        }
        return parsed, usage
