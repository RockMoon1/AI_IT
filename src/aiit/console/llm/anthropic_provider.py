"""Claude via the official `anthropic` SDK.

Only use this with PHI-bearing bundles when your organization has a signed
BAA and a HIPAA-ready org (docs/compliance/hipaa.md section 5). The API key
is read by the SDK from ANTHROPIC_API_KEY; it is never written to disk by AI_IT.
Set AIIT_HIPAA_MODE=1 to keep the request on the generally available,
BAA-covered surface (no beta features such as server-side refusal fallbacks).
"""
from __future__ import annotations

import os
from typing import Any

from .base import LLMProvider, ProviderError, ProviderRefusal, parse_json_text

DEFAULT_MODEL = "claude-opus-5-5"


def _truthy(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    hosted = True
    endpoint_host = "api.anthropic.com"

    def __init__(self, model: str | None = None, effort: str | None = None, fallbacks: bool | None = None, max_tokens: int = 16000, **_: Any):
        try:
            import anthropic  # noqa: F401
        except ImportError as e:
            raise ProviderError("the `anthropic` package is not installed: pip install 'aiit[anthropic]'") from e
        self.model = model or os.environ.get("AIIT_ANTHROPIC_MODEL") or DEFAULT_MODEL
        self.effort = effort or os.environ.get("AIIT_ANTHROPIC_EFFORT") or "high"
        self.hipaa_mode = _truthy(os.environ.get("AIIT_HIPAA_MODE"), False)
        env_fb = _truthy(os.environ.get("AIIT_ANTHROPIC_FALLBACKS"), True)
        self.fallbacks = (fallbacks if fallbacks is not None else env_fb) and not self.hipaa_mode
        self.max_tokens = max_tokens
        try:
            self.max_retries = int(os.environ.get("AIIT_LLM_MAX_RETRIES", "2") or 2)
        except ValueError:
            self.max_retries = 2
        try:
            self.timeout = float(os.environ.get("AIIT_LLM_TIMEOUT", "600") or 600)
        except ValueError:
            self.timeout = 600.0

    def _request(self, client: Any, kwargs: dict[str, Any]) -> tuple[Any, bool]:
        """Returns (response, fallbacks_degraded)."""
        import anthropic

        degraded = False
        if self.fallbacks:
            try:
                # Server-side refusal fallback (Claude API only): if a safety classifier declines,
                # the request is re-run on a fallback model inside the same call.
                return client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs), False
            except (anthropic.BadRequestError, TypeError):
                # BadRequestError: the org or platform does not accept the beta.
                # TypeError: the installed SDK predates the `fallbacks`/`betas` keywords.
                # Either way run the plain request once.
                degraded = True
        try:
            return client.messages.create(**kwargs), degraded
        except TypeError as e:
            # unexpected keyword argument: the SDK is too old for structured output
            raise ProviderError(f"anthropic SDK too old for output_config (structured output): {e}; pip install -U anthropic") from e

    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        import anthropic

        client = anthropic.Anthropic(max_retries=self.max_retries, timeout=self.timeout)
        kwargs: dict[str, Any] = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        )
        try:
            response, degraded = self._request(client, kwargs)
        except anthropic.AuthenticationError as e:
            raise ProviderError("Anthropic authentication failed: set ANTHROPIC_API_KEY in the console .env") from e
        except anthropic.RateLimitError as e:
            raise ProviderError(f"Anthropic rate limit still exceeded after {self.max_retries} automatic retries; wait a minute and run diagnose again") from e
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
        parsed = parse_json_text(text)
        u = response.usage
        usage = {
            "provider": self.name, "model": getattr(response, "model", self.model), "effort": self.effort,
            "input_tokens": getattr(u, "input_tokens", None), "output_tokens": getattr(u, "output_tokens", None),
            "cache_read_input_tokens": getattr(u, "cache_read_input_tokens", None),
            "cache_creation_input_tokens": getattr(u, "cache_creation_input_tokens", None),
            "fallbacks_enabled": self.fallbacks, "fallbacks_degraded": degraded, "hipaa_mode": self.hipaa_mode, "hosted": True,
        }
        return parsed, usage
