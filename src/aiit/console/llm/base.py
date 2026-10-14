from __future__ import annotations

import json
import re
from typing import Any

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.S)


class ProviderError(Exception):
    pass


class ProviderRefusal(ProviderError):
    """The model declined the request (safety classifier or policy)."""


class ProviderOutputError(ProviderError):
    """The model answered, but the answer was not usable JSON. raw_text is kept for the repair loop."""

    def __init__(self, message: str, raw_text: str = ""):
        super().__init__(message)
        self.raw_text = raw_text


def parse_json_text(text: str) -> dict[str, Any]:
    """Parse a model reply that should be one JSON object.

    Tolerates a ```json fence and prose around the outermost {...}. Raises
    ProviderOutputError (carrying the raw text) when no object can be parsed.
    """
    if not isinstance(text, str) or not text.strip():
        raise ProviderOutputError("model returned empty output", raw_text=text or "")
    candidate = text.strip()
    m = _FENCE_RE.match(candidate)
    if m:
        candidate = m.group(1)
    try:
        obj = json.loads(candidate)
    except json.JSONDecodeError:
        start, end = candidate.find("{"), candidate.rfind("}")
        if start == -1 or end <= start:
            raise ProviderOutputError("model output contains no JSON object", raw_text=text)
        try:
            obj = json.loads(candidate[start:end + 1])
        except json.JSONDecodeError as e:
            raise ProviderOutputError(f"model output is not valid JSON ({e.msg} at {e.pos})", raw_text=text) from e
    if not isinstance(obj, dict):
        raise ProviderOutputError("model output is JSON but not an object", raw_text=text)
    return obj


class LLMProvider:
    """Interface every provider implements.

    complete_json(system, user, schema, meta) returns (parsed_json, usage).
    `system` and `user` are the only text that may leave the console; both have
    already been redacted. `meta` holds local-only hints (target_os, case_id,
    redacted issue text) that a provider may read but must never transmit.
    `usage` is written to the audit log, so it must contain no content, only
    provider, model, token counts and flags.
    """

    name: str = "base"
    model: str = ""
    hosted: bool = False          # True when data leaves the operator machine
    endpoint_host: str = "local"
    max_input_chars: int = 150_000

    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        raise NotImplementedError
