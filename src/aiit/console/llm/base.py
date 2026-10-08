from __future__ import annotations

from typing import Any


class ProviderError(Exception):
    pass


class ProviderRefusal(ProviderError):
    """The model declined the request (safety classifier or policy)."""


class LLMProvider:
    name: str = "base"
    model: str = ""

    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return (parsed_json, usage_metadata). usage never contains content."""
        raise NotImplementedError
