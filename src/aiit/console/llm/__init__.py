"""LLM provider registry. Providers return a dict matching the FixPlanDraft schema."""
from __future__ import annotations

from .base import LLMProvider, ProviderError, ProviderRefusal


def get_provider(name: str, **opts) -> LLMProvider:
    name = (name or "dryrun").lower()
    if name == "dryrun":
        from .dryrun import DryRunProvider
        return DryRunProvider(**opts)
    if name == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(**opts)
    if name == "anthropic":
        from .anthropic_provider import AnthropicProvider
        return AnthropicProvider(**opts)
    raise ProviderError(f"unknown provider {name!r}; use dryrun, ollama or anthropic")


__all__ = ["get_provider", "LLMProvider", "ProviderError", "ProviderRefusal"]
