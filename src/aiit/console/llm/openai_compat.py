"""OpenAI-style chat completions: OpenAI, Azure OpenAI and any local server that speaks the same API.

One class, three flavors:

* ``openai``: ``https://api.openai.com/v1`` with a bearer key from ``OPENAI_API_KEY`` or
  ``AIIT_OPENAI_API_KEY``. Always ``hosted`` (the redacted prompt leaves the operator machine), even
  when the base URL is a local proxy that forwards to OpenAI.
* ``azure``: Azure OpenAI, ``{base}/openai/deployments/{deployment}/chat/completions?api-version=...``
  with an ``api-key`` header; deployment from ``AIIT_AZURE_OPENAI_DEPLOYMENT``. Always ``hosted``.
* ``compat``: anything else that serves ``/chat/completions`` (llama.cpp server, vLLM, LM Studio,
  LocalAI, LiteLLM, a corporate gateway). ``hosted`` only when the base URL is not loopback or
  private, so the hosted-egress gate stays closed for a model on the operator's machine or LAN.
  A key is optional and, when given, sent only as a header.

Registered provider names: ``openai``, ``azure-openai``, ``openai-compat`` and the aliases
``llamacpp``, ``vllm`` and ``lmstudio`` (``compat`` with each server's usual loopback base URL).

Structured output asks for ``response_format`` ``json_schema`` (strict, shaped from the schema the
planner passes to ``complete_json``) and degrades once to ``json_object`` and then to no
``response_format`` when the server answers 400 for the mode; the mode that finally worked is
written to the usage dict as ``format_mode`` with ``format_degraded`` set when it is not the one
requested. The API key never appears in the request body, the usage dict, an exception or a log
line. Amazon Bedrock and Google Vertex are deliberately out of scope here: they do not speak this
API shape and are reachable later through the Anthropic SDK's AnthropicBedrock and AnthropicVertex
clients instead.
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import quote, urlsplit

from ...common.net import HttpStatusError, NetError, http_json, is_loopback_or_private
from .base import LLMProvider, ProviderError, ProviderRefusal, parse_json_text

FLAVORS = ("openai", "azure", "compat")
# registered name -> (flavor, default base URL; None means the operator must set AIIT_OPENAI_BASE_URL)
PRESETS: dict[str, tuple[str, str | None]] = {
    "openai": ("openai", "https://api.openai.com/v1"),
    "azure-openai": ("azure", None),
    "openai-compat": ("compat", None),
    "llamacpp": ("compat", "http://127.0.0.1:8080/v1"),
    "vllm": ("compat", "http://127.0.0.1:8000/v1"),
    "lmstudio": ("compat", "http://127.0.0.1:1234/v1"),
}
DEFAULT_OPENAI_MODEL = "gpt-5"
DEFAULT_AZURE_API_VERSION = "2024-10-21"
FORMAT_MODES = ("json_schema", "json_object", "none")
SCHEMA_NAME = "fix_plan"
# A 400 whose body mentions one of these is the server rejecting the response_format mode, not the prompt.
_FORMAT_REJECTION_WORDS = ("response_format", "unsupported", "json_schema", "schema", "strict")
# Azure answers 400 with code "content_filter" when the prompt itself trips its content policy.
_CONTENT_FILTER_WORDS = ("content_filter", "content management policy", "content filter")
_SERVER_HINTS = {
    "llamacpp": "Is llama-server running?",
    "vllm": "Is `vllm serve` running?",
    "lmstudio": "Is the LM Studio server started (Developer tab)?",
}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


def _env_key(flavor: str) -> str:
    names = ("AIIT_OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "OPENAI_API_KEY") if flavor == "azure" else ("AIIT_OPENAI_API_KEY", "OPENAI_API_KEY")
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


def strict_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``schema`` shaped for OpenAI strict mode.

    Every object is closed (``additionalProperties: false``) with every property required, and
    ``default``/``examples`` are dropped because the model must emit every field anyway. Optional
    fields keep their ``anyOf [..., null]`` so the planner's pydantic model still accepts ``null``.
    Property and ``$defs`` names are never treated as keywords. The input is not modified.
    """
    def walk(node: Any) -> Any:
        if isinstance(node, list):
            return [walk(x) for x in node]
        if not isinstance(node, dict):
            return node
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in ("default", "examples"):
                continue
            if key in ("properties", "$defs") and isinstance(value, dict):
                out[key] = {name: walk(sub) for name, sub in value.items()}
            else:
                out[key] = walk(value)
        if isinstance(out.get("properties"), dict):
            out["required"] = list(out["properties"])
            out.setdefault("additionalProperties", False)
        elif out.get("type") == "object":
            out.setdefault("additionalProperties", False)
        return out

    return walk(schema)


def _error_message(snippet: str) -> str:
    """The human message out of an OpenAI/Azure/vLLM style error body, or the snippet itself."""
    text = snippet.strip()
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text[:300]
    if isinstance(obj, dict):
        err = obj.get("error", obj.get("detail", obj.get("message")))
        if isinstance(err, dict):
            err = err.get("message") or err.get("code") or json.dumps(err)
        if err:
            return str(err)[:300]
    return text[:300]


def _content_text(content: Any) -> str:
    """Chat content as text: a string, or the text parts of a list of content parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(part.get("text", "") for part in content if isinstance(part, dict) and part.get("type", "text") == "text")
    return ""


class OpenAICompatProvider(LLMProvider):
    name = "openai"
    flavor = "openai"

    def __init__(self, preset: str = "openai", *, flavor: str | None = None, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None, timeout: float | None = None, max_retries: int | None = None, deployment: str | None = None,
                 api_version: str | None = None, format_mode: str = "json_schema", **_: Any):
        if preset not in PRESETS:
            raise ProviderError(f"unknown OpenAI-compatible preset {preset!r}; use one of {', '.join(PRESETS)}")
        self.name = preset
        self.flavor = flavor or PRESETS[preset][0]
        if self.flavor not in FLAVORS:
            raise ProviderError(f"unknown flavor {self.flavor!r}; use one of {', '.join(FLAVORS)}")
        if format_mode not in FORMAT_MODES:
            raise ProviderError(f"unknown format mode {format_mode!r}; use one of {', '.join(FORMAT_MODES)}")
        self.format_mode = format_mode
        base = base_url or os.environ.get("AIIT_OPENAI_BASE_URL") or PRESETS[preset][1] or ""
        if not base:
            example = "https://<resource>.openai.azure.com" if self.flavor == "azure" else "http://127.0.0.1:8080/v1"
            raise ProviderError(f"{preset} needs AIIT_OPENAI_BASE_URL (for example {example})")
        base = base.strip().rstrip("/")
        if self.flavor == "azure" and base.endswith("/openai"):
            base = base[: -len("/openai")]
        parts = urlsplit(base)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            raise ProviderError(f"AIIT_OPENAI_BASE_URL must be an http(s) URL with a host, got {base!r}")
        self.base_url = base
        self.endpoint_host = parts.hostname
        self._api_key = api_key if api_key is not None else _env_key(self.flavor)
        self.deployment = deployment or os.environ.get("AIIT_AZURE_OPENAI_DEPLOYMENT") or ""
        self.api_version = api_version or os.environ.get("AIIT_AZURE_OPENAI_API_VERSION") or DEFAULT_AZURE_API_VERSION
        if self.flavor == "azure" and not self.deployment:
            raise ProviderError("azure-openai needs AIIT_AZURE_OPENAI_DEPLOYMENT (the deployment name from the Azure portal)")
        default_model = DEFAULT_OPENAI_MODEL if self.flavor == "openai" else self.deployment
        self.model = model or os.environ.get("AIIT_OPENAI_MODEL") or default_model
        self.timeout = timeout if timeout is not None else _env_float("AIIT_LLM_TIMEOUT", 600.0)
        self.max_retries = max_retries if max_retries is not None else _env_int("AIIT_LLM_MAX_RETRIES", 2)
        # openai/azure always send the prompt to a third party; compat only when the server is not on the LAN
        self.hosted = True if self.flavor in ("openai", "azure") else not is_loopback_or_private(self.base_url)

    def __repr__(self) -> str:  # never the key
        return f"<OpenAICompatProvider {self.name} flavor={self.flavor} host={self.endpoint_host} model={self.model!r} hosted={self.hosted}>"

    # ---- request shape -----------------------------------------------------
    def _url(self) -> str:
        if self.flavor == "azure":
            return (f"{self.base_url}/openai/deployments/{quote(self.deployment, safe='')}/chat/completions"
                    f"?api-version={quote(self.api_version, safe='')}")
        return self.base_url + "/chat/completions"

    def _headers(self) -> dict[str, str]:
        if not self._api_key:
            return {}
        if self.flavor == "azure":
            return {"api-key": self._api_key}
        return {"Authorization": "Bearer " + self._api_key}

    def _body(self, system: str, user: str, schema: dict[str, Any], mode: str) -> dict[str, Any]:
        system_text = system
        if mode != "json_schema" and "json" not in (system + user).lower():
            # json_object mode is refused by OpenAI unless the prompt mentions JSON; the other modes need the ask too
            system_text = system.rstrip() + "\nRespond with a single JSON object and nothing else."
        body: dict[str, Any] = {"messages": [{"role": "system", "content": system_text}, {"role": "user", "content": user}]}
        if self.model:
            body["model"] = self.model
        if mode == "json_schema":
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": SCHEMA_NAME, "strict": True, "schema": strict_schema(schema)}}
        elif mode == "json_object":
            body["response_format"] = {"type": "json_object"}
        return body

    # ---- error mapping -------------------------------------------------------
    def _status_error(self, e: HttpStatusError) -> ProviderError:
        msg = _error_message(e.body_snippet)
        where = f"{self.name} at {self.endpoint_host}"
        if e.status == 400 and any(w in e.body_snippet.lower() for w in _CONTENT_FILTER_WORDS):
            return ProviderRefusal(f"{where} declined the request (its content filter flagged the prompt); "
                                   "review the redacted bundle and retry with a narrower prompt")
        if e.status in (401, 403):
            if self.flavor == "azure":
                key_hint = "AIIT_OPENAI_API_KEY (or AZURE_OPENAI_API_KEY) must hold the Azure OpenAI resource key"
            elif self.flavor == "openai":
                key_hint = "check OPENAI_API_KEY (or AIIT_OPENAI_API_KEY) in the console .env"
            else:
                key_hint = ("the server wants a key: set AIIT_OPENAI_API_KEY (or OPENAI_API_KEY)" if not self._api_key
                            else "check AIIT_OPENAI_API_KEY (or OPENAI_API_KEY)")
            what = "authentication failed" if e.status == 401 else "access denied (the key cannot use this model)"
            return ProviderError(f"{where}: {what} (HTTP {e.status}); {key_hint}: {msg}")
        if e.status == 404:
            if self.flavor == "azure":
                return ProviderError(f"{where}: HTTP 404 for deployment {self.deployment!r} (api-version {self.api_version}); "
                                     f"check AIIT_AZURE_OPENAI_DEPLOYMENT, AIIT_AZURE_OPENAI_API_VERSION and AIIT_OPENAI_BASE_URL: {msg}")
            return ProviderError(f"{where}: HTTP 404 from {self._url()}; check AIIT_OPENAI_BASE_URL (it usually ends with /v1) "
                                 f"and AIIT_OPENAI_MODEL={self.model!r}: {msg}")
        if e.status == 429:
            return ProviderError(f"{where}: rate limited (HTTP 429) after {self.max_retries} automatic retries; "
                                 f"wait a minute and run diagnose again: {msg}")
        if e.status == 400:
            return ProviderError(f"{where} rejected the request (HTTP 400): {msg}")
        return ProviderError(f"{where} returned HTTP {e.status}: {msg}")

    def _net_error(self, e: NetError) -> ProviderError:
        text = f"cannot reach {self.name} at {self.base_url}: {e}"
        if is_loopback_or_private(self.base_url):
            text += ". " + _SERVER_HINTS.get(self.name, "Is the local model server running?")
        else:
            text += ". Check the network, the proxy settings and AIIT_OPENAI_BASE_URL"
        return ProviderError(f"{text} (timeout {self.timeout:g}s)")

    # ---- the call ----------------------------------------------------------
    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.flavor in ("openai", "azure") and not self._api_key:
            names = "AIIT_OPENAI_API_KEY or AZURE_OPENAI_API_KEY" if self.flavor == "azure" else "OPENAI_API_KEY or AIIT_OPENAI_API_KEY"
            raise ProviderError(f"{self.name} needs an API key: set {names} in the console .env (nothing was sent)")
        modes = FORMAT_MODES[FORMAT_MODES.index(self.format_mode):]
        data: Any = None
        mode = self.format_mode
        for mode in modes:
            try:
                data = http_json("POST", self._url(), body=self._body(system, user, schema, mode), headers=self._headers(),
                                 timeout=self.timeout, retries=self.max_retries)
                break
            except HttpStatusError as e:
                body_l = e.body_snippet.lower()
                rejected_format = (e.status == 400 and mode != "none" and not any(w in body_l for w in _CONTENT_FILTER_WORDS)
                                   and any(w in body_l for w in _FORMAT_REJECTION_WORDS))
                if rejected_format:
                    continue  # one step down the ladder: json_schema -> json_object -> none
                raise self._status_error(e) from e
            except NetError as e:
                raise self._net_error(e) from e
        where = f"{self.name} at {self.endpoint_host}"
        choices = data.get("choices") if isinstance(data, dict) else None
        if not choices or not isinstance(choices[0], dict):
            raise ProviderError(f"{where} returned no choices (is {self._url()} a chat completions endpoint?)")
        choice = choices[0]
        message = choice.get("message") or {}
        finish = choice.get("finish_reason")
        if message.get("refusal") or finish == "content_filter":
            why = "its content filter stopped the reply" if finish == "content_filter" else "the model refused"
            raise ProviderRefusal(f"{where} declined this request ({why}); review the redacted bundle and retry with a narrower prompt")
        if finish == "length":
            raise ProviderError(f"{where}: the reply was cut off (finish_reason=length); raise the server's output token limit "
                                "or reduce --max-chars")
        parsed = parse_json_text(_content_text(message.get("content")))
        u = data.get("usage") or {}
        prompt_details = u.get("prompt_tokens_details") or {}
        completion_details = u.get("completion_tokens_details") or {}
        usage: dict[str, Any] = {
            "provider": self.name, "flavor": self.flavor, "model": str(data.get("model") or self.model),
            "endpoint_host": self.endpoint_host, "hosted": self.hosted,
            "format_mode": mode, "format_degraded": mode != self.format_mode,
            "input_tokens": u.get("prompt_tokens"), "output_tokens": u.get("completion_tokens"), "total_tokens": u.get("total_tokens"),
            "cached_input_tokens": prompt_details.get("cached_tokens"), "reasoning_tokens": completion_details.get("reasoning_tokens"),
            "finish_reason": finish,
        }
        if self.flavor == "azure":
            usage["deployment"] = self.deployment
        return parsed, usage
