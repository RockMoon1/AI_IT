"""Small, dependency-free HTTP JSON client with bounded retries.

Every network call in AI_IT goes through http_json so that timeouts, dropped
connections, proxy HTML pages and transient 5xx responses surface as one
exception type (NetError) instead of a traceback, and so retries are safe and
bounded. Only methods whose server side is idempotent should set retries > 0
on POST; the console mailbox is idempotent on bundle_id for that reason.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import random
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

RETRY_STATUSES = (408, 425, 429, 500, 502, 503, 504)
MAX_RESPONSE = 4 * 1024 * 1024


class NetError(Exception):
    """Transport-level failure (timeout, refused, reset, bad JSON, oversized)."""


class HttpStatusError(NetError):
    def __init__(self, status: int, body_snippet: str, url: str):
        self.status = status
        self.body_snippet = body_snippet
        self.url = url
        super().__init__(f"HTTP {status} from {url}: {body_snippet[:200]}")


def _default_retries() -> int:
    try:
        return max(0, int(os.environ.get("AIIT_HTTP_RETRIES", "3")))
    except ValueError:
        return 3


def _read_capped(resp: Any, max_response: int) -> bytes:
    data = resp.read(max_response + 1)
    if len(data) > max_response:
        raise NetError(f"response larger than {max_response} bytes")
    return data


def http_json(
    method: str,
    url: str,
    body: Any = None,
    headers: dict[str, str] | None = None,
    *,
    timeout: float = 60.0,
    retries: int | None = None,
    backoff: float = 0.5,
    max_backoff: float = 8.0,
    retry_statuses: tuple[int, ...] = RETRY_STATUSES,
    sleep: Callable[[float], None] = time.sleep,
    max_response: int = MAX_RESPONSE,
    raw_body: bytes | None = None,
    expect_json: bool = True,
) -> Any:
    """Send a JSON request and return the parsed JSON response.

    body is JSON-encoded unless raw_body is given. Retries on connection
    errors, timeouts and retry_statuses with full-jitter exponential backoff,
    honouring Retry-After. Never retries other 4xx. Raises HttpStatusError for
    non-2xx after retries are exhausted and NetError for transport failures.
    """
    if retries is None:
        retries = _default_retries()
    data: bytes | None
    hdrs = dict(headers or {})
    if raw_body is not None:
        data = raw_body
        hdrs.setdefault("Content-Type", "application/octet-stream")
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    else:
        data = None
    hdrs.setdefault("Accept", "application/json")
    hdrs.setdefault("User-Agent", "aiit/0.1")

    attempt = 0
    while True:
        attempt += 1
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=hdrs)
        retry_after: float | None = None
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = _read_capped(resp, max_response)
                if not expect_json:
                    return raw
                if not raw.strip():
                    return None
                try:
                    return json.loads(raw.decode("utf-8", "replace"))
                except json.JSONDecodeError as e:
                    raise NetError(f"non-JSON response from {url} ({e.msg}): {raw[:120]!r}") from e
        except urllib.error.HTTPError as e:
            snippet = ""
            try:
                snippet = e.read(512).decode("utf-8", "replace")
            except Exception:
                pass
            if e.code in retry_statuses and attempt <= retries:
                ra = e.headers.get("Retry-After") if e.headers else None
                if ra and ra.strip().isdigit():
                    retry_after = min(float(ra), max_backoff)
                err: Exception = HttpStatusError(e.code, snippet, url)
            else:
                raise HttpStatusError(e.code, snippet, url) from e
        except NetError:
            raise
        except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError,
                http.client.HTTPException, OSError) as e:
            reason = getattr(e, "reason", None) or e
            err = NetError(f"{type(e).__name__} talking to {url}: {reason}")
            if attempt > retries:
                raise err from e
        # retry path
        delay = retry_after if retry_after is not None else min(max_backoff, backoff * (2 ** (attempt - 1))) * random.random()
        sleep(delay)
        if attempt > retries:  # pragma: no cover - defensive; loop exits above
            raise err


def is_loopback_or_private(url: str) -> bool:
    """True when the URL's host is loopback, link-local or RFC1918/ULA (data stays on the LAN)."""
    host = urllib.parse.urlsplit(url).hostname or ""
    if host in ("localhost", "localhost.localdomain") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, ValueError, OSError):
            return False
    return bool(ip.is_loopback or ip.is_link_local or ip.is_private)
