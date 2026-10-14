"""LAN mailbox: agents upload sealed bundles and fetch signed plans.

Payloads are encrypted and signed at the application layer, so this server
only authenticates callers (shared token), bounds resource use, and stores
files. TLS is required for any bind other than loopback unless the operator
explicitly passes --insecure-no-tls.
"""
from __future__ import annotations

import hmac
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import ValidationError

from .. import __version__
from ..common.crypto import CryptoError
from ..common.util import new_id, read_json, safe_join, validate_id
from .store import ConsoleState

MAX_BODY = 64 * 1024 * 1024
CHUNK = 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
AUTH_FAIL_WINDOW = 60.0
AUTH_FAIL_LIMIT = 10


class MailboxHandler(BaseHTTPRequestHandler):
    server_version = f"aiit-console/{__version__}"
    sys_version = ""
    timeout = 30  # socket timeout for slow or stalled clients
    state: ConsoleState
    token: str
    lock: threading.Lock
    auth_failures: dict[str, list[float]]

    # -- plumbing ---------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        line = "".join(ch if ch.isprintable() else "?" for ch in (fmt % args))[:400]
        print(f"[serve {ts}] {self.address_string()} {line}", file=sys.stderr)

    def _json(self, code: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "?"

    def _auth(self) -> bool:
        ip = self._client_ip()
        now = time.monotonic()
        with self.lock:
            fails = [t for t in self.auth_failures.get(ip, []) if now - t < AUTH_FAIL_WINDOW]
            self.auth_failures[ip] = fails
            if len(fails) >= AUTH_FAIL_LIMIT:
                self._json(429, {"error": "too many failed authentications"}, {"Retry-After": str(int(AUTH_FAIL_WINDOW))})
                return False
        hdr = self.headers.get("Authorization", "")
        ok = hdr.startswith("Bearer ") and hmac.compare_digest(hdr[7:], self.token)
        if not ok:
            with self.lock:
                self.auth_failures.setdefault(ip, []).append(now)
                if len(self.auth_failures[ip]) <= 3:
                    self.state.audit.record("serve_auth_fail", ip=ip, path=urlparse(self.path).path)
            self._json(401, {"error": "unauthorized"})
        return ok

    def _read_body_to_temp(self) -> Path | None:
        raw_len = self.headers.get("Content-Length", "")
        try:
            n = int(raw_len)
        except (TypeError, ValueError):
            self._json(400, {"error": "missing or invalid Content-Length"})
            return None
        if n <= 0:
            self._json(400, {"error": "empty body"})
            return None
        if n > MAX_BODY:
            self._json(413, {"error": f"body exceeds {MAX_BODY} bytes"})
            return None
        self.state.inbox.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="in-", suffix=".aiit", dir=self.state.inbox)
        remaining = n
        try:
            with os.fdopen(fd, "wb") as f:
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK, remaining))
                    if not chunk:
                        raise ConnectionError("client closed the connection mid-body")
                    f.write(chunk)
                    remaining -= len(chunk)
        except (OSError, ConnectionError, socket.timeout) as e:
            os.unlink(tmp_name)
            self._json(400, {"error": f"incomplete upload: {type(e).__name__}"})
            return None
        return Path(tmp_name)

    # -- routes -------------------------------------------------------------
    def do_POST(self) -> None:
        if not self._auth():
            return
        if urlparse(self.path).path not in ("/v1/bundles", "/v1/reports"):
            self._json(404, {"error": "not found"})
            return
        tmp = self._read_body_to_temp()
        if tmp is None:
            return
        try:
            with self.lock:
                case_id, manifest, _ = self.state.ingest_bundle(tmp)
            self._json(200, {"case_id": case_id, "kind": manifest.kind, "bundle_id": manifest.bundle_id})
        except (CryptoError, ValidationError, ValueError) as e:
            with self.lock:
                self.state.audit.record("serve_ingest_error", error=f"{type(e).__name__}: {str(e)[:200]}", ip=self._client_ip())
            self._json(422, {"error": str(e)[:300]})
        except OSError as e:
            with self.lock:
                self.state.audit.record("serve_ingest_error", error=f"{type(e).__name__}: {str(e)[:200]}", ip=self._client_ip())
            self._json(503, {"error": "storage error; try again later"})
        except Exception as e:  # pragma: no cover - defensive
            with self.lock:
                self.state.audit.record("serve_ingest_error", error=f"{type(e).__name__}: {str(e)[:200]}", ip=self._client_ip())
            self._json(500, {"error": "internal error"})
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass

    def do_GET(self) -> None:
        if not self._auth():
            return
        u = urlparse(self.path)
        if u.path == "/v1/health":
            self._json(200, {"ok": True, "console_id": self.state.console_id_or_none(), "version": __version__})
            return
        if u.path != "/v1/plans":
            self._json(404, {"error": "not found"})
            return
        agent_id = (parse_qs(u.query).get("agent_id") or [""])[0]
        try:
            validate_id(agent_id, "agent_id")
        except ValueError:
            self._json(400, {"error": "agent_id required"})
            return
        try:
            ob = safe_join(self.state.outbox, agent_id)
        except ValueError:
            self._json(400, {"error": "agent_id required"})
            return
        plans = [read_json(p) for p in sorted(ob.glob("*.signed.json"))] if ob.exists() else []
        self._json(200, plans)


class MailboxServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, addr: tuple[str, int], handler: type, max_concurrent: int = 32, tls_context: ssl.SSLContext | None = None):
        super().__init__(addr, handler)
        self.slots = threading.BoundedSemaphore(max_concurrent)
        self.tls_context = tls_context
        self.handshake_timeout = 10.0

    def process_request_thread(self, request: Any, client_address: Any) -> None:  # type: ignore[override]
        if not self.slots.acquire(timeout=5.0):
            try:
                request.close()
            finally:
                return
        try:
            if self.tls_context is not None:
                try:
                    request.settimeout(self.handshake_timeout)
                    request = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                    request.do_handshake()
                except (ssl.SSLError, OSError, socket.timeout):
                    request.close()
                    return
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def make_server(state: ConsoleState, host: str, port: int, token: str, tls_cert: str | None = None, tls_key: str | None = None,
                *, insecure_no_tls: bool = False, max_concurrent: int = 32) -> MailboxServer:
    if not token or len(token) < 16:
        raise ValueError("server token must be at least 16 characters (set AIIT_SERVER_TOKEN)")
    tls_ctx: ssl.SSLContext | None = None
    if tls_cert or tls_key:
        if not (tls_cert and tls_key):
            raise ValueError("--tls-cert and --tls-key must be given together")
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
    if tls_ctx is None and host not in LOOPBACK_HOSTS and not insecure_no_tls:
        raise ValueError(f"refusing to listen on {host} without TLS; pass --tls-cert/--tls-key or --insecure-no-tls on a trusted LAN")
    handler = type("BoundMailboxHandler", (MailboxHandler,),
                   {"state": state, "token": token, "lock": threading.Lock(), "auth_failures": {}})
    return MailboxServer((host, port), handler, max_concurrent=max_concurrent, tls_context=tls_ctx)
