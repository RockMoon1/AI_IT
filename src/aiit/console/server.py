"""Minimal LAN mailbox: agents upload sealed bundles and fetch signed plans.

Payloads are already encrypted and signed at the application layer, so this
server only authenticates callers (shared token) and stores files. TLS is
optional (pass a cert and key) and recommended outside a trusted LAN.
"""
from __future__ import annotations

import hmac
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..common.util import new_id, read_json
from .store import ConsoleState

MAX_BODY = 256 * 1024 * 1024


class MailboxHandler(BaseHTTPRequestHandler):
    server_version = "aiit-console/0.1"
    state: ConsoleState
    token: str
    lock: threading.Lock

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[serve] {self.address_string()} {fmt % args}")

    def _auth(self) -> bool:
        hdr = self.headers.get("Authorization", "")
        ok = hdr.startswith("Bearer ") and hmac.compare_digest(hdr[7:], self.token)
        if not ok:
            self._json(401, {"error": "unauthorized"})
        return ok

    def _json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes | None:
        n = int(self.headers.get("Content-Length", "0"))
        if n <= 0 or n > MAX_BODY:
            self._json(413 if n > MAX_BODY else 400, {"error": "bad content length"})
            return None
        return self.rfile.read(n)

    def do_POST(self) -> None:
        if not self._auth():
            return
        if urlparse(self.path).path not in ("/v1/bundles", "/v1/reports"):
            self._json(404, {"error": "not found"})
            return
        data = self._body()
        if data is None:
            return
        tmp = self.state.inbox / f"{new_id('in-')}.aiit"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        try:
            with self.lock:
                case_id, manifest, _ = self.state.ingest_bundle(tmp)
            self._json(200, {"case_id": case_id, "kind": manifest.kind, "bundle_id": manifest.bundle_id})
        except Exception as e:
            self.state.audit.record("serve_ingest_error", error=str(e)[:300])
            self._json(400, {"error": str(e)[:300]})

    def do_GET(self) -> None:
        if not self._auth():
            return
        u = urlparse(self.path)
        if u.path == "/v1/health":
            self._json(200, {"ok": True, "console_id": self.state.console_id_or_none()})
            return
        if u.path != "/v1/plans":
            self._json(404, {"error": "not found"})
            return
        agent_id = (parse_qs(u.query).get("agent_id") or [""])[0]
        if not agent_id or any(ch in agent_id for ch in "/\\") or ".." in agent_id:
            self._json(400, {"error": "agent_id required"})
            return
        ob = self.state.outbox / agent_id
        plans = [read_json(p) for p in sorted(ob.glob("*.signed.json"))] if ob.exists() else []
        self._json(200, plans)


def make_server(state: ConsoleState, host: str, port: int, token: str, tls_cert: str | None = None, tls_key: str | None = None) -> ThreadingHTTPServer:
    if not token or len(token) < 16:
        raise ValueError("server token must be at least 16 characters (set AIIT_SERVER_TOKEN)")
    handler = type("BoundMailboxHandler", (MailboxHandler,), {"state": state, "token": token, "lock": threading.Lock()})
    srv = ThreadingHTTPServer((host, port), handler)
    if tls_cert and tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv
