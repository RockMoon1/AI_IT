"""Shared test helpers: puts src/ on the path and gives cross-platform shell snippets."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.pop("AIIT_KEY_PASSPHRASE", None)


def echo_cmd(text: str) -> str:
    return f"Write-Output '{text}'" if os.name == "nt" else f"echo {text}"


def fail_cmd(code: int = 3) -> str:
    return f"exit {code}"


def sleep_cmd(seconds: int) -> str:
    return f"Start-Sleep -Seconds {seconds}" if os.name == "nt" else f"sleep {seconds}"


# ---------------------------------------------------------------------------
# FakeHTTP: a scripted HTTP server for tests of anything network-bound.
# Each queued reply is (status, headers, body, delay_seconds). Bodies may be
# bytes, str, or a JSON-serialisable object. Requests are recorded.
# ---------------------------------------------------------------------------
import json as _json
import threading as _threading
import time as _time
from http.server import BaseHTTPRequestHandler as _BaseHandler, ThreadingHTTPServer as _ThreadingServer


class FakeHTTP:
    def __init__(self):
        self.replies: list = []
        self.requests: list = []
        self._lock = _threading.Lock()
        outer = self

        class Handler(_BaseHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                n = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(n) if n else b""
                with outer._lock:
                    outer.requests.append({
                        "method": self.command, "path": self.path, "headers": dict(self.headers.items()), "body": body,
                    })
                    reply = outer.replies.pop(0) if outer.replies else (200, {}, {"ok": True}, 0)
                status, headers, payload, delay = reply
                if delay:
                    _time.sleep(delay)
                if status is None:  # drop the connection
                    self.close_connection = True
                    self.wfile.close()
                    return
                if isinstance(payload, (dict, list)):
                    data = _json.dumps(payload).encode("utf-8")
                    ctype = "application/json"
                elif isinstance(payload, str):
                    data = payload.encode("utf-8")
                    ctype = "text/html"
                else:
                    data = payload or b""
                    ctype = "application/octet-stream"
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", headers.get("Content-Type", ctype))
                    self.send_header("Content-Length", str(len(data)))
                    for k, v in headers.items():
                        if k != "Content-Type":
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionError, OSError):
                    pass  # the client gave up (timeout tests); nothing to report

            do_GET = do_POST = do_PUT = do_DELETE = _serve

        self.server = _ThreadingServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = _threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> "FakeHTTP":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def queue(self, status, body=None, headers=None, delay=0.0) -> "FakeHTTP":
        self.replies.append((status, headers or {}, body, delay))
        return self


# ---------------------------------------------------------------------------
# Bundle builders for store/server/CLI tests.
# ---------------------------------------------------------------------------
import tempfile as _tempfile
from pathlib import Path as _Path


def make_console(root):
    """Initialised ConsoleState in root (a Path)."""
    from aiit.console.store import ConsoleState
    st = ConsoleState(_Path(root))
    st.init(label="test")
    return st


def agent_identity(agent_id="agent-000000000001"):
    from aiit.common.crypto import Identity
    return Identity.generate(agent_id, with_box=False)


def seal_diagnostics(state, agent, out_path, files=None, *, hostname="lab-pc-07", issue="", bundle_id=None,
                     manifest_override=None, tamper=None, kind="diagnostics", extra_header=None):
    """Write a sealed diagnostics bundle the console in `state` can open.

    files: {relative_path: text}. manifest_override: callable(manifest_dict) -> dict applied before packing.
    tamper: callable(dir_path) run after the manifest is written (to break hashes or drop files).
    """
    from aiit import __version__
    from aiit.common.bundle import pack_dir, write_bundle
    from aiit.common.schema import BundleManifest, FileEntry
    from aiit.common.util import current_os, iso, new_id, os_version, sha256_file, write_json
    bundle_id = bundle_id or new_id("b-")
    files = files if files is not None else {"sys/echo.txt": "svc ok\n"}
    with _tempfile.TemporaryDirectory() as d:
        root = _Path(d)
        entries = []
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            entries.append(FileEntry(path=rel, sha256=sha256_file(p), size=p.stat().st_size, collector=rel.split("/")[-1], exit_code=0))
        manifest = BundleManifest(bundle_id=bundle_id, agent_id=agent.id, hostname=hostname, platform=current_os(), os_version=os_version(),
                                  collected_at=iso(), aiit_version=__version__, issue_description=issue, files=entries, kind=kind)
        m = manifest.model_dump()
        if manifest_override:
            m = manifest_override(m)
        write_json(root / "manifest.json", m)
        if tamper:
            tamper(root)
        plaintext = pack_dir(root)
    enr = state.identity()
    write_bundle(_Path(out_path), plaintext, enr.box_pub_hex, agent, kind=kind, bundle_id=bundle_id, console_id=enr.id, extra=extra_header)
    return _Path(out_path)


def seal_report(state, agent, out_path, case_id, plan_id, results, *, bundle_id=None, report_override=None, hostname="lab-pc-07"):
    from aiit import __version__
    from aiit.common.bundle import pack_dir, write_bundle
    from aiit.common.schema import BundleManifest, ExecutionReport, StepResult
    from aiit.common.util import current_os, iso, new_id, os_version, write_json
    bundle_id = bundle_id or new_id("r-")
    report = ExecutionReport(plan_id=plan_id, case_id=case_id, agent_id=agent.id, hostname=hostname, platform=current_os(), started_at=iso(),
                             ended_at=iso(), mode="dry_run", policy_version="2", results=[StepResult(**r) for r in results])
    rep = report.model_dump()
    if report_override:
        rep = report_override(rep)
    with _tempfile.TemporaryDirectory() as d:
        root = _Path(d)
        write_json(root / "report.json", rep)
        manifest = BundleManifest(kind="execution_report", bundle_id=bundle_id, agent_id=agent.id, hostname=hostname, platform=current_os(),
                                  os_version=os_version(), collected_at=iso(), aiit_version=__version__, case_id=case_id, plan_id=plan_id)
        write_json(root / "manifest.json", manifest.model_dump())
        plaintext = pack_dir(root)
    enr = state.identity()
    write_bundle(_Path(out_path), plaintext, enr.box_pub_hex, agent, kind="execution_report", bundle_id=bundle_id, console_id=enr.id,
                 extra={"case_id": case_id, "plan_id": plan_id})
    return _Path(out_path)
