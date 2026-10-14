"""Hash-chained, append-only audit log (JSON lines) with signed checkpoints.

Every entry carries ``seq``, ``prev_hash`` (the hash of the previous entry, or
GENESIS for the first) and ``hash`` (SHA-256 of the canonical JSON of the entry
without ``hash``). ``verify()`` recomputes the whole chain.

Design notes:

* Parsing is tolerant. A torn line (power loss mid-append) or a line someone
  replaced with garbage never raises; it is reported by ``verify_detailed()``
  as a ``Break`` and the chain continues from the last entry that does parse.
* ``record()`` reads only the tail of the file (backwards, 64 KiB window that
  grows when needed) under ``util.file_lock`` so concurrent threads and
  processes serialise, then appends with flush and fsync.
* ``checkpoint(identity)`` writes a signed ``<path>.head.json`` so that a log
  truncated below the checkpoint, or rewritten with a different entry at the
  checkpoint seq, is detected even though every line still chains.
* The log never contains bundle content or command output, only metadata.
  Nothing in this module writes anything but what callers pass as details,
  a few counters and hashes.
"""
from __future__ import annotations

import contextlib
import csv
import html
import io
import json
import logging
import logging.handlers
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from . import crypto
from .net import http_json
from .util import atomic_write_bytes, canonical_json, file_lock, iso, os_user, parse_iso, read_json, sha256_hex, write_json

GENESIS = "0" * 64
TAIL_WINDOW = 64 * 1024
EXPORT_COLUMNS = ("seq", "ts", "actor_id", "os_user", "action", "case_id", "plan_id", "details_json", "hash")
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_REQUIRED_STR = ("hash", "prev_hash", "action", "ts", "actor_id")

TIMELINE_LABELS = {
    "ingest": "Bundle ingested",
    "ingest_duplicate": "Duplicate bundle",
    "ingest_failed": "Ingest failed",
    "llm_request": "LLM request",
    "llm_response": "LLM response",
    "llm_invalid_plan": "LLM plan rejected",
    "llm_output_error": "LLM output unusable",
    "llm_refused": "LLM refused",
    "llm_repair": "LLM repair attempt",
    "llm_error": "LLM error",
    "plan_created": "Plan created",
    "plan_approved": "Plan approved",
    "report": "Report received",
    "report_written": "Report written",
    "audit_regression": "Agent audit regression",
}


@dataclass
class Break:
    """One problem found in the chain. ``seq`` is 0 when it is not known (unparseable line)."""

    line_no: int
    seq: int
    reason: str

    def __str__(self) -> str:
        where = f"line {self.line_no}" if self.line_no else "checkpoint"
        return f"{self.reason} ({where}, seq {self.seq})"


@dataclass
class _Line:
    """A physical line of the log: 1-based number, byte range, raw bytes and the parsed entry (None if bad)."""

    line_no: int
    start: int
    end: int
    raw: bytes
    entry: dict[str, Any] | None
    terminated: bool


def _parse_line(raw: bytes) -> dict[str, Any] | None:
    """Parse one log line. Returns None for anything that is not a well-formed entry."""
    raw = raw.rstrip(b"\r\n")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    seq = obj.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        return None
    for key in _REQUIRED_STR:
        if not isinstance(obj.get(key), str):
            return None
    if not isinstance(obj.get("details"), dict):
        return None
    return obj


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256_hex(canonical_json(body))


def _is_blank(raw: bytes) -> bool:
    return not raw.strip()


def _guard_cell(value: Any) -> str:
    """Render a CSV cell; prefix a single quote when a spreadsheet would read it as a formula."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _split_argv(command: str) -> list[str]:
    """Split an alert command into argv without a shell. Windows paths keep their backslashes."""
    if os.name == "nt":
        parts = shlex.split(command, posix=False)
        out = []
        for p in parts:
            if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'":
                p = p[1:-1]
            out.append(p)
        return out
    return shlex.split(command)


class AuditLog:
    """Append-only, hash-chained JSON lines log at ``path`` written on behalf of ``actor_id``."""

    def __init__(self, path: Path, actor_id: str):
        self.path = Path(path)
        self.actor_id = actor_id
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- paths
    @property
    def head_path(self) -> Path:
        return self.path.with_name(self.path.name + ".head.json")

    @property
    def corrupt_path(self) -> Path:
        return self.path.with_name(self.path.name + ".corrupt")

    # ------------------------------------------------------------- reading
    def _scan(self, start_offset: int = 0, first_line_no: int = 1) -> Iterator[_Line]:
        """Yield every physical line from ``start_offset``. Blank lines are skipped. Never raises on bad lines."""
        if not self.path.exists():
            return
        with open(self.path, "rb") as f:
            f.seek(start_offset)
            pos = start_offset
            line_no = first_line_no - 1
            for raw in f:
                line_no += 1
                start, pos = pos, pos + len(raw)
                if _is_blank(raw):
                    continue
                yield _Line(line_no, start, pos, raw, _parse_line(raw), raw.endswith(b"\n"))

    def _entries(self) -> Iterator[dict[str, Any]]:
        for ln in self._scan():
            if ln.entry is not None:
                yield ln.entry

    def entries(self) -> list[dict[str, Any]]:
        """All entries that parse, in file order. Bad lines are skipped (see verify_detailed)."""
        return list(self._entries())

    def _tail_last_good(self) -> tuple[dict[str, Any] | None, int]:
        """Find the last well-formed, newline-terminated entry by reading the file backwards.

        Returns (entry, byte offset just after that entry's newline); (None, 0) when there is none.
        """
        if not self.path.exists():
            return None, 0
        with open(self.path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return None, 0
            window = TAIL_WINDOW
            while True:
                start = max(0, size - window)
                f.seek(start)
                buf = f.read(size - start)
                base = start
                if start > 0:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        window *= 2
                        continue
                    base = start + nl + 1
                    buf = buf[nl + 1:]
                end = buf.rfind(b"\n") + 1
                while end > 0:
                    prev_nl = buf.rfind(b"\n", 0, end - 1)
                    line = buf[prev_nl + 1:end]
                    if not _is_blank(line):
                        entry = _parse_line(line)
                        if entry is not None:
                            return entry, base + end
                    end = prev_nl + 1
                if start == 0:
                    return None, 0
                window *= 2

    def _ends_with_newline(self) -> bool:
        with open(self.path, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                return True
            f.seek(-1, os.SEEK_END)
            return f.read(1) == b"\n"

    def head(self) -> dict[str, Any] | None:
        """``{"seq", "hash"}`` of the last good entry, or None for an empty log (witness field for bundles)."""
        last, _ = self._tail_last_good()
        if last is None:
            return None
        return {"seq": last["seq"], "hash": last["hash"]}

    # ------------------------------------------------------------- writing
    def _append_locked(self, action: str, details: dict[str, Any]) -> dict[str, Any]:
        last, _ = self._tail_last_good()
        entry: dict[str, Any] = {
            "seq": (last["seq"] + 1) if last else 1,
            "ts": iso(),
            "actor_id": self.actor_id,
            "os_user": os_user(),
            "action": action,
            "details": details,
            "prev_hash": last["hash"] if last else GENESIS,
        }
        entry["hash"] = _entry_hash(entry)
        data = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        if self.path.exists() and not self._ends_with_newline():
            data = b"\n" + data  # keep a torn fragment on its own line for repair_tail()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_BINARY"):  # pragma: no cover - Windows
            flags |= os.O_BINARY
        fd = os.open(self.path, flags, 0o644)
        with os.fdopen(fd, "ab") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        return entry

    def record(self, action: str, **details: Any) -> dict[str, Any]:
        """Append one entry continuing the chain from the last good entry and return it."""
        with file_lock(self.path):
            return self._append_locked(action, dict(details))

    # ------------------------------------------------------------- checkpoint
    def checkpoint(self, identity: crypto.Identity) -> dict[str, Any] | None:
        """Write ``<path>.head.json`` signed by ``identity`` for the last good entry. None if the log is empty."""
        with file_lock(self.path):
            last, offset = self._tail_last_good()
            if last is None:
                return None
            cp: dict[str, Any] = {
                "seq": last["seq"],
                "hash": last["hash"],
                "offset": offset,
                "ts": iso(),
                "signer_id": identity.id,
                "signer_pub": identity.sign_pub_hex,
            }
            cp["signature"] = crypto.sign_object(identity, cp)
            write_json(self.head_path, cp)
            return cp

    def _load_checkpoint(self, expected_pub: str | None) -> tuple[dict[str, Any] | None, list[Break]]:
        """Read and authenticate the checkpoint. Returns (checkpoint or None, breaks)."""
        if not self.head_path.exists():
            return None, []
        try:
            cp = read_json(self.head_path)
        except (OSError, ValueError) as e:
            return None, [Break(0, 0, f"checkpoint unreadable: {type(e).__name__}")]
        if not isinstance(cp, dict):
            return None, [Break(0, 0, "checkpoint unreadable: not an object")]
        seq = cp.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            return None, [Break(0, 0, "checkpoint unreadable: bad seq")]
        for key in ("hash", "signer_pub", "signature", "signer_id", "ts"):
            if not isinstance(cp.get(key), str):
                return None, [Break(0, seq, f"checkpoint unreadable: missing {key}")]
        offset = cp.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            return None, [Break(0, seq, "checkpoint unreadable: bad offset")]
        pub = expected_pub or cp["signer_pub"]
        if expected_pub and expected_pub != cp["signer_pub"]:
            return None, [Break(0, seq, "checkpoint signer does not match the expected key")]
        body = {k: v for k, v in cp.items() if k != "signature"}
        if not crypto.verify_object(pub, body, cp["signature"]):
            return None, [Break(0, seq, "checkpoint signature invalid")]
        return cp, []

    # ------------------------------------------------------------- verification
    def _chain(self, lines: Iterable[_Line], prev: str, seq: int, want_seq: int | None) -> tuple[list[Break], int, int, str | None]:
        """Walk lines checking the chain. Returns (breaks, good count, last seq, hash of the entry with want_seq)."""
        breaks: list[Break] = []
        count = 0
        want_hash: str | None = None
        for ln in lines:
            e = ln.entry
            if e is None:
                kind = "torn" if not ln.terminated else "corrupt"
                breaks.append(Break(ln.line_no, 0, f"unparseable line {ln.line_no} ({kind}, {len(ln.raw)} bytes)"))
                continue
            expected = seq + 1
            if e["seq"] != expected:
                breaks.append(Break(ln.line_no, e["seq"], f"sequence gap at entry {expected} (found seq {e['seq']})"))
            elif e["prev_hash"] != prev:
                breaks.append(Break(ln.line_no, e["seq"], f"broken chain at entry {e['seq']}: prev_hash mismatch"))
            elif _entry_hash(e) != e["hash"]:
                breaks.append(Break(ln.line_no, e["seq"], f"hash mismatch at entry {e['seq']}"))
            if want_seq is not None and want_hash is None and e["seq"] == want_seq:
                want_hash = e["hash"]
            prev, seq = e["hash"], e["seq"]
            count += 1
        return breaks, count, seq, want_hash

    def _verify(self, expected_pub: str | None, incremental: bool) -> tuple[list[Break], int]:
        """Shared verifier. Returns (breaks, number of good entries checked)."""
        cp, breaks = self._load_checkpoint(expected_pub)
        if cp is not None and incremental:
            inc = self._verify_from_checkpoint(cp)
            if inc is not None:
                return inc
        want = cp["seq"] if cp else None
        chain_breaks, count, last_seq, want_hash = self._chain(self._scan(), GENESIS, 0, want)
        breaks.extend(chain_breaks)
        if cp is not None:
            if want_hash is None:
                breaks.append(Break(0, cp["seq"], f"log shorter than checkpoint (last seq {last_seq}, checkpoint seq {cp['seq']})"))
            elif want_hash != cp["hash"]:
                breaks.append(Break(0, cp["seq"], f"checkpoint hash mismatch at entry {cp['seq']}"))
        return breaks, count

    def _verify_from_checkpoint(self, cp: dict[str, Any]) -> tuple[list[Break], int] | None:
        """Check only the part after an authenticated checkpoint. None means fall back to a full scan."""
        offset = cp["offset"]
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        if size < offset or offset == 0:
            return [Break(0, cp["seq"], f"log shorter than checkpoint (checkpoint seq {cp['seq']})")], 0
        line_no = 0
        with open(self.path, "rb") as f:
            remaining = offset
            while remaining > 0:
                chunk = f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                line_no += chunk.count(b"\n")
                remaining -= len(chunk)
            f.seek(max(0, offset - TAIL_WINDOW))
            buf = f.read(offset - max(0, offset - TAIL_WINDOW))
        if not buf.endswith(b"\n"):
            return [Break(line_no, cp["seq"], "checkpoint offset is not at a line boundary")], 0
        last = _parse_line(buf[buf.rfind(b"\n", 0, len(buf) - 1) + 1:])
        if last is None or last["seq"] != cp["seq"] or last["hash"] != cp["hash"]:
            return None  # offset does not point at the checkpointed entry: do the full scan and report properly
        breaks, count, _, _ = self._chain(self._scan(offset, line_no + 1), cp["hash"], cp["seq"], None)
        return breaks, cp["seq"] + count

    def verify_detailed(self, expected_pub: str | None = None) -> list[Break]:
        """Every problem in the log: seq gaps, prev_hash and hash mismatches, unparseable lines, checkpoint issues.

        When a checkpoint exists its signature is checked against ``expected_pub`` if given, else against the
        embedded ``signer_pub``; the log must reach the checkpoint seq with the checkpointed hash.
        """
        breaks, _ = self._verify(expected_pub, incremental=False)
        return breaks

    def verify(self, expected_pub: str | None = None) -> tuple[bool, str]:
        """(True, "<n> entries verified") or (False, first break as text)."""
        breaks, count = self._verify(expected_pub, incremental=False)
        if breaks:
            return False, str(breaks[0])
        return True, f"{count} entries verified"

    # ------------------------------------------------------------- filtering and export
    def iter_filtered(self, since: str | datetime | None = None, until: str | datetime | None = None,
                      actions: Iterable[str] | None = None, case_id: str | None = None, plan_id: str | None = None,
                      actor_id: str | None = None) -> Iterator[dict[str, Any]]:
        """Good entries matching every given filter, in file order. case_id and plan_id match inside details."""
        since_dt = parse_iso(since) if isinstance(since, str) else since
        until_dt = parse_iso(until) if isinstance(until, str) else until
        action_set = set(actions) if actions else None
        for e in self._entries():
            if action_set is not None and e["action"] not in action_set:
                continue
            if actor_id is not None and e["actor_id"] != actor_id:
                continue
            d = e["details"]
            if case_id is not None and d.get("case_id") != case_id:
                continue
            if plan_id is not None and d.get("plan_id") != plan_id:
                continue
            if since_dt is not None or until_dt is not None:
                try:
                    ts = parse_iso(e["ts"])
                except ValueError:
                    continue
                if since_dt is not None and ts < since_dt:
                    continue
                if until_dt is not None and ts > until_dt:
                    continue
            yield e

    def timeline(self, case_id: str) -> list[dict[str, Any]]:
        """Entries of one case in order, each copied with a short human ``label`` for the action."""
        out = []
        for e in self.iter_filtered(case_id=case_id):
            item = dict(e)
            item["label"] = self.label_for(e["action"])
            out.append(item)
        return out

    @staticmethod
    def label_for(action: str) -> str:
        if action in TIMELINE_LABELS:
            return TIMELINE_LABELS[action]
        if action.startswith("apply_"):
            return "Apply " + action[len("apply_"):].replace("_", " ")
        return action.replace("_", " ")

    def export(self, fmt: str, out_path: Path, *, since: str | datetime | None = None, until: str | datetime | None = None,
               actions: Iterable[str] | None = None, case_id: str | None = None, plan_id: str | None = None,
               actor_id: str | None = None, expected_pub: str | None = None) -> int:
        """Write filtered entries as ``csv``, ``jsonl`` or ``html`` to out_path. Returns the number of entries written."""
        fmt = fmt.lower()
        if fmt not in ("csv", "jsonl", "html"):
            raise ValueError(f"unknown export format: {fmt!r}")
        filters = {"since": str(since) if since else None, "until": str(until) if until else None,
                   "actions": sorted(actions) if actions else None, "case_id": case_id, "plan_id": plan_id, "actor_id": actor_id}
        rows = list(self.iter_filtered(since=since, until=until, actions=actions, case_id=case_id, plan_id=plan_id, actor_id=actor_id))
        ok, msg = self.verify(expected_pub=expected_pub)
        cp, _ = self._load_checkpoint(expected_pub)
        summary = {"verified": ok, "message": msg, "rows": len(rows), "checkpoint_hash": cp["hash"] if cp else None,
                   "checkpoint_seq": cp["seq"] if cp else None, "exported_at": iso(), "log_path": str(self.path),
                   "filters": {k: v for k, v in filters.items() if v is not None}}
        if fmt == "jsonl":
            data = "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in rows).encode("utf-8")
        elif fmt == "csv":
            data = self._to_csv(rows, summary).encode("utf-8")
        else:
            data = self._to_html(rows, summary).encode("utf-8")
        atomic_write_bytes(Path(out_path), data)
        return len(rows)

    @staticmethod
    def _row_values(e: dict[str, Any]) -> list[Any]:
        d = e["details"]
        return [e["seq"], e["ts"], e["actor_id"], e.get("os_user", ""), e["action"], d.get("case_id", ""), d.get("plan_id", ""),
                json.dumps(d, sort_keys=True, ensure_ascii=False), e["hash"]]

    def _to_csv(self, rows: list[dict[str, Any]], summary: dict[str, Any]) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(EXPORT_COLUMNS)
        for e in rows:
            w.writerow([_guard_cell(v) for v in self._row_values(e)])
        w.writerow([_guard_cell(v) for v in ["", summary["exported_at"], "", "", "export_summary", "", "",
                                              json.dumps(summary, sort_keys=True, ensure_ascii=False), summary["checkpoint_hash"] or ""]])
        return buf.getvalue()

    def _to_html(self, rows: list[dict[str, Any]], summary: dict[str, Any]) -> str:
        esc = html.escape
        status = "VERIFIED" if summary["verified"] else "BROKEN"
        head = [
            "<!DOCTYPE html>", "<html lang=\"en\"><head><meta charset=\"utf-8\">",
            f"<title>Audit export {esc(summary['exported_at'])}</title>",
            "<style>",
            "body{font-family:system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif;margin:24px;color:#111}",
            "h1{font-size:1.4em}table{border-collapse:collapse;width:100%;font-size:12px}",
            "th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-all}",
            "th{background:#eee}tr:nth-child(even){background:#fafafa}.meta td{border:none;padding:2px 8px}",
            ".ok{color:#0a6b1e;font-weight:bold}.bad{color:#b00020;font-weight:bold}",
            "@media print{body{margin:8mm}table{font-size:9px}thead{display:table-header-group}tr{page-break-inside:avoid}}",
            "</style></head><body>",
            "<h1>Audit log export</h1>",
            "<table class=\"meta\">",
            f"<tr><td>Verification</td><td class=\"{'ok' if summary['verified'] else 'bad'}\">{esc(status)}: {esc(summary['message'])}</td></tr>",
            f"<tr><td>Checkpoint hash</td><td>{esc(str(summary['checkpoint_hash'] or 'none'))}</td></tr>",
            f"<tr><td>Checkpoint seq</td><td>{esc(str(summary['checkpoint_seq'] or 'none'))}</td></tr>",
            f"<tr><td>Export time</td><td>{esc(summary['exported_at'])}</td></tr>",
            f"<tr><td>Log file</td><td>{esc(summary['log_path'])}</td></tr>",
            f"<tr><td>Filters</td><td>{esc(json.dumps(summary['filters'], sort_keys=True) if summary['filters'] else 'none')}</td></tr>",
            f"<tr><td>Rows</td><td>{summary['rows']}</td></tr>",
            "</table>",
            "<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in EXPORT_COLUMNS) + "</tr></thead><tbody>",
        ]
        body = []
        for e in rows:
            body.append("<tr>" + "".join(f"<td>{esc(str(v))}</td>" for v in self._row_values(e)) + "</tr>")
        tail = ["</tbody></table>", "</body></html>", ""]
        return "\n".join(head + body + tail)

    # ------------------------------------------------------------- repair
    def repair_tail(self) -> dict[str, Any]:
        """Move unparseable fragments (a torn trailing write) to ``<path>.corrupt`` and record the repair.

        The usual case is a torn last line: the file is truncated back to the last good entry. When
        entries were already recorded after the fragment (they chain from the last good entry, so
        the chain is intact once the fragment is gone) the fragment is spliced out with an atomic
        rewrite. Entries that parse are never touched, so tampering cannot be hidden this way.
        """
        with file_lock(self.path):
            lines = list(self._scan())
            bad = [ln for ln in lines if ln.entry is None]
            if not bad:
                return {"repaired": False, "fragments": 0, "reason": "no torn or unparseable line"}
            fragment = b"".join(ln.raw for ln in bad)
            fragment_bytes = fragment.rstrip(b"\r\n")
            with open(self.corrupt_path, "ab") as cf:
                cf.write(fragment_bytes + b"\n")
                cf.flush()
                os.fsync(cf.fileno())
            good = [ln for ln in lines if ln.entry is not None]
            last_good_end = good[-1].end if good else 0
            trailing = all(ln.start >= last_good_end for ln in bad)
            if trailing:
                with open(self.path, "r+b") as f:
                    f.truncate(last_good_end)
                    f.flush()
                    os.fsync(f.fileno())
                how = "truncated"
            else:
                with open(self.path, "rb") as f:
                    data = f.read()
                keep = bytearray()
                pos = 0
                for ln in bad:
                    keep += data[pos:ln.start]
                    pos = ln.end
                keep += data[pos:]
                atomic_write_bytes(self.path, bytes(keep))
                how = "spliced"
            entry = self._append_locked("audit_tail_repaired", {
                "fragment_sha256": sha256_hex(fragment_bytes), "bytes": len(fragment_bytes), "fragments": len(bad),
                "line_no": bad[0].line_no, "method": how, "corrupt_file": self.corrupt_path.name,
            })
            return {"repaired": True, "fragments": len(bad), "bytes": len(fragment_bytes), "line_no": bad[0].line_no,
                    "fragment_sha256": sha256_hex(fragment_bytes), "method": how, "corrupt_file": str(self.corrupt_path),
                    "recorded_seq": entry["seq"]}

    # ------------------------------------------------------------- alerting
    def check_and_alert(self, expected_pub: str | None = None, sinks_from_env: bool = True, stream: Any = None) -> Break | None:
        """Verify (incrementally from a valid checkpoint) and raise the alarm on any break. Never raises.

        On a break: prints a one-line red banner to ``stream`` (sys.stderr by default; ANSI only on a TTY),
        appends an ``audit_chain_broken`` entry continuing from the last good entry (skipped when the last
        entry already reports the same break) and dispatches the sinks named in the environment:
        AIIT_ALERT_CMD (argv, JSON on stdin), AIIT_ALERT_SYSLOG (host:port, UDP) and AIIT_ALERT_WEBHOOK (POST).
        Returns the first Break, or None when the log is clean.
        """
        stream = stream if stream is not None else sys.stderr
        try:
            breaks, _ = self._verify(expected_pub, incremental=True)
            if not breaks:
                return None
            first = breaks[0]
            extra = f" (+{len(breaks) - 1} more)" if len(breaks) > 1 else ""
            text = f"AUDIT CHAIN BROKEN: {self.path}: {first}{extra}"
            try:
                if getattr(stream, "isatty", lambda: False)():
                    text = "\x1b[1;31m" + text + "\x1b[0m"
                print(text, file=stream, flush=True)
            except Exception:
                pass
            with contextlib.suppress(Exception):
                with file_lock(self.path):
                    last, _ = self._tail_last_good()
                    same = (last is not None and last["action"] == "audit_chain_broken"
                            and last["details"].get("line_no") == first.line_no and last["details"].get("reason") == first.reason)
                    if not same:
                        self._append_locked("audit_chain_broken", {"reason": first.reason, "line_no": first.line_no,
                                                                   "seq": first.seq, "problems": len(breaks)})
            if sinks_from_env:
                payload = {"actor_id": self.actor_id, "seq": first.seq, "line_no": first.line_no, "reason": first.reason,
                           "log_path": str(self.path)}
                self._dispatch_sinks(payload)
            return first
        except Exception as e:  # pragma: no cover - defensive: an alert check must never take a command down
            with contextlib.suppress(Exception):
                print(f"audit check failed: {type(e).__name__}: {str(e)[:200]}", file=stream, flush=True)
            return None

    def _dispatch_sinks(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        cmd = os.environ.get("AIIT_ALERT_CMD", "").strip()
        if cmd:
            with contextlib.suppress(Exception):
                argv = _split_argv(cmd)
                if argv:
                    subprocess.run(argv, input=data.encode("utf-8"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=10, shell=False, check=False)
        target = os.environ.get("AIIT_ALERT_SYSLOG", "").strip()
        if target:
            with contextlib.suppress(Exception):
                host, _, port = target.rpartition(":")
                if not host:
                    host, port = port, "514"
                handler = logging.handlers.SysLogHandler(address=(host.strip("[]"), int(port)))
                handler.handleError = lambda record: None  # a dead syslog host must not print a traceback
                try:
                    rec = logging.LogRecord("aiit.audit", logging.CRITICAL, __file__, 0, "aiit audit chain broken " + data, None, None)
                    handler.emit(rec)
                finally:
                    handler.close()
        url = os.environ.get("AIIT_ALERT_WEBHOOK", "").strip()
        if url:
            with contextlib.suppress(Exception):
                http_json("POST", url, payload, timeout=10, retries=1, backoff=0.2, expect_json=False)
