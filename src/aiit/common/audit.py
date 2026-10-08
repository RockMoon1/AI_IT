"""Hash-chained, append-only audit log (JSON lines).

Each entry carries the hash of the previous entry; `verify()` recomputes the
chain. The log never contains bundle content, only metadata.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from .util import canonical_json, iso, os_user, sha256_hex

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path, actor_id: str):
        self.path = path
        self.actor_id = actor_id
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _entries(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        with open(self.path, "r", encoding="utf-8") as f:
            return iter([json.loads(line) for line in f if line.strip()])

    def _last(self) -> dict[str, Any] | None:
        last = None
        for e in self._entries():
            last = e
        return last

    def record(self, action: str, **details: Any) -> dict[str, Any]:
        last = self._last()
        entry: dict[str, Any] = {
            "seq": (last["seq"] + 1) if last else 1,
            "ts": iso(),
            "actor_id": self.actor_id,
            "os_user": os_user(),
            "action": action,
            "details": details,
            "prev_hash": last["hash"] if last else GENESIS,
        }
        entry["hash"] = sha256_hex(canonical_json(entry))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        seq = 0
        for e in self._entries():
            seq += 1
            if e.get("seq") != seq:
                return False, f"sequence gap at entry {seq}"
            if e.get("prev_hash") != prev:
                return False, f"broken chain at entry {seq}"
            body = {k: v for k, v in e.items() if k != "hash"}
            if sha256_hex(canonical_json(body)) != e.get("hash"):
                return False, f"hash mismatch at entry {seq}"
            prev = e["hash"]
        return True, f"{seq} entries verified"

    def entries(self) -> list[dict[str, Any]]:
        return list(self._entries())
