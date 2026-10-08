"""Small helpers shared by agent and console."""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat(timespec="seconds")


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def in_hours(h: float) -> str:
    return iso(utcnow() + timedelta(hours=h))


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def current_os() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


def os_version() -> str:
    try:
        return f"{platform.system()} {platform.release()} ({platform.version()})"
    except Exception:  # pragma: no cover
        return platform.platform()


def hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:  # pragma: no cover
        return "unknown-host"


def os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except Exception:  # pragma: no cover - Windows ignores POSIX bits
        pass
    return path


def write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except Exception:  # pragma: no cover
        pass


def read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, obj: Any, private: bool = False) -> None:
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    if private:
        write_private_file(path, data)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 40] + f"\n... [truncated {len(text) - limit + 40} chars]"
