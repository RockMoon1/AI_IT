"""Small helpers shared by agent and console."""
from __future__ import annotations

import contextlib
import getpass
import hashlib
import json
import os
import platform
import re
import secrets
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

ID_RE = re.compile(r"^[a-z]{1,16}-[0-9a-f]{12}$")


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


def validate_id(value: Any, what: str = "id") -> str:
    """Accept only ids shaped like new_id() output. Anything else from a header,
    a manifest or the network is rejected before it can become a path component."""
    if not isinstance(value, str) or not ID_RE.match(value):
        raise ValueError(f"invalid {what}: {str(value)[:80]!r}")
    return value


def safe_join(base: Path, *parts: str) -> Path:
    """Join parts under base and refuse anything that escapes it (absolute, drive, '..')."""
    base_r = Path(base).resolve()
    for part in parts:
        if not isinstance(part, str) or not part or "\x00" in part:
            raise ValueError(f"invalid path component: {str(part)[:80]!r}")
    base_abs = os.path.abspath(str(base_r))
    candidate = os.path.normpath(os.path.join(base_abs, *parts))
    if candidate != base_abs and not candidate.startswith(os.path.join(base_abs, "")):
        raise ValueError(f"path escapes {base_r}: {'/'.join(parts)[:120]!r}")
    target = Path(candidate).resolve()
    if target != base_r and base_r not in target.parents:
        raise ValueError(f"path escapes {base_r}: {'/'.join(parts)[:120]!r}")
    return target


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


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Cross-process exclusive lock on a sidecar <path>.lock file (msvcrt on Windows, flock elsewhere)."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":  # pragma: no cover - exercised on the Windows runner
            import msvcrt
            import time as _time
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    _time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":  # pragma: no cover
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def atomic_write_bytes(path: Path, data: bytes, private: bool = False) -> None:
    """Write to a temp file in the same directory, fsync, then rename over the target.

    A crash mid-write leaves either the old file or the new file, never a torn one.
    Every file is created 0600 (nothing the tool writes needs to be readable
    by another account; the operator copies enrollment files and plans by
    hand), and the target name is never a followed symlink. ``private`` adds
    an explicit chmod so the mode holds even where the creation mode is
    widened.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):  # pragma: no cover - Windows
        flags |= os.O_BINARY
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if private and os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    if os.name != "nt":
        with contextlib.suppress(OSError):
            dfd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)


def write_private_file(path: Path, data: bytes) -> None:
    atomic_write_bytes(Path(path), data, private=True)


def read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, obj: Any, private: bool = False) -> None:
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    atomic_write_bytes(Path(path), data, private=private)


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 40] + f"\n... [truncated {len(text) - limit + 40} chars]"
