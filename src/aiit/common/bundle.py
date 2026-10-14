"""Sealed bundle file format (.aiit): magic line, header JSON line, ciphertext."""
from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .crypto import CryptoError, Identity, open_sealed, seal
from .util import iso, validate_id

MAGIC = b"AIIT1\n"
MAX_MEMBERS = 2000
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


def pack_dir(src: Path) -> bytes:
    """tar.gz of a directory, deterministic ordering, relative paths."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                tar.add(p, arcname=p.relative_to(src).as_posix(), recursive=False)
    return buf.getvalue()


def _safe_member(member: tarfile.TarInfo) -> bool:
    name = member.name
    if not name or "\x00" in name or "\\" in name:
        return False
    if PureWindowsPath(name).drive or PurePosixPath(name).is_absolute() or name.startswith("/"):
        return False
    if any(part in ("..", ".") for part in PurePosixPath(name).parts):
        return False
    if any(ord(ch) < 32 for ch in name):
        return False
    return member.isfile() or member.isdir()


def unpack_to(data: bytes, dest: Path) -> list[str]:
    """Extract a bundle payload into dest with path, count and size limits.

    Only regular files and directories are extracted (no links, devices or
    attributes). Every member is checked before anything is written so a
    hostile archive leaves nothing behind.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_r = dest.resolve()
    names: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise CryptoError(f"bundle has {len(members)} members (limit {MAX_MEMBERS})")
        total = 0
        for m in members:
            if not _safe_member(m):
                raise CryptoError(f"unsafe path in bundle: {m.name[:120]!r}")
            if m.isfile():
                if m.size > MAX_MEMBER_BYTES:
                    raise CryptoError(f"bundle member {m.name[:80]!r} is {m.size} bytes (limit {MAX_MEMBER_BYTES})")
                total += m.size
                if total > MAX_TOTAL_BYTES:
                    raise CryptoError(f"bundle exceeds {MAX_TOTAL_BYTES} bytes uncompressed")
            dest_abs = os.path.abspath(str(dest_r))
            member_abs = os.path.normpath(os.path.join(dest_abs, m.name))
            if member_abs != dest_abs and not member_abs.startswith(os.path.join(dest_abs, "")):
                raise CryptoError(f"bundle member escapes destination: {m.name[:120]!r}")
            target = Path(member_abs).resolve()
            if target != dest_r and dest_r not in target.parents:
                raise CryptoError(f"bundle member escapes destination: {m.name[:120]!r}")
        for m in members:
            if hasattr(tarfile, "data_filter"):
                tar.extract(m, path=dest, set_attrs=False, filter="data")
            else:  # pragma: no cover - Python < 3.12 without the backport
                tar.extract(m, path=dest, set_attrs=False)
            if m.isfile():
                names.append(m.name)
    return names


def write_bundle(path: Path, plaintext: bytes, recipient_box_pub: str, signer: Identity, kind: str, bundle_id: str, console_id: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    header: dict[str, Any] = {
        "version": 1,
        "kind": kind,
        "bundle_id": bundle_id,
        "console_id": console_id,
        "created_at": iso(),
    }
    if extra:
        header.update(extra)
    hdr, ct = seal(plaintext, recipient_box_pub, header, signer)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(MAGIC)
        f.write(json.dumps(hdr, sort_keys=True).encode("utf-8") + b"\n")
        f.write(ct)
    return hdr


def read_bundle_header(path: Path) -> dict[str, Any]:
    with open(path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise CryptoError("not an AI_IT bundle (bad magic)")
        return json.loads(f.readline().decode("utf-8"))


def read_bundle(path: Path, recipient: Identity) -> tuple[dict[str, Any], bytes]:
    with open(path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise CryptoError("not an AI_IT bundle (bad magic)")
        hdr = json.loads(f.readline().decode("utf-8"))
        ct = f.read()
    try:
        validate_id(hdr.get("bundle_id"), "bundle_id")
        validate_id(hdr.get("agent_id"), "agent_id")
        validate_id(hdr.get("console_id"), "console_id")
        for key in ("case_id", "plan_id"):
            if hdr.get(key) is not None:
                validate_id(hdr.get(key), key)
    except ValueError as e:
        raise CryptoError(f"bundle header rejected: {e}") from e
    if hdr.get("console_id") != recipient.id:
        raise CryptoError(f"bundle was sealed for console {hdr.get('console_id')}, this console is {recipient.id}")
    return hdr, open_sealed(hdr, ct, recipient)
