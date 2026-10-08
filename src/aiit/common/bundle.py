"""Sealed bundle file format (.aiit): magic line, header JSON line, ciphertext."""
from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

from .crypto import CryptoError, Identity, open_sealed, seal
from .util import iso

MAGIC = b"AIIT1\n"


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
    if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
        return False
    return member.isfile() or member.isdir()


def unpack_to(data: bytes, dest: Path) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if not _safe_member(m):
                raise CryptoError(f"unsafe path in bundle: {m.name}")
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
    if hdr.get("console_id") != recipient.id:
        raise CryptoError(f"bundle was sealed for console {hdr.get('console_id')}, this console is {recipient.id}")
    return hdr, open_sealed(hdr, ct, recipient)
