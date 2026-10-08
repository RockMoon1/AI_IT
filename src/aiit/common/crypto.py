"""Key management, bundle sealing and plan signing.

Primitives (all from the `cryptography` package):
  * Ed25519 for signatures (agent signs bundles, console signs plans)
  * X25519 + HKDF-SHA256 + AES-256-GCM for sealing bundles to the console key
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .util import canonical_json, read_json, sha256_hex, write_json, write_private_file

HKDF_INFO = b"aiit-bundle-v1"


class CryptoError(Exception):
    pass


# ---------------------------------------------------------------- key files

def _passphrase() -> bytes | None:
    p = os.environ.get("AIIT_KEY_PASSPHRASE")
    return p.encode("utf-8") if p else None


def _save_private(path: Path, key: Any) -> None:
    pw = _passphrase()
    enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    write_private_file(path, pem)


def _load_private(path: Path) -> Any:
    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=_passphrase())
    except TypeError as e:  # encrypted key without passphrase, or vice versa
        raise CryptoError(
            f"Cannot load {path.name}: set AIIT_KEY_PASSPHRASE to the passphrase used at init"
        ) from e
    except ValueError as e:
        raise CryptoError(f"Cannot load {path.name}: wrong passphrase or corrupt key") from e


def pub_hex(key: Any) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def ed25519_pub_from_hex(h: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(h))


def x25519_pub_from_hex(h: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(h))


@dataclass
class Identity:
    """A signing key plus (optionally) a box key, as held by a console or agent."""

    id: str
    sign_priv: ed25519.Ed25519PrivateKey
    box_priv: x25519.X25519PrivateKey | None = None

    @property
    def sign_pub_hex(self) -> str:
        return pub_hex(self.sign_priv.public_key())

    @property
    def box_pub_hex(self) -> str | None:
        return pub_hex(self.box_priv.public_key()) if self.box_priv else None

    def sign(self, data: bytes) -> str:
        return self.sign_priv.sign(data).hex()

    # -- persistence
    @classmethod
    def generate(cls, id: str, with_box: bool) -> "Identity":
        return cls(
            id=id,
            sign_priv=ed25519.Ed25519PrivateKey.generate(),
            box_priv=x25519.X25519PrivateKey.generate() if with_box else None,
        )

    def save(self, keys_dir: Path) -> None:
        keys_dir.mkdir(parents=True, exist_ok=True)
        _save_private(keys_dir / "sign.key", self.sign_priv)
        if self.box_priv is not None:
            _save_private(keys_dir / "box.key", self.box_priv)
        meta = {"id": self.id, "sign_pub": self.sign_pub_hex, "box_pub": self.box_pub_hex}
        write_json(keys_dir / "identity.json", meta, private=True)

    @classmethod
    def load(cls, keys_dir: Path) -> "Identity":
        meta = read_json(keys_dir / "identity.json")
        sign_priv = _load_private(keys_dir / "sign.key")
        box_path = keys_dir / "box.key"
        box_priv = _load_private(box_path) if box_path.exists() else None
        return cls(id=meta["id"], sign_priv=sign_priv, box_priv=box_priv)


# ---------------------------------------------------------------- signatures

def verify_signature(pub_hex_str: str, data: bytes, sig_hex: str) -> bool:
    try:
        ed25519_pub_from_hex(pub_hex_str).verify(bytes.fromhex(sig_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_object(identity: Identity, obj: Any) -> str:
    """Sign the canonical JSON of obj; returns hex signature."""
    return identity.sign(canonical_json(obj))


def verify_object(pub_hex_str: str, obj: Any, sig_hex: str) -> bool:
    return verify_signature(pub_hex_str, canonical_json(obj), sig_hex)


# ---------------------------------------------------------------- sealing

def _derive_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO + eph_pub + recipient_pub,
    ).derive(shared)


def seal(plaintext: bytes, recipient_box_pub_hex: str, header: dict[str, Any], signer: Identity) -> tuple[dict[str, Any], bytes]:
    """Encrypt plaintext to the recipient and sign the header.

    Returns (signed_header, ciphertext). The header passed in must not contain
    'eph_pub', 'nonce', 'plaintext_sha256' or 'signature'; they are added here.
    """
    recipient_pub = x25519_pub_from_hex(recipient_box_pub_hex)
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    shared = eph_priv.exchange(recipient_pub)
    key = _derive_key(shared, eph_pub_bytes, bytes.fromhex(recipient_box_pub_hex))
    nonce = os.urandom(12)

    hdr = dict(header)
    hdr.update(
        {
            "eph_pub": eph_pub_bytes.hex(),
            "nonce": nonce.hex(),
            "plaintext_sha256": sha256_hex(plaintext),
            "agent_sign_pub": signer.sign_pub_hex,
            "agent_id": signer.id,
        }
    )
    aad = canonical_json(hdr)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    hdr["signature"] = signer.sign(aad)
    return hdr, ciphertext


def open_sealed(header: dict[str, Any], ciphertext: bytes, recipient: Identity) -> bytes:
    """Decrypt and authenticate. Raises CryptoError on any failure."""
    if recipient.box_priv is None:
        raise CryptoError("recipient identity has no box key")
    hdr = {k: v for k, v in header.items() if k != "signature"}
    sig = header.get("signature")
    if not sig or not verify_signature(hdr["agent_sign_pub"], canonical_json(hdr), sig):
        raise CryptoError("bundle header signature is invalid")
    eph_pub_bytes = bytes.fromhex(hdr["eph_pub"])
    shared = recipient.box_priv.exchange(x25519_pub_from_hex(hdr["eph_pub"]))
    key = _derive_key(shared, eph_pub_bytes, bytes.fromhex(recipient.box_pub_hex or ""))
    try:
        plaintext = AESGCM(key).decrypt(bytes.fromhex(hdr["nonce"]), ciphertext, canonical_json(hdr))
    except InvalidTag as e:
        raise CryptoError("bundle failed authentication (wrong console key or tampered file)") from e
    if sha256_hex(plaintext) != hdr["plaintext_sha256"]:
        raise CryptoError("plaintext hash mismatch")
    return plaintext
