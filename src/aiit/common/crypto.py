"""Key management, bundle sealing and plan signing.

Primitives (all from the `cryptography` package):
  * Ed25519 for signatures (agent signs bundles, console signs plans)
  * X25519 + HKDF-SHA256 + AES-256-GCM for sealing bundles to the console key
"""
from __future__ import annotations

import base64
import codecs
import getpass
import hashlib
import hmac
import os
import re
import stat
import sys
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

PASSPHRASE_ENV = "AIIT_KEY_PASSPHRASE"
PASSPHRASE_FILE_ENV = "AIIT_KEY_PASSPHRASE_FILE"
NO_PROMPT_ENV = "AIIT_NO_PROMPT"
RAW_PUBLIC_KEY_LEN = 32  # Ed25519 and X25519


class CryptoError(Exception):
    pass


# ---------------------------------------------------------------- passphrase

# Interactive prompting is opt-in: the CLIs enable it in main(); library use
# and the test-suite never block on a terminal.
_prompt_allowed = False
# The answer typed at the prompt, kept for the rest of the process so a console
# with two key files (sign.key, box.key) asks once, not twice.
_prompt_answer: list[bytes | None] = []


def set_passphrase_prompt(enabled: bool) -> None:
    """Allow (or forbid) ``_passphrase`` to ask on the terminal; also forgets any earlier answer."""
    global _prompt_allowed
    _prompt_allowed = bool(enabled)
    _prompt_answer.clear()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _can_prompt() -> bool:
    if not _prompt_allowed or _truthy(os.environ.get(NO_PROMPT_ENV)):
        return False
    stream = sys.stdin
    try:
        return stream is not None and bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def _read_passphrase_file(path: Path) -> bytes:
    try:
        st = os.stat(path)
    except OSError as e:
        raise CryptoError(f"{PASSPHRASE_FILE_ENV}={path}: {e.strerror or e}") from None
    if not stat.S_ISREG(st.st_mode):
        raise CryptoError(f"{PASSPHRASE_FILE_ENV}={path} is not a regular file")
    if os.name != "nt" and st.st_mode & (stat.S_IRWXO):
        raise CryptoError(f"refusing {PASSPHRASE_FILE_ENV}={path}: it is accessible by other users "
                          f"(mode {stat.S_IMODE(st.st_mode):04o}); chmod 600 it")
    try:
        data = path.read_bytes()
    except OSError as e:
        raise CryptoError(f"{PASSPHRASE_FILE_ENV}={path}: {e.strerror or e}") from None
    first = data.split(b"\n", 1)[0].rstrip(b"\r")
    if first.startswith(codecs.BOM_UTF8):
        first = first[len(codecs.BOM_UTF8):]
    if not first:
        raise CryptoError(f"{PASSPHRASE_FILE_ENV}={path} is empty (the first line is the passphrase)")
    return first


def _prompt_passphrase(confirm: bool) -> bytes | None:
    if _prompt_answer:
        return _prompt_answer[0]
    first = getpass.getpass("Key passphrase (empty for an unencrypted key): ")
    if confirm and first:
        if getpass.getpass("Repeat passphrase: ") != first:
            raise CryptoError("the passphrases do not match")
    answer = first.encode("utf-8") if first else None
    _prompt_answer.append(answer)
    return answer


def passphrase_source() -> str | None:
    """Where a passphrase would come from without asking: ``"env"``, ``"file"`` or None."""
    if os.environ.get(PASSPHRASE_ENV):
        return "env"
    if os.environ.get(PASSPHRASE_FILE_ENV):
        return "file"
    return None


def _passphrase(*, confirm: bool = False) -> bytes | None:
    """The passphrase that encrypts private keys at rest, or None for an unencrypted key.

    Precedence:

    1. ``AIIT_KEY_PASSPHRASE`` when set and non-empty.
    2. ``AIIT_KEY_PASSPHRASE_FILE``: the first line of that file, trailing
       newline stripped. A missing or empty file is a CryptoError; on POSIX a
       file that other users can access (any ``o`` bit) is refused.
    3. An interactive ``getpass`` prompt, when ``set_passphrase_prompt(True)``
       was called, ``AIIT_NO_PROMPT`` is not set and stdin is a terminal. The
       answer is remembered for the rest of the process. With ``confirm`` the
       prompt is repeated and a mismatch is a CryptoError. An empty answer
       means no passphrase.
    4. None: keys are stored unencrypted (the CLIs print a note).
    """
    env = os.environ.get(PASSPHRASE_ENV)
    if env:
        return env.encode("utf-8")
    file = os.environ.get(PASSPHRASE_FILE_ENV)
    if file:
        return _read_passphrase_file(Path(file))
    if _can_prompt():
        return _prompt_passphrase(confirm)
    return None


# ---------------------------------------------------------------- key files

def key_pem_is_encrypted(pem: bytes) -> bool:
    return b"ENCRYPTED" in pem


def key_file_is_encrypted(path: Path) -> bool:
    """True when the PEM private key at ``path`` is stored encrypted (no passphrase needed to tell)."""
    return key_pem_is_encrypted(Path(path).read_bytes())


def _save_private(path: Path, key: Any, pw: bytes | None) -> None:
    enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    write_private_file(path, pem)


def _load_private(path: Path) -> Any:
    pem = path.read_bytes()
    # Only an encrypted key needs a passphrase; an unencrypted one loads as is,
    # so a configured passphrase does not break keys made before it was set.
    pw = _passphrase() if key_pem_is_encrypted(pem) else None
    try:
        return serialization.load_pem_private_key(pem, password=pw)
    except TypeError as e:  # encrypted key without passphrase
        raise CryptoError(
            f"Cannot load {path.name}: it is encrypted; set {PASSPHRASE_ENV} or {PASSPHRASE_FILE_ENV} "
            f"to the passphrase used at init"
        ) from e
    except ValueError as e:
        raise CryptoError(f"Cannot load {path.name}: wrong passphrase or corrupt key") from e


def pub_hex(key: Any) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


# ---------------------------------------------------------------- fingerprints

def public_key_bytes(value: Any) -> bytes:
    """Raw 32 public-key bytes from a key object, raw bytes, hex (as stored in identity and
    enrollment files) or base64 (standard or URL-safe, padded or not). ValueError otherwise."""
    if hasattr(value, "public_key") and not hasattr(value, "public_bytes"):
        value = value.public_key()
    if hasattr(value, "public_bytes"):
        raw = value.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    elif isinstance(value, str):
        s = "".join(value.split())
        if re.fullmatch(r"[0-9a-fA-F]{64}", s):
            raw = bytes.fromhex(s)
        else:
            try:
                padded = s + "=" * (-len(s) % 4)
                raw = base64.b64decode(padded, validate=True) if not re.search(r"[-_]", s) else base64.urlsafe_b64decode(padded)
            except (ValueError, TypeError) as e:
                raise ValueError("public key must be raw bytes, hex or base64") from e
    else:
        raise ValueError(f"cannot take a public key from {type(value).__name__}")
    if len(raw) != RAW_PUBLIC_KEY_LEN:
        raise ValueError(f"public key must be {RAW_PUBLIC_KEY_LEN} bytes, got {len(raw)}")
    return raw


def fingerprint(public_key: Any) -> str:
    """SHA-256 of the raw public key as 16 blocks of 4 hex digits (``a1b2 c3d4 ...``).

    The same key gives the same string on every platform; it is what an
    operator reads out at ``init`` and types at ``enroll --fingerprint``.
    """
    digest = hashlib.sha256(public_key_bytes(public_key)).hexdigest()
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def _normalize_fingerprint(text: str) -> str | None:
    s = str(text).strip().lower()
    if s.startswith("sha256:"):
        s = s[len("sha256:"):]
    s = re.sub(r"[\s:\-]", "", s)
    return s if re.fullmatch(r"[0-9a-f]{64}", s) else None


def fingerprint_matches(given: str, actual: str) -> bool:
    """Compare a typed or pasted fingerprint with the real one, ignoring case, spaces, colons and
    dashes (and a ``sha256:`` prefix); a malformed or partial value never matches."""
    g, a = _normalize_fingerprint(given), _normalize_fingerprint(actual)
    if g is None or a is None:
        return False
    return hmac.compare_digest(g.encode("ascii"), a.encode("ascii"))


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

    @property
    def fingerprint(self) -> str:
        """Fingerprint of the signing public key, the value peers pin."""
        return fingerprint(self.sign_priv.public_key())

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
        pw = _passphrase(confirm=True)
        _save_private(keys_dir / "sign.key", self.sign_priv, pw)
        if self.box_priv is not None:
            _save_private(keys_dir / "box.key", self.box_priv, pw)
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
