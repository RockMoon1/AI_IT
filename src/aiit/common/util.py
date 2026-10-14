"""Small helpers shared by agent and console."""
from __future__ import annotations

import codecs
import contextlib
import functools
import getpass
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
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


# ---------------------------------------------------------------- private directories
#
# A state directory holds private keys, the policy and the audit chain. On POSIX
# it is mode 0700. On Windows ``os.chmod`` cannot express that, so the directory
# gets an explicit ACL through ``icacls``: inheritance removed, full control for
# SYSTEM and Administrators (agent) or for the account running the console.
# A state directory that already exists is checked before it is used: one owned
# by another account, or writable by other accounts, is refused with the fix in
# the message unless AIIT_ALLOW_LOOSE_STATE_DIR=1.

STATE_DIR_OWNERS = ("agent", "console")
LOOSE_STATE_DIR_ENV = "AIIT_ALLOW_LOOSE_STATE_DIR"

# Well-known SIDs. icacls takes a SID with a "*" prefix; SDDL writes the common
# ones as two-letter aliases, which ``_sddl_sid`` maps back to the SID form.
WINDOWS_SID_SYSTEM = "S-1-5-18"
WINDOWS_SID_ADMINISTRATORS = "S-1-5-32-544"
WINDOWS_SID_CREATOR_OWNER = "S-1-3-0"
_SDDL_ALIASES = {
    "SY": WINDOWS_SID_SYSTEM, "BA": WINDOWS_SID_ADMINISTRATORS, "CO": WINDOWS_SID_CREATOR_OWNER,
    "BU": "S-1-5-32-545", "BG": "S-1-5-32-546", "PU": "S-1-5-32-547", "AU": "S-1-5-11", "WD": "S-1-1-0",
    "IU": "S-1-5-4", "AN": "S-1-5-7", "NU": "S-1-5-2", "LS": "S-1-5-19", "NS": "S-1-5-20", "RC": "S-1-5-12",
    "SU": "S-1-5-6", "OW": "S-1-3-4", "AC": "S-1-15-2-1",
}
_SID_NAMES = {
    WINDOWS_SID_SYSTEM: "SYSTEM", WINDOWS_SID_ADMINISTRATORS: "Administrators", WINDOWS_SID_CREATOR_OWNER: "CREATOR OWNER",
    "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests", "S-1-5-32-547": "Power Users", "S-1-5-11": "Authenticated Users",
    "S-1-1-0": "Everyone", "S-1-5-4": "INTERACTIVE", "S-1-5-7": "ANONYMOUS LOGON", "S-1-5-2": "NETWORK",
    "S-1-5-19": "LOCAL SERVICE", "S-1-5-20": "NETWORK SERVICE", "S-1-5-6": "SERVICE", "S-1-15-2-1": "ALL APPLICATION PACKAGES",
}
# SDDL access-right tokens (the file-system meaning of the directory-service letters).
_SDDL_RIGHTS = {
    "GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
    "RC": 0x00020000, "SD": 0x00010000, "WD": 0x00040000, "WO": 0x00080000,
    "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
    "FA": 0x1F01FF, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200A0,
    "KA": 0xF003F, "KR": 0x20019, "KW": 0x20006, "KX": 0x20019,
}
# Anything in this mask lets the holder add, change or remove entries in a directory
# (write/add file, append/add subdirectory, write EA, delete child, write attributes,
# delete, write DAC, take ownership, generic write, generic all).
_SDDL_WRITE_MASK = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
_SID_RE = re.compile(r"S-1-\d+(?:-\d+)+")
_ACE_RE = re.compile(r"\(([^()]*)\)")
_DACL_RE = re.compile(r"D:[A-Z]*(?:\([^()]*\))+")


def _is_windows() -> bool:
    return os.name == "nt"


def _loose_state_dir_allowed() -> bool:
    return os.environ.get(LOOSE_STATE_DIR_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def _run_windows_tool(argv: list[str]) -> tuple[int, str]:
    """Run a Windows system tool (absolute path under System32) with the scrubbed child environment.

    Returns (exit code, combined decoded output). A tool that cannot be started
    or that hangs is reported as (-1, reason) so the caller fails closed.
    """
    from ..agent.procs import console_codec, scrubbed_env

    try:
        proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, env=scrubbed_env(),
                              timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return -1, f"{type(e).__name__}: {e}"
    out = (proc.stdout or b"") + (proc.stderr or b"")
    return proc.returncode, out.decode(console_codec(), "replace")


def _windows_is_elevated() -> bool:
    """True when the process holds a full administrator token (UAC elevated); True off Windows (moot)."""
    if not _is_windows():
        return True
    try:  # pragma: no cover - Windows only
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover
        return False


# Injection points: tests on POSIX replace these with fakes to exercise the Windows path.
windows_tool_runner = _run_windows_tool
windows_is_elevated = _windows_is_elevated


@functools.lru_cache(maxsize=1)
def windows_current_user_sid() -> str | None:
    """SID of the account running this process (``whoami /user``), or None when it cannot be determined."""
    from ..agent.procs import windows_system32

    rc, out = windows_tool_runner([windows_system32("whoami.exe"), "/user", "/fo", "csv", "/nh"])
    if rc != 0:
        return None
    m = _SID_RE.search(out)
    return m.group(0).upper() if m else None


def _icacls_principal(who: str) -> str:
    return f"*{who}" if _SID_RE.fullmatch(who) else who


def _sid_label(sid: str) -> str:
    name = _SID_NAMES.get(sid)
    return f"{name} ({sid})" if name else sid


def _sddl_sid(token: str) -> str:
    t = token.strip().upper()
    return _SDDL_ALIASES.get(t, t)


def _sddl_rights_mask(token: str) -> int:
    t = token.strip().upper()
    if not t:
        return 0
    if t.startswith("0X"):
        try:
            return int(t, 16)
        except ValueError:
            return _SDDL_WRITE_MASK  # unparseable: assume the worst
    mask = 0
    for i in range(0, len(t), 2):
        part = t[i:i + 2]
        if part not in _SDDL_RIGHTS:
            return _SDDL_WRITE_MASK  # unknown token: assume the worst
        mask |= _SDDL_RIGHTS[part]
    return mask


def sddl_write_principals(sddl: str) -> list[tuple[str, int]]:
    """(SID, access mask) for every allow ACE in an SDDL DACL that grants some form of write.

    Aliases are returned in SID form (``SY`` -> ``S-1-5-18``); inherit-only ACEs
    count because they apply to the files created inside the directory.
    """
    m = _DACL_RE.search(sddl)
    if not m:
        return []
    found: list[tuple[str, int]] = []
    for ace in _ACE_RE.findall(m.group(0)):
        fields = ace.split(";")
        if len(fields) < 6 or fields[0].strip().upper() != "A":
            continue
        mask = _sddl_rights_mask(fields[2])
        if mask & _SDDL_WRITE_MASK:
            found.append((_sddl_sid(fields[5]), mask))
    return found


def _decode_icacls_save(data: bytes) -> str:
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        return data.decode("utf-16", "replace")
    if b"\x00" in data:
        return data.decode("utf-16-le", "replace")
    return data.decode("utf-8", "replace")


def windows_dir_sddl(path: Path) -> str:
    """The DACL of ``path`` as an SDDL string, via ``icacls <dir> /save <file>``.

    ``/save`` writes SIDs, not account names, so the result does not depend on
    the display language. Raises PermissionError when icacls fails or prints
    something that is not a DACL.
    """
    from ..agent.procs import windows_system32

    tmp = tempfile.mkdtemp(prefix="aiit-acl-")
    try:
        out_file = os.path.join(tmp, "acl.txt")
        rc, out = windows_tool_runner([windows_system32("icacls.exe"), str(path), "/save", out_file])
        if rc != 0:
            raise PermissionError(f"cannot read the ACL of {path}: icacls exited {rc}: {out.strip()[:300]}")
        try:
            data = Path(out_file).read_bytes()
        except OSError as e:
            raise PermissionError(f"cannot read the ACL of {path}: icacls wrote no ACL file ({e})") from None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    m = _DACL_RE.search(_decode_icacls_save(data))
    if not m:
        raise PermissionError(f"cannot read the ACL of {path}: no DACL in the icacls output")
    return m.group(0)


def windows_state_dir_grants(owner: str) -> list[str]:
    """The ``<principal>:(OI)(CI)F`` grants a fresh state directory gets on Windows.

    agent: SYSTEM and Administrators (so a service running as SYSTEM and an
    elevated operator can use it and nobody else can). console: the account
    running the console, by SID, or by name when the SID cannot be found.
    """
    if owner == "agent":
        who = [WINDOWS_SID_SYSTEM, WINDOWS_SID_ADMINISTRATORS]
    else:
        who = [windows_current_user_sid() or os.environ.get("USERNAME") or os_user()]
    return [f"{_icacls_principal(w)}:(OI)(CI)F" for w in who]


def _windows_fix_command(path: Path, owner: str) -> str:
    from ..agent.procs import windows_system32

    grants = " ".join(f'"{g}"' for g in windows_state_dir_grants(owner))
    return f'{windows_system32("icacls.exe")} "{path}" /inheritance:r /grant:r {grants}'


def _restrict_windows_state_dir(path: Path, owner: str) -> None:
    """Replace the inherited ACL of a directory this process just created."""
    from ..agent.procs import windows_system32

    loose = _loose_state_dir_allowed()
    grants = windows_state_dir_grants(owner)
    if owner == "agent" and not windows_is_elevated():
        msg = (f"refusing to create the agent state directory {path} from a non-elevated process: it is restricted to "
               f"SYSTEM and Administrators, which this process could not use afterwards. Run aiit-agent from an "
               f"elevated (Administrator) prompt, or set {LOOSE_STATE_DIR_ENV}=1 to also grant the current account")
        if not loose:
            raise PermissionError(msg)
        _warn(msg)
        me = windows_current_user_sid() or os.environ.get("USERNAME") or os_user()
        grants.append(f"{_icacls_principal(me)}:(OI)(CI)F")
    argv = [windows_system32("icacls.exe"), str(path), "/inheritance:r", "/grant:r", *grants]
    rc, out = windows_tool_runner(argv)
    if rc != 0:
        msg = (f"could not restrict the {owner} state directory {path} (icacls exited {rc}: {out.strip()[:300]}). "
               f"Fix: run  {_windows_fix_command(path, owner)}  as an administrator, or set {LOOSE_STATE_DIR_ENV}=1 "
               f"to use it unprotected")
        if not loose:
            raise PermissionError(msg)
        _warn(msg)


def _refuse_state_dir(path: Path, owner: str, problem: str, fix: str) -> None:
    if _loose_state_dir_allowed():
        _warn(f"using {owner} state directory {path} although {problem} ({LOOSE_STATE_DIR_ENV}=1 is set)")
        return
    raise PermissionError(f"refusing {owner} state directory {path}: {problem}. Fix: {fix}, point "
                          f"AIIT_{owner.upper()}_DIR at a private directory, or set {LOOSE_STATE_DIR_ENV}=1 to accept the risk")


def _check_windows_state_dir(path: Path, owner: str) -> None:
    """Refuse a pre-existing directory that an unexpected account can write to."""
    try:
        sddl = windows_dir_sddl(path)
    except PermissionError as e:
        _refuse_state_dir(path, owner, str(e), f"run  {_windows_fix_command(path, owner)}  as an administrator")
        return
    expected = {WINDOWS_SID_SYSTEM, WINDOWS_SID_ADMINISTRATORS, WINDOWS_SID_CREATOR_OWNER}
    me = windows_current_user_sid()
    if me:
        expected.add(me)
        if me.endswith("-500"):
            expected.add("LA")  # SDDL alias for the built-in Administrator account
    bad = sorted({sid for sid, _ in sddl_write_principals(sddl) if sid not in expected})
    if bad:
        _refuse_state_dir(path, owner, f"these accounts can write to it: {', '.join(_sid_label(s) for s in bad)}",
                          f"run  {_windows_fix_command(path, owner)}  as an administrator")


def _check_posix_state_dir(path: Path, owner: str) -> None:
    """Refuse a pre-existing directory owned by someone else or writable by group/others."""
    st = os.stat(path)
    me = os.geteuid()
    problems = []
    if st.st_uid != me:
        problems.append(f"it is owned by uid {st.st_uid}, not by this account (uid {me})")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        who = "group- and world" if st.st_mode & stat.S_IWOTH and st.st_mode & stat.S_IWGRP else (
            "world" if st.st_mode & stat.S_IWOTH else "group")
        problems.append(f"it is {who}-writable (mode {stat.S_IMODE(st.st_mode):04o})")
    if problems:
        _refuse_state_dir(path, owner, "; ".join(problems), f"chown {me} {path} && chmod 700 {path}")


def ensure_private_dir(path: Path, *, owner: str | None = None) -> Path:
    """Create ``path`` as a directory only its owner can use, and return it.

    ``owner`` is None for a directory inside a state directory (created
    0700 on POSIX; on Windows it inherits the state directory's ACL) and
    ``"agent"`` or ``"console"`` for the state directory itself. For the state
    directory:

    * POSIX: a new directory is 0700. A pre-existing one that is owned by
      another account or writable by group or others is refused with
      PermissionError; one that is merely readable by others is tightened.
    * Windows: a new directory gets ``icacls /inheritance:r /grant:r`` with
      full control for SYSTEM and Administrators (agent, which must run
      elevated) or for the current account (console). A pre-existing one whose
      DACL lets any other account write is refused with PermissionError.

    AIIT_ALLOW_LOOSE_STATE_DIR=1 turns each refusal into a warning on stderr.
    """
    if owner is not None and owner not in STATE_DIR_OWNERS:
        raise ValueError(f"owner must be one of {STATE_DIR_OWNERS} or None, not {owner!r}")
    path = Path(path)
    existed = path.is_dir()
    path.mkdir(parents=True, exist_ok=True)
    if _is_windows():
        if owner is not None:
            if existed:
                _check_windows_state_dir(path, owner)
            else:
                _restrict_windows_state_dir(path, owner)
        return path
    if owner is not None and existed:
        _check_posix_state_dir(path, owner)
    try:
        os.chmod(path, 0o700)
    except OSError:
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
