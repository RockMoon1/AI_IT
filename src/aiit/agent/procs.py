"""Hardened process execution for the endpoint agent.

Every external command (plan steps and diagnostic collectors) runs through
``run_capped``. It gives each child a scrubbed environment so endpoint secrets
such as the key passphrase or the LAN server token never leak into command
output, bounds the captured output by spooling it to temporary files, and kills
the whole process group (POSIX) or process tree (Windows) when a step times out
so no grandchildren are left running.

On Windows, built in binaries are started by absolute ``System32`` paths through
``windows_system32`` and ``powershell_exe`` so ``CreateProcess`` never searches
the current directory first. The documented flow runs
``aiit-agent apply E:\\plan.signed.json`` from removable media, and a planted
``powershell.exe`` next to the plan must never win.

Text exchanged with a child's console streams goes through ``console_codec``:
UTF-8 everywhere except Windows, where ``powershell.exe`` and the native console
tools read stdin and write a redirected stdout in the OEM code page.
"""
from __future__ import annotations

import codecs
import contextlib
import ntpath
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

OUTPUT_CAP = 20_000

# Environment variable names that are copied from the agent's environment into a
# child, when present. PATH is always overwritten with a fixed value below.
_KEEP_ENV = (
    "SystemRoot", "windir", "ComSpec", "PATHEXT", "SystemDrive",
    "TEMP", "TMP", "LANG", "LC_ALL", "HOME", "USERPROFILE", "PATH",
)

# Directories, relative to SystemRoot, that make up the fixed Windows child
# PATH (in search order). ``CreateProcess`` hands an environment block to the
# child verbatim and never expands ``%VAR%`` references, so the absolute value
# is built at call time by ``windows_path``.
_WINDOWS_PATH_SUBDIRS = (
    "System32",
    "",
    r"System32\WindowsPowerShell\v1.0",
    r"System32\Wbem",
)
_POSIX_PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin"

_DEFAULT_WINDOWS_ROOT = r"C:\Windows"


@dataclass
class ProcResult:
    """Outcome of a single ``run_capped`` call.

    stdout and stderr are decoded text, each at most ``cap`` bytes with a
    truncation marker appended when the real output was longer.
    """

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


def windows_root() -> str:
    """Return ``%SystemRoot%``, falling back to ``C:\\Windows`` when unset."""
    return os.environ.get("SystemRoot") or _DEFAULT_WINDOWS_ROOT


def windows_system32(name: str) -> str:
    """Return the absolute path to ``name`` under ``%SystemRoot%\\System32``.

    ``name`` may contain sub directories (for example the relative path to
    ``powershell.exe``). ``SystemRoot`` falls back to ``C:\\Windows`` when it is
    not set in the environment. Windows path rules are used regardless of the
    host so the result is the same string on every platform.
    """
    return ntpath.join(windows_root(), "System32", name)


def powershell_exe() -> str:
    """Return the absolute path to Windows PowerShell under System32."""
    return windows_system32(ntpath.join("WindowsPowerShell", "v1.0", "powershell.exe"))


def windows_path() -> str:
    """Return the fixed, fully expanded PATH given to children on Windows.

    Built from the real ``SystemRoot`` at call time: System32, the Windows
    directory, the Windows PowerShell directory and Wbem, separated by ``;``.
    """
    root = windows_root()
    return ";".join(ntpath.join(root, sub) if sub else root for sub in _WINDOWS_PATH_SUBDIRS)


def child_locale(platform: str | None = None) -> str:
    """Return the ``LC_ALL`` value pinned into children for ``platform``.

    Only a locale that exists on the platform is used: ``C.UTF-8`` on Linux,
    ``en_US.UTF-8`` on macOS (which ships no ``C.UTF-8``; forcing one makes
    every setlocale() user print a warning to stderr) and plain ``C`` elsewhere.
    ``platform`` defaults to ``sys.platform``.
    """
    plat = sys.platform if platform is None else platform
    if plat.startswith("linux"):
        return "C.UTF-8"
    if plat == "darwin":
        return "en_US.UTF-8"
    return "C"


def console_codec(os_name: str | None = None) -> str:
    """Return the codec for bytes exchanged with a child's console streams.

    On Windows, ``powershell.exe`` reads stdin through ``[Console]::In`` and
    writes a redirected stdout with ``[Console]::OutputEncoding``; both default
    to the OEM code page (cp437, cp850, cp1252, ...), never UTF-8, and native
    console tools behave the same. The code page is asked from ``GetOEMCP`` at
    call time and returned as ``cp<N>``; when that is unavailable the ``mbcs``
    codec (the ANSI code page) is used. On every other platform the answer is
    ``utf-8``. ``os_name`` defaults to ``os.name``.
    """
    if (os.name if os_name is None else os_name) != "nt":
        return "utf-8"
    try:
        import ctypes

        name = f"cp{int(ctypes.windll.kernel32.GetOEMCP())}"
        codecs.lookup(name)
        return name
    except Exception:
        return "mbcs"


def _is_sensitive(name: str) -> bool:
    """True when an environment variable name looks secret bearing.

    Matching is case insensitive because Windows environment names are.
    """
    upper = name.upper()
    return (
        upper.startswith("AIIT_")
        or upper.endswith("_TOKEN")
        or upper.endswith("_KEY")
        or upper.endswith("_SECRET")
        or "PASS" in upper
        or "CREDENTIAL" in upper
    )


def scrubbed_env() -> dict[str, str]:
    """Build a minimal, secret-free environment for a child process.

    Only a small allow list of variables is copied from the agent's own
    environment, and any of those that look secret bearing are dropped as a
    defence in depth. PATH is replaced with a fixed system PATH (built from the
    real ``SystemRoot`` on Windows), the current directory is removed from
    executable search, and the locale is pinned so output is deterministic
    across machines.
    """
    env: dict[str, str] = {}
    for name in _KEEP_ENV:
        val = os.environ.get(name)
        if val is not None and not _is_sensitive(name):
            env[name] = val
    env["PATH"] = windows_path() if os.name == "nt" else _POSIX_PATH
    # CreateProcess and the loader must not search the current directory first.
    env["NoDefaultCurrentDirectoryInExePath"] = "1"
    # Pin the locale so numeric and date formatting does not vary by host.
    env["LC_ALL"] = child_locale()
    return env


def _read_capped(handle, cap: int, encoding: str = "utf-8") -> str:
    """Read at most ``cap`` bytes back from a spool file, as decoded text.

    Bytes are decoded with ``encoding`` (undecodable ones become U+FFFD). When
    the file held more than ``cap`` bytes a truncation marker is appended so
    the reader can tell the output was cut.
    """
    handle.seek(0)
    data = handle.read(cap + 1)
    text = data[:cap].decode(encoding, "replace")
    if len(data) > cap:
        text += "\n... [truncated by aiit-agent]\n"
    return text


def _kill_tree(proc: subprocess.Popen) -> None:
    """Terminate a timed out child and every process it spawned.

    Every failure here is ignored on purpose: the child may already be gone,
    and the caller still waits for it and reports the timeout either way.
    """
    if os.name == "nt":
        taskkill = windows_system32("taskkill.exe")
        with contextlib.suppress(Exception):
            subprocess.run(
                [taskkill, "/T", "/F", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, timeout=10, check=False,
            )
        with contextlib.suppress(Exception):
            proc.kill()
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass  # the group is already gone
        except Exception:
            with contextlib.suppress(Exception):
                proc.kill()  # fall back to the child alone


def run_capped(argv, timeout, stdin_bytes: bytes | None = None,
               cap: int = OUTPUT_CAP, cwd=None) -> ProcResult:
    """Run ``argv`` with a scrubbed environment and bounded, spooled output.

    stdout and stderr are written to temporary files and read back up to ``cap``
    bytes each, decoded with ``console_codec()``, so a runaway command cannot
    exhaust memory. stdin is ``/dev/null`` unless ``stdin_bytes`` is given, in
    which case those exact bytes are written and the pipe is closed (used to
    feed PowerShell the policy evaluated command on stdin; the caller encodes
    them with ``console_codec()``). On POSIX the child gets its own session so
    a timeout kills the whole process group; on Windows the child is started in
    a new process group with no window and a timeout runs ``taskkill /T /F``.
    """
    env = scrubbed_env()
    codec = console_codec()
    start = time.monotonic()
    out_f = tempfile.TemporaryFile()
    err_f = tempfile.TemporaryFile()
    popen_kwargs: dict = {"stdout": out_f, "stderr": err_f, "env": env, "cwd": cwd}
    if stdin_bytes is None:
        popen_kwargs["stdin"] = subprocess.DEVNULL
    else:
        popen_kwargs["stdin"] = subprocess.PIPE
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
    else:
        popen_kwargs["start_new_session"] = True

    timed_out = False
    try:
        proc = subprocess.Popen(argv, **popen_kwargs)
    except Exception:
        out_f.close()
        err_f.close()
        raise
    try:
        proc.communicate(input=stdin_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)  # a stuck zombie is reported as timed out anyway
    finally:
        # Make sure the stdin pipe is closed even on an unusual error path.
        if proc.stdin is not None:
            with contextlib.suppress(Exception):
                proc.stdin.close()
    exit_code = proc.returncode
    stdout = _read_capped(out_f, cap, codec)
    stderr = _read_capped(err_f, cap, codec)
    out_f.close()
    err_f.close()
    duration_ms = int((time.monotonic() - start) * 1000)
    return ProcResult(
        exit_code=exit_code, stdout=stdout, stderr=stderr,
        timed_out=timed_out, duration_ms=duration_ms,
    )
