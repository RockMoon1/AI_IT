"""Terminal presentation: colour detection, risk and status labels, progress lines and a spinner.

Colour is opt-out and opt-in aware: ``NO_COLOR`` (any value) disables it,
``FORCE_COLOR`` enables it, otherwise it is used only when the stream is a
terminal. On Windows the console is switched to virtual-terminal mode once;
if that fails colour stays off. Everything here degrades to plain text, so
output piped into a file or a ticket never carries escape sequences.
"""
from __future__ import annotations

import itertools
import os
import sys
import threading
import time
from typing import IO, Any

__all__ = [
    "RISK_STYLES", "STATUS_STYLES", "Progress", "Spinner", "paint", "report_error",
    "risk_label", "set_color", "status_label", "supports_color", "use_color",
]

_CODES = {
    "reset": "0", "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
}
_override: bool | None = None
_vt_enabled: bool | None = None


def set_color(enabled: bool | None) -> None:
    """Force colour on or off for the process (None restores auto-detection)."""
    global _override
    _override = enabled


def _enable_windows_vt() -> bool:
    """Turn on ANSI processing for the Windows console; True when escapes will render."""
    global _vt_enabled
    if _vt_enabled is not None:
        return _vt_enabled
    if os.name != "nt":
        _vt_enabled = True
        return True
    try:
        import ctypes  # pragma: no cover - Windows only
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            _vt_enabled = False
            return False
        if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            _vt_enabled = False
            return False
        _vt_enabled = True
    except Exception:  # pragma: no cover - any ctypes failure means no colour
        _vt_enabled = False
    return _vt_enabled


def supports_color(stream: IO[Any] | None = None) -> bool:
    """Auto-detection only (ignores set_color): NO_COLOR, FORCE_COLOR, TERM=dumb, isatty, Windows VT."""
    if os.environ.get("NO_COLOR") not in (None, ""):
        return False
    if os.environ.get("FORCE_COLOR") not in (None, ""):
        return True
    if os.environ.get("TERM", "") == "dumb":
        return False
    stream = stream if stream is not None else sys.stdout
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    return _enable_windows_vt()


def use_color(stream: IO[Any] | None = None) -> bool:
    """Effective answer: an explicit set_color() wins, otherwise supports_color()."""
    if _override is not None:
        return _override
    return supports_color(stream)


def paint(text: str, *styles: str, stream: IO[Any] | None = None) -> str:
    """Wrap text in ANSI styles when colour is in use, else return it unchanged."""
    if not styles or not use_color(stream):
        return text
    codes = ";".join(_CODES[s] for s in styles if s in _CODES)
    return f"\x1b[{codes}m{text}\x1b[0m" if codes else text


RISK_STYLES = {"read_only": ("green",), "low": ("cyan",), "medium": ("yellow", "bold"), "high": ("red", "bold")}
STATUS_STYLES = {
    "success": ("green",), "ok": ("green",), "dry_run": ("cyan",), "manual": ("blue",), "skipped": ("dim",),
    "blocked": ("yellow", "bold"), "failed": ("red", "bold"), "timeout": ("red", "bold"), "error": ("red", "bold"),
    "nonzero": ("yellow",), "missing": ("yellow",), "denied": ("yellow",), "empty": ("dim",), "invalid_json": ("yellow",),
}


def risk_label(risk: str, width: int = 9, stream: IO[Any] | None = None) -> str:
    """A fixed-width, coloured risk word (read_only/low/medium/high)."""
    return paint(f"{risk:<{width}}", *RISK_STYLES.get(risk, ()), stream=stream)


def status_label(status: str, width: int = 12, stream: IO[Any] | None = None) -> str:
    """A fixed-width, coloured step or collector status."""
    return paint(f"{status:<{width}}", *STATUS_STYLES.get(status, ()), stream=stream)


def report_error(message: str, hint: str | None = None, *, stream: IO[Any] | None = None, label: str = "error") -> None:
    """One coloured line for the operator plus an optional hint line; never a traceback."""
    out = stream if stream is not None else sys.stderr
    first = str(message).splitlines()[0][:300] if str(message).strip() else label
    print(f"{paint(label + ':', 'red', 'bold', stream=out)} {first}", file=out)
    if hint:
        print(f"  {paint('hint:', 'dim', stream=out)} {hint}", file=out)


class Progress:
    """Per-item progress lines: ``  - name ... ok (123 ms)`` or ``FAIL: reason``.

    On a terminal the trailing status is written on the same line; elsewhere
    each item is one plain line, so logs stay readable.
    """

    def __init__(self, stream: IO[Any] | None = None, prefix: str = "  - "):
        self.stream = stream if stream is not None else sys.stdout
        self.prefix = prefix
        self._live = use_color(self.stream) and bool(getattr(self.stream, "isatty", lambda: False)())
        self._started: dict[str, float] = {}

    def start(self, name: str) -> None:
        self._started[name] = time.monotonic()
        if self._live:
            self.stream.write(f"{self.prefix}{name} ... ")
            self.stream.flush()

    def done(self, name: str, ok: bool = True, note: str = "", duration_ms: int | None = None) -> None:
        if duration_ms is None:
            t0 = self._started.pop(name, None)
            duration_ms = int((time.monotonic() - t0) * 1000) if t0 is not None else 0
        verdict = paint("ok", "green", stream=self.stream) if ok else paint("FAIL", "red", "bold", stream=self.stream)
        tail = f"{verdict} ({duration_ms} ms)" + (f"  {note}" if note else "")
        if self._live:
            self.stream.write(tail + "\n")
        else:
            self.stream.write(f"{self.prefix}{name} ... {tail}\n")
        self.stream.flush()


class Spinner:
    """``with Spinner("Waiting for the model"):`` animates on a terminal, prints one line elsewhere."""

    _frames = "|/-\\"

    def __init__(self, message: str, stream: IO[Any] | None = None, interval: float = 0.1):
        self.message = message
        self.stream = stream if stream is not None else sys.stderr
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._live = use_color(self.stream) and bool(getattr(self.stream, "isatty", lambda: False)())

    def _spin(self) -> None:
        for frame in itertools.cycle(self._frames):
            if self._stop.is_set():
                break
            self.stream.write(f"\r{self.message} {frame}")
            self.stream.flush()
            self._stop.wait(self.interval)

    def __enter__(self) -> "Spinner":
        if self._live:
            self._thread = threading.Thread(target=self._spin, name="aiit-spinner", daemon=True)
            self._thread.start()
        else:
            self.stream.write(f"{self.message} ...\n")
            self.stream.flush()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=2.0)
            self.stream.write("\r" + " " * (len(self.message) + 2) + "\r")
            self.stream.flush()
