"""Shared test helpers: puts src/ on the path and gives cross-platform shell snippets."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.pop("AIIT_KEY_PASSPHRASE", None)


def echo_cmd(text: str) -> str:
    return f"Write-Output '{text}'" if os.name == "nt" else f"echo {text}"


def fail_cmd(code: int = 3) -> str:
    return f"exit {code}"


def sleep_cmd(seconds: int) -> str:
    return f"Start-Sleep -Seconds {seconds}" if os.name == "nt" else f"sleep {seconds}"
