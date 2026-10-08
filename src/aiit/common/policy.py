"""Endpoint-side execution policy. Lives on the endpoint; the console cannot loosen it."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schema import RISK_ORDER, PlanStep
from .util import read_json, write_json

POLICY_VERSION = "1"

# Commands that are never run, whatever the plan says.
DEFAULT_DENY: list[str] = [
    r"(?i)\bformat(\.com)?\b\s+[a-z]:",            # format C:
    r"(?i)\bdiskpart\b",
    r"(?i)\bbcdedit\b",
    r"(?i)\bRemove-Item\b.*-Recurse.*[A-Z]:\\(?:Windows|Users|Program Files)?\s*$",
    r"(?i)\brd\b\s+/s\s+/q\s+[a-z]:\\\s*$",
    r"(?i)\bdel\b\s+/[sq]\s+.*\*\.\*",
    r"(?i)\bnet\s+user\b.*\s/add\b",
    r"(?i)\bnet\s+localgroup\s+administrators\b.*\s/add\b",
    r"(?i)\bNew-LocalUser\b",
    r"(?i)\bAdd-LocalGroupMember\b",
    r"(?i)\bSet-MpPreference\b.*-Disable",
    r"(?i)\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off\b",
    r"(?i)\bSet-NetFirewallProfile\b.*-Enabled\s+False",
    r"(?i)\breg\s+delete\s+HKLM\b",
    r"(?i)\bRemove-Item\b.*HKLM:",
    r"(?i)\bvssadmin\s+delete\s+shadows\b",
    r"(?i)\bwbadmin\s+delete\b",
    r"(?i)\bcipher\s+/w\b",
    r"(?i)\bInvoke-(?:WebRequest|RestMethod)\b.*\|\s*(?:iex|Invoke-Expression)",
    r"(?i)\bcurl\b.*\|\s*(?:sh|bash)\b",
    r"(?i)\bwget\b.*\|\s*(?:sh|bash)\b",
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/(?:\s|$|\*)",     # rm -rf /
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+/(?:etc|usr|var|home|boot|bin|lib)\b",
    r"\bmkfs(\.\w+)?\b",
    r"\bdd\s+.*of=/dev/(?:sd|nvme|disk|hd)",
    r"\b(?:shred|wipefs)\b",
    r":\(\)\s*\{\s*:\|:&\s*\};:",                     # fork bomb
    r"\buseradd\b|\badduser\b",
    r"\bchmod\s+-R\s+777\s+/",
    r"\bchown\s+-R\b.*\s/\s*$",
    r"(?i)\bsystemctl\s+(?:disable|mask)\s+(?:sshd|firewalld|ufw|apparmor)\b",
    r"\bufw\s+disable\b",
    r"\bsetenforce\s+0\b",
    r"\biptables\s+-F\b",
    r"\bnc\b.*\s-e\s",                                  # reverse shell
    r"/dev/tcp/",
    r"\bcsrutil\s+disable\b",
    r"\bspctl\s+--master-disable\b",
    r"\bfdesetup\s+disable\b",
    r"\bdiskutil\s+(?:eraseDisk|eraseVolume|zeroDisk)\b",
]

# Commands that also need the --allow-reboot flag on apply.
REBOOT_PATTERNS: list[str] = [
    r"(?i)\bshutdown\b",
    r"(?i)\bRestart-Computer\b",
    r"\breboot\b",
    r"\binit\s+[06]\b",
]


@dataclass
class Policy:
    mode: str = "dry_run"           # dry_run | enforce
    max_risk: str = "low"           # read_only | low | medium | high
    deny_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_DENY))
    allow_patterns: list[str] = field(default_factory=list)
    reboot_patterns: list[str] = field(default_factory=lambda: list(REBOOT_PATTERNS))
    version: str = POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "mode": self.mode,
            "max_risk": self.max_risk,
            "deny_patterns": self.deny_patterns,
            "allow_patterns": self.allow_patterns,
            "reboot_patterns": self.reboot_patterns,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        p = cls()
        p.version = str(d.get("version", POLICY_VERSION))
        p.mode = d.get("mode", p.mode)
        p.max_risk = d.get("max_risk", p.max_risk)
        p.deny_patterns = list(d.get("deny_patterns", p.deny_patterns))
        p.allow_patterns = list(d.get("allow_patterns", p.allow_patterns))
        p.reboot_patterns = list(d.get("reboot_patterns", p.reboot_patterns))
        if p.mode not in ("dry_run", "enforce"):
            raise ValueError(f"invalid policy mode {p.mode!r}")
        if p.max_risk not in RISK_ORDER:
            raise ValueError(f"invalid max_risk {p.max_risk!r}")
        return p

    def save(self, path: Path) -> None:
        write_json(path, self.to_dict(), private=True)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        return cls.from_dict(read_json(path))

    # -- evaluation
    def evaluate(self, step: PlanStep, current_os: str, allow_reboot: bool = False) -> tuple[bool, str]:
        """Return (allowed, reason). Reason is non-empty when blocked."""
        if step.action != "command":
            return True, ""
        cmd = step.command or ""
        if step.os not in ("any", current_os):
            return False, f"step targets {step.os}, this endpoint is {current_os}"
        for pat in self.deny_patterns:
            if re.search(pat, cmd):
                return False, f"matches deny pattern: {pat}"
        if self.allow_patterns and not any(re.search(p, cmd) for p in self.allow_patterns):
            return False, "does not match any allow pattern"
        if RISK_ORDER[step.risk] > RISK_ORDER[self.max_risk]:
            return False, f"risk {step.risk} exceeds policy max_risk {self.max_risk}"
        if (step.requires_reboot or any(re.search(p, cmd) for p in self.reboot_patterns)) and not allow_reboot:
            return False, "step reboots the machine; re-run apply with --allow-reboot"
        return True, ""
