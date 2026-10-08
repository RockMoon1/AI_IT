"""Deterministic redaction of identifiers and secrets before anything reaches a model.

Identifiers (emails, phones, IPs, usernames, hostnames...) are pseudonymized
with HMAC-SHA256 keyed per case so repeated values map to the same token and
the mapping can be kept locally for the operator. Secrets are replaced
irreversibly.

This is a regex layer. It does not find free-text names or addresses; see
docs/compliance/hipaa.md section 4 and the Presidio roadmap item.
"""
from __future__ import annotations

import hmac
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable

# ---- secret patterns: replaced with <SECRET_REDACTED>, never mapped back
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\s*[:=]\s*[\"']?([^\s\"',;]{4,})"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{16,}=*"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"(?i)\b(?:connection\s*string|conn_str)\s*[:=].*?(?:password|pwd)=([^;\s]+)"),
]

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PHONE = re.compile(r"(?<![\w.])(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?![\w.])")
CREDIT_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
WIN_USER_PATH = re.compile(r"(?i)([A-Z]:\\Users\\)([^\\\s\"']+)")
NIX_USER_PATH = re.compile(r"(/(?:home|Users)/)([^/\s\"']+)")
MRN = re.compile(r"(?i)\b(?:MRN|medical record(?: number)?|patient id)\s*[:#]?\s*([A-Z0-9-]{4,})")
DOB = re.compile(r"(?i)\b(?:DOB|date of birth|birth ?date)\s*[:#]?\s*(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class RedactionConfig:
    redact_public_ips: bool = True
    redact_private_ips: bool = False
    redact_mac: bool = True
    redact_hostnames: list[str] = field(default_factory=list)
    extra_literals: list[str] = field(default_factory=list)  # e.g. known patient names the operator adds


@dataclass
class RedactionStats:
    counts: dict[str, int] = field(default_factory=dict)

    def bump(self, kind: str) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + 1

    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    def __init__(self, key: bytes, config: RedactionConfig | None = None):
        self.key = key
        self.config = config or RedactionConfig()
        self.map: dict[str, str] = {}  # token -> original
        self.stats = RedactionStats()

    # -- token generation
    def token(self, kind: str, value: str) -> str:
        digest = hmac.new(self.key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        tok = f"<{kind}_{digest}>"
        self.map[tok] = value
        self.stats.bump(kind)
        return tok

    def _sub(self, pattern: re.Pattern[str], kind: str, text: str, group: int = 0,
             predicate: Callable[[str], bool] | None = None) -> str:
        def repl(m: re.Match[str]) -> str:
            value = m.group(group)
            if predicate and not predicate(value):
                return m.group(0)
            tok = self.token(kind, value)
            if group == 0:
                return tok
            return m.group(0).replace(value, tok)
        return pattern.sub(repl, text)

    def _ip_should_redact(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
        if ip.is_global:
            return self.config.redact_public_ips
        return self.config.redact_private_ips

    def redact(self, text: str) -> str:
        # 1. secrets first (irreversible)
        for pat in SECRET_PATTERNS:
            if pat.search(text):
                text, n = pat.subn("<SECRET_REDACTED>", text)
                for _ in range(n):
                    self.stats.bump("SECRET")
        # 2. operator-supplied literals (names, etc.)
        for lit in self.config.extra_literals:
            if lit and lit in text:
                text = text.replace(lit, self.token("NAME", lit))
        # 3. structured identifiers
        text = self._sub(MRN, "MRN", text, group=1)
        text = self._sub(DOB, "DOB", text, group=1)
        text = self._sub(EMAIL, "EMAIL", text)
        text = self._sub(SSN, "SSN", text)
        text = self._sub(CREDIT_CARD, "CARD", text, predicate=lambda v: luhn_ok(re.sub(r"\D", "", v)) and 13 <= len(re.sub(r"\D", "", v)) <= 19)
        text = self._sub(PHONE, "PHONE", text)
        text = self._sub(IPV4, "IP", text, predicate=self._ip_should_redact)
        if self.config.redact_mac:
            text = self._sub(MAC, "MAC", text)
        text = self._sub(WIN_USER_PATH, "USER", text, group=2, predicate=lambda v: v.lower() not in {"public", "default", "all users", "default user"})
        text = self._sub(NIX_USER_PATH, "USER", text, group=2)
        for host in self.config.redact_hostnames:
            if host and len(host) >= 3:
                text = re.sub(re.escape(host), lambda m: self.token("HOST", m.group(0)), text, flags=re.I)
        return text
