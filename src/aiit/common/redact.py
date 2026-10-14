"""Deterministic redaction of identifiers and secrets before anything reaches a model.

Identifiers (emails, phones, IPs, usernames, hostnames, serial numbers, SIDs,
and so on) are pseudonymized with HMAC-SHA256 keyed per case, so a repeated
value maps to the same ``<KIND_8hex>`` token and the token-to-value map can be
kept locally for the operator. Secrets (passwords, API keys, bearer tokens,
PEM blocks, URL userinfo) are replaced irreversibly with ``<SECRET_REDACTED>``
and never enter the map.

Processing order inside :meth:`Redactor.redact` is fixed and matters:

1. secrets (irreversible),
2. operator-supplied literals,
3. structured identifiers (reversible tokens).

This is a regex layer. It does not find free-text names or addresses; see
docs/compliance/hipaa.md section 4 and the Presidio roadmap item.
"""
from __future__ import annotations

import hmac
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field, fields
from typing import Any, Callable

__all__ = [
    "SECRET_TOKEN",
    "SECRET_PATTERNS",
    "RedactionConfig",
    "RedactionStats",
    "Redactor",
    "luhn_ok",
]

SECRET_TOKEN = "<SECRET_REDACTED>"

# ---------------------------------------------------------------------------
# Secret rules: the matched groups (or the whole match when ``groups`` is
# empty) are replaced with SECRET_TOKEN and counted under stats "SECRET".
# ---------------------------------------------------------------------------

# Words that mark a key or flag as holding a secret. ``auth`` must not match
# ``author``.
_SECRET_WORDS = (
    r"(?:passphrase|password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|subscription[_-]?key|account[_-]?key|shared[_-]?key|"
    r"signing[_-]?key|master[_-]?key|client[_-]?key|credential|auth(?!or))"
)
# A key is a short identifier that contains one of the words above. It must
# start at an identifier boundary and the prefix is bounded, so the scan stays
# linear on long base64 or underscore-joined runs.
_SECRET_KEY = r"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]{0,64}?" + _SECRET_WORDS + r"[A-Za-z0-9_.\-]*"
# A value is either quoted (anything up to the closing quote) or a bare run of
# at least four characters that does not look like the end of the statement.
_SECRET_VALUE = r"""(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s"',;<>]{4,}))"""

# Keys that match a secret word but are not secrets (shell working directory).
_KEY_EXCLUDE = {"pwd", "oldpwd"}
# Values that are placeholders, not secrets.
_VALUE_EXCLUDE = {"null", "true", "false", "none", "nil", "undefined", SECRET_TOKEN.lower()}


def _skip_kv(m: re.Match[str]) -> bool:
    """Skip key/value matches whose key or value is a known non-secret."""
    key = (m.group(1) or "").lower()
    if key in _KEY_EXCLUDE:
        return True
    value = next((g for g in m.groups()[1:] if g), "")
    return value.lower() in _VALUE_EXCLUDE


@dataclass(frozen=True)
class _SecretRule:
    name: str
    pattern: "re.Pattern[str]"
    groups: tuple = ()
    skip: Callable[["re.Match[str]"], bool] | None = None


SECRET_RULES: list[_SecretRule] = [
    _SecretRule("pem", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    # scheme://user:password@host  (must run before EMAIL so the userinfo never
    # becomes a reversible token)
    _SecretRule("url_userinfo", re.compile(
        r"(?i)\b[a-z][a-z0-9+.\-]{1,15}://([^\s/@:\"'<>]{1,64}:[^\s/@\"'<>]{1,256})@"), (1,)),
    _SecretRule("authorization", re.compile(
        r"(?i)\b(?:proxy-)?authorization\s*[:=]\s*[\"']?(?:(?:basic|bearer|digest|negotiate|ntlm|token|apikey|hmac)\s+)?"
        r"([A-Za-z0-9\-._~+/=]{6,})"), (1,)),
    _SecretRule("bearer", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{16,}=*)"), (1,)),
    _SecretRule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    # XML attribute pairs: key="ApiKey" value="..."  /  name="password" value="..."
    _SecretRule("xml_attr", re.compile(
        r"(?i)\b(?:key|name)\s*=\s*[\"'](" + _SECRET_KEY + r")[\"']\s+value\s*=\s*(?:\"([^\"]+)\"|'([^']+)')"),
        (2, 3), _skip_kv),
    # KEY=value, key: value, "key": "value", --key=value
    _SecretRule("kv", re.compile(
        r"(?i)[\"']?(" + _SECRET_KEY + r")[\"']?[ \t]*(?:[:=]|=>)[ \t]*" + _SECRET_VALUE),
        (2, 3, 4), _skip_kv),
    # command-line flags with a separate argument: -Password 'x', --token x, --api-key x
    _SecretRule("flag", re.compile(
        r"(?i)(?<![\w-])--?(?:[a-z]+[-_]?)?" + _SECRET_WORDS + r"\b[ \t]+(?!-)" + _SECRET_VALUE.replace("{4,}", "{1,}")),
        (1, 2, 3)),
    # mysql/mariadb style -pSECRET (no space) and the quoted -p'x' form anywhere
    _SecretRule("mysql_p", re.compile(
        r"(?i)\b(?:mysql\w*|mariadb\w*)\b[^\r\n]*?(?<=\s)-p(?!\s)[\"']?([^\s\"']+)[\"']?"), (1,)),
    _SecretRule("quoted_p", re.compile(r"(?<![\w-])-p(?:'([^'\r\n<>]+)'|\"([^\"\r\n<>]+)\")"), (1, 2)),
    # well-known token shapes
    _SecretRule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _SecretRule("aws_secret", re.compile(
        r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b[^A-Za-z0-9\r\n]{0,8}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), (1,)),
    _SecretRule("github", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    _SecretRule("gitlab", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    _SecretRule("openai_like", re.compile(r"\bsk-(?:ant|proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}\b")),
    _SecretRule("sk_generic", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    _SecretRule("slack", re.compile(r"\b(?:xox[abeoprs]-[A-Za-z0-9\-]{10,}|xapp-\d-[A-Za-z0-9\-]{10,})\b")),
    _SecretRule("google_api", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    _SecretRule("discord", re.compile(
        r"\b(?:[MN][A-Za-z0-9_\-]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}|mfa\.[A-Za-z0-9_\-]{84})\b")),
    _SecretRule("telegram", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    _SecretRule("azure_api_key", re.compile(
        r"(?i)\bapi[_-]?key\b[^A-Za-z0-9\r\n]{0,8}([0-9a-f]{32})\b"), (1,)),
    _SecretRule("conn_string", re.compile(
        r"(?i)\b(?:connection\s*string|conn_str)\s*[:=].*?(?:password|pwd)=([^;\s]+)"), (1,)),
]

# Compatibility: the bare patterns, in order.
SECRET_PATTERNS: list = [r.pattern for r in SECRET_RULES]

# ---------------------------------------------------------------------------
# Identifier patterns: replaced with reversible <KIND_8hex> tokens.
# ---------------------------------------------------------------------------
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PHONE = re.compile(r"(?<![\w.])(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?![\w.])")
CREDIT_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# Candidate runs of hex digits and colons (with an optional scope id); each
# candidate is validated with the ipaddress module before it is tokened.
IPV6 = re.compile(r"(?<![A-Za-z0-9:.])(?=[0-9A-Fa-f]{0,4}:)([0-9A-Fa-f:]{2,}(?:%[0-9A-Za-z]{1,16})?)(?![A-Za-z0-9:])")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
# C:\Users\name, C:\\Users\\name (JSON-escaped) and C:/Users/name
WIN_USER_PATH = re.compile(r"(?i)(?<![A-Za-z0-9])([A-Z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/))([^\\/\s\"'<>]+)")
# /home/name, /Users/name, and the same segments with one or two backslashes
# (UNC home shares such as \\\\server\\home\\name).
NIX_USER_PATH = re.compile(r"((?:/|\\{1,2})(?:home|Users)(?:/|\\{1,2}))([^\\/\s\"'<>]+)")
# scheme://user@host  (user only; user:password@ was already removed as a secret)
URL_USER = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{1,15}://([^\s/@:\"'<>]{1,64})@")
# DOMAIN\user and DOMAIN\\user. The label is a NetBIOS-style name (all upper or
# all lower case, so mixed-case path segments such as Windows\System32 do not
# qualify); the right side is a 2-20 character account name.
DOMAIN_USER = re.compile(
    r"(?<![A-Za-z0-9_.\-\\/:$])(NT AUTHORITY|NT SERVICE|BUILTIN|[A-Z0-9_-]{1,15}|[a-z0-9_-]{1,15})"
    r"(\\{1,2})((?:LOCAL|NETWORK) SERVICE|[A-Za-z0-9._$\-]{2,20})(?![A-Za-z0-9._$\-\\/])")
# Domain and Azure AD account SIDs. Well-known SIDs (S-1-5-18, S-1-5-32-544...)
# do not match these shapes and are kept.
SID = re.compile(r"\bS-1-(?:5-21-\d+-\d+-\d+(?:-\d+)?|12-1-\d+-\d+-\d+-\d+)\b")
# \\server\share and \\\\server\\share (JSON-escaped); the server name is tokened.
UNC = re.compile(r"(?<![A-Za-z0-9_:\\/>])\\\\(?:\\\\)?([A-Za-z0-9][A-Za-z0-9._\-]{1,253})(?![A-Za-z0-9._\-])")
MRN = re.compile(r"(?i)\b(?:MRN|medical record(?: number)?|patient id)\s*[:#]?\s*([A-Z0-9-]{4,})")
DOB = re.compile(r"(?i)\b(?:DOB|date of birth|birth ?date)\s*[:#]?\s*(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})")

# Labelled values: "<label>: <value>" in text, JSON, INI or ipconfig layouts.
# The label may carry a prefix (CsUserName, WindowsRegisteredOwner,
# IOPlatformSerialNumber), so a label may start at a word boundary or at a
# camelCase hump; the value is only tokened when it is labelled, so unlabelled
# GUIDs and serial-looking strings elsewhere are left alone. Anchoring on the
# label words keeps the scan linear on large prose.
_LABEL_START = r"(?:(?<![A-Za-z0-9])|(?-i:(?<=[a-z0-9])(?=[A-Z]))|(?-i:(?<=[A-Z])(?=[A-Z][a-z])))"
_LABEL_SEP = r"""[ \t.]*["']?[ \t.]*(?:[:=]|\bis\b)[ \t]*"""
_LABEL_VALUE = r"""(?:"(?P<q1>[^"\r\n]+)"|'(?P<q2>[^'\r\n]+)'|(?P<bare>[^\r\n"',;<>]+?)[ \t]*(?=[,;\r\n]|$))"""
_LABELS = {
    "serial": (r"ser(?:i)?al(?:[ _-]?(?:number|no|num))?(?:[ \t]*\([a-z ]+\))?|product[ _-]?id"),
    "uuid": (r"(?:hardware|platform|io[ _-]?platform|provisioning|provision|machine|system|smbios|host|instance)"
             r"[ _-]?(?:uuid|udid|guid)|(?<![A-Za-z0-9])udid|machine[ _-]?id"),
    "user": (r"user[ _-]?name|logged[ _-]?(?:in|on)[ _-]?users?|logon[ _-]?user|current[ _-]?user|login[ _-]?name"),
    "name": r"registered[ _-]?owner",
    "org": r"registered[ _-]?organi[sz]ation",
    "host": (r"host[ _-]?name|computer[ _-]?name|(?<![A-Za-z0-9])(?:cs|ds|dns|netbios)[ _-]?name|node[ _-]?name|fqdn"
             r"|(?:cs|logon|user|ad|dns)[ _-]?domain|(?<![A-Za-z0-9])domain(?:[ _-]?name)?"
             r"|dns[ _-]?suffix(?:[ _-]?search[ _-]?list)?"),
}
LABELLED = re.compile(
    _LABEL_START
    + "(?:" + "|".join(f"(?P<{k}>{v})" for k, v in _LABELS.items()) + ")"
    + _LABEL_SEP + _LABEL_VALUE,
    re.I | re.M,
)
_LABEL_KINDS = {"serial": "SERIAL", "uuid": "UUID", "user": "USER", "name": "NAME", "org": "ORG", "host": "HOST"}
_LABEL_VALUE_EXCLUDE = {
    "true", "false", "null", "none", "yes", "no", "n/a", "na", "unknown", "(none)", "not available", "-",
    "enabled", "disabled", "not set", "workgroup",
}
# "Jane Smith (jsmith)" -> display name plus short account name
_NAME_WITH_ACCOUNT = re.compile(r"^(.*?[^\s])\s*\(([A-Za-z0-9._\-]{2,32})\)$")

_BUILTIN_PROFILES = {"public", "default", "all users", "default user", "shared", ".localized", "*"}
_DOMAIN_LABEL_SKIP = {
    "nt authority", "nt service", "builtin", "windows", "programdata", "users", "system32", "temp", "tmp",
    "inetpub", "hklm", "hkcu", "hkcr", "hku", "hkcc", "hkey_local_machine", "hkey_current_user",
    "hkey_classes_root", "hkey_users",
}
_DOMAIN_USER_SKIP = {
    "system", "local service", "network service", "administrator", "administrators", "users", "guest",
    "everyone", "authenticated users",
}
_JSON_ESCAPES = set("ntrbfu")


def luhn_ok(digits: str) -> bool:
    """Return True when ``digits`` passes the Luhn checksum used by card numbers."""
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
    """Operator-tunable redaction policy for one case.

    ``redact_public_ips`` / ``redact_private_ips`` apply to IPv4 and IPv6
    alike; loopback and link-local addresses are never tokened.
    ``redact_hostnames`` are matched case-insensitively on word boundaries.
    ``extra_literals`` are replaced verbatim wherever they occur (for known
    patient or staff names the operator adds).
    """

    redact_public_ips: bool = True
    redact_private_ips: bool = False
    redact_mac: bool = True
    redact_hostnames: list[str] = field(default_factory=list)
    extra_literals: list[str] = field(default_factory=list)
    redact_ipv6: bool = True
    redact_domain_users: bool = True
    redact_sids: bool = True
    redact_unc: bool = True
    redact_serials: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable copy of the effective configuration."""
        out: dict[str, Any] = {}
        for f in fields(self):
            v = getattr(self, f.name)
            out[f.name] = list(v) if isinstance(v, list) else v
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "RedactionConfig":
        """Build a config from :meth:`to_dict` output; unknown keys are ignored."""
        known = {f.name: f for f in fields(cls)}
        kwargs: dict[str, Any] = {}
        for k, v in (data or {}).items():
            if k not in known:
                continue
            if k in ("redact_hostnames", "extra_literals"):
                if isinstance(v, str):
                    v = [v]
                kwargs[k] = [str(x) for x in (v or []) if x is not None and str(x) != ""]
            else:
                kwargs[k] = bool(v)
        return cls(**kwargs)


@dataclass
class RedactionStats:
    """Per-kind counts of replacements made by one :class:`Redactor`."""

    counts: dict[str, int] = field(default_factory=dict)

    def bump(self, kind: str) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + 1

    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    """Stateful redactor: ``map`` accumulates token -> original across calls."""

    def __init__(self, key: bytes, config: RedactionConfig | None = None):
        self.key = key
        self.config = config or RedactionConfig()
        self.map: dict[str, str] = {}  # token -> original
        self.stats = RedactionStats()

    # -- token generation
    def token(self, kind: str, value: str) -> str:
        """Return the deterministic ``<KIND_8hex>`` token for ``value`` and record it."""
        digest = hmac.new(self.key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        tok = f"<{kind}_{digest}>"
        self.map[tok] = value
        self.stats.bump(kind)
        return tok

    def _sub(self, pattern: "re.Pattern[str]", kind: str, text: str, group: int = 0,
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

    def _sub_literal(self, text: str, value: str, kind: str, ignore_case: bool = False) -> str:
        """Token every word-bounded occurrence of ``value``."""
        if len(value) < 3:
            return text
        pat = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(value) + r"(?![A-Za-z0-9_-])",
                         re.I if ignore_case else 0)
        canon = value.lower() if ignore_case else value
        return pat.sub(lambda m: self.token(kind, canon), text)

    def _ip_should_redact(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value.split("%", 1)[0])
        except ValueError:
            return False
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
        if ip.is_global:
            return self.config.redact_public_ips
        return self.config.redact_private_ips

    # -- secrets
    def _apply_secret(self, rule: _SecretRule, text: str) -> str:
        def repl(m: re.Match[str]) -> str:
            if rule.skip and rule.skip(m):
                return m.group(0)
            whole = m.group(0)
            if not rule.groups:
                self.stats.bump("SECRET")
                return SECRET_TOKEN
            base = m.start()
            spans = sorted((m.start(g) - base, m.end(g) - base) for g in rule.groups
                           if m.group(g) and m.group(g) != SECRET_TOKEN)
            if not spans:
                return whole
            out: list[str] = []
            pos = 0
            for a, b in spans:
                out.append(whole[pos:a])
                out.append(SECRET_TOKEN)
                self.stats.bump("SECRET")
                pos = b
            out.append(whole[pos:])
            return "".join(out)
        return rule.pattern.sub(repl, text)

    # -- identifiers
    def _domain_user(self, text: str) -> str:
        def repl(m: re.Match[str]) -> str:
            label, sep, user = m.group(1), m.group(2), m.group(3)
            if label.lower() in _DOMAIN_LABEL_SKIP or user.lower() in _DOMAIN_USER_SKIP:
                return m.group(0)
            if not re.search(r"[A-Za-z]", user):
                return m.group(0)
            # A single backslash followed by n, t, r, b, f or u inside a
            # lower/mixed-case string is most likely a JSON escape sequence.
            if len(sep) == 1 and user[0] in _JSON_ESCAPES and not label.isupper():
                return m.group(0)
            if len(sep) == 1 and user[0] == "u" and re.fullmatch(r"u[0-9A-Fa-f]{4}.*", user):
                return m.group(0)
            return f"{label}{sep}{self.token('USER', user)}"
        return DOMAIN_USER.sub(repl, text)

    def _unc_predicate(self, server: str) -> bool:
        if server.lower() in ("localhost",):
            return False
        try:
            ipaddress.ip_address(server)
            return False
        except ValueError:
            return True

    def _labelled(self, text: str) -> tuple[str, list[tuple[str, str, bool]]]:
        """Token labelled values; return the new text and the values found."""
        found: list[tuple[str, str, bool]] = []

        def repl(m: re.Match[str]) -> str:
            group = next((k for k in _LABELS if m.group(k) is not None), None)
            if group is None:
                return m.group(0)
            if group in ("serial", "uuid") and not self.config.redact_serials:
                return m.group(0)
            value = m.group("q1") or m.group("q2") or m.group("bare") or ""
            value = value.strip()
            if not value or "<" in value or value.lower() in _LABEL_VALUE_EXCLUDE:
                return m.group(0)
            if not re.search(r"[A-Za-z0-9]", value):
                return m.group(0)
            kind = _LABEL_KINDS[group]
            if kind == "USER":
                nm = _NAME_WITH_ACCOUNT.match(value)
                if nm:
                    name, account = nm.group(1), nm.group(2)
                    found.append(("NAME", name, False))
                    found.append(("USER", account, False))
                    replacement = f"{self.token('NAME', name)} ({self.token('USER', account)})"
                elif re.search(r"\s", value):
                    found.append(("NAME", value, False))
                    replacement = self.token("NAME", value)
                else:
                    found.append(("USER", value, False))
                    replacement = self.token("USER", value)
            elif kind == "HOST":
                canon = value.lower().rstrip(".")
                found.append(("HOST", canon, True))
                replacement = self.token("HOST", canon)
            else:
                found.append((kind, value, False))
                replacement = self.token(kind, value)
            whole = m.group(0)
            start = m.start("q1") if m.group("q1") else m.start("q2") if m.group("q2") else m.start("bare")
            end = m.end("q1") if m.group("q1") else m.end("q2") if m.group("q2") else m.end("bare")
            base = m.start()
            return whole[: start - base] + replacement + whole[end - base:]

        return LABELLED.sub(repl, text), found

    def redact(self, text: str) -> str:
        """Return ``text`` with secrets removed and identifiers tokened."""
        if not text:
            return text
        # 1. secrets first (irreversible)
        for rule in SECRET_RULES:
            text = self._apply_secret(rule, text)
        # 2. operator-supplied literals (names, etc.)
        for lit in self.config.extra_literals:
            if lit and lit in text:
                text = text.replace(lit, self.token("NAME", lit))
        # 3. structured identifiers
        text = self._sub(MRN, "MRN", text, group=1)
        text = self._sub(DOB, "DOB", text, group=1)
        text = self._sub(URL_USER, "USER", text, group=1)
        if self.config.redact_domain_users:
            text = self._domain_user(text)
        text = self._sub(WIN_USER_PATH, "USER", text, group=2, predicate=lambda v: v.lower() not in _BUILTIN_PROFILES)
        text = self._sub(NIX_USER_PATH, "USER", text, group=2, predicate=lambda v: v.lower() not in _BUILTIN_PROFILES)
        text, found = self._labelled(text)
        seen: set[tuple[str, str]] = set()
        for kind, value, ignore_case in found:
            if (kind, value) in seen:
                continue
            seen.add((kind, value))
            text = self._sub_literal(text, value, kind, ignore_case=ignore_case)
        if self.config.redact_sids:
            text = self._sub(SID, "SID", text)
        text = self._sub(EMAIL, "EMAIL", text)
        text = self._sub(SSN, "SSN", text)
        text = self._sub(CREDIT_CARD, "CARD", text, predicate=lambda v: luhn_ok(re.sub(r"\D", "", v)) and 13 <= len(re.sub(r"\D", "", v)) <= 19)
        text = self._sub(PHONE, "PHONE", text)
        text = self._sub(IPV4, "IP", text, predicate=self._ip_should_redact)
        if self.config.redact_ipv6:
            text = self._sub(IPV6, "IP", text, predicate=self._ip_should_redact)
        if self.config.redact_mac:
            text = self._sub(MAC, "MAC", text)
        if self.config.redact_unc:
            text = self._sub(UNC, "HOST", text, group=1, predicate=self._unc_predicate)
        for host in self.config.redact_hostnames:
            if host and len(host) >= 3:
                text = self._sub_literal(text, host, "HOST", ignore_case=True)
        return text
