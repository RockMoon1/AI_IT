"""Endpoint-side execution policy. Lives on the endpoint; the console cannot loosen it.

The policy is a layered gate run against every command step before execution:

1. OS targeting check.
2. Deny patterns (regexes) matched against both the raw command and an
   OS-aware normalised form, so alias and quoting tricks cannot slip past.
3. Structural denies: order independent checks for whole families of evasion
   (encoded commands, interpreter pipes, command substitution, nested shells,
   recursive deletes of system roots) that fragile anchored regexes miss.
4. Allow-list (when configured): a command must fully match one entry and may
   not smuggle shell control characters the entry does not itself contain.
5. Risk ceiling applied to the effective risk, where the effective risk is the
   larger of the model-declared risk and a locally computed floor, so a
   mislabelled step cannot run above the policy maximum.
6. Reboot gate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .schema import RISK_ORDER, PlanStep
from .util import canonical_json, read_json, sha256_hex, write_json

POLICY_VERSION = "2"


# ---------------------------------------------------------------------------
# Deny patterns. Matched (case-insensitively) against the raw command and the
# normalised command. Kept semantically a superset of the historical list.
# ---------------------------------------------------------------------------
DEFAULT_DENY: list[str] = [
    # --- Windows: disk / boot / partitions ---------------------------------
    r"\bformat(?:\.com)?\b\s+[a-z]:",
    r"\bdiskpart\b",
    r"\bbcdedit\b",
    r"\bformat-volume\b",
    r"\bclear-disk\b",
    r"\binitialize-disk\b",
    r"\bremove-partition\b",
    r"\brd\b\s+/s\s+/q\s+[a-z]:\\",
    r"\bdel\b\s+/[sq]\s+.*\*\.\*",
    # --- Windows: accounts / privilege -------------------------------------
    r"\bnet\s+user\b.*\s/add\b",
    r"\bnet\s+localgroup\s+administrators\b.*\s/add\b",
    r"\bnew-localuser\b",
    r"\badd-localgroupmember\b",
    r"\benable-psremoting\b",
    r"\bset-executionpolicy\b.*(?:unrestricted|bypass)\b",
    r"\bset-itemproperty\b.*\benablelua\b.*\b0\b",
    r"\breg(?:\.exe)?\s+add\b.*\benablelua\b.*\b0\b",
    # --- Windows: Defender / firewall / BitLocker / event logs -------------
    r"\bset-mppreference\b.*-disable",
    r"\badd-mppreference\b.*-exclusionpath\b",
    r"\bset-netfirewallprofile\b.*-enabled\s+false\b",
    r"\bnetsh\s+advfirewall\b.*\boff\b",
    r"\bdisable-bitlocker\b",
    r"\bmanage-bde\b.*(?:-off\b|-protectors\s+-disable\b)",
    r"\bclear-eventlog\b",
    r"\bwevtutil\s+(?:cl|clear-log)\b",
    r"(?:\bstop-service\b|\bsc(?:\.exe)?\s+stop\b|\bsc(?:\.exe)?\s+config\b)"
    r".*\b(?:windefend|msmpsvc|sense|wscsvc|eventlog|mpssvc)\b",
    # --- Windows: persistence / living off the land ------------------------
    r"(?:\breg(?:\.exe)?\s+add\b|\bnew-itemproperty\b|\bset-itemproperty\b)"
    r".*(?:\\run\b|\\runonce\b|\\winlogon\b|image file execution options)",
    r"\bschtasks\b.*\s/create\b",
    r"\bbitsadmin\b.*\s/transfer\b",
    r"\bcertutil\b.*(?:-urlcache\b|-decode\b)",
    r"\bmshta\b",
    r"\brundll32\b.*javascript",
    r"\bregsvr32\b.*\s/i:",
    r"\bwmic\b.*\bprocess\s+call\s+create\b",
    r"\breg\s+delete\s+hklm\b",
    r"\bremove-item\b.*\bhklm:",
    r"\bvssadmin\s+delete\s+shadows\b",
    r"\bwbadmin\s+delete\b",
    r"\bcipher\s+/w\b",
    r"\bstop-computer\b",
    # --- Linux: filesystem destruction -------------------------------------
    r"\bmkfs(?:\.\w+)?\b",
    r"\bdd\b.*\bof=/dev/(?:sd|nvme|mmcblk|vd|xvd|hd|disk)",
    r">\s*/dev/sd",
    r"\b(?:shred|wipefs)\b",
    r"\bfind\s+/\s+.*-delete\b",
    r"\bfind\s+/\s+.*-exec\s+rm\b",
    r"\brm\b.*\s/var/log/",
    r"\bchmod\s+-r\s+777\s+/",
    r"\bchown\s+-r\b.*\s/\s*$",
    r"\bchattr\s+-i\b.*(?:/etc|/usr|/bin|/sbin|/boot)",
    # --- Linux: accounts / privilege / auth --------------------------------
    r"\b(?:useradd|adduser)\b",
    r"\busermod\b.*-a?g\b.*\b(?:sudo|wheel)\b",
    r"\btee\s+-a\s+/etc/sudoers",
    r">>?\s*/etc/sudoers",
    r"\bvisudo\b",
    r"\bpasswd\s+-d\b",
    r"\bchpasswd\b",
    # --- Linux: firewall / security services / logging ---------------------
    r"\biptables\b.*(?:-f\b|--flush\b|-p\s+\w+\s+accept\b)",
    r"\bnft\s+flush\b",
    r"\bsystemctl\s+(?:stop|disable|mask)\b.*\b(?:sshd|firewalld|ufw|auditd|rsyslog|apparmor)\b",
    r"\bufw\s+disable\b",
    r"\bsetenforce\s+0\b",
    r"\bjournalctl\b.*--vacuum",
    r"\bhistory\s+-c\b",
    r"\bcrontab\s+-r\b",
    # --- Linux: boot / fstab / remount -------------------------------------
    r"\bmount\s+-o\s+remount,rw\s+/boot\b",
    r">>?\s*/etc/fstab",
    r">>?\s*/boot\b",
    r"\b(?:curl|wget)\b.*\s-o\b.*\s/(?:etc|usr)/",
    # --- macOS: disk / backups ---------------------------------------------
    r"\bdiskutil\s+(?:secureerase|partitiondisk|erasedisk|erasevolume|zerodisk)\b",
    r"\bdiskutil\s+apfs\s+(?:deletecontainer|deletevolume)\b",
    r"\btmutil\s+(?:delete|disable|disablelocal)\b",
    # --- macOS: accounts / directory services ------------------------------
    r"\bsysadminctl\b.*(?:-adduser|-deleteuser)\b",
    r"\bdscl\s+\.\s+-(?:create|delete|append)\b.*admin",
    r"\bdseditgroup\s+-o\s+edit\s+-a\b",
    # --- macOS: security subsystems ----------------------------------------
    r"\bsocketfilterfw\b.*--setglobalstate\s+off\b",
    r"\bspctl\b.*(?:--master-disable|--global-disable)\b",
    r"\bcsrutil\s+(?:disable|authenticated-root\s+disable)\b",
    r"\bnvram\s+boot-args\b",
    r"\blaunchctl\s+unload\b.*com\.apple\.(?:securityd|syspolicyd|auditd)\b",
    r"\blog\s+erase\b",
    r"\bfdesetup\s+disable\b",
    r"\bkextload\b",
    r"\bkmutil\s+load\b",
    r"\bprofiles\s+remove\s+-all\b",
    # --- Any OS: reverse shells / fork bomb --------------------------------
    r"\bnc\b.*\s-e\s",
    r":\(\)\s*\{\s*:\|:&\s*\};:",
]

# Commands that also need the --allow-reboot flag on apply.
REBOOT_PATTERNS: list[str] = [
    r"\bshutdown\b",
    r"\brestart-computer\b",
    r"\bstop-computer\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r"\bhalt\b",
    r"\bsystemctl\s+(?:poweroff|halt|reboot)\b",
    r"\binit\s+[06]\b",
    r"\bosascript\b.*\brestart\b",
]


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
_PS_ALIASES: dict[str, str] = {
    "ri": "remove-item", "rm": "remove-item", "del": "remove-item",
    "erase": "remove-item", "rd": "remove-item", "rmdir": "remove-item",
    "iex": "invoke-expression",
    "iwr": "invoke-webrequest", "irm": "invoke-webrequest",
    "curl": "invoke-webrequest", "wget": "invoke-webrequest",
    "sal": "set-alias",
    "saps": "start-process", "start": "start-process",
    "spsv": "stop-service",
    "gci": "get-childitem", "ls": "get-childitem", "dir": "get-childitem",
    "cat": "get-content", "gc": "get-content", "type": "get-content",
    "sc": "set-content",
    "cp": "copy-item", "copy": "copy-item",
    "mv": "move-item", "move": "move-item",
    "ni": "new-item",
    "sv": "set-variable",
}

_POSIX_PREFIXES = {
    "sudo", "doas", "env", "command", "exec", "nohup", "nice",
    "xargs", "busybox", "time",
}


def normalise(command: str, os_name: str) -> str:
    """Return an OS-aware normalised form of a command for matching.

    PowerShell (windows): drop backticks, lowercase, collapse whitespace and
    expand the common aliases to their full cmdlet names. POSIX
    (linux/macos/any): drop quotes and backslashes, collapse duplicate and
    "/./" path separators, strip wrapper prefixes (sudo, env, exec, ...)
    repeatedly, and lowercase on macos. The result is only ever used for
    matching, never executed.
    """
    if os_name == "windows":
        s = command.replace("`", "").lower()
        s = re.sub(r"\s+", " ", s).strip()
        toks = s.split(" ")
        toks = [_PS_ALIASES.get(t, t) for t in toks]
        return " ".join(toks)
    # POSIX family (linux, macos, any)
    s = command.replace('"', "").replace("'", "").replace("\\", "")
    s = re.sub(r"/{2,}", "/", s)
    s = re.sub(r"/\./", "/", s)
    if os_name == "macos":
        s = s.lower()
    s = s.strip()
    while True:
        m = re.match(r"^([A-Za-z0-9_]+)\b\s*", s)
        if m and m.group(1).lower() in _POSIX_PREFIXES:
            s = s[m.end():]
            continue
        break
    return re.sub(r"\s+", " ", s).strip()


# ---------------------------------------------------------------------------
# Structural denies (order independent, cross OS)
# ---------------------------------------------------------------------------
_SYS_ROOTS_POSIX = r"(?:/etc|/usr|/var|/home|/boot|/bin|/sbin|/lib|/sys|/opt|/root|/|~|\$home)"
_STRUCTURAL: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-(?:encodedcommand|enc|ec)\b\s+[A-Za-z0-9+/=]{3,}", re.I),
     "encoded PowerShell command"),
    (re.compile(r"(?:powershell|pwsh)\b[^|]*\s-e\b\s+[A-Za-z0-9+/=]{3,}", re.I),
     "encoded PowerShell command"),
    (re.compile(r"\binvoke-expression\b|\biex\b", re.I), "Invoke-Expression"),
    (re.compile(r"\[scriptblock\]::create", re.I), "scriptblock::Create"),
    (re.compile(r"\bfrombase64string\b", re.I), "FromBase64String decode"),
    (re.compile(r"\b(?:downloadstring|downloadfile)\b", re.I), "web download to memory"),
    (re.compile(r"\bbase64\b\s+--?(?:d|decode)\b.*\|", re.I), "base64 decode piped to a shell"),
    (re.compile(r"\|\s*(?:sudo\s+|doas\s+|env\s+)*"
                r"(?:sh|bash|zsh|dash|ksh|python3?|perl|ruby|node|pwsh|powershell|cmd)\b", re.I),
     "pipe into an interpreter"),
    (re.compile(r"\bcmd(?:\.exe)?\s*/[ck]\b", re.I), "nested cmd shell"),
    (re.compile(r"(?:powershell|pwsh)\b.*\b(?:powershell|pwsh)\b", re.I), "nested PowerShell"),
    (re.compile(r"\bosascript\b", re.I), "osascript"),
    (re.compile(r"\bpython3?\s+-c\b", re.I), "python -c inline code"),
    (re.compile(r"\bperl\s+-e\b", re.I), "perl -e inline code"),
    (re.compile(r"\bruby\s+-e\b", re.I), "ruby -e inline code"),
    (re.compile(r"\bnode\s+-e\b", re.I), "node -e inline code"),
    (re.compile(r"/dev/tcp/", re.I), "/dev/tcp redirection"),
    (re.compile(r"\bbash\s+-i\b", re.I), "interactive bash shell"),
    (re.compile(r"\beval\b", re.I), "eval"),
]

# Command substitution: only meaningful for POSIX shells.
_SUBST = re.compile(r"\$\(|`")

# Recursive removal of a system root, order independent.
_RM_POSIX = re.compile(r"\brm\b", re.I)
_RM_RECURSE = re.compile(r"(?:^|\s)-[a-z]*r[a-z]*\b|--recursive\b|\s-rf?\b|\s-fr\b", re.I)
_RM_POSIX_ROOT = re.compile(
    r"(?:\s|=)" + _SYS_ROOTS_POSIX + r"(?:/\S*)?(?:\s|;|&|\||$)", re.I)
_REMOVE_ITEM = re.compile(r"\bremove-item\b", re.I)
_REMOVE_ITEM_RECURSE = re.compile(r"-recurse\b|\s-r\b", re.I)
_WIN_ROOT = re.compile(r"[a-z]:\\(?:windows|users|program files)?(?:\s|$|\\)", re.I)


def _recursive_delete_reason(raw: str, norm: str) -> str:
    """Detect a recursive delete that targets a system root, on any OS."""
    for s in (raw, norm):
        if _RM_POSIX.search(s) and _RM_RECURSE.search(s) and _RM_POSIX_ROOT.search(s):
            return "recursive delete of a system path"
        if _REMOVE_ITEM.search(s) and _REMOVE_ITEM_RECURSE.search(s) and _WIN_ROOT.search(s):
            return "recursive delete of a system path"
    return ""


def _structural_reason(raw: str, norm: str, os_name: str) -> str:
    """Return a label for the first matching structural deny, else ''."""
    hit = _recursive_delete_reason(raw, norm)
    if hit:
        return hit
    for s in (raw, norm):
        for pat, label in _STRUCTURAL:
            if pat.search(s):
                return label
        if os_name != "windows" and _SUBST.search(s):
            return "shell command substitution"
    return ""


# ---------------------------------------------------------------------------
# Risk floor verb table
# ---------------------------------------------------------------------------
_READ_RE = re.compile(
    r"\b(?:get|test|select|measure|show|find|resolve)-\w+"
    r"|\b(?:cat|ls|dir|df|du|free|uptime|ip|ss|netstat|ipconfig|ping|nslookup|dig|scutil|sw_vers)\b"
    r"|\bjournalctl\b"
    r"|\bsystemctl\s+(?:status|is-active|list-\w+)\b"
    r"|\bsfc\s+/verifyonly\b"
    r"|\bchkdsk\b(?![^;&|]*\s/[fr]\b)"
    r"|\bdism\b[^;&|]*(?:/checkhealth|/scanhealth)\b"
    r"|\blaunchctl\s+list\b"
    r"|\bdiskutil\s+(?:list|info)\b"
    r"|\blog\s+show\b",
    re.I,
)
_LOW_RE = re.compile(
    r"\b(?:restart|start)-service\b"
    r"|\bsystemctl\s+(?:restart|start)\b"
    r"|\bipconfig\s+/flushdns\b"
    r"|\bdscacheutil\s+-flushcache\b"
    r"|\bkillall\s+-hup\s+mdnsresponder\b"
    r"|\bnet\s+(?:stop|start)\s+spooler\b"
    r"|\bgpupdate\b"
    r"|\bsfc\s+/scannow\b"
    r"|\bdism\b[^;&|]*/restorehealth\b"
    r"|\bchkdsk\b[^;&|]*/scan\b"
    r"|\blaunchctl\s+kickstart\b",
    re.I,
)
_MUT_RE = re.compile(
    r"\b(?:set|remove|stop|new|enable|disable|install|uninstall|rename|move|clear|reset|update|register|unregister)-\w+"
    r"|\b(?:rm|mv)\b"
    r"|\b(?:chmod|chown)\b"
    r"|\b(?:apt|apt-get|dnf|yum|zypper|pacman|brew)\b[^;&|]*\b(?:install|remove|purge|upgrade)\b"
    r"|\bpip3?\b[^;&|]*\binstall\b"
    r"|\bsystemctl\s+(?:enable|disable|stop|mask)\b"
    r"|\bdefaults\s+write\b"
    r"|\breg(?:\.exe)?\s+(?:add|delete)\b"
    r"|\bnetsh\b[^;&|]*\b(?:set|add|delete)\b"
    r"|\b(?:bcdedit|diskpart|mkfs|fdisk|parted|useradd|usermod)\b"
    r"|\bcp\b[^;&|]*\s/(?:etc|usr|bin|sbin|boot|lib)/",
    re.I,
)


def floor_risk(command: str, os_name: str) -> str:
    """Compute a local minimum risk for a command from a verb table.

    Read-only verbs (Get-*, cat, df, systemctl status, ...) impose no floor and
    return "read_only". Service restarts and cache clears floor to "low".
    Mutating verbs (Set-*, Remove-*, package installs, rm, chmod, ...) floor to
    "medium". Anything unrecognised floors to "low". The floor is independent of
    and never lowers the model-declared risk; see effective_risk.
    """
    if not command or not command.strip():
        return "read_only"
    norm = normalise(command, os_name)
    for s in (command, norm):
        if _LOW_RE.search(s):
            return "low"
    for s in (command, norm):
        if _READ_RE.search(s):
            return "read_only"
    for s in (command, norm):
        if _MUT_RE.search(s):
            return "medium"
    return "low"


def _max_risk(a: str, b: str) -> str:
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


# Shell control characters refused in allow-list mode unless the matching allow
# entry itself contains the character. Multi-character operators are checked
# before single-character ones so the message names the real operator.
_CONTROL_CHARS = [";", "&&", "||", "|", "\n", "`", "$(", ">", "<"]


@dataclass
class Policy:
    mode: str = "dry_run"           # dry_run | enforce
    max_risk: str = "low"           # read_only | low | medium | high
    deny_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_DENY))
    allow_patterns: list[str] = field(default_factory=list)
    reboot_patterns: list[str] = field(default_factory=lambda: list(REBOOT_PATTERNS))
    max_plan_hours: int = 72
    risk_floor_overrides: dict[str, str] = field(default_factory=dict)
    version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        self._snapshot: Any = None
        self._deny: list[re.Pattern[str]] = []
        self._allow: list[tuple[str, re.Pattern[str]]] = []
        self._reboot: list[re.Pattern[str]] = []
        self._overrides: list[tuple[re.Pattern[str], str]] = []
        self._ensure_compiled()

    # -- compilation --------------------------------------------------------
    @staticmethod
    def _compile(pattern: str) -> re.Pattern[str]:
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"invalid regex pattern {pattern!r}: {e}") from e

    def _ensure_compiled(self) -> None:
        """Compile and cache every pattern; recompile only when a list changed."""
        snap = (
            tuple(self.deny_patterns),
            tuple(self.allow_patterns),
            tuple(self.reboot_patterns),
            tuple(sorted(self.risk_floor_overrides.items())),
        )
        if snap == self._snapshot:
            return
        self._deny = [self._compile(p) for p in self.deny_patterns]
        self._allow = [(p, self._compile(p)) for p in self.allow_patterns]
        self._reboot = [self._compile(p) for p in self.reboot_patterns]
        overrides: list[tuple[re.Pattern[str], str]] = []
        for pat, risk in self.risk_floor_overrides.items():
            if risk not in RISK_ORDER:
                raise ValueError(f"invalid override risk {risk!r} for pattern {pat!r}")
            overrides.append((self._compile(pat), risk))
        self._overrides = overrides
        self._snapshot = snap

    # -- serialisation ------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "mode": self.mode,
            "max_risk": self.max_risk,
            "deny_patterns": self.deny_patterns,
            "allow_patterns": self.allow_patterns,
            "reboot_patterns": self.reboot_patterns,
            "max_plan_hours": self.max_plan_hours,
            "risk_floor_overrides": self.risk_floor_overrides,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        """Load a policy, applying defaults for keys absent from old files.

        Every pattern is compiled; a bad regex raises ValueError naming the
        offending pattern. Mode and max_risk are validated.
        """
        p = cls.__new__(cls)  # avoid double compile from __post_init__
        p.version = str(d.get("version", POLICY_VERSION))
        p.mode = d.get("mode", "dry_run")
        p.max_risk = d.get("max_risk", "low")
        p.deny_patterns = list(d.get("deny_patterns", list(DEFAULT_DENY)))
        p.allow_patterns = list(d.get("allow_patterns", []))
        p.reboot_patterns = list(d.get("reboot_patterns", list(REBOOT_PATTERNS)))
        p.max_plan_hours = int(d.get("max_plan_hours", 72))
        p.risk_floor_overrides = dict(d.get("risk_floor_overrides", {}))
        if p.mode not in ("dry_run", "enforce"):
            raise ValueError(f"invalid policy mode {p.mode!r}")
        if p.max_risk not in RISK_ORDER:
            raise ValueError(f"invalid max_risk {p.max_risk!r}")
        p._snapshot = None
        p._deny = []
        p._allow = []
        p._reboot = []
        p._overrides = []
        p._ensure_compiled()
        return p

    def save(self, path) -> None:
        write_json(path, self.to_dict(), private=True)

    @classmethod
    def load(cls, path) -> "Policy":
        return cls.from_dict(read_json(path))

    def digest(self) -> str:
        """SHA-256 hex of the canonical JSON of to_dict(), for policy pinning."""
        return sha256_hex(canonical_json(self.to_dict()))

    # -- risk ---------------------------------------------------------------
    def effective_risk(self, step: PlanStep, os_name: str) -> str:
        """max(declared risk, computed floor), honouring risk_floor_overrides.

        risk_floor_overrides is a mapping of regex to risk that a site can use
        to tighten (raise) the floor for commands it considers more dangerous
        than the built-in table does. Overrides can only raise the effective
        risk, never lower it.
        """
        self._ensure_compiled()
        cmd = step.command or ""
        risk = _max_risk(step.risk, floor_risk(cmd, os_name))
        if cmd:
            norm = normalise(cmd, os_name)
            for pat, override in self._overrides:
                if pat.search(cmd) or pat.search(norm):
                    risk = _max_risk(risk, override)
        return risk

    # -- evaluation ---------------------------------------------------------
    def evaluate(self, step: PlanStep, current_os: str, allow_reboot: bool = False) -> tuple[bool, str]:
        """Return (allowed, reason). Reason is non-empty when blocked."""
        if step.action != "command":
            return True, ""
        self._ensure_compiled()
        cmd = step.command or ""
        if step.os not in ("any", current_os):
            return False, f"step targets {step.os}, this endpoint is {current_os}"

        norm = normalise(cmd, current_os)

        for pat in self._deny:
            if pat.search(cmd) or pat.search(norm):
                return False, f"matches deny pattern: {pat.pattern}"

        structural = _structural_reason(cmd, norm, current_os)
        if structural:
            return False, f"structural deny: {structural}"

        if self._allow:
            matched: str | None = None
            for src, pat in self._allow:
                if pat.fullmatch(cmd):
                    matched = src
                    break
            if matched is None:
                return False, "does not match any allow pattern"
            for ch in _CONTROL_CHARS:
                if ch in cmd and ch not in matched:
                    return False, f"command contains {ch!r} which its allow pattern does not permit"

        eff = self.effective_risk(step, current_os)
        if RISK_ORDER[eff] > RISK_ORDER[self.max_risk]:
            return False, (
                f"effective risk {eff} (declared {step.risk}) "
                f"exceeds policy max_risk {self.max_risk}"
            )

        if (step.requires_reboot or any(p.search(cmd) or p.search(norm) for p in self._reboot)) and not allow_reboot:
            return False, "step reboots the machine; re-run apply with --allow-reboot"
        return True, ""
