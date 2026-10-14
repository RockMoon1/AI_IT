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
    + r".*\b(?:windefend|msmpsvc|sense|wscsvc|eventlog|mpssvc)\b",
    # --- Windows: persistence / living off the land ------------------------
    r"(?:\breg(?:\.exe)?\s+add\b|\bnew-itemproperty\b|\bset-itemproperty\b)"
    + r".*(?:\\run\b|\\runonce\b|\\winlogon\b|image file execution options)",
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

_SC_EXE_VERBS = {
    "query", "qc", "queryex", "enumdepend", "config", "create", "delete", "start", "stop", "pause",
    "continue", "failure", "sdshow", "sdset", "description", "interrogate", "control", "qdescription",
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
        s = re.sub(r"\$\{([\w:]+)\}", r"$\1", s)
        s = re.sub(r"\s+", " ", s).strip()
        toks = s.split(" ")
        out = []
        for i, t in enumerate(toks):
            # sc.exe (service control) is not the Set-Content alias when a
            # service verb follows it.
            if t == "sc" and i + 1 < len(toks) and toks[i + 1] in _SC_EXE_VERBS:
                out.append(t)
            else:
                out.append(_PS_ALIASES.get(t, t))
        return " ".join(out)
    # POSIX family (linux, macos, any)
    s = command.replace('"', "").replace("'", "").replace("\\", "")
    s = re.sub(r"\$\{(\w+)\}", r"$\1", s)
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
    (re.compile(r"\bchmod\b[^;&|]*\s(?:[0-7]*[4-7][0-7]{3}\b|[ugoa]*[+=][rwxXt]*s)", re.I), "setuid/setgid bit"),
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
_WIN_ROOT = re.compile(
    r"[a-z]:\\(?:windows|users|program files)?(?:\s|$|\\)"
    r"|\$(?:home|env:userprofile|env:systemroot|env:windir|env:programfiles|env:systemdrive)\b"
    r"|%(?:userprofile|systemroot|windir|programfiles|systemdrive)%",
    re.I)


def _recursive_delete_reason(raw: str, norm: str) -> str:
    """Detect a recursive delete that targets a system root, on any OS."""
    for s in (raw, norm):
        if _RM_POSIX.search(s) and _RM_RECURSE.search(s) and _RM_POSIX_ROOT.search(s):
            return "recursive delete of a system path"
        if _REMOVE_ITEM.search(s) and _REMOVE_ITEM_RECURSE.search(s) and _WIN_ROOT.search(s):
            return "recursive delete of a system path"
    return ""


# ---------------------------------------------------------------------------
# Command segments and output redirection
# ---------------------------------------------------------------------------
_SEG_SPLIT_RE = re.compile(r"\s*(?:\|\|?|&&?|;|\r?\n)\s*")
# An output redirection and its target. The leading class keeps ``->``, ``=>``
# and ``<>`` out; descriptor duplication (``2>&1``) is folded away before use.
_REDIR_RE = re.compile(r"(?:^|[^<>=\-])\d*>>?\s*([^\s;&|<>]+)?")
_NULL_TARGET_RE = re.compile(r"^(?:/dev/null|\$null|nul)$", re.I)
_TEMP_TARGET_RE = re.compile(
    r"/tmp/|/var/tmp/|/private/tmp/|/var/folders/|/private/var/folders/|\$tmpdir\b|\$env:te?mp\b|%te?mp%"
    r"|[a-z]:[\\/](?:temp|tmp)[\\/]|[a-z]:[\\/]windows[\\/]temp[\\/]|[\\/]appdata[\\/]local[\\/]temp[\\/]"
    r"|^~/|^\$home/|^\$env:userprofile[\\/]|^%userprofile%[\\/]",
    re.I)
# Verbs whose first path argument is a file they write to.
_WRITER_VERB_RE = re.compile(
    r"^\s*(?:tee|tee-object|out-file|set-content|add-content|export-csv|export-clixml)\b", re.I)
_PATHISH_RE = re.compile(r"[\\/.:~$%]")


def _strip_quote_chars(s: str) -> str:
    return s.replace('"', "").replace("'", "")


def _segments(s: str) -> list[str]:
    """Split a command on shell separators (; && || | &) after folding fd redirections.

    ``&>file`` becomes ``>file`` (it writes a file); ``2>&1``-style descriptor
    duplication is dropped so its ``&`` does not split the segment.
    """
    s = re.sub(r"&>>?", ">", s)
    s = re.sub(r"\d*>&\s*\d+", " ", s)
    return [seg for seg in _SEG_SPLIT_RE.split(s) if seg.strip()] or [s]


_WRAPPERS = _POSIX_PREFIXES | {
    "timeout", "ionice", "setsid", "stdbuf", "unbuffer", "chroot", "watch", "strace", "ltrace",
    "sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "powershell.exe", "pwsh.exe",
}
# Wrapper flags that take an argument (sudo -u user, env -C dir, timeout -s SIG, ...).
_WRAPPER_ARG_FLAGS = {"-u", "-g", "-d", "-h", "-p", "-r", "-t", "-T", "-U", "-s", "-k", "-n",
                      "--user", "--group", "--chdir", "--host", "--prompt", "--signal", "--kill-after",
                      "-executionpolicy", "-ep", "-version", "-v", "-workingdirectory", "-wd"}
# Wrapper flags after which the wrapped command itself follows (sh -c, pwsh -Command).
_WRAPPER_CMD_FLAGS = {"-c", "-lc", "-ec", "-command", "-noprofile", "-noninteractive", "-nologo", "-noexit",
                      "-sta", "-mta", "-file", "-f"}


def _lead_verb(seg: str) -> tuple[str, int]:
    """Return (verb, index) of the first token that is not a wrapper, its flag or VAR=value.

    ``sudo -u root cp a b`` -> ("cp", 3); ``sh -c cp a b`` -> ("cp", 2);
    ``timeout 5 rm x`` -> ("rm", 2). Quoted strings were stripped by the caller.
    """
    toks = seg.split()
    skip_next = False
    for i, t in enumerate(toks):
        if skip_next:
            skip_next = False
            continue
        low = t.lower()
        base = low.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if base in _WRAPPERS or ("=" in t and not t.startswith("-")) or re.fullmatch(r"\d+[smhd]?", low):
            continue
        if t.startswith("-"):
            skip_next = low in _WRAPPER_ARG_FLAGS and low not in _WRAPPER_CMD_FLAGS
            continue
        return base, i
    return "", len(toks)


def _write_targets(seg: str) -> list[str]:
    """Targets of output redirections and writer verbs in one segment ('' = unknown)."""
    out = [m.group(1) or "" for m in _REDIR_RE.finditer(seg)]
    if _WRITER_VERB_RE.match(seg):
        toks = [t for t in seg.split()[1:] if not t.startswith("-") and _PATHISH_RE.search(t)]
        out.extend(toks or [""])
    return out


def _write_floor(seg: str) -> str | None:
    """Floor implied by file writes: medium, low for temp or home targets, None without writes."""
    floor: str | None = None
    for t in _write_targets(seg):
        if t and _NULL_TARGET_RE.match(t):
            continue
        if t and _TEMP_TARGET_RE.search(t):
            floor = floor or "low"
        else:
            return "medium"
    return floor


# ---------------------------------------------------------------------------
# Protected files and keys: never written by a plan, whatever max_risk says
# (authentication, persistence, boot, kernel, security software, CA stores).
# Reads stay allowed except for credential stores, which are never touched.
# ---------------------------------------------------------------------------
_SENSITIVE_POSIX_RE = re.compile(
    r"(?:^|[\s=:,(])(?:/private)?(?:"
    r"/etc/(?:passwd|shadow|group|gshadow|sudoers|sudoers\.d|ssh|pam\.d|pam\.conf|security|login\.defs|securetty"
    r"|ld\.so\.preload|ld\.so\.conf|ld\.so\.conf\.d|profile|profile\.d|bash\.bashrc|bashrc|zshrc|zprofile|zshenv|environment"
    r"|cron\S*|crontab|anacrontab|systemd|init\.d|rc\.local|rc\d?\.d|xdg/autostart|polkit-1|modprobe\.d|modules-load\.d|modules"
    r"|ssl|pki|ca-certificates\S*|apparmor\S*|selinux|audit\S*|default/grub|grub\S*|authorization|sudo\.conf)"
    r"|/var/spool/cron|/var/db/sudo|/var/db/dslocal|/var/root|/boot|/efi|/lib/systemd|/usr/lib/systemd|/lib/modules|/usr/lib/modules"
    r"|/usr/local/share/ca-certificates"
    r"|/library/(?:launchdaemons|launchagents|startupitems|privilegedhelpertools|security|keychains|extensions|systemextensions"
    r"|managed preferences|preferences/com\.apple\.loginwindow\S*|preferences/systemconfiguration/com\.apple\.boot\S*)"
    r"|/system/library|/private/var/db/(?:sudo|dslocal|configurationprofiles)"
    r"|(?:~|\$home|/home/[^/\s]+|/users/[^/\s]+|/root|/var/root)/(?:\.ssh|\.bashrc|\.bash_profile|\.bash_login|\.bash_logout|\.profile"
    r"|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.config/autostart|\.config/systemd|\.gnupg|\.aws|\.kube|\.docker|\.npmrc|\.pypirc|\.netrc"
    r"|\.gitconfig|library/launchagents|\.local/share/systemd)"
    r")(?=[/\s;&|)*]|$)"
    r"|(?<![\w-])\.ssh/",
    re.I)
# System directory writes are protected except the usual cleanup targets.
_WIN_SYSDIR_EXEMPT = (
    r"(?!(?:temp|logs|prefetch|softwaredistribution|ccmcache|minidump|servicing[\\/]lcu"
    r"|system32[\\/](?:drivers[\\/]etc|spool[\\/]printers|catroot2|logfiles|config[\\/]systemprofile[\\/]appdata))"
    r"(?:[\\/]|\s|\*|$))"
)
_SENSITIVE_WIN_RE = re.compile(
    r"(?:(?<![\w.])[a-z]:[\\/](?:windows|winnt)|%systemroot%|\$env:systemroot|%windir%|\$env:windir)[\\/]" + _WIN_SYSDIR_EXEMPT
    + r"|\$(?:profile|psprofile)\b|[\\/](?:my )?documents[\\/](?:windows)?powershell[\\/]"
    r"|[\\/]start menu[\\/]programs[\\/]startup|[\\/]programdata[\\/]ssh[\\/]|(?<![\w-])\.ssh[\\/]"
    r"|[\\/]program files(?: \(x86\))?[\\/]windows defender|[\\/]programdata[\\/]microsoft[\\/]windows defender|[\\/]windows defender[\\/]"
    r"|[\\/]system volume information|[\\/]boot[\\/]bcd|[\\/]efi[\\/]|[\\/]\$recycle\.bin"
    r"|hk(?:lm|ey_local_machine)[:\\/]+(?:sam|security)\b"
    r"|[\\/]currentversion[\\/](?:run|runonce|runonceex|runservices|runservicesonce|policies[\\/]explorer[\\/]run|winlogon"
    r"|image file execution options|explorer[\\/]shellserviceobjectdelayload|explorer[\\/]browser helper objects|app paths)\b"
    r"|[\\/]control[\\/](?:lsa|securityproviders|session manager|safeboot|terminal server)\b"
    r"|[\\/]policies[\\/](?:system|microsoft[\\/]windows defender)\b|appinit_dlls"
    r"|[\\/]classes[\\/](?:exefile|batfile|cmdfile|comfile|msifile|mscfile|scrfile|\.exe|\.bat|\.cmd|\.ps1|\.com)\b",
    re.I)
# Credential stores: a plan never reads or copies these, on any OS.
_CRED_STORE_RE = re.compile(
    r"/etc/(?:shadow|gshadow|master\.passwd)\b|/etc/shadow-|/etc/gshadow-"
    r"|\.ssh[\\/]id_[a-z0-9]+\b(?!\.pub)|\.aws[\\/]credentials\b|\.netrc\b|\.pgpass\b|\.my\.cnf\b|\.git-credentials\b"
    r"|\.docker[\\/]config\.json\b|\.kube[\\/]config\b|/var/db/dslocal/nodes/default/users|/var/db/shadow/hash"
    r"|\breg(?:\.exe)?\s+(?:save|export)\s+(?:hklm|hkey_local_machine)[\\/](?:sam|security|system)\b"
    r"|\bntds\.dit\b|\blsass\b|\bprocdump\b|\bmimikatz\b|\bsekurlsa\b|\bvaultcmd\b|\bcmdkey\s+/list"
    r"|harddiskvolumeshadowcopy|\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain|export)\b"
    r"|/library/keychains|\.keychain(?:-db)?\b|\bdscl\b[^;&|]*-read[^;&|]*(?:authenticationauthority|shadowhashdata)"
    r"|\bgetent\s+(?:shadow|gshadow)\b|\bunshadow\b",
    re.I)
_COPY_VERBS = frozenset({
    "cp", "mv", "install", "ln", "rsync", "scp", "sftp", "copy", "move", "copy-item", "move-item",
    "xcopy", "robocopy", "rename-item", "ren", "rename", "dd",
})
_DEST_FLAG_RE = re.compile(r"^(?:-destination|-dest|-t|--target-directory)(?:[:=]|$)|^of=", re.I)
_WRITERS_POSIX_RE = re.compile(
    r"^(?:tee|cp|mv|install|ln|dd|truncate|chmod|chown|chgrp|chattr|setfacl|chflags|rm|unlink|shred|touch|mkdir|rmdir"
    r"|patch|rsync|scp|sftp|curl|wget|sed\s+-[a-z]*i|perl\s+-[a-z]*i|crontab|visudo|usermod|useradd|chpasswd|passwd"
    r"|ssh-keygen|ssh-copy-id|security\s+(?:add|import|delete|set)\S*|defaults\s+(?:write|delete)|plutil|launchctl\s+(?:load|bootstrap|enable|submit)"
    r"|systemctl\s+(?:enable|edit|link|set-\w+)|update-rc\.d|chkconfig|update-ca-certificates|update-grub|grub-install|mkinitcpio|dracut"
    r"|update-initramfs|kextload|kmutil|nvram|pmset|profiles|find\b[^;&|]*\s-(?:delete|exec|execdir|ok|okdir)|git)\b",
    re.I)
_WRITERS_WIN_RE = re.compile(
    r"^(?:out-file|set-content|add-content|clear-content|tee-object|tee|copy-item|move-item|new-item|remove-item|rename-item"
    r"|set-itemproperty|new-itemproperty|remove-itemproperty|rename-itemproperty|clear-itemproperty|set-item|clear-item|set-acl"
    r"|export-\w+|invoke-webrequest|invoke-restmethod|start-bitstransfer|copy|move|del|erase|rd|rmdir|md|mkdir|ren|rename|icacls|takeown|attrib|cacls"
    r"|xcopy|robocopy|expand|makecab|cipher|compact|certutil|bitsadmin|curl|wget|reg(?:\.exe)?\s+(?:add|delete|import|restore|load|copy)"
    r"|new-scheduledtask\w*|register-scheduledtask|schtasks|get-childitem\b[^;&|]*\|?\s*remove-item|forfiles)\b",
    re.I)
_DOTNET_FILE_RE = re.compile(
    r"\[(?:system\.)?io\.(?:file|directory)\]::(?:write|append|copy|move|delete|create|replace|set)", re.I)


def _copy_dest_sensitive(seg: str, sens: "re.Pattern[str]") -> bool:
    """For copy-like verbs, deny only when a protected path is the destination."""
    toks = seg.split()
    _, vi = _lead_verb(seg)
    args = toks[vi + 1:]
    # Explicit destination flag (-Destination, -t, of=): anything after it counts.
    pos = len(seg)
    for i, t in enumerate(args):
        if _DEST_FLAG_RE.match(t):
            pos = seg.find(t)
            break
    if pos < len(seg):
        return bool(sens.search(seg[pos:]))
    # Otherwise the first non-flag argument is the source; later mentions are destinations.
    first = next((t for t in args if not t.startswith("-") and not re.match(r"^/[a-z]{1,4}(?::\S*)?$", t, re.I)), None)
    if first is None:
        return bool(sens.search(seg))
    start = seg.find(first) + len(first)
    return bool(sens.search(seg[start:]))


def _sensitive_write_reason(raw: str, norm: str, os_name: str) -> str:
    """Deny writes to protected files or keys and any touch of a credential store."""
    win = os_name == "windows"
    sens = _SENSITIVE_WIN_RE if win else _SENSITIVE_POSIX_RE
    writers = _WRITERS_WIN_RE if win else _WRITERS_POSIX_RE
    for text in (raw, norm):
        text = _strip_quote_chars(text)
        if _CRED_STORE_RE.search(text):
            return "access to a credential store"
        for seg in _segments(text):
            if not sens.search(seg):
                continue
            for t in _write_targets(seg):
                if t and sens.search(" " + t):
                    return "write to a protected system file or key"
            if _DOTNET_FILE_RE.search(seg):
                return "write to a protected system file or key"
            verb, vi = _lead_verb(seg)
            if verb in _COPY_VERBS:
                if _copy_dest_sensitive(seg, sens):
                    return "write to a protected system file or key"
                continue
            if writers.match(" ".join(seg.split()[vi:])):
                return "write to a protected system file or key"
    return ""


def _structural_reason(raw: str, norm: str, os_name: str) -> str:
    """Return a label for the first matching structural deny, else ''."""
    hit = _recursive_delete_reason(raw, norm)
    if hit:
        return hit
    hit = _sensitive_write_reason(raw, norm, os_name)
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
    r"|\b(?:ps|pgrep|lsof|who|last|lsblk|lspci|lsusb|lshw|dmesg|dmidecode|lscpu|lsmod|nproc|arp|route|traceroute|tracert|pathping"
    r"|tasklist|systeminfo|driverquery|gpresult|whoami|hostname|ver|tree|getmac|nbtstat|klist|nltest|dsregcmd|system_profiler|ioreg"
    r"|vm_stat|vmstat|iostat|mpstat|sar|nstat|iwconfig|netsh\b[^;&|]*\bshow)\b"
    r"|(?<![\w-])w(?=\s|$)|\bmount(?=\s*$|\s*[|;&])"
    r"|\b(?:fdesetup|csrutil)\s+status\b|\bspctl\s+--status\b|\bpmset\s+-g\b|\btmutil\s+(?:status|listbackups|latestbackup|destinationinfo)\b"
    r"|\bsoftwareupdate\s+(?:-l|--list|--history)\b|\bdefaults\s+read\b|\blaunchctl\s+print\b|\bprofiles\s+(?:list|show|status)\b"
    r"|\bnetworksetup\s+-(?:get|list)\w*|\bscutil\s+--\w+|\bsysctl\s+(?:-a|-n)\b"
    r"|\bsc(?:\.exe)?\s+(?:query|qc|queryex|enumdepend)\b|\bnet\s+(?:view|statistics|config|session)\b|\breg(?:\.exe)?\s+query\b"
    r"|\bschtasks\s+/query\b|\bwevtutil\s+(?:qe|gl|el|gp)\b|\bpowercfg\s+[/-](?:list|l|query|q|energy|batteryreport|sleepstudy|a|devicequery)\b"
    r"|\bmanage-bde\s+-status\b|\bfsutil\s+(?:fsinfo|volume\s+diskfree|dirty\s+query)\b|\bvssadmin\s+list\b|\bw32tm\s+/query\b"
    r"|\bpnputil\s+/enum-\w+|\bwmic\b[^;&|]*\b(?:get|list)\b|\btop\s+-b|\bnmcli\b[^;&|]*\b(?:show|status)\b"
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
    r"|\b(?:stop-process|taskkill|killall|pkill|kill)\b"
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
    r"|\bcp\b[^;&|]*\s/(?:etc|usr|bin|sbin|boot|lib)/"
    r"|\bfind\b[^;&|]*\s-(?:delete|exec|execdir|ok|okdir)\b"
    r"|\bsysctl\s+-w\b"
    r"|\bmount\s+[^|;&\s]|\bspctl\s+--(?:master|global|add|remove|enable|disable)\S*|\bcsrutil\s+(?:disable|enable|clear)"
    r"|\blaunchctl\s+(?:load|unload|bootstrap|bootout|remove|enable|disable)\b"
    r"|\btmutil\s+(?:delete|disable)\b"
    r"|\bnetworksetup\s+-set\w*"
    r"|\bdscl\b[^;&|]*\s-(?:create|delete|append|change|passwd)\b"
    r"|\bsoftwareupdate\b[^;&|]*\s(?:-i|--install)\b"
    r"|\b(?:sed|perl)\s+-[a-z]*i\b"
    r"|\bschtasks\s+/(?:create|delete|change|run|end)\b"
    r"|\bsc(?:\.exe)?\s+(?:config|create|delete|start|stop|pause|continue|failure)\b"
    r"|\bnet\s+(?:user|localgroup|group|share|accounts|stop|start|use)\b"
    r"|\bwmic\b[^;&|]*\b(?:call|set|delete|create)\b"
    r"|\bdism\b[^;&|]*/(?:add|remove|enable-feature|disable-feature|cleanup-image)\b"
    r"|\bpowercfg\s+[/-](?:change|setactive|h|hibernate|x)\b"
    r"|\bcipher\s+/w\b"
    r"|\b(?:winget|choco|scoop)\s+(?:install|uninstall|upgrade)\b"
    r"|\b(?:npm|yarn|gem|cargo|go|snap|flatpak|port|mas)\s+(?:install|i|add|remove|refresh|uninstall)\b"
    r"|\b(?:curl|wget)\b[^;&|]*\s(?:-o|-O|--output|--remote-name|-outfile)\b"
    r"|\[(?:system\.)?io\.(?:file|directory)\]::(?:write|append|delete|copy|move|create|replace|set)",
    re.I,
)
# Mutating verbs that are also common file names: only counted in verb position.
_MUT_VERB_RE = re.compile(
    r"^(?:dd|truncate|chattr|setfacl|chflags|crontab|ln|shred|unlink|userdel|groupadd|groupdel|passwd|chpasswd|visudo"
    r"|umount|modprobe|rmmod|insmod|kextload|kextunload|nvram|sysadminctl|msiexec|icacls|takeown|attrib|cacls"
    r"|xcopy|robocopy|copy|move|del|erase|rd|rmdir|ren|rename|invoke-webrequest|start-bitstransfer|install)\b",
    re.I,
)
# Pure filters that keep a pipeline read-only when they follow a read verb.
_FILTER_RE = re.compile(
    r"^\s*(?:grep|egrep|fgrep|zgrep|awk|gawk|sed(?![^;&|]*\s-[a-z]*i\b)|head|tail|sort|uniq|wc|cut|tr|column|more|less|strings|xxd|od"
    r"|hexdump|jq|yq|findstr|where-object|where|\?|select-object|select|select-string|sls|format-(?:table|list|wide|custom|hex)|ft|fl|fw"
    r"|sort-object|group-object|group|measure-object|measure|out-string|out-host|out-default|convertto-(?:json|csv|html|xml)"
    r"|convertfrom-(?:json|csv)|echo|write-output|write-host|printf|true|date|hostname|whoami|id|uname|env|printenv|stat|file"
    r"|readlink|realpath|basename|dirname|md5sum|sha\d*sum|shasum|base64(?![^;&|]*\s-(?:d|decode)\b)|type|nl|tac|rev|paste|comm|diff)"
    r"(?:\s|$)",
    re.I,
)


def _segment_floor(seg: str) -> str:
    """Floor for one separator-free command segment."""
    low = _LOW_RE.search(seg)
    # A known low-risk repair verb is exempt from the mutating table, but only
    # its own span: anything else mutating in the same segment still counts.
    rest = seg if not low else seg[:low.start()] + " " + seg[low.end():]
    if _MUT_RE.search(rest):
        return "medium"
    _, vi = _lead_verb(seg)
    if _MUT_VERB_RE.match(" ".join(seg.split()[vi:])):
        return "medium"
    w = _write_floor(seg)
    if w == "medium":
        return "medium"
    if low or w == "low":
        return "low"
    if _READ_RE.search(seg) or _FILTER_RE.match(seg):
        return "read_only"
    return "low"


def floor_risk(command: str, os_name: str) -> str:
    """Compute a local minimum risk for a command from a verb table.

    The command is split on shell separators and the floor is the maximum over
    its segments, so a read verb in front never lowers a mutating one behind
    it. Read-only verbs (Get-*, cat, df, systemctl status, ...) and pure
    filters impose no floor and return "read_only". Service restarts, cache
    clears and process kills floor to "low", as do writes into temp or home
    directories. Mutating verbs (Set-*, Remove-*, package installs, rm, chmod,
    ...) and writes anywhere else floor to "medium". Anything unrecognised
    floors to "low". The floor is independent of and never lowers the
    model-declared risk; see effective_risk.
    """
    if not command or not command.strip():
        return "read_only"
    norm = normalise(command, os_name)
    floor = "read_only"
    for text in (_strip_quote_chars(command), _strip_quote_chars(norm)):
        for seg in _segments(text):
            floor = _max_risk(floor, _segment_floor(seg))
    return floor


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
