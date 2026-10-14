"""Diagnostic collectors for Windows, Linux and macOS.

Every collector is a single non-interactive command with a timeout, started
directly (no shell wrapper, no ``| head``/``| tail`` pipelines: the first or
last N lines are kept in Python through ``Collector.keep_lines``). Failures
are recorded in the manifest, never fatal, and classified into
``FileEntry.status`` (``ok``, ``nonzero``, ``timeout``, ``missing``,
``denied``, ``empty``, ``invalid_json``) so a field tester can see at a
glance which collectors work on a given machine. A collector's stderr goes to
a sidecar ``<category>/<name>.stderr.txt`` with its own manifest entry, so
JSON outputs stay parseable. Nothing here changes the system.
"""
from __future__ import annotations

import dataclasses
import json
import ntpath
import os
import platform
import re
import shutil
import string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..common.schema import FileEntry
from ..common.util import atomic_write_bytes, canonical_json, current_os, sha256_file, sha256_hex, write_json
from .procs import powershell_exe, run_capped, windows_system32

MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # per file
# A collector that keeps the *last* N lines reads more of the stream so the
# tail is not taken from a front-truncated capture; the file is still capped
# at MAX_OUTPUT_BYTES when written.
TAIL_READ_BYTES = 8 * 1024 * 1024
TRUNCATED_MARK = "[truncated by aiit-agent]"
STATUSES = ("ok", "nonzero", "timeout", "missing", "denied", "empty", "invalid_json")
# Statuses that count as a failure for ``selftest --strict`` and the pinned
# runner test. ``empty`` is not one: "no failed devices" is healthy output.
FAILURE_STATUSES = ("nonzero", "timeout", "missing", "denied", "invalid_json")

# stderr markers. Matched case-insensitively against the whole stderr text;
# the matched literal is what ``error_class`` reports, so it never carries
# machine content.
_DENIED_RE = re.compile(
    r"access is denied|access denied|e_accessdenied|0x80070005|requires elevation|run as administrator|"
    r"administrator privileges|requires administrator|unauthorizedaccess|unauthorized operation|"
    r"permissiondenied|permission denied|operation not permitted|not permitted|must be run as root|"
    r"must be root|are you root|requires root|only root|superuser|insufficient privilege",
    re.IGNORECASE,
)
_MISSING_RE = re.compile(
    r"command not found|is not recognized as|not recognized as an internal|: not found\s*$",
    re.IGNORECASE | re.MULTILINE,
)
# Keys dropped from macOS system_profiler JSON at collection time (defence in
# depth; the console redactor tokens the same values again).
_HARDWARE_ID_RE = re.compile(r"serial|uuid|udid", re.IGNORECASE)


@dataclass
class Collector:
    name: str            # file name without extension
    category: str        # sub-directory: sys, logs, net, config, osquery
    argv: list[str]      # command and args (no shell)
    ext: str = "txt"
    timeout: int = 60
    quick: bool = True   # included in --quick runs
    oses: tuple[str, ...] = ("windows", "linux", "macos")
    requires_admin: bool = False               # needs administrator/root for full output; run anyway, classified cleanly
    keep_lines: tuple[str, int] | None = None  # ("head", N) or ("tail", N): keep only those lines of stdout
    output_filter: str | None = None           # key into OUTPUT_FILTERS, applied to stdout before keep_lines


def _ps(script: str) -> list[str]:
    return [powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]


def windows_system32_argv(exe: str, *args: str) -> list[str]:
    """Build an argv whose program is an absolute path under System32.

    Starting Windows binaries by bare name lets CreateProcess search the
    current directory first, which is dangerous when apply runs from removable
    media. Resolving to System32 removes that search.
    """
    return [windows_system32(exe), *args]


_PS_NAMES = ("powershell", "powershell.exe")
_PS_FLAGS = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass")
_PS_SCRIPT_SWITCHES = ("-command", "-c", "-file", "-f", "-encodedcommand", "-e", "-ec")


def resolve_windows_argv(argv: list[str], exists=os.path.exists) -> list[str]:
    """Return ``argv`` with a bare Windows program name made absolute.

    A bare ``powershell``/``powershell.exe`` becomes the absolute Windows
    PowerShell under System32 with the same switches ``_ps`` uses
    (``-NoProfile -NonInteractive -ExecutionPolicy Bypass``, deduplicated,
    ahead of the caller's ``-Command``/``-File``): on Windows a PowerShell
    started without those switches has been seen to take 20 s or more to exit
    on otherwise idle hosts, while the ``_ps`` form returns in well under a
    second. Any other bare name that exists under System32 is started from
    there. Names that carry a directory component are left alone, as are
    bare names with no System32 counterpart (``run_one`` still looks those up
    on PATH).
    """
    if not argv:
        return argv
    prog = argv[0]
    if ntpath.basename(prog) != prog or not prog:
        return argv
    if prog.lower() in _PS_NAMES:
        rest = list(argv[1:])
        kept: list[str] = []
        i = 0
        while i < len(rest):
            tok = rest[i]
            low = tok.lower()
            if low in _PS_SCRIPT_SWITCHES:
                kept.extend(rest[i:])
                break
            if low == "-executionpolicy":
                i += 2  # drop the switch and its value; Bypass is re-added
                continue
            if low in ("-noprofile", "-noninteractive"):
                i += 1
                continue
            kept.append(tok)
            i += 1
        return [powershell_exe(), *_PS_FLAGS, *kept]
    candidate = windows_system32(prog if ntpath.splitext(prog)[1] else prog + ".exe")
    if exists(candidate):
        return [candidate, *argv[1:]]
    return argv


# PowerShell output is read back in the console's OEM code page (see
# procs.console_codec), which keeps ConvertTo-Json structurally intact in every
# case; a name the code page cannot represent degrades to "?" exactly as it
# does for the native console tools. A UTF-8 output prefix is deliberately not
# added: it would need a per-collector decoder in procs.run_capped to be
# correct, and today the loss is confined to such names, never to structure.
WINDOWS: list[Collector] = [
    Collector("computerinfo", "sys", _ps("Get-ComputerInfo | ConvertTo-Json -Depth 2"), "json", 90),
    Collector("systeminfo", "sys", windows_system32_argv("systeminfo.exe"), "txt", 90),
    Collector("uptime_boot", "sys", _ps("Get-CimInstance Win32_OperatingSystem | Select LastBootUpTime,LocalDateTime,FreePhysicalMemory,TotalVisibleMemorySize | ConvertTo-Json"), "json", 30),
    Collector("hotfixes", "sys", _ps("Get-HotFix | Sort InstalledOn -Desc | Select HotFixID,Description,InstalledOn | ConvertTo-Json"), "json", 60),
    Collector("services", "sys", _ps("Get-Service | Select Name,DisplayName,Status,StartType | ConvertTo-Json"), "json", 60),
    Collector("services_stopped_auto", "sys", _ps("Get-CimInstance Win32_Service | Where {$_.StartMode -eq 'Auto' -and $_.State -ne 'Running'} | Select Name,DisplayName,State,StartMode,ExitCode | ConvertTo-Json"), "json", 60),
    Collector("processes_top", "sys", _ps("Get-Process | Sort CPU -Desc | Select -First 60 Name,Id,CPU,WS,Path | ConvertTo-Json"), "json", 60),
    Collector("pnp_errors", "sys", _ps("Get-PnpDevice | Where Status -ne 'OK' | Select FriendlyName,Status,Class,InstanceId | ConvertTo-Json"), "json", 60),
    Collector("drivers", "sys", windows_system32_argv("driverquery.exe", "/v"), "txt", 90, quick=False, requires_admin=True),
    Collector("volumes", "sys", _ps("Get-Volume | Select DriveLetter,FileSystemLabel,FileSystem,HealthStatus,SizeRemaining,Size | ConvertTo-Json"), "json", 60),
    Collector("disks", "sys", _ps("Get-PhysicalDisk | Select FriendlyName,MediaType,HealthStatus,OperationalStatus,Size | ConvertTo-Json"), "json", 60),
    Collector("startup", "sys", _ps("Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User | ConvertTo-Json"), "json", 60, quick=False),
    Collector("installed_software", "sys", _ps("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where DisplayName | Select DisplayName,DisplayVersion,Publisher,InstallDate | Sort DisplayName | ConvertTo-Json"), "json", 90, quick=False),
    Collector("defender", "sys", _ps("Get-MpComputerStatus | Select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime | ConvertTo-Json"), "json", 60, requires_admin=True),
    Collector("bitlocker", "sys", _ps("Get-BitLockerVolume | Select MountPoint,ProtectionStatus,EncryptionPercentage,VolumeStatus | ConvertTo-Json"), "json", 60, requires_admin=True),
    Collector("local_users", "sys", _ps("Get-LocalUser | Select Name,Enabled,LastLogon,PasswordExpires | ConvertTo-Json"), "json", 60),
    Collector("power", "sys", windows_system32_argv("powercfg.exe", "/l"), "txt", 30, quick=False),
    Collector("printers", "sys", _ps("Get-Printer | Select Name,DriverName,PortName,PrinterStatus,Shared | ConvertTo-Json"), "json", 60, quick=False),
    Collector("scheduled_tasks", "sys", _ps("Get-ScheduledTask | Where {$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*'} | Select TaskName,TaskPath,State | ConvertTo-Json"), "json", 60, quick=False),
    Collector("ipconfig", "net", windows_system32_argv("ipconfig.exe", "/all"), "txt", 30),
    Collector("adapters", "net", _ps("Get-NetAdapter | Select Name,InterfaceDescription,Status,LinkSpeed,MacAddress,DriverVersion | ConvertTo-Json"), "json", 60),
    Collector("routes", "net", windows_system32_argv("route.exe", "print"), "txt", 30),
    Collector("dns", "net", _ps("Get-DnsClientServerAddress | Where {$_.ServerAddresses} | Select InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json"), "json", 30),
    Collector("connections", "net", windows_system32_argv("netstat.exe", "-ano"), "txt", 60, quick=False, requires_admin=True),
    Collector("proxy", "net", windows_system32_argv("netsh.exe", "winhttp", "show", "proxy"), "txt", 30),
    Collector("firewall_profiles", "net", _ps("Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction | ConvertTo-Json"), "json", 30),
    Collector("system_errors_7d", "logs", _ps("Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 300 -ErrorAction SilentlyContinue | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json"), "json", 120, requires_admin=True),
    Collector("application_errors_7d", "logs", _ps("Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2,3; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 300 -ErrorAction SilentlyContinue | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json"), "json", 120, requires_admin=True),
    Collector("windows_update", "logs", _ps("Get-WinEvent -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue | Select TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Json"), "json", 60, quick=False, requires_admin=True),
    Collector("kernel_power_bugchecks", "logs", _ps("Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power','Microsoft-Windows-WER-SystemErrorReporting'} -MaxEvents 50 -ErrorAction SilentlyContinue | Select TimeCreated,Id,ProviderName,Message | ConvertTo-Json"), "json", 60, requires_admin=True),
    Collector("hosts_file", "config", _ps("Get-Content $env:SystemRoot\\System32\\drivers\\etc\\hosts"), "txt", 15),
    Collector("env_names", "config", _ps("Get-ChildItem Env: | Select -Expand Name"), "txt", 15),
]

_PS_COLUMNS = "pid,ppid,user,%cpu,%mem,etime,comm"

LINUX: list[Collector] = [
    Collector("os_release", "sys", ["cat", "/etc/os-release"], "txt", 10),
    Collector("uname", "sys", ["uname", "-a"], "txt", 10),
    Collector("uptime", "sys", ["uptime"], "txt", 10),
    Collector("hostnamectl", "sys", ["hostnamectl"], "txt", 10),
    Collector("failed_units", "sys", ["systemctl", "--failed", "--no-pager", "--plain"], "txt", 30),
    Collector("running_services", "sys", ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"], "txt", 30),
    Collector("processes_top", "sys", ["ps", "-e", "-o", _PS_COLUMNS, "--sort=-%cpu"], "txt", 30, keep_lines=("head", 60)),
    Collector("memory", "sys", ["free", "-m"], "txt", 10),
    Collector("disk_df", "sys", ["df", "-h"], "txt", 20),
    Collector("lsblk", "sys", ["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"], "txt", 20),
    Collector("mounts", "sys", ["mount"], "txt", 10, quick=False),
    Collector("lspci", "sys", ["lspci"], "txt", 20, quick=False),
    Collector("lsusb", "sys", ["lsusb"], "txt", 20, quick=False),
    Collector("ip_addr", "net", ["ip", "addr"], "txt", 10),
    Collector("ip_route", "net", ["ip", "route"], "txt", 10),
    Collector("resolv_conf", "net", ["cat", "/etc/resolv.conf"], "txt", 10),
    Collector("listening", "net", ["ss", "-tulpn"], "txt", 20),
    # journalctl shows only the caller's own messages without the systemd-journal/adm group; root sees the system scope
    Collector("journal_errors", "logs", ["journalctl", "-p", "3", "-n", "500", "--no-pager", "-o", "short-iso"], "txt", 60, requires_admin=True),
    Collector("journal_boot", "logs", ["journalctl", "-b", "-n", "300", "--no-pager", "-o", "short-iso"], "txt", 60, requires_admin=True),
    Collector("dmesg_err", "logs", ["dmesg", "--level=err,warn"], "txt", 30, requires_admin=True, keep_lines=("tail", 200)),
    Collector("apt_history", "logs", ["tail", "-n", "200", "/var/log/apt/history.log"], "txt", 30, quick=False),
    Collector("dnf_history", "logs", ["dnf", "history"], "txt", 30, quick=False, keep_lines=("head", 40)),
    Collector("fstab", "config", ["cat", "/etc/fstab"], "txt", 10),
    Collector("crontab", "config", ["crontab", "-l"], "txt", 10, quick=False),
    Collector("cron_d", "config", ["ls", "-la", "/etc/cron.d"], "txt", 10, quick=False),
    Collector("hosts_file", "config", ["cat", "/etc/hosts"], "txt", 10),
    Collector("env_names", "config", ["env"], "txt", 10, output_filter="env_names"),
]

MACOS: list[Collector] = [
    Collector("sw_vers", "sys", ["sw_vers"], "txt", 10),
    Collector("uname", "sys", ["uname", "-a"], "txt", 10),
    Collector("uptime", "sys", ["uptime"], "txt", 10),
    Collector("hardware", "sys", ["system_profiler", "-json", "SPHardwareDataType", "SPSoftwareDataType"], "json", 60, output_filter="drop_hardware_ids"),
    Collector("storage", "sys", ["system_profiler", "-json", "SPStorageDataType"], "json", 60, output_filter="drop_hardware_ids"),
    Collector("diskutil", "sys", ["diskutil", "list"], "txt", 30),
    Collector("disk_df", "sys", ["df", "-h"], "txt", 20),
    Collector("processes_top", "sys", ["ps", "-A", "-r", "-o", _PS_COLUMNS], "txt", 30, keep_lines=("head", 60)),
    Collector("launchd", "sys", ["launchctl", "list"], "txt", 30),
    Collector("battery", "sys", ["pmset", "-g", "batt"], "txt", 10),
    Collector("gatekeeper", "sys", ["spctl", "--status"], "txt", 20),
    Collector("filevault", "sys", ["fdesetup", "status"], "txt", 20),
    Collector("sip", "sys", ["csrutil", "status"], "txt", 20),
    Collector("updates_history", "sys", ["softwareupdate", "--history"], "txt", 60, quick=False),
    Collector("network", "net", ["system_profiler", "-json", "SPNetworkDataType"], "json", 60),
    Collector("ifconfig", "net", ["ifconfig"], "txt", 10),
    Collector("routes", "net", ["netstat", "-rn"], "txt", 10),
    Collector("dns", "net", ["scutil", "--dns"], "txt", 10),
    Collector("log_errors_30m", "logs", ["log", "show", "--last", "30m", "--predicate", "messageType == error", "--style", "compact"], "txt", 120,
              requires_admin=True, keep_lines=("tail", 500)),
    Collector("hosts_file", "config", ["cat", "/etc/hosts"], "txt", 10),
    Collector("env_names", "config", ["env"], "txt", 10, output_filter="env_names"),
]

OSQUERY_QUERIES: dict[str, str] = {
    "system_info": "SELECT hostname, cpu_brand, physical_memory, hardware_vendor, hardware_model FROM system_info;",
    "os_version": "SELECT name, version, build, platform FROM os_version;",
    "uptime": "SELECT * FROM uptime;",
    "logged_in_users": "SELECT type, user, host, time FROM logged_in_users;",
    "listening_ports": "SELECT p.name, l.port, l.protocol, l.address FROM listening_ports l JOIN processes p USING (pid);",
    "startup_items": "SELECT name, path, status, source FROM startup_items;",
    "interface_addresses": "SELECT interface, address, mask FROM interface_addresses;",
    "kernel_info": "SELECT version, path FROM kernel_info;",
    "disk_encryption": "SELECT name, encrypted, type FROM disk_encryption;",
}


def collectors_for(os_name: str) -> list[Collector]:
    return {"windows": WINDOWS, "linux": LINUX, "macos": MACOS}[os_name]


def collector_table_sha256(os_name: str) -> str:
    """SHA-256 of the collector table for ``os_name``, recorded in the manifest.

    Lets an operator tell which collector definitions produced a bundle
    without comparing agent versions.
    """
    return sha256_hex(canonical_json([dataclasses.asdict(c) for c in collectors_for(os_name)]))


def is_elevated() -> bool | None:
    """True when the agent runs as administrator (Windows) or root (elsewhere); None when it cannot tell."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return None


# ------------------------------------------------------------------ output filters

def _env_names(text: str) -> str:
    """``env`` output reduced to sorted variable names (values never reach a bundle)."""
    names = sorted({line.split("=", 1)[0] for line in text.splitlines() if "=" in line})
    return "\n".join(names) + ("\n" if names else "")


def _drop_hardware_ids(text: str) -> str:
    """Drop serial number, UUID and UDID keys from system_profiler JSON.

    Falls back to dropping matching lines when the text is not JSON.
    """
    def strip(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: strip(v) for k, v in obj.items() if not _HARDWARE_ID_RE.search(str(k))}
        if isinstance(obj, list):
            return [strip(v) for v in obj]
        return obj

    try:
        data = json.loads(text.lstrip("﻿"))
    except ValueError:
        return "".join(line for line in text.splitlines(keepends=True) if not _HARDWARE_ID_RE.search(line))
    return json.dumps(strip(data), indent=2, ensure_ascii=False) + "\n"


OUTPUT_FILTERS: dict[str, Callable[[str], str]] = {
    "env_names": _env_names,
    "drop_hardware_ids": _drop_hardware_ids,
}


def keep_lines(text: str, spec: tuple[str, int] | None) -> str:
    """Keep the first (``("head", n)``) or last (``("tail", n)``) ``n`` lines of ``text``."""
    if not spec:
        return text
    mode, n = spec
    lines = text.splitlines(keepends=True)
    if len(lines) <= n:
        return text
    if mode == "head":
        return "".join(lines[:n])
    if mode == "tail":
        return "".join(lines[-n:])
    raise ValueError(f"keep_lines mode must be 'head' or 'tail', not {mode!r}")


def _postprocess(c: Collector, stdout: str) -> str:
    if c.output_filter:
        stdout = OUTPUT_FILTERS[c.output_filter](stdout)
    return keep_lines(stdout, c.keep_lines)


# ------------------------------------------------------------------ classification

def _first_line(text: str, limit: int = 200) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return ""


def classify(ext: str, exit_code: int | None, stdout: str, stderr: str) -> tuple[str, str | None]:
    """Classify a finished (not timed out) collector run.

    Returns ``(status, error)``. stderr markers decide ``missing`` and
    ``denied`` only when the run also failed (non-zero exit or no output), so
    a warning next to good output is still ``ok``. ``empty`` carries the first
    stderr line as ``error`` when there was one, so the console counts it as
    a collector error; a plain empty result has no error.
    """
    text = stdout.strip()
    err_line = _first_line(stderr)
    failed = exit_code not in (0, None) or not text
    if failed and _MISSING_RE.search(stderr):
        return "missing", err_line or f"exit {exit_code}"
    if failed and _DENIED_RE.search(stderr):
        return "denied", err_line or f"exit {exit_code}"
    if exit_code not in (0, None):
        return "nonzero", f"exit {exit_code}" + (f": {err_line}" if err_line else "")
    if not text:
        return "empty", err_line or None
    if ext == "json":
        try:
            json.loads(text.lstrip("﻿"))
        except ValueError as e:
            note = " (output truncated)" if TRUNCATED_MARK in stdout else ""
            return "invalid_json", f"output is not valid JSON{note}: {str(e)[:120]}"
    return "ok", None


def error_class(entry: FileEntry) -> str | None:
    """A short, content-free label for a failed entry (for selftest output).

    Only fixed tokens are returned: the status, the exit code, or the stderr
    marker literal that matched; never a line of collector output.
    """
    s = entry.status
    if s == "ok":
        return None
    if s == "timeout":
        return "timeout"
    if s == "nonzero":
        return f"exit {entry.exit_code}"
    if s == "missing":
        return "command not found"
    if s == "denied":
        m = _DENIED_RE.search(entry.error or "")
        return m.group(0).lower() if m else "denied"
    if s == "empty":
        return "no output (stderr present)" if entry.error else "no output"
    if s == "invalid_json":
        return "json decode error (output truncated)" if entry.error and "truncated" in entry.error else "json decode error"
    return s


# ------------------------------------------------------------------ running

def _write_capped(path: Path, data: bytes) -> int:
    if len(data) > MAX_OUTPUT_BYTES:
        data = data[:MAX_OUTPUT_BYTES] + f"\n... {TRUNCATED_MARK}\n".encode("utf-8")
    atomic_write_bytes(path, data)
    return len(data)


def run_one(c: Collector, out_root: Path) -> list[FileEntry]:
    """Run one collector; returns its manifest entry plus a stderr sidecar entry when stderr was not empty."""
    rel = f"{c.category}/{c.name}.{c.ext}"
    path = out_root / rel
    started = time.time()
    exit_code: int | None = None
    error: str | None = None
    status = "ok"
    stdout = stderr = ""
    argv = resolve_windows_argv(c.argv) if os.name == "nt" else c.argv
    try:
        if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
            raise FileNotFoundError(argv[0])
        cap = TAIL_READ_BYTES if c.keep_lines and c.keep_lines[0] == "tail" else MAX_OUTPUT_BYTES
        pr = run_capped(argv, c.timeout, cap=cap)
        stdout, stderr = pr.stdout, pr.stderr
        if pr.timed_out:
            status, error = "timeout", f"timeout after {c.timeout}s"
            stdout += "\n[timeout]\n"
        else:
            exit_code = pr.exit_code
            stdout = _postprocess(c, stdout)
            status, error = classify(c.ext, exit_code, stdout, stderr)
    except FileNotFoundError:
        status, error = "missing", f"command not found: {argv[0]}"
    except PermissionError as e:
        status, error = "denied", f"cannot start {argv[0]}: {e.strerror or e}"
    except Exception as e:  # pragma: no cover - defensive (exec format error, broken loader, ...)
        status, error = "missing", f"cannot start {argv[0]}: {type(e).__name__}: {e}"
    if status == "denied" and c.requires_admin and is_elevated() is False:
        error = f"{error} (needs administrator/root; the agent is not elevated)"
    body = stdout.encode("utf-8", "replace")
    if not body.strip() and status not in ("ok", "empty") and error:
        body = (error + "\n").encode("utf-8")
    size = _write_capped(path, body)
    command = " ".join(argv)[:300]
    duration_ms = int((time.time() - started) * 1000)
    entries = [FileEntry(
        path=rel, sha256=sha256_file(path), size=size, collector=c.name, command=command,
        exit_code=exit_code, duration_ms=duration_ms, error=error, status=status,
    )]
    if stderr.strip():
        rel_err = f"{c.category}/{c.name}.stderr.txt"
        err_path = out_root / rel_err
        err_size = _write_capped(err_path, stderr.encode("utf-8", "replace"))
        entries.append(FileEntry(
            path=rel_err, sha256=sha256_file(err_path), size=err_size, collector=f"{c.name}.stderr",
            command=command, exit_code=exit_code, duration_ms=duration_ms,
        ))
    return entries


def _native_platform(out_root: Path) -> FileEntry:
    rel = "sys/python_platform.json"
    path = out_root / rel
    u = platform.uname()
    data = {
        "system": u.system, "node": u.node, "release": u.release, "version": u.version,
        "machine": u.machine, "processor": u.processor, "python": platform.python_version(),
    }
    write_json(path, data)
    return FileEntry(path=rel, sha256=sha256_file(path), size=path.stat().st_size, collector="python_platform")


def _native_disk_usage(out_root: Path, os_name: str) -> FileEntry:
    rel = "sys/disk_usage.json"
    path = out_root / rel
    targets: list[str] = []
    if os_name == "windows":
        targets = [f"{d}:\\" for d in string.ascii_uppercase if Path(f"{d}:\\").exists()]
    else:
        targets = ["/"]
        try:
            with open("/proc/mounts", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > 2 and parts[2] in ("ext4", "xfs", "btrfs", "apfs", "hfs", "ntfs", "vfat", "exfat", "zfs"):
                        targets.append(parts[1])
        except Exception:
            pass  # no /proc/mounts (macOS) or unreadable: "/" alone is reported
    out = {}
    for t in dict.fromkeys(targets):
        try:
            u = shutil.disk_usage(t)
            out[t] = {"total_gb": round(u.total / 1e9, 2), "used_gb": round(u.used / 1e9, 2), "free_gb": round(u.free / 1e9, 2), "pct_used": round(100 * u.used / u.total, 1) if u.total else None}
        except Exception as e:
            out[t] = {"error": str(e)}
    write_json(path, out)
    return FileEntry(path=rel, sha256=sha256_file(path), size=path.stat().st_size, collector="disk_usage")


def _osquery(out_root: Path) -> list[FileEntry]:
    exe = shutil.which("osqueryi")
    if not exe:
        return []
    entries: list[FileEntry] = []
    for name, sql in OSQUERY_QUERIES.items():
        entries.extend(run_one(Collector(name, "osquery", [exe, "--json", sql], "json", 60), out_root))
    return entries


def collect_all(out_root: Path, quick: bool = False, os_name: str | None = None,
                progress: Callable[[str], None] | None = None, include_osquery: bool = True) -> list[FileEntry]:
    os_name = os_name or current_os()
    entries: list[FileEntry] = [_native_platform(out_root), _native_disk_usage(out_root, os_name)]
    for c in collectors_for(os_name):
        if quick and not c.quick:
            continue
        if progress:
            progress(f"{c.category}/{c.name}")
        entries.extend(run_one(c, out_root))
    if include_osquery:
        if progress:
            progress("osquery (if installed)")
        entries.extend(_osquery(out_root))
    return entries


# ------------------------------------------------------------------ selftest support

def is_sidecar(entry: FileEntry) -> bool:
    return entry.collector.endswith(".stderr")


def status_counts(entries: list[FileEntry]) -> dict[str, int]:
    """Count of each status over the primary (non-sidecar) entries, in STATUSES order, zeros omitted."""
    counts = {s: 0 for s in STATUSES}
    for e in entries:
        if not is_sidecar(e):
            counts[e.status] = counts.get(e.status, 0) + 1
    return {k: v for k, v in counts.items() if v}


def selftest_rows(entries: list[FileEntry], os_name: str) -> list[dict[str, Any]]:
    """Per-collector metadata rows for ``aiit-agent selftest``.

    Only metadata is included: collector name and category, status, exit
    code, duration, sizes, whether the collector needs elevation, and the
    content-free ``error_class``. Never the command line (it can embed
    arguments), the error text or any output.
    """
    admin = {c.name: c.requires_admin for c in collectors_for(os_name)}
    sidecar_size = {e.path: e.size for e in entries if is_sidecar(e)}
    rows: list[dict[str, Any]] = []
    for e in entries:
        if is_sidecar(e):
            continue
        category, _, _ = e.path.partition("/")
        stderr_path = f"{category}/{e.collector}.stderr.txt"
        rows.append({
            "name": e.collector, "category": category, "requires_admin": admin.get(e.collector, False),
            "status": e.status, "exit_code": e.exit_code, "duration_ms": e.duration_ms, "size": e.size,
            "stderr_size": sidecar_size.get(stderr_path, 0), "error_class": error_class(e),
        })
    return rows
