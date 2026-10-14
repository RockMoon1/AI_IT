"""Diagnostic collectors for Windows, Linux and macOS.

Every collector is a single non-interactive command with a timeout. Failures
are recorded in the manifest, never fatal. Nothing here changes the system.
"""
from __future__ import annotations

import json
import ntpath
import os
import platform
import shutil
import string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..common.schema import FileEntry
from ..common.util import current_os, sha256_file
from .procs import powershell_exe, run_capped, windows_system32

MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # per file


@dataclass
class Collector:
    name: str            # file name without extension
    category: str        # sub-directory: sys, logs, net, config, osquery
    argv: list[str]      # command and args (no shell)
    ext: str = "txt"
    timeout: int = 60
    quick: bool = True   # included in --quick runs
    oses: tuple[str, ...] = ("windows", "linux", "macos")


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


WINDOWS: list[Collector] = [
    Collector("computerinfo", "sys", _ps("Get-ComputerInfo | ConvertTo-Json -Depth 2"), "json", 90),
    Collector("systeminfo", "sys", windows_system32_argv("systeminfo.exe"), "txt", 90),
    Collector("uptime_boot", "sys", _ps("Get-CimInstance Win32_OperatingSystem | Select LastBootUpTime,LocalDateTime,FreePhysicalMemory,TotalVisibleMemorySize | ConvertTo-Json"), "json", 30),
    Collector("hotfixes", "sys", _ps("Get-HotFix | Sort InstalledOn -Desc | Select HotFixID,Description,InstalledOn | ConvertTo-Json"), "json", 60),
    Collector("services", "sys", _ps("Get-Service | Select Name,DisplayName,Status,StartType | ConvertTo-Json"), "json", 60),
    Collector("services_stopped_auto", "sys", _ps("Get-CimInstance Win32_Service | Where {$_.StartMode -eq 'Auto' -and $_.State -ne 'Running'} | Select Name,DisplayName,State,StartMode,ExitCode | ConvertTo-Json"), "json", 60),
    Collector("processes_top", "sys", _ps("Get-Process | Sort CPU -Desc | Select -First 60 Name,Id,CPU,WS,Path | ConvertTo-Json"), "json", 60),
    Collector("pnp_errors", "sys", _ps("Get-PnpDevice | Where Status -ne 'OK' | Select FriendlyName,Status,Class,InstanceId | ConvertTo-Json"), "json", 60),
    Collector("drivers", "sys", windows_system32_argv("driverquery.exe", "/v"), "txt", 90, quick=False),
    Collector("volumes", "sys", _ps("Get-Volume | Select DriveLetter,FileSystemLabel,FileSystem,HealthStatus,SizeRemaining,Size | ConvertTo-Json"), "json", 60),
    Collector("disks", "sys", _ps("Get-PhysicalDisk | Select FriendlyName,MediaType,HealthStatus,OperationalStatus,Size | ConvertTo-Json"), "json", 60),
    Collector("startup", "sys", _ps("Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User | ConvertTo-Json"), "json", 60, quick=False),
    Collector("installed_software", "sys", _ps("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where DisplayName | Select DisplayName,DisplayVersion,Publisher,InstallDate | Sort DisplayName | ConvertTo-Json"), "json", 90, quick=False),
    Collector("defender", "sys", _ps("Get-MpComputerStatus | Select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime | ConvertTo-Json"), "json", 60),
    Collector("bitlocker", "sys", _ps("Get-BitLockerVolume | Select MountPoint,ProtectionStatus,EncryptionPercentage,VolumeStatus | ConvertTo-Json"), "json", 60),
    Collector("local_users", "sys", _ps("Get-LocalUser | Select Name,Enabled,LastLogon,PasswordExpires | ConvertTo-Json"), "json", 60),
    Collector("power", "sys", windows_system32_argv("powercfg.exe", "/l"), "txt", 30, quick=False),
    Collector("printers", "sys", _ps("Get-Printer | Select Name,DriverName,PortName,PrinterStatus,Shared | ConvertTo-Json"), "json", 60, quick=False),
    Collector("scheduled_tasks", "sys", _ps("Get-ScheduledTask | Where {$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*'} | Select TaskName,TaskPath,State | ConvertTo-Json"), "json", 60, quick=False),
    Collector("ipconfig", "net", windows_system32_argv("ipconfig.exe", "/all"), "txt", 30),
    Collector("adapters", "net", _ps("Get-NetAdapter | Select Name,InterfaceDescription,Status,LinkSpeed,MacAddress,DriverVersion | ConvertTo-Json"), "json", 60),
    Collector("routes", "net", windows_system32_argv("route.exe", "print"), "txt", 30),
    Collector("dns", "net", _ps("Get-DnsClientServerAddress | Where {$_.ServerAddresses} | Select InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json"), "json", 30),
    Collector("connections", "net", windows_system32_argv("netstat.exe", "-ano"), "txt", 60, quick=False),
    Collector("proxy", "net", windows_system32_argv("netsh.exe", "winhttp", "show", "proxy"), "txt", 30),
    Collector("firewall_profiles", "net", _ps("Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction | ConvertTo-Json"), "json", 30),
    Collector("system_errors_7d", "logs", _ps("Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 300 -ErrorAction SilentlyContinue | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json"), "json", 120),
    Collector("application_errors_7d", "logs", _ps("Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2,3; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 300 -ErrorAction SilentlyContinue | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json"), "json", 120),
    Collector("windows_update", "logs", _ps("Get-WinEvent -LogName 'Microsoft-Windows-WindowsUpdateClient/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue | Select TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Json"), "json", 60, quick=False),
    Collector("kernel_power_bugchecks", "logs", _ps("Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power','Microsoft-Windows-WER-SystemErrorReporting'} -MaxEvents 50 -ErrorAction SilentlyContinue | Select TimeCreated,Id,ProviderName,Message | ConvertTo-Json"), "json", 60),
    Collector("hosts_file", "config", _ps("Get-Content $env:SystemRoot\\System32\\drivers\\etc\\hosts"), "txt", 15),
    Collector("env_names", "config", _ps("Get-ChildItem Env: | Select -Expand Name"), "txt", 15),
]

LINUX: list[Collector] = [
    Collector("os_release", "sys", ["cat", "/etc/os-release"], "txt", 10),
    Collector("uname", "sys", ["uname", "-a"], "txt", 10),
    Collector("uptime", "sys", ["uptime"], "txt", 10),
    Collector("hostnamectl", "sys", ["hostnamectl"], "txt", 10),
    Collector("failed_units", "sys", ["systemctl", "--failed", "--no-pager", "--plain"], "txt", 30),
    Collector("running_services", "sys", ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"], "txt", 30),
    Collector("processes_top", "sys", ["sh", "-c", "ps aux --sort=-%cpu | head -60"], "txt", 30),
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
    Collector("journal_errors", "logs", ["journalctl", "-p", "3", "-n", "500", "--no-pager", "-o", "short-iso"], "txt", 60),
    Collector("journal_boot", "logs", ["journalctl", "-b", "-n", "300", "--no-pager", "-o", "short-iso"], "txt", 60),
    Collector("dmesg_err", "logs", ["sh", "-c", "dmesg --level=err,warn 2>/dev/null | tail -200"], "txt", 30),
    Collector("apt_history", "logs", ["sh", "-c", "tail -200 /var/log/apt/history.log 2>/dev/null; dnf history 2>/dev/null | head -40"], "txt", 30, quick=False),
    Collector("fstab", "config", ["cat", "/etc/fstab"], "txt", 10),
    Collector("crontab", "config", ["sh", "-c", "crontab -l 2>/dev/null; ls -la /etc/cron.d 2>/dev/null"], "txt", 10, quick=False),
    Collector("hosts_file", "config", ["cat", "/etc/hosts"], "txt", 10),
    Collector("env_names", "config", ["sh", "-c", "env | cut -d= -f1 | sort"], "txt", 10),
]

MACOS: list[Collector] = [
    Collector("sw_vers", "sys", ["sw_vers"], "txt", 10),
    Collector("uname", "sys", ["uname", "-a"], "txt", 10),
    Collector("uptime", "sys", ["uptime"], "txt", 10),
    Collector("hardware", "sys", ["system_profiler", "-json", "SPHardwareDataType", "SPSoftwareDataType"], "json", 60),
    Collector("storage", "sys", ["system_profiler", "-json", "SPStorageDataType"], "json", 60),
    Collector("diskutil", "sys", ["diskutil", "list"], "txt", 30),
    Collector("disk_df", "sys", ["df", "-h"], "txt", 20),
    Collector("processes_top", "sys", ["sh", "-c", "ps aux -r | head -60"], "txt", 30),
    Collector("launchd", "sys", ["launchctl", "list"], "txt", 30),
    Collector("battery", "sys", ["pmset", "-g", "batt"], "txt", 10),
    Collector("security", "sys", ["sh", "-c", "spctl --status; fdesetup status; csrutil status"], "txt", 20),
    Collector("updates_history", "sys", ["softwareupdate", "--history"], "txt", 60, quick=False),
    Collector("network", "net", ["system_profiler", "-json", "SPNetworkDataType"], "json", 60),
    Collector("ifconfig", "net", ["ifconfig"], "txt", 10),
    Collector("routes", "net", ["netstat", "-rn"], "txt", 10),
    Collector("dns", "net", ["scutil", "--dns"], "txt", 10),
    Collector("log_errors_30m", "logs", ["sh", "-c", "log show --last 30m --predicate 'messageType == error' --style compact 2>/dev/null | tail -500"], "txt", 120),
    Collector("hosts_file", "config", ["cat", "/etc/hosts"], "txt", 10),
    Collector("env_names", "config", ["sh", "-c", "env | cut -d= -f1 | sort"], "txt", 10),
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


def _write_capped(path: Path, data: bytes) -> int:
    if len(data) > MAX_OUTPUT_BYTES:
        data = data[:MAX_OUTPUT_BYTES] + b"\n... [truncated by aiit-agent]\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return len(data)


def run_one(c: Collector, out_root: Path) -> FileEntry:
    rel = f"{c.category}/{c.name}.{c.ext}"
    path = out_root / rel
    started = time.time()
    exit_code: int | None = None
    error: str | None = None
    output = b""
    argv = resolve_windows_argv(c.argv) if os.name == "nt" else c.argv
    try:
        if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
            raise FileNotFoundError(argv[0])
        pr = run_capped(argv, c.timeout, cap=MAX_OUTPUT_BYTES)
        if pr.timed_out:
            error = f"timeout after {c.timeout}s"
            output = pr.stdout.encode("utf-8", "replace") + b"\n[timeout]\n"
        else:
            exit_code = pr.exit_code
            output = pr.stdout.encode("utf-8", "replace")
            if pr.stderr:
                output += b"\n--- stderr ---\n" + pr.stderr.encode("utf-8", "replace")
    except FileNotFoundError:
        error = f"command not found: {argv[0]}"
    except Exception as e:  # pragma: no cover - defensive
        error = f"{type(e).__name__}: {e}"
    size = _write_capped(path, output if output else (error or "").encode("utf-8"))
    return FileEntry(
        path=rel, sha256=sha256_file(path), size=size, collector=c.name,
        command=" ".join(argv)[:300], exit_code=exit_code,
        duration_ms=int((time.time() - started) * 1000), error=error,
    )


def _native_platform(out_root: Path) -> FileEntry:
    rel = "sys/python_platform.json"
    path = out_root / rel
    u = platform.uname()
    data = {
        "system": u.system, "node": u.node, "release": u.release, "version": u.version,
        "machine": u.machine, "processor": u.processor, "python": platform.python_version(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return FileEntry(path=rel, sha256=sha256_file(path), size=path.stat().st_size, collector="disk_usage")


def _osquery(out_root: Path) -> list[FileEntry]:
    exe = shutil.which("osqueryi")
    if not exe:
        return []
    entries = []
    for name, sql in OSQUERY_QUERIES.items():
        entries.append(run_one(Collector(name, "osquery", [exe, "--json", sql], "json", 60), out_root))
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
        entries.append(run_one(c, out_root))
    if include_osquery:
        if progress:
            progress("osquery (if installed)")
        entries.extend(_osquery(out_root))
    return entries
