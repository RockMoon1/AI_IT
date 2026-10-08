"""No-model provider: emits a safe, read-only checklist so the pipeline works offline."""
from __future__ import annotations

from typing import Any

from .base import LLMProvider

CHECKS: dict[str, list[tuple[str, str, str]]] = {
    "windows": [
        ("Check disk space", "Get-Volume | Select DriveLetter,SizeRemaining,Size", "Low free space on C: causes many update and application failures"),
        ("Check automatic services that are not running", "Get-CimInstance Win32_Service | Where {$_.StartMode -eq 'Auto' -and $_.State -ne 'Running'} | Select Name,State", "Stopped auto services point at the failing component"),
        ("Scan system files", "sfc /verifyonly", "Read-only integrity check before any repair"),
        ("Recent critical system events", "Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2} -MaxEvents 20 | Select TimeCreated,Id,ProviderName,Message", "Confirms whether errors recur during the session"),
    ],
    "linux": [
        ("Check disk space", "df -h", "Full filesystems break logging, updates and logins"),
        ("List failed systemd units", "systemctl --failed --no-pager", "Failed units identify the broken service"),
        ("Recent kernel and service errors", "journalctl -p 3 -n 50 --no-pager", "Confirms whether errors recur"),
        ("Memory pressure", "free -m", "Swapping or OOM explains slowness and kills"),
    ],
    "macos": [
        ("Check disk space", "df -h", "Full disks break updates and logins"),
        ("Recent error log lines", "log show --last 15m --predicate 'messageType == error' --style compact | tail -50", "Confirms whether errors recur"),
        ("Launch agents and daemons", "launchctl list | head -50", "Crashing agents show non-zero exit codes"),
    ],
}


class DryRunProvider(LLMProvider):
    name = "dryrun"
    model = "none"

    def __init__(self, **_: Any):
        pass

    def complete_json(self, system: str, user: str, schema: dict[str, Any], meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        os_name = meta.get("target_os", "linux")
        if os_name not in CHECKS:
            os_name = "linux"
        steps = []
        for i, (title, cmd, why) in enumerate(CHECKS[os_name], start=1):
            steps.append({
                "id": f"s{i}", "title": title, "rationale": why, "action": "command", "os": os_name,
                "command": cmd, "risk": "read_only", "requires_reboot": False,
                "expected_outcome": "Output reviewed by the operator", "rollback": None, "timeout_seconds": 120,
            })
        steps.append({
            "id": f"s{len(steps)+1}", "title": "Operator review", "rationale": "No model was used (dryrun provider)",
            "action": "manual", "os": "any", "command": None, "risk": "read_only", "requires_reboot": False,
            "expected_outcome": "Operator reads the collected files and decides the next step", "rollback": None, "timeout_seconds": 60,
        })
        plan = {
            "issue_summary": meta.get("issue", "") or "No issue description provided",
            "diagnosis": "Dry-run provider: no diagnosis. Read-only checks only.",
            "confidence": 0.0,
            "alternative_causes": [],
            "steps": steps,
            "notes_for_operator": "Switch AIIT_PROVIDER to ollama or anthropic for a real diagnosis.",
            "more_data_needed": [],
        }
        return plan, {"provider": self.name, "model": self.model, "input_chars": len(system) + len(user)}
