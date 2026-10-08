"""Verify a signed plan and execute it under the local policy."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..common.audit import AuditLog
from ..common.crypto import verify_object
from ..common.policy import Policy
from ..common.schema import Enrollment, ExecutionReport, PlanStep, SignedPlan, StepResult
from ..common.util import current_os, hostname, iso, parse_iso, read_json, truncate, utcnow

OUTPUT_CAP = 20_000


def load_signed_plan(path: Path) -> SignedPlan:
    return SignedPlan.model_validate(read_json(path))


def verify_signed_plan(sp: SignedPlan, enrollment: Enrollment, agent_id: str, applied_ids: list[str]) -> list[str]:
    """Return a list of reasons the plan must be refused (empty = OK)."""
    problems: list[str] = []
    if sp.signer_pub != enrollment.console_sign_pub or sp.signer_id != enrollment.console_id:
        problems.append("plan is not signed by the enrolled console")
    if not verify_object(sp.signer_pub, sp.plan.model_dump(), sp.signature):
        problems.append("plan signature is invalid (plan was modified after approval)")
    if sp.plan.target_agent_id != agent_id:
        problems.append(f"plan targets agent {sp.plan.target_agent_id}, this agent is {agent_id}")
    try:
        if parse_iso(sp.plan.expires_at) < utcnow():
            problems.append(f"plan expired at {sp.plan.expires_at}")
    except Exception:
        problems.append("plan has an unreadable expiry")
    if sp.plan.plan_id in applied_ids:
        problems.append("plan was already applied on this endpoint (replay refused)")
    return problems


def shell_argv(command: str, os_name: str) -> list[str]:
    if os_name == "windows":
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]
    return ["/bin/sh", "-c", command]


def run_step(step: PlanStep, os_name: str) -> StepResult:
    started = iso()
    argv = shell_argv(step.command or "", os_name)
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=step.timeout_seconds, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        return StepResult(
            step_id=step.id, title=step.title, command=step.command,
            status="success" if proc.returncode == 0 else "failed",
            exit_code=proc.returncode,
            stdout=truncate(proc.stdout.decode("utf-8", "replace"), OUTPUT_CAP),
            stderr=truncate(proc.stderr.decode("utf-8", "replace"), OUTPUT_CAP),
            started_at=started, ended_at=iso(),
        )
    except subprocess.TimeoutExpired as e:
        return StepResult(
            step_id=step.id, title=step.title, command=step.command, status="timeout",
            stdout=truncate((e.stdout or b"").decode("utf-8", "replace"), OUTPUT_CAP),
            reason=f"timed out after {step.timeout_seconds}s", started_at=started, ended_at=iso(),
        )
    except Exception as e:  # pragma: no cover - defensive
        return StepResult(step_id=step.id, title=step.title, command=step.command, status="failed",
                          reason=f"{type(e).__name__}: {e}", started_at=started, ended_at=iso())


def apply_plan(sp: SignedPlan, policy: Policy, agent_id: str, audit: AuditLog, *,
               dry_run: bool | None = None, allow_reboot: bool = False,
               stop_on_failure: bool = True, os_name: str | None = None) -> ExecutionReport:
    os_name = os_name or current_os()
    effective_dry = policy.mode != "enforce" if dry_run is None else (dry_run or policy.mode != "enforce")
    mode = "dry_run" if effective_dry else "enforce"
    started = iso()
    results: list[StepResult] = []
    audit.record("apply_start", plan_id=sp.plan.plan_id, case_id=sp.plan.case_id, mode=mode, steps=len(sp.plan.steps))
    halted = False
    for step in sp.plan.steps:
        if halted:
            results.append(StepResult(step_id=step.id, title=step.title, command=step.command, status="skipped", reason="earlier step failed"))
            continue
        if step.action == "manual":
            results.append(StepResult(step_id=step.id, title=step.title, status="manual", reason="instruction for the operator; not executed"))
            continue
        ok, reason = policy.evaluate(step, os_name, allow_reboot=allow_reboot)
        if not ok:
            r = StepResult(step_id=step.id, title=step.title, command=step.command, status="blocked_by_policy", reason=reason)
            results.append(r)
            audit.record("step_blocked", plan_id=sp.plan.plan_id, step_id=step.id, reason=reason)
            continue
        if effective_dry:
            results.append(StepResult(step_id=step.id, title=step.title, command=step.command, status="dry_run", reason="policy mode is dry_run"))
            continue
        r = run_step(step, os_name)
        results.append(r)
        audit.record("step_run", plan_id=sp.plan.plan_id, step_id=step.id, status=r.status, exit_code=r.exit_code, risk=step.risk)
        if r.status in ("failed", "timeout") and stop_on_failure:
            halted = True
    report = ExecutionReport(
        plan_id=sp.plan.plan_id, case_id=sp.plan.case_id, agent_id=agent_id, hostname=hostname(),
        platform=os_name, started_at=started, ended_at=iso(), mode=mode, policy_version=policy.version, results=results,
    )
    audit.record("apply_end", plan_id=sp.plan.plan_id, mode=mode,
                 summary={s: sum(1 for r in results if r.status == s) for s in sorted({r.status for r in results})})
    return report
