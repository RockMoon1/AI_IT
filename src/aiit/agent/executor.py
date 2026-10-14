"""Verify a signed plan and execute it under the local policy."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Callable

from ..common.audit import AuditLog
from ..common.crypto import verify_object
from ..common.policy import Policy
from ..common.schema import Enrollment, ExecutionReport, PlanStep, SignedPlan, StepResult
from ..common.util import current_os, hostname, iso, parse_iso, read_json, utcnow
from .procs import OUTPUT_CAP, powershell_exe, run_capped

__all__ = [
    "OUTPUT_CAP", "load_signed_plan", "verify_signed_plan", "shell_argv",
    "run_step", "preflight", "apply_plan",
]


def load_signed_plan(path: Path) -> SignedPlan:
    return SignedPlan.model_validate(read_json(path))


def verify_signed_plan(sp: SignedPlan, enrollment: Enrollment, agent_id: str,
                       applied_ids: list[str], *, max_plan_hours: int = 72) -> list[str]:
    """Return a list of reasons the plan must be refused (empty = OK).

    In addition to the signature, target, expiry and replay checks, the plan's
    timestamps are sanity checked: a ``created_at`` more than five minutes in
    the future is refused (clock skew or a forged future dating), and a plan
    whose lifetime (``expires_at - created_at``) is longer than
    ``max_plan_hours`` is refused so an over long approval window cannot be
    smuggled in.
    """
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
    try:
        created = parse_iso(sp.plan.created_at)
        if created > utcnow() + timedelta(minutes=5):
            problems.append("plan created_at is in the future")
        try:
            expires = parse_iso(sp.plan.expires_at)
            if expires - created > timedelta(hours=max_plan_hours):
                problems.append("plan lifetime too long")
        except Exception:
            pass  # unreadable expiry already reported above
    except Exception:
        problems.append("plan has an unreadable created_at")
    if sp.plan.plan_id in applied_ids:
        problems.append("plan was already applied on this endpoint (replay refused)")
    return problems


def shell_argv(command: str, os_name: str) -> list[str]:
    """Return the argv that runs ``command`` under the OS shell.

    On Windows the command is not placed on the argv: PowerShell is invoked
    with ``-Command -`` so it reads the script from stdin (see ``run_step``).
    This runs exactly the bytes the policy evaluated and avoids PowerShell
    re-parsing quotes on the command line. ``-EncodedCommand`` is deliberately
    not used because EDR flags it, and ``.ps1`` files are deliberately not used
    because AppLocker blocks them.
    """
    if os_name == "windows":
        return [powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"]
    return ["/bin/sh", "-c", command]


def run_step(step: PlanStep, os_name: str) -> StepResult:
    """Execute one command step through ``run_capped`` and build a StepResult."""
    started = iso()
    command = step.command or ""
    argv = shell_argv(command, os_name)
    stdin_bytes = (command.encode("utf-8") + b"\n") if os_name == "windows" else None
    try:
        pr = run_capped(argv, step.timeout_seconds, stdin_bytes=stdin_bytes, cap=OUTPUT_CAP)
    except Exception as e:  # pragma: no cover - defensive (e.g. shell missing)
        return StepResult(step_id=step.id, title=step.title, command=step.command, status="failed",
                          reason=f"{type(e).__name__}: {e}", started_at=started, ended_at=iso())
    if pr.timed_out:
        return StepResult(
            step_id=step.id, title=step.title, command=step.command, status="timeout",
            stdout=pr.stdout, reason=f"timed out after {step.timeout_seconds}s",
            started_at=started, ended_at=iso(),
        )
    return StepResult(
        step_id=step.id, title=step.title, command=step.command,
        status="success" if pr.exit_code == 0 else "failed", exit_code=pr.exit_code,
        stdout=pr.stdout, stderr=pr.stderr, started_at=started, ended_at=iso(),
    )


def preflight(sp: SignedPlan, policy: Policy, os_name: str,
              allow_reboot: bool) -> list[tuple[PlanStep, bool, str]]:
    """Evaluate every step against the policy before any step runs.

    Returns one ``(step, allowed, reason)`` tuple per step, in order. Manual
    steps are always allowed (they are instructions for the operator, not
    commands). This lets ``apply_plan`` refuse an entire plan up front rather
    than running half of it before discovering a later policy block.
    """
    out: list[tuple[PlanStep, bool, str]] = []
    for step in sp.plan.steps:
        if step.action != "command":
            out.append((step, True, ""))
            continue
        ok, reason = policy.evaluate(step, os_name, allow_reboot=allow_reboot)
        out.append((step, ok, reason))
    return out


def apply_plan(sp: SignedPlan, policy: Policy, agent_id: str, audit: AuditLog, *,
               dry_run: bool | None = None, allow_reboot: bool = False,
               stop_on_failure: bool = True, os_name: str | None = None,
               skip_step_ids: set[str] | None = None,
               on_step: Callable[[int, PlanStep, StepResult | None], None] | None = None) -> ExecutionReport:
    """Verify every step up front, then execute the allowed command steps.

    ``skip_step_ids`` names steps that completed in an earlier run (resume): they
    are reported as ``skipped`` with reason "completed in an earlier run" and
    never re-executed. ``on_step`` is called as ``on_step(index, step, None)``
    just before a command step runs and ``on_step(index, step, result)`` just
    after, so a caller can maintain a write ahead marker for resuming.

    If preflight finds any command step blocked by policy, nothing is executed:
    the report marks the blocked steps ``blocked_by_policy`` and all other steps
    ``skipped`` with reason "preflight: step <id> blocked".
    """
    os_name = os_name or current_os()
    skip_step_ids = skip_step_ids or set()
    effective_dry = policy.mode != "enforce" if dry_run is None else (dry_run or policy.mode != "enforce")
    mode = "dry_run" if effective_dry else "enforce"
    started = iso()

    pf = preflight(sp, policy, os_name, allow_reboot)
    blocked = [(step, reason) for step, ok, reason in pf if not ok]
    if blocked:
        first_id = blocked[0][0].id
        results: list[StepResult] = []
        for step, ok, reason in pf:
            if not ok:
                results.append(StepResult(step_id=step.id, title=step.title, command=step.command,
                                          status="blocked_by_policy", reason=reason))
            else:
                results.append(StepResult(step_id=step.id, title=step.title, command=step.command,
                                          status="skipped", reason=f"preflight: step {first_id} blocked"))
        audit.record("apply_preflight_failed", plan_id=sp.plan.plan_id, case_id=sp.plan.case_id,
                     mode=mode, blocked=[s.id for s, _ in blocked])
        return ExecutionReport(
            plan_id=sp.plan.plan_id, case_id=sp.plan.case_id, agent_id=agent_id, hostname=hostname(),
            platform=os_name, started_at=started, ended_at=iso(), mode=mode,
            policy_version=policy.version, results=results,
        )

    results = []
    audit.record("apply_start", plan_id=sp.plan.plan_id, case_id=sp.plan.case_id, mode=mode, steps=len(sp.plan.steps))
    halted = False
    for index, step in enumerate(sp.plan.steps):
        if step.id in skip_step_ids:
            results.append(StepResult(step_id=step.id, title=step.title, command=step.command,
                                      status="skipped", reason="completed in an earlier run"))
            continue
        if halted:
            results.append(StepResult(step_id=step.id, title=step.title, command=step.command,
                                      status="skipped", reason="earlier step failed"))
            continue
        if step.action == "manual":
            results.append(StepResult(step_id=step.id, title=step.title, status="manual",
                                      reason="instruction for the operator; not executed"))
            continue
        if effective_dry:
            results.append(StepResult(step_id=step.id, title=step.title, command=step.command,
                                      status="dry_run", reason="policy mode is dry_run"))
            continue
        if on_step:
            on_step(index, step, None)
        r = run_step(step, os_name)
        if on_step:
            on_step(index, step, r)
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
