"""Build a bounded, redacted prompt from a case and turn the model's answer into a signed plan."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from pydantic import ValidationError

from ..common.crypto import sign_object
from ..common.redact import Redactor
from ..common.schema import RISK_ORDER, FixPlan, FixPlanDraft, SignedPlan, plan_json_schema
from ..common.util import in_hours, iso, new_id, os_user, read_json, truncate, write_json
from .llm import LLMProvider, ProviderError
from .store import ConsoleState

SYSTEM_PROMPT = """You are a senior IT support engineer producing a repair plan for one endpoint.

You receive a diagnostic bundle collected from the machine. Identifiers in it have been
replaced with tokens such as <EMAIL_1a2b3c4d>, <USER_9f8e7d6c>, <HOST_...>, <IP_...>; treat each
token as a stable placeholder and never try to guess the original value.

Produce a JSON plan that matches the schema you were given. Rules:
- Base the diagnosis on evidence in the bundle and cite the file and the line you relied on in each rationale.
- Order steps safest first: read-only checks, then low-risk repairs, then anything medium or high.
- Every "command" step is one non-interactive command line for the stated OS (PowerShell on Windows,
  POSIX sh on Linux and macOS). No prompts, no pagers, no interactive editors, no piping remote content to a shell.
- Never propose formatting disks, deleting user data, creating accounts, disabling security tools or firewalls,
  or changing boot configuration. If such an action seems necessary, make it a "manual" step for the human.
- Set risk honestly. read_only changes nothing. low is a service restart or cache clear. medium changes
  configuration. high can affect data or boot.
- Give a concrete expected outcome for each step and a rollback for anything that is not read-only.
- If the bundle is not enough, keep the plan to read-only checks and list what else you need in more_data_needed.
- Confidence is your calibrated probability that the diagnosis is correct.
"""

PRIORITY = ["failed", "error", "journal", "event", "bugcheck", "dmesg", "services", "launchd", "disk", "volume", "df", "lsblk",
            "memory", "free", "uptime", "net", "ip", "dns", "route", "adapter", "proxy", "firewall", "process", "hotfix",
            "update", "driver", "pnp", "defender", "bitlocker", "osquery"]


def _rank(path: str) -> int:
    low = path.lower()
    for i, kw in enumerate(PRIORITY):
        if kw in low:
            return i
    return len(PRIORITY)


def _case_redactor(cdir: Path) -> Redactor:
    key = (cdir / "redaction.key").read_bytes()
    r = Redactor(key)
    mp = cdir / "redaction_map.json"
    if mp.exists():
        r.map.update(read_json(mp))
    return r


def build_context(cdir: Path, operator_issue: str = "", max_chars: int = 150_000, per_file_cap: int = 24_000) -> tuple[str, list[str]]:
    case = read_json(cdir / "case.json")
    rdir = cdir / "redacted"
    manifest = read_json(rdir / "manifest.json")
    parts: list[str] = []
    parts.append(f"# Case {case['case_id']}\nplatform: {manifest['platform']}\nos_version: {manifest['os_version']}\n"
                 f"hostname: {manifest['hostname']}\ncollected_at: {manifest['collected_at']}\n")
    if manifest.get("issue_description"):
        parts.append(f"Issue as reported at the endpoint: {manifest['issue_description']}\n")
    if operator_issue:
        parts.append(f"Issue as described by the operator: {operator_issue}\n")
    errs = [f for f in manifest["files"] if f.get("error") or (f.get("exit_code") not in (0, None))]
    if errs:
        parts.append("Collectors that failed or returned non-zero (their output may be partial):\n" +
                     "\n".join(f"- {f['path']}: exit={f.get('exit_code')} error={f.get('error')}" for f in errs) + "\n")
    reports_dir = cdir / "reports"
    if reports_dir.exists():
        red = _case_redactor(cdir)
        for rd in sorted(reports_dir.iterdir()):
            rj = rd / "report.json"
            if rj.exists():
                txt = red.redact(json.dumps(read_json(rj), indent=1))
                parts.append(f"## Previous execution report {rd.name}\n{truncate(txt, per_file_cap)}\n")
        write_json(cdir / "redaction_map.json", red.map, private=True)
    header = "\n".join(parts)
    budget = max_chars - len(header)
    included: list[str] = []
    body: list[str] = []
    files = sorted(manifest["files"], key=lambda f: (_rank(f["path"]), f["path"]))
    for f in files:
        p = rdir / f["path"]
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            continue
        chunk = f"\n### {f['path']} (exit={f.get('exit_code')})\n{truncate(text, per_file_cap)}\n"
        if len(chunk) > budget:
            if budget > 2000:
                chunk = truncate(chunk, budget)
            else:
                break
        body.append(chunk)
        included.append(f["path"])
        budget -= len(chunk)
    return header + "\n## Collected files\n" + "".join(body), included


def diagnose(state: ConsoleState, case_id: str, issue: str, provider: LLMProvider, max_chars: int = 150_000, hours_valid: float = 24.0) -> FixPlan:
    cdir = state.case_dir(case_id)
    case = read_json(cdir / "case.json")
    context, included = build_context(cdir, issue, max_chars=max_chars)
    meta = {"target_os": case["platform"], "issue": issue or case.get("issue_description", ""), "case_id": case_id}
    state.audit.record("llm_request", case_id=case_id, provider=provider.name, model=provider.model, files_included=len(included), chars=len(context))
    try:
        raw, usage = provider.complete_json(SYSTEM_PROMPT, context, plan_json_schema(), meta)
    except ProviderError as e:
        state.audit.record("llm_error", case_id=case_id, provider=provider.name, error=str(e)[:300])
        raise
    state.audit.record("llm_response", case_id=case_id, usage=usage)
    try:
        draft = FixPlanDraft.model_validate(raw)
    except ValidationError as e:
        state.audit.record("llm_invalid_plan", case_id=case_id, provider=provider.name, errors=str(e)[:500])
        raise ProviderError(f"model output did not match the plan schema:\n{e}") from e
    plan = FixPlan(
        **draft.model_dump(), plan_id=new_id("plan-"), case_id=case_id, target_agent_id=case["agent_id"], target_os=case["platform"],
        created_at=iso(), expires_at=in_hours(hours_valid), provider=provider.name, model=str(usage.get("model") or provider.model),
    )
    write_json(cdir / "plans" / f"{plan.plan_id}.json", plan.model_dump(), private=True)
    case.setdefault("plans", []).append({"plan_id": plan.plan_id, "created_at": plan.created_at, "provider": plan.provider, "model": plan.model,
                                         "confidence": plan.confidence, "steps": len(plan.steps), "approved": False})
    write_json(cdir / "case.json", case, private=True)
    max_risk = max((s.risk for s in plan.steps), key=lambda r: RISK_ORDER[r], default="read_only")
    state.audit.record("plan_created", case_id=case_id, plan_id=plan.plan_id, steps=len(plan.steps), confidence=plan.confidence, max_risk=max_risk)
    return plan


def load_plan(cdir: Path, plan_id: str) -> FixPlan:
    return FixPlan.model_validate(read_json(cdir / "plans" / f"{plan_id}.json"))


def approve(state: ConsoleState, case_id: str, plan_id: str, operator: str | None = None, out_dir: Path | None = None, hours_valid: float | None = None) -> Path:
    cdir = state.case_dir(case_id)
    plan = load_plan(cdir, plan_id)
    if hours_valid is not None:
        plan.expires_at = in_hours(hours_valid)
        write_json(cdir / "plans" / f"{plan_id}.json", plan.model_dump(), private=True)
    ident = state.identity()
    sp = SignedPlan(
        plan=plan, signer_id=ident.id, signer_pub=ident.sign_pub_hex, approved_by=operator or os_user(), approved_at=iso(),
        signature=sign_object(ident, plan.model_dump()),
    )
    path = cdir / "plans" / f"{plan_id}.signed.json"
    write_json(path, sp.model_dump(), private=True)
    write_json(state.outbox / plan.target_agent_id / f"{plan_id}.signed.json", sp.model_dump(), private=True)
    case = read_json(cdir / "case.json")
    for p in case.get("plans", []):
        if p["plan_id"] == plan_id:
            p.update({"approved": True, "approved_by": sp.approved_by, "approved_at": sp.approved_at})
    write_json(cdir / "case.json", case, private=True)
    state.audit.record("plan_approved", case_id=case_id, plan_id=plan_id, approved_by=sp.approved_by, expires_at=plan.expires_at,
                       target_agent_id=plan.target_agent_id, steps=len(plan.steps))
    if out_dir:
        out_dir = Path(out_dir)
        if out_dir.is_dir() or not out_dir.suffix:
            out_dir.mkdir(parents=True, exist_ok=True)
            dest = out_dir / path.name
        else:
            dest = out_dir
        shutil.copyfile(path, dest)
        return dest
    return path


def format_plan(plan: FixPlan) -> str:
    lines = [f"Plan {plan.plan_id}  case={plan.case_id}  target={plan.target_agent_id} ({plan.target_os})  provider={plan.provider}/{plan.model}",
             f"Expires: {plan.expires_at}", "", f"Issue: {plan.issue_summary}", f"Diagnosis ({plan.confidence:.0%}): {plan.diagnosis}"]
    if plan.alternative_causes:
        lines.append("Alternatives: " + "; ".join(plan.alternative_causes))
    lines.append("")
    for s in plan.steps:
        lines.append(f"[{s.id}] ({s.risk}{', reboot' if s.requires_reboot else ''}) {s.title}")
        lines.append(f"     why: {s.rationale}")
        if s.action == "command":
            lines.append(f"     $ {s.command}")
            if s.expected_outcome:
                lines.append(f"     expect: {s.expected_outcome}")
        else:
            lines.append(f"     manual: {s.expected_outcome or s.rationale}")
        if s.rollback:
            lines.append(f"     rollback: {s.rollback}")
    if plan.more_data_needed:
        lines.append("\nMore data needed: " + "; ".join(plan.more_data_needed))
    if plan.notes_for_operator:
        lines.append(f"\nNotes: {plan.notes_for_operator}")
    return "\n".join(lines)
