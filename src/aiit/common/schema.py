"""Pydantic models for everything that crosses a trust boundary."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

OSName = Literal["windows", "linux", "macos", "any"]
Risk = Literal["read_only", "low", "medium", "high"]
RISK_ORDER: dict[str, int] = {"read_only": 0, "low": 1, "medium": 2, "high": 3}


class FileEntry(BaseModel):
    path: str
    sha256: str
    size: int
    collector: str
    command: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    error: str | None = None


class BundleManifest(BaseModel):
    version: int = 1
    kind: Literal["diagnostics", "execution_report"] = "diagnostics"
    bundle_id: str
    agent_id: str
    hostname: str
    platform: OSName
    os_version: str
    collected_at: str
    aiit_version: str
    issue_description: str = ""
    case_id: str | None = None
    plan_id: str | None = None
    files: list[FileEntry] = Field(default_factory=list)


class PlanStep(BaseModel):
    id: str = Field(description="Short unique id like s1, s2")
    title: str
    rationale: str = Field(description="Why this step; cite the evidence from the bundle")
    action: Literal["command", "manual"] = Field(
        description="'command' runs on the endpoint via the OS shell; 'manual' is an instruction for the human"
    )
    os: OSName = "any"
    command: str | None = Field(default=None, description="Single non-interactive command line; required when action=command")
    risk: Risk = Field(description="read_only: changes nothing; low: safe service restarts/cache clears; medium: config changes; high: data or boot affecting")
    requires_reboot: bool = False
    expected_outcome: str = ""
    rollback: str | None = Field(default=None, description="How to undo if the step makes things worse")
    timeout_seconds: int = Field(default=120, ge=5, le=3600)

    @model_validator(mode="after")
    def _cmd_required(self) -> "PlanStep":
        if self.action == "command" and not (self.command and self.command.strip()):
            raise ValueError("command is required when action is 'command'")
        return self


class FixPlanDraft(BaseModel):
    """What the model is asked to produce. The console fills in the rest."""

    issue_summary: str
    diagnosis: str = Field(description="Most likely root cause with evidence")
    confidence: float = Field(ge=0.0, le=1.0)
    alternative_causes: list[str] = Field(default_factory=list)
    steps: list[PlanStep]
    notes_for_operator: str = ""
    more_data_needed: list[str] = Field(default_factory=list, description="Extra logs or facts that would raise confidence")


class FixPlan(FixPlanDraft):
    plan_id: str
    case_id: str
    target_agent_id: str
    target_os: OSName
    created_at: str
    expires_at: str
    provider: str
    model: str
    redaction_applied: bool = True


class SignedPlan(BaseModel):
    plan: FixPlan
    signer_id: str
    signer_pub: str
    approved_by: str
    approved_at: str
    signature: str


class StepResult(BaseModel):
    step_id: str
    title: str
    status: Literal["success", "failed", "dry_run", "blocked_by_policy", "skipped", "manual", "timeout"]
    command: str | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    reason: str = ""
    started_at: str = ""
    ended_at: str = ""


class ExecutionReport(BaseModel):
    plan_id: str
    case_id: str
    agent_id: str
    hostname: str
    platform: OSName
    started_at: str
    ended_at: str
    mode: Literal["dry_run", "enforce"]
    policy_version: str
    results: list[StepResult]


class Enrollment(BaseModel):
    """Public information an endpoint needs to trust a console. Safe to copy anywhere."""

    version: int = 1
    console_id: str
    console_sign_pub: str
    console_box_pub: str
    created_at: str
    label: str = ""


def plan_json_schema() -> dict[str, Any]:
    """JSON schema handed to LLM providers for structured output."""
    return FixPlanDraft.model_json_schema()
