"""Pydantic models for everything that crosses a trust boundary."""
from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

from .util import ID_RE

OSName = Literal["windows", "linux", "macos", "any"]
Risk = Literal["read_only", "low", "medium", "high"]
RISK_ORDER: dict[str, int] = {"read_only": 0, "low": 1, "medium": 2, "high": 3}

# Ids minted by util.new_id look like "case-3f9a1c2b7d4e". Anything else that
# arrives in a header, manifest or plan is rejected before it can touch a path.
IdStr = Annotated[str, StringConstraints(pattern=ID_RE.pattern)]
MAX_COMMAND_CHARS = 4096


def validate_relative_path(value: str) -> str:
    """Bundle member paths: relative, forward slashes, no drive, no '..', no control chars."""
    if not value or len(value) > 512 or "\x00" in value:
        raise ValueError("empty, too long or contains NUL")
    if "\\" in value:
        raise ValueError("backslashes are not allowed in bundle paths")
    if PureWindowsPath(value).drive or PurePosixPath(value).is_absolute() or value.startswith("/"):
        raise ValueError("absolute paths are not allowed in bundle paths")
    parts = PurePosixPath(value).parts
    if any(part in ("..", ".") for part in parts):
        raise ValueError("'.' and '..' are not allowed in bundle paths")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("control characters are not allowed in bundle paths")
    return value


class FileEntry(BaseModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int
    collector: str
    command: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    error: str | None = None

    @field_validator("path")
    @classmethod
    def _safe_path(cls, v: str) -> str:
        return validate_relative_path(v)


class BundleManifest(BaseModel):
    version: int = 1
    kind: Literal["diagnostics", "execution_report"] = "diagnostics"
    bundle_id: IdStr
    agent_id: IdStr
    hostname: str = Field(max_length=253)
    platform: OSName
    os_version: str = Field(max_length=512)
    collected_at: str
    aiit_version: str = Field(max_length=32)
    issue_description: str = Field(default="", max_length=20_000)
    case_id: IdStr | None = None
    plan_id: IdStr | None = None
    files: list[FileEntry] = Field(default_factory=list, max_length=2000)
    audit_head: dict[str, Any] | None = None


class PlanStep(BaseModel):
    id: str = Field(description="Short unique id like s1, s2")
    title: str
    rationale: str = Field(description="Why this step; cite the evidence from the bundle")
    action: Literal["command", "manual"] = Field(
        description="'command' runs on the endpoint via the OS shell; 'manual' is an instruction for the human"
    )
    os: OSName = "any"
    command: str | None = Field(default=None, max_length=MAX_COMMAND_CHARS, description="Single non-interactive command line; required when action=command")
    risk: Risk = Field(description="read_only: changes nothing; low: safe service restarts/cache clears; medium: config changes; high: data or boot affecting")
    requires_reboot: bool = False
    expected_outcome: str = ""
    rollback: str | None = Field(default=None, description="How to undo if the step makes things worse")
    timeout_seconds: int = Field(default=120, ge=5, le=3600)

    @model_validator(mode="after")
    def _cmd_required(self) -> "PlanStep":
        if self.action == "command":
            if not (self.command and self.command.strip()):
                raise ValueError("command is required when action is 'command'")
            if "\n" in self.command or "\r" in self.command or "\x00" in self.command:
                raise ValueError("command must be a single line without control characters")
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
    plan_id: IdStr
    case_id: IdStr
    target_agent_id: IdStr
    target_os: OSName
    created_at: str
    expires_at: str
    provider: str
    model: str
    redaction_applied: bool = True


class SignedPlan(BaseModel):
    plan: FixPlan
    signer_id: IdStr
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
    plan_id: IdStr
    case_id: IdStr
    agent_id: IdStr
    hostname: str = Field(max_length=253)
    platform: OSName
    started_at: str
    ended_at: str
    mode: Literal["dry_run", "enforce"]
    policy_version: str
    results: list[StepResult]
    audit_head: dict[str, Any] | None = None


class Enrollment(BaseModel):
    """Public information an endpoint needs to trust a console. Safe to copy anywhere."""

    version: int = 1
    console_id: IdStr
    console_sign_pub: str = Field(pattern=r"^[0-9a-f]{64}$")
    console_box_pub: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: str
    label: str = ""


def plan_json_schema() -> dict[str, Any]:
    """JSON schema handed to LLM providers for structured output."""
    return FixPlanDraft.model_json_schema()
