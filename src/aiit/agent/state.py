"""On-disk state of an endpoint agent."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..common.audit import AuditLog
from ..common.crypto import Identity
from ..common.policy import Policy
from ..common.schema import Enrollment
from ..common.util import ensure_private_dir, iso, new_id, read_json, write_json


def default_agent_dir() -> Path:
    env = os.environ.get("AIIT_AGENT_DIR")
    if env:
        return Path(env)
    if os.name == "nt":
        base = Path(os.environ.get("ProgramData", "C:\\ProgramData"))
        return base / "aiit" / "agent"
    return Path.home() / ".aiit" / "agent"


class AgentState:
    def __init__(self, root: Path | None = None):
        self.root = ensure_private_dir(root or default_agent_dir())
        self.keys_dir = self.root / "keys"
        self.console_file = self.root / "console-enrollment.json"
        self.policy_file = self.root / "policy.json"
        self.applied_file = self.root / "applied_plans.json"
        self.applying_file = self.root / "applying.json"
        self.inbox = self.root / "inbox"
        self.outbox = self.root / "outbox"
        self.sent = self.outbox / "sent"
        self.audit = AuditLog(self.root / "audit.jsonl", actor_id=self.agent_id_or_none() or "unenrolled")

    # -- identity -----------------------------------------------------------
    def agent_id_or_none(self) -> str | None:
        meta = self.keys_dir / "identity.json"
        if meta.exists():
            return read_json(meta).get("id")
        return None

    def public_sign_key(self) -> str | None:
        meta = self.keys_dir / "identity.json"
        return read_json(meta).get("sign_pub") if meta.exists() else None

    def is_enrolled(self) -> bool:
        return (self.keys_dir / "identity.json").exists() and self.console_file.exists()

    def identity(self) -> Identity:
        return Identity.load(self.keys_dir)

    def enroll(self, enrollment: Enrollment) -> Identity:
        ident = Identity.generate(new_id("agent-"), with_box=False)
        ident.save(self.keys_dir)
        write_json(self.console_file, enrollment.model_dump(), private=True)
        if not self.policy_file.exists():
            Policy().save(self.policy_file)
        if not self.applied_file.exists():
            write_json(self.applied_file, [], private=True)
        self.audit = AuditLog(self.root / "audit.jsonl", actor_id=ident.id)
        self.audit.record("enroll", console_id=enrollment.console_id, console_sign_pub=enrollment.console_sign_pub)
        return ident

    def enrollment(self) -> Enrollment:
        return Enrollment.model_validate(read_json(self.console_file))

    def policy(self) -> Policy:
        if not self.policy_file.exists():
            Policy().save(self.policy_file)
        return Policy.load(self.policy_file)

    # -- plan bookkeeping ---------------------------------------------------
    def applied_plan_ids(self) -> list[str]:
        if not self.applied_file.exists():
            return []
        return list(read_json(self.applied_file))

    def mark_applied(self, plan_id: str) -> None:
        ids = self.applied_plan_ids()
        if plan_id not in ids:
            ids.append(plan_id)
        write_json(self.applied_file, ids, private=True)

    def applying(self) -> dict[str, Any] | None:
        """Write-ahead marker of an enforce run in progress (survives a crash mid-plan)."""
        if not self.applying_file.exists():
            return None
        try:
            return read_json(self.applying_file)
        except Exception:
            return None

    def mark_applying(self, plan_id: str, completed_step_ids: list[str], current_step_id: str | None) -> None:
        write_json(self.applying_file, {"plan_id": plan_id, "completed": list(completed_step_ids), "current": current_step_id,
                                        "updated_at": iso()}, private=True)

    def clear_applying(self) -> None:
        self.applying_file.unlink(missing_ok=True)
