"""Console state: identity, enrollment file, agent registry, cases, audit."""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from ..common.audit import AuditLog
from ..common.bundle import read_bundle, unpack_to
from ..common.crypto import CryptoError, Identity
from ..common.redact import RedactionConfig, Redactor
from ..common.schema import BundleManifest, Enrollment, ExecutionReport
from ..common.util import ensure_private_dir, iso, new_id, read_json, sha256_file, write_json, write_private_file


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader (KEY=VALUE lines) so operators keep secrets out of shell history."""
    p = path or Path.cwd() / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def default_console_dir() -> Path:
    env = os.environ.get("AIIT_CONSOLE_DIR")
    return Path(env) if env else Path.home() / ".aiit" / "console"


class ConsoleState:
    def __init__(self, root: Path | None = None):
        self.root = ensure_private_dir(root or default_console_dir())
        self.keys_dir = self.root / "keys"
        self.enrollment_file = self.root / "enrollment" / "console-enrollment.json"
        self.agents_file = self.root / "agents.json"
        self.cases_dir = self.root / "cases"
        self.inbox = self.root / "inbox"
        self.outbox = self.root / "outbox"
        self.audit = AuditLog(self.root / "audit.jsonl", actor_id=self.console_id_or_none() or "uninitialized")

    def console_id_or_none(self) -> str | None:
        meta = self.keys_dir / "identity.json"
        return read_json(meta).get("id") if meta.exists() else None

    def is_initialized(self) -> bool:
        return (self.keys_dir / "identity.json").exists()

    def identity(self) -> Identity:
        return Identity.load(self.keys_dir)

    def init(self, label: str = "") -> Enrollment:
        if self.is_initialized():
            raise RuntimeError(f"console already initialized at {self.root}")
        ident = Identity.generate(new_id("console-"), with_box=True)
        ident.save(self.keys_dir)
        enr = Enrollment(console_id=ident.id, console_sign_pub=ident.sign_pub_hex, console_box_pub=ident.box_pub_hex or "", created_at=iso(), label=label)
        write_json(self.enrollment_file, enr.model_dump())
        write_json(self.agents_file, {}, private=True)
        self.audit = AuditLog(self.root / "audit.jsonl", actor_id=ident.id)
        self.audit.record("init", label=label)
        return enr

    # -- agents (trust on first use)
    def agents(self) -> dict[str, Any]:
        return read_json(self.agents_file) if self.agents_file.exists() else {}

    def register_agent(self, agent_id: str, sign_pub: str, hostname: str) -> str:
        """Returns 'new', 'known' or raises CryptoError on key mismatch."""
        agents = self.agents()
        known = agents.get(agent_id)
        if known is None:
            agents[agent_id] = {"sign_pub": sign_pub, "hostname": hostname, "first_seen": iso(), "last_seen": iso()}
            write_json(self.agents_file, agents, private=True)
            return "new"
        if known["sign_pub"] != sign_pub:
            raise CryptoError(f"agent {agent_id} presented a different signing key than the one on record")
        known["last_seen"] = iso()
        known["hostname"] = hostname
        write_json(self.agents_file, agents, private=True)
        return "known"

    # -- cases
    def case_dir(self, case_id: str) -> Path:
        d = self.cases_dir / case_id
        if not d.exists():
            raise FileNotFoundError(f"no case {case_id}")
        return d

    def list_cases(self) -> list[dict[str, Any]]:
        out = []
        if self.cases_dir.exists():
            for d in sorted(self.cases_dir.iterdir()):
                cj = d / "case.json"
                if cj.exists():
                    out.append(read_json(cj))
        return out

    def ingest_bundle(self, path: Path, redaction: RedactionConfig | None = None) -> tuple[str, BundleManifest, dict[str, Any]]:
        """Decrypt, verify, redact. Returns (case_id, manifest, summary)."""
        ident = self.identity()
        hdr, plaintext = read_bundle(path, ident)
        kind = hdr.get("kind", "diagnostics")
        if kind == "execution_report":
            return self._ingest_report(path, hdr, plaintext)
        case_id = new_id("case-")
        cdir = ensure_private_dir(self.cases_dir / case_id)
        raw = cdir / "raw"
        names = unpack_to(plaintext, raw)
        if "manifest.json" not in names:
            raise CryptoError("bundle has no manifest.json")
        manifest = BundleManifest.model_validate(read_json(raw / "manifest.json"))
        if manifest.agent_id != hdr.get("agent_id"):
            raise CryptoError("manifest agent id does not match the sealed header")
        bad = [f.path for f in manifest.files if not (raw / f.path).exists() or sha256_file(raw / f.path) != f.sha256]
        if bad:
            raise CryptoError(f"file hash mismatch inside bundle: {bad[:5]}")
        trust = self.register_agent(manifest.agent_id, hdr["agent_sign_pub"], manifest.hostname)
        (cdir / "bundle.aiit").write_bytes(path.read_bytes())
        # redaction
        key = secrets.token_bytes(32)
        write_private_file(cdir / "redaction.key", key)
        cfg = redaction or RedactionConfig()
        cfg.redact_hostnames = list(dict.fromkeys(cfg.redact_hostnames + [manifest.hostname]))
        red = Redactor(key, cfg)
        rdir = cdir / "redacted"
        for f in manifest.files:
            src = raw / f.path
            dst = rdir / f.path
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                text = src.read_text(encoding="utf-8", errors="replace")
            except Exception:
                dst.write_text("[binary or unreadable file omitted]", encoding="utf-8")
                continue
            dst.write_text(red.redact(text), encoding="utf-8")
        # manifest copy with hostname/issue redacted too
        m_red = manifest.model_dump()
        m_red["hostname"] = red.token("HOST", manifest.hostname) if manifest.hostname else ""
        m_red["issue_description"] = red.redact(manifest.issue_description)
        write_json(rdir / "manifest.json", m_red)
        write_json(cdir / "redaction_map.json", red.map, private=True)
        case = {
            "case_id": case_id, "created_at": iso(), "agent_id": manifest.agent_id, "hostname": manifest.hostname,
            "platform": manifest.platform, "os_version": manifest.os_version, "collected_at": manifest.collected_at,
            "issue_description": manifest.issue_description, "bundle_id": manifest.bundle_id, "agent_trust": trust,
            "files": len(manifest.files), "collector_errors": sum(1 for f in manifest.files if f.error),
            "redaction_counts": red.stats.counts, "plans": [], "reports": [],
        }
        write_json(cdir / "case.json", case, private=True)
        self.audit.record("ingest", case_id=case_id, bundle_id=manifest.bundle_id, agent_id=manifest.agent_id, agent_trust=trust,
                          files=len(manifest.files), redactions=red.stats.counts)
        return case_id, manifest, case

    def _ingest_report(self, path: Path, hdr: dict[str, Any], plaintext: bytes) -> tuple[str, BundleManifest, dict[str, Any]]:
        case_id = hdr.get("case_id")
        if not case_id:
            raise CryptoError("execution report has no case id")
        cdir = self.case_dir(case_id)
        rdir = cdir / "reports" / hdr["bundle_id"]
        names = unpack_to(plaintext, rdir)
        manifest = BundleManifest.model_validate(read_json(rdir / "manifest.json"))
        case = read_json(cdir / "case.json")
        if manifest.agent_id != case["agent_id"]:
            raise CryptoError("report comes from a different agent than the case")
        self.register_agent(manifest.agent_id, hdr["agent_sign_pub"], manifest.hostname)
        report = ExecutionReport.model_validate(read_json(rdir / "report.json"))
        (rdir / "bundle.aiit").write_bytes(path.read_bytes())
        summary = {s: sum(1 for r in report.results if r.status == s) for s in sorted({r.status for r in report.results})}
        case["reports"].append({"bundle_id": hdr["bundle_id"], "plan_id": report.plan_id, "mode": report.mode, "received_at": iso(), "summary": summary})
        write_json(cdir / "case.json", case, private=True)
        self.audit.record("report", case_id=case_id, plan_id=report.plan_id, bundle_id=hdr["bundle_id"], mode=report.mode, summary=summary)
        return case_id, manifest, case
