"""Console state: identity, enrollment file, agent registry, cases, audit.

Ingest is the console's main trust boundary. Everything that arrives in a
bundle header or manifest is treated as hostile until validated: ids must
match the strict id shape, member paths must be relative, every listed file
must exist in the archive with the recorded hash, and nothing is written to
its final location until all of that has passed.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..common.audit import AuditLog
from ..common.bundle import read_bundle, unpack_to
from ..common.crypto import CryptoError, Identity
from ..common.redact import RedactionConfig, Redactor
from ..common.schema import BundleManifest, Enrollment, ExecutionReport
from ..common.util import (ensure_private_dir, file_lock, iso, new_id, read_json, safe_join, sha256_file,
                           validate_id, write_json, write_private_file)

USERNAME_STOPLIST = {"administrator", "guest", "defaultaccount", "wdagutilityaccount", "root", "system", "public",
                     "default", "nobody", "daemon", "local service", "network service", "admin", "user", "test"}


def load_dotenv(explicit: Path | None = None, console_dir: Path | None = None) -> Path | None:
    """Load KEY=VALUE lines from the console's own .env (never the current directory).

    Order: explicit path, AIIT_ENV_FILE, <console_dir>/.env. Existing environment
    variables win. AIIT_CONSOLE_DIR is ignored inside the file (it decides where
    the file lives, so it cannot come from the file). On POSIX a group- or
    world-writable file is refused. Returns the path that was loaded, if any.
    """
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    elif os.environ.get("AIIT_ENV_FILE"):
        candidates.append(Path(os.environ["AIIT_ENV_FILE"]))
    elif console_dir is not None:
        candidates.append(Path(console_dir) / ".env")
    loaded: Path | None = None
    for p in candidates:
        if not p.is_file():
            continue
        if os.name != "nt":
            mode = p.stat().st_mode
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                print(f"warning: refusing to load {p}: it is group- or world-writable (chmod 600 it)", file=sys.stderr)
                continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k == "AIIT_CONSOLE_DIR" or not k:
                continue
            os.environ.setdefault(k, v)
        loaded = p
        break
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file() and (loaded is None or cwd_env.resolve() != loaded.resolve()):
        print(f"note: {cwd_env} was not loaded; the console reads <data dir>/.env or --env-file", file=sys.stderr)
    return loaded


def default_console_dir() -> Path:
    env = os.environ.get("AIIT_CONSOLE_DIR")
    return Path(env) if env else Path.home() / ".aiit" / "console"


def _harvest_usernames(raw: Path) -> list[str]:
    """Best-effort list of account names found in a bundle, used as extra redaction literals."""
    found: set[str] = set()

    def add(value: Any) -> None:
        if not isinstance(value, str):
            return
        v = value.strip()
        if "\\" in v:
            v = v.rsplit("\\", 1)[-1]
        m = re.match(r"^(.*?)\s*\(([^)]+)\)\s*$", v)  # macOS "Jane Smith (jsmith)"
        if m:
            add(m.group(1))
            v = m.group(2)
        v = v.strip()
        if len(v) >= 4 and v.lower() not in USERNAME_STOPLIST and not v.isdigit():
            found.add(v)

    def walk(obj: Any, keys: set[str]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in keys:
                    add(v)
                walk(v, keys)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, keys)

    sources = {
        "sys/local_users.json": {"name"},
        "sys/computerinfo.json": {"csusername", "registeredowner", "csprimaryownername"},
        "osquery/logged_in_users.json": {"user"},
        "sys/hardware.json": {"user_name"},
    }
    for rel, keys in sources.items():
        p = raw / rel
        if not p.is_file():
            continue
        try:
            walk(json.loads(p.read_text(encoding="utf-8", errors="replace")), keys)
        except Exception:
            continue
    return sorted(found)


class ConsoleState:
    def __init__(self, root: Path | None = None):
        self.root = ensure_private_dir(root or default_console_dir())
        self.keys_dir = self.root / "keys"
        self.enrollment_file = self.root / "enrollment" / "console-enrollment.json"
        self.agents_file = self.root / "agents.json"
        self.bundles_index_file = self.root / "bundles_index.json"
        self.state_lock = self.root / "state"
        self.cases_dir = self.root / "cases"
        self.inbox = self.root / "inbox"
        self.outbox = self.root / "outbox"
        self.audit = AuditLog(self.root / "audit.jsonl", actor_id=self.console_id_or_none() or "uninitialized")

    # -- identity -----------------------------------------------------------
    def console_id_or_none(self) -> str | None:
        meta = self.keys_dir / "identity.json"
        return read_json(meta).get("id") if meta.exists() else None

    def is_initialized(self) -> bool:
        return (self.keys_dir / "identity.json").exists()

    def identity(self) -> Identity:
        return Identity.load(self.keys_dir)

    def public_sign_key(self) -> str | None:
        meta = self.keys_dir / "identity.json"
        return read_json(meta).get("sign_pub") if meta.exists() else None

    def init(self, label: str = "") -> Enrollment:
        if self.is_initialized():
            raise RuntimeError(f"console already initialized at {self.root}")
        ident = Identity.generate(new_id("console-"), with_box=True)
        ident.save(self.keys_dir)
        enr = Enrollment(console_id=ident.id, console_sign_pub=ident.sign_pub_hex, console_box_pub=ident.box_pub_hex or "",
                         created_at=iso(), label=label)
        write_json(self.enrollment_file, enr.model_dump())
        write_json(self.agents_file, {}, private=True)
        write_json(self.bundles_index_file, {}, private=True)
        self.audit = AuditLog(self.root / "audit.jsonl", actor_id=ident.id)
        self.audit.record("init", label=label)
        return enr

    # -- agents (trust on first use, key pinned afterwards) ------------------
    def agents(self) -> dict[str, Any]:
        return read_json(self.agents_file) if self.agents_file.exists() else {}

    def register_agent(self, agent_id: str, sign_pub: str, hostname: str, **extra: Any) -> str:
        """Returns 'new' or 'known'; raises CryptoError when a known agent presents a different key."""
        validate_id(agent_id, "agent_id")
        agents = self.agents()
        known = agents.get(agent_id)
        if known is None:
            agents[agent_id] = {"sign_pub": sign_pub, "hostname": hostname, "first_seen": iso(), "last_seen": iso(), **extra}
            write_json(self.agents_file, agents, private=True)
            return "new"
        if known["sign_pub"] != sign_pub:
            raise CryptoError(f"agent {agent_id} presented a different signing key than the one on record")
        known["last_seen"] = iso()
        known["hostname"] = hostname
        known.update(extra)
        write_json(self.agents_file, agents, private=True)
        return "known"

    def note_audit_head(self, agent_id: str, head: dict[str, Any] | None) -> None:
        """Witness: remember the agent's last audit head and flag regressions."""
        if not head or not isinstance(head, dict):
            return
        agents = self.agents()
        a = agents.get(agent_id)
        if a is None:
            return
        prev = a.get("last_audit_head")
        try:
            seq, h = int(head.get("seq", 0)), str(head.get("hash", ""))
        except (TypeError, ValueError):
            return
        if prev:
            pseq, ph = int(prev.get("seq", 0)), str(prev.get("hash", ""))
            if seq < pseq or (seq == pseq and h != ph):
                self.audit.record("audit_regression", agent_id=agent_id, previous=prev, current={"seq": seq, "hash": h})
                print(f"WARNING: audit chain on agent {agent_id} went backwards (seq {pseq} -> {seq}); investigate the endpoint", file=sys.stderr)
        a["last_audit_head"] = {"seq": seq, "hash": h, "seen_at": iso()}
        write_json(self.agents_file, agents, private=True)

    # -- cases ------------------------------------------------------------------
    def case_dir(self, case_id: str) -> Path:
        validate_id(case_id, "case_id")
        d = self.cases_dir / case_id
        if not d.exists():
            raise FileNotFoundError(f"no case {case_id}")
        return d

    def list_cases(self) -> list[dict[str, Any]]:
        out = []
        if self.cases_dir.exists():
            for d in sorted(self.cases_dir.iterdir()):
                cj = d / "case.json"
                if cj.exists() and not d.name.startswith("."):
                    out.append(read_json(cj))
        return out

    def _bundles_index(self) -> dict[str, Any]:
        return read_json(self.bundles_index_file) if self.bundles_index_file.exists() else {}

    def ingest_bundle(self, path: Path, redaction: RedactionConfig | None = None) -> tuple[str, BundleManifest, dict[str, Any]]:
        """Decrypt, verify, redact. Idempotent on bundle_id. Returns (case_id, manifest, case)."""
        path = Path(path)
        ident = self.identity()
        hdr, plaintext = read_bundle(path, ident)
        bundle_id = hdr["bundle_id"]
        with file_lock(self.state_lock):
            idx = self._bundles_index()
            prior = idx.get(bundle_id)
            if prior:
                self.audit.record("ingest_duplicate", bundle_id=bundle_id, case_id=prior["case_id"], kind=prior["kind"])
                cdir = self.case_dir(prior["case_id"])
                mpath = cdir / "raw" / "manifest.json" if prior["kind"] == "diagnostics" else cdir / "reports" / bundle_id / "manifest.json"
                return prior["case_id"], BundleManifest.model_validate(read_json(mpath)), read_json(cdir / "case.json")
            try:
                if hdr.get("kind") == "execution_report":
                    result = self._ingest_report(path, hdr, plaintext)
                else:
                    result = self._ingest_diagnostics(path, hdr, plaintext, redaction)
            except (CryptoError, ValidationError, ValueError, OSError) as e:
                self.audit.record("ingest_failed", bundle_id=bundle_id, agent_id=hdr.get("agent_id"), error=f"{type(e).__name__}: {str(e)[:200]}")
                if isinstance(e, ValidationError):
                    locs = sorted({".".join(str(x) for x in err["loc"]) for err in e.errors(include_input=False, include_url=False)})
                    raise CryptoError(f"bundle manifest failed validation at {locs[:6]}") from e
                if isinstance(e, ValueError) and not isinstance(e, CryptoError):
                    raise CryptoError(str(e)) from e
                raise
            idx[bundle_id] = {"case_id": result[0], "kind": result[1].kind, "agent_id": hdr["agent_id"], "ingested_at": iso()}
            write_json(self.bundles_index_file, idx, private=True)
            return result

    def _ingest_diagnostics(self, path: Path, hdr: dict[str, Any], plaintext: bytes, redaction: RedactionConfig | None) -> tuple[str, BundleManifest, dict[str, Any]]:
        case_id = new_id("case-")
        final = self.cases_dir / case_id
        tmp = ensure_private_dir(self.cases_dir / f".tmp-{case_id}")
        try:
            raw = tmp / "raw"
            names = unpack_to(plaintext, raw)
            if "manifest.json" not in names:
                raise CryptoError("bundle has no manifest.json")
            manifest = BundleManifest.model_validate(read_json(raw / "manifest.json"))
            if manifest.kind != "diagnostics":
                raise CryptoError("manifest kind does not match the sealed header")
            if manifest.agent_id != hdr.get("agent_id") or manifest.bundle_id != hdr.get("bundle_id"):
                raise CryptoError("manifest ids do not match the sealed header")
            name_set = set(names)
            missing = [f.path for f in manifest.files if f.path not in name_set]
            if missing:
                raise CryptoError(f"manifest lists files that are not in the bundle: {missing[:5]}")
            bad = [f.path for f in manifest.files if sha256_file(safe_join(raw, f.path)) != f.sha256]
            if bad:
                raise CryptoError(f"file hash mismatch inside bundle: {bad[:5]}")
            trust = self.register_agent(manifest.agent_id, hdr["agent_sign_pub"], manifest.hostname, platform=manifest.platform,
                                        os_version=manifest.os_version, aiit_version=manifest.aiit_version)
            self.note_audit_head(manifest.agent_id, manifest.audit_head)
            (tmp / "bundle.aiit").write_bytes(path.read_bytes())
            # redaction: one HMAC key per case; the effective config is persisted so later
            # material (reports, operator text) is redacted with the same settings
            key = secrets.token_bytes(32)
            write_private_file(tmp / "redaction.key", key)
            cfg = redaction or RedactionConfig()
            cfg.redact_hostnames = list(dict.fromkeys(list(cfg.redact_hostnames) + [manifest.hostname]))
            cfg.extra_literals = list(dict.fromkeys(list(cfg.extra_literals) + _harvest_usernames(raw)))
            write_json(tmp / "redaction_config.json", cfg.to_dict(), private=True)
            red = Redactor(key, cfg)
            rdir = tmp / "redacted"
            for f in manifest.files:
                src = safe_join(raw, f.path)
                dst = safe_join(rdir, f.path)
                dst.parent.mkdir(parents=True, exist_ok=True)
                try:
                    text = src.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    dst.write_text("[binary or unreadable file omitted]", encoding="utf-8")
                    continue
                dst.write_text(red.redact(text), encoding="utf-8")
            m_red = manifest.model_dump()
            m_red["hostname"] = red.token("HOST", manifest.hostname.lower()) if manifest.hostname else ""
            m_red["issue_description"] = red.redact(manifest.issue_description)
            m_red["audit_head"] = None
            write_json(rdir / "manifest.json", m_red)
            write_json(tmp / "redaction_map.json", red.map, private=True)
            case = {
                "case_id": case_id, "created_at": iso(), "agent_id": manifest.agent_id, "hostname": manifest.hostname,
                "platform": manifest.platform, "os_version": manifest.os_version, "collected_at": manifest.collected_at,
                "issue_description": manifest.issue_description, "bundle_id": manifest.bundle_id, "agent_trust": trust,
                "files": len(manifest.files), "collector_errors": sum(1 for f in manifest.files if f.error),
                "redaction_counts": red.stats.counts, "plans": [], "reports": [],
            }
            write_json(tmp / "case.json", case, private=True)
            os.replace(tmp, final)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        self.audit.record("ingest", case_id=case_id, bundle_id=manifest.bundle_id, agent_id=manifest.agent_id, agent_trust=trust,
                          files=len(manifest.files), redactions=red.stats.counts)
        return case_id, manifest, case

    def _ingest_report(self, path: Path, hdr: dict[str, Any], plaintext: bytes) -> tuple[str, BundleManifest, dict[str, Any]]:
        case_id = hdr.get("case_id")
        bundle_id = hdr["bundle_id"]
        if not case_id:
            raise CryptoError("execution report has no case id")
        try:
            cdir = self.case_dir(case_id)
        except FileNotFoundError as e:
            raise CryptoError(f"execution report refers to unknown case {case_id}") from e
        case = read_json(cdir / "case.json")
        # ownership and key pinning are checked BEFORE anything is unpacked
        if hdr.get("agent_id") != case["agent_id"]:
            raise CryptoError("report comes from a different agent than the case")
        self.register_agent(hdr["agent_id"], hdr["agent_sign_pub"], case["hostname"])
        reports_dir = ensure_private_dir(cdir / "reports")
        final = safe_join(reports_dir, bundle_id)
        if final.exists():
            raise CryptoError(f"report {bundle_id} already attached to case {case_id}")
        tmp = ensure_private_dir(reports_dir / f".tmp-{bundle_id}")
        try:
            names = unpack_to(plaintext, tmp)
            if "manifest.json" not in names or "report.json" not in names:
                raise CryptoError("report bundle is missing manifest.json or report.json")
            manifest = BundleManifest.model_validate(read_json(tmp / "manifest.json"))
            report = ExecutionReport.model_validate(read_json(tmp / "report.json"))
            if manifest.kind != "execution_report" or manifest.agent_id != hdr["agent_id"] or manifest.bundle_id != bundle_id:
                raise CryptoError("report manifest does not match the sealed header")
            if manifest.case_id != case_id or report.case_id != case_id or report.agent_id != case["agent_id"]:
                raise CryptoError("report does not belong to this case")
            if hdr.get("plan_id") and report.plan_id != hdr.get("plan_id"):
                raise CryptoError("report plan id does not match the sealed header")
            self.note_audit_head(manifest.agent_id, manifest.audit_head or report.audit_head)
            (tmp / "bundle.aiit").write_bytes(path.read_bytes())
            # keep the report hostname inside the case's redaction scope
            cfg_path = cdir / "redaction_config.json"
            if cfg_path.exists() and report.hostname:
                cfg = RedactionConfig.from_dict(read_json(cfg_path))
                if report.hostname not in cfg.redact_hostnames:
                    cfg.redact_hostnames.append(report.hostname)
                    write_json(cfg_path, cfg.to_dict(), private=True)
            os.replace(tmp, final)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        summary = {s: sum(1 for r in report.results if r.status == s) for s in sorted({r.status for r in report.results})}
        case["reports"].append({"bundle_id": bundle_id, "plan_id": report.plan_id, "mode": report.mode, "received_at": iso(), "summary": summary})
        write_json(cdir / "case.json", case, private=True)
        self.audit.record("report", case_id=case_id, plan_id=report.plan_id, bundle_id=bundle_id, mode=report.mode, summary=summary)
        return case_id, manifest, case
