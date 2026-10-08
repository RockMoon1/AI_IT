# Roadmap

## Phase 0 (this PR): research, decisions, working skeleton

* Verified license table and decision record.
* HIPAA mapping and deployment checklist.
* `aiit-agent` and `aiit-console` with the full offline loop working on
  Linux in CI; Windows and macOS collectors written but need field testing.
* Dry-run provider, Ollama provider, Anthropic provider.
* Secret hygiene: gitignore, gitleaks, pre-commit, CI scan.

## Phase 1: usable in the field (target: weeks)

1. Field-test Windows collectors on Windows 10/11 laptops; tune the event
   log filters and timeouts.
2. Agent packaging: single-file executable with PyInstaller for offline
   install, plus a signed MSI/PKG later.
3. `aiit-console chat`: conversational wrapper that keeps the case context
   and lets the operator ask follow-up questions, with the plan as the
   final artifact.
4. Operator web UI (FastAPI) with idle logoff and per-user login behind a
   reverse proxy that enforces MFA.
5. Plan editing in the console before approval.
6. osquery query pack tuned per OS.

## Phase 2: team and network features

1. LAN mode hardening: mTLS, per-agent enrollment approval, agent heartbeat.
2. MeshCentral integration for live desktop/terminal when reachable.
3. Multi-operator RBAC and per-operator signing keys.
4. SIEM export of the audit chain (JSON over syslog, Wazuh).
5. Knowledge base: store successful plans and reuse them as retrieval
   context for similar issues.

## Phase 3: compliance maturity

1. Encrypted case store with key wrapping (not only FDE).
2. Retention policies and automatic purge.
3. Presidio-based NLP redaction with a measured recall test set.
4. Risk analysis template, operator training runbook, incident runbook.
5. Asset inventory export (proposed Security Rule requirement).
6. Third-party security review.
