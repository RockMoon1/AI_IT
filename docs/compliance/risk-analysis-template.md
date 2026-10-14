# HIPAA security risk analysis worksheet

45 CFR 164.308(a)(1)(ii)(A) requires a covered entity or business associate to
"conduct an accurate and thorough assessment of the potential risks and
vulnerabilities to the confidentiality, integrity, and availability of
electronic protected health information". This worksheet is a starting point
for an organisation that deploys AI_IT. It is **not** legal advice and it does
not make a deployment compliant by being filled in; it records the analysis
your privacy and security officers perform. Fill in every blank, keep the
completed copy with your compliance records (not in this repository), and
review it on the schedule in section 7.

Rows pre-filled with AI_IT specifics come from `docs/security/threat-model.md`
and `docs/compliance/hipaa.md`. Replace or extend them for your environment.

---

**Organisation:** ________________________________

**Scope of this analysis:** ______________________ (for example "AI_IT
console on the helpdesk laptop and agents on clinic workstations")

**Prepared by:** _______________________ **Role:** ______________________

**Date:** ____________ **Next review due:** ____________

**Approved by (security officer):** ______________________ **Date:** ________

---

## 1. Asset inventory

List every system component, data store and medium that creates, receives,
maintains or transmits ePHI, or that protects such a component.

| # | Asset | Type (hardware / software / data / media / people) | Location | Owner | Contains ePHI? | Protects ePHI? | Notes |
|---|---|---|---|---|---|---|---|
| 1 | Operator console machine | hardware | | | Yes (case folders) | | FDE enabled? ____ OS login with MFA? ____ |
| 2 | `aiit-console` data directory (`~/.aiit/console` or `AIIT_CONSOLE_DIR`) | data | | | Yes (`cases/*/raw`, `redacted`, `redaction_map.json`) | | Backup location: ____ |
| 3 | Console private keys (`keys/sign.key`, `keys/box.key`) | data | | | No | Yes | Passphrase set (`AIIT_KEY_PASSPHRASE`)? ____ Backup media: ____ |
| 4 | Endpoint workstations running `aiit-agent` | hardware | | | Yes (local logs) | | Count: ____ OS mix: ____ |
| 5 | Agent state directories (`policy.json`, `audit.jsonl`, keys) | data | | | No | Yes | Windows ACL reviewed? ____ |
| 6 | Removable media used for bundles and plans | media | | | Yes (sealed) | | Inventory kept? ____ Wipe procedure: ____ |
| 7 | LAN mailbox (`aiit-console serve`) | software | | | Yes (in transit, sealed) | | TLS certificate source: ____ Token rotation: ____ |
| 8 | Local model server (Ollama) | software | | | Yes (redacted prompt in memory) | | Bound to loopback? ____ |
| 9 | Hosted model provider (if any) | service | | | Yes (redacted prompt) | | BAA signed? ____ `AIIT_HIPAA_MODE=1`? ____ `AIIT_ALLOW_HOSTED` set by whom? ____ |
| 10 | Audit logs (console and agents) and exports | data | | | No (metadata) | Yes | Retention period: ____ Export destination: ____ |
| 11 | Alert sinks (`AIIT_ALERT_CMD` / `AIIT_ALERT_SYSLOG` / `AIIT_ALERT_WEBHOOK`) | software | | | No | Yes | |
| 12 | Operators with console access | people | | | | Yes | Named list: ____ Training date: ____ |
| 13 | | | | | | | |
| 14 | | | | | | | |

## 2. Threat and vulnerability identification

For each asset, list the threats (what could go wrong) and the vulnerabilities
(why it could go wrong here). The threat-model document gives the technical
list; add the organisational ones (lost devices, departing staff, vendor
outages, natural events).

| # | Asset # | Threat | Vulnerability | Existing control | Control owner |
|---|---|---|---|---|---|
| 1 | 6 | Removable media lost or stolen | Media leaves the building | Bundles sealed to console key (threat model I1); media inventory | |
| 2 | 2 | Operator machine stolen or compromised | Raw case data readable to anyone with the disk | Full disk encryption; OS login; 0700 directories | |
| 3 | 9 | PHI sent to a model provider without a BAA | Operator chooses a hosted provider; redaction misses free text | Local default; redaction; `preview`; BAA; `AIIT_HIPAA_MODE`; hosted gate (PR 2) | |
| 4 | 4 | Harmful command executed on a workstation | Model proposes it; policy misses it | Operator approval; deny list; risk ceiling; dry-run default; typed confirmation | |
| 5 | 10 | Audit trail altered or lost | Log file editable by local administrator | Hash chain; signed checkpoint; console witness; alerting; off-host export | |
| 6 | 3 | Console key compromised | Weak or absent passphrase; key backup mishandled | Passphrase; backup procedure; re-enrollment plan | |
| 7 | 12 | Departing operator retains access | No offboarding step for console keys | Offboarding checklist (section 5) | |
| 8 | 7 | LAN token disclosed | Shared token in environment or file | Token file permissions; TLS; rotation; per-agent signing (PR 3) | |
| 9 | 1 | Ransomware or disk failure on the operator machine | No backup of case store and keys | Backup procedure; restoration test | |
| 10 | | | | | |
| 11 | | | | | |
| 12 | | | | | |

## 3. Likelihood, impact and risk rating

Rate each threat row from section 2. Use the scales below or substitute your
organisation's.

Likelihood: **1** rare (less than once in 5 years), **2** unlikely (once in
1 to 5 years), **3** possible (once a year), **4** likely (several times a
year), **5** almost certain (monthly or more).

Impact: **1** negligible (no ePHI exposure, minutes of downtime), **2** minor
(no ePHI exposure, hours of downtime), **3** moderate (ePHI of fewer than 500
individuals, or a day of downtime), **4** major (reportable breach, days of
downtime), **5** severe (large breach, regulatory action, patient safety).

Risk = Likelihood x Impact. **1 to 5** low, **6 to 11** medium, **12 to 19**
high, **20 to 25** critical.

| Threat # | Likelihood (1-5) | Impact (1-5) | Risk score | Rating | Rationale |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |
| 6 | | | | | |
| 7 | | | | | |
| 8 | | | | | |
| 9 | | | | | |
| 10 | | | | | |
| 11 | | | | | |
| 12 | | | | | |

## 4. Risk treatment plan

For every medium or higher risk, decide: **mitigate** (add a control),
**accept** (document why), **transfer** (contract, insurance, BAA) or **avoid**
(stop doing the activity).

| Threat # | Decision | Additional control or justification | Owner | Due date | Status | Residual risk score |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |
| | | | | | | |
| | | | | | | |
| | | | | | | |

## 5. Control mapping to 45 CFR 164.308 and 164.312

Record how each standard is met in your deployment. The "AI_IT provides"
column is what the software does; the "Organisation provides" column is what
you must do. Mark each row Implemented, Partial, Planned or Not applicable
with a justification.

### 164.308 Administrative safeguards

| Standard | Spec | AI_IT provides | Organisation provides (fill in) | Status |
|---|---|---|---|---|
| (a)(1)(i) Security management process | (ii)(A) Risk analysis | This worksheet; `docs/security/threat-model.md` | Completed analysis, review dates | |
| | (ii)(B) Risk management | Hardening defaults (dry run, local model, redaction) | Treatment plan (section 4) | |
| | (ii)(C) Sanction policy | | Written sanction policy: ____ | |
| | (ii)(D) Information system activity review | `aiit-console audit verify`, `audit export`, `audit timeline`; `audit_regression` and alerting | Monthly review procedure and sign-off: ____ | |
| (a)(2) Assigned security responsibility | | | Named security officer: ____ | |
| (a)(3) Workforce security | (ii)(A)-(C) authorization, clearance, termination | Console keys per installation; `approved_by` in every approval | Who may hold a console key; offboarding step that retires keys and re-enrolls endpoints: ____ | |
| (a)(4) Information access management | (ii)(B) access authorization | 0700 data directory; agents trust one console | Access list for the operator machine: ____ | |
| (a)(5) Security awareness and training | (ii)(A)-(D) | `SUPPORT.md` (what never to share), operator runbook (PR 2) | Training record per operator: ____ | |
| (a)(6) Security incident procedures | (ii) response and reporting | `SECURITY.md`; chain-break alerts; `ingest_failed`, `serve_auth_fail` audit entries | Incident response plan and breach notification procedure: ____ | |
| (a)(7) Contingency plan | (ii)(A) data backup | Keys and case store are plain directories | Backup schedule and location: ____ | |
| | (ii)(B) disaster recovery | Re-enrollment procedure | Restoration test date: ____ | |
| | (ii)(C) emergency mode operation | Sneakernet works with no network | Procedure: ____ | |
| (a)(8) Evaluation | | CI test matrix; threat model; third-party assessment scope | Periodic evaluation schedule: ____ | |
| (b)(1) Business associate contracts | | `hosted` flag in every `llm_request` audit entry; `AIIT_HIPAA_MODE`; hosted-provider gate (PR 2) | BAA with each hosted model vendor and with any MSP operating the console: ____ | |

### 164.312 Technical safeguards

| Standard | Spec | AI_IT provides | Organisation provides (fill in) | Status |
|---|---|---|---|---|
| (a)(1) Access control | (2)(i) Unique user identification | OS user recorded in every audit entry and approval | Individual OS accounts, no shared logins: ____ | |
| | (2)(ii) Emergency access procedure | | Sealed key backup and who may open it: ____ | |
| | (2)(iii) Automatic logoff | CLI runs under the OS session | OS screen lock policy (minutes): ____ | |
| | (2)(iv) Encryption and decryption | Bundles sealed with X25519 + HKDF + AES-256-GCM; keys encrypted with a passphrase | FDE on operator machine and endpoints: ____ | |
| (b) Audit controls | | Hash-chained, checkpointed audit logs on both sides; exports; alerting | Review schedule and retention (typically six years): ____ | |
| (c)(1) Integrity | (2) Mechanism to authenticate ePHI | SHA-256 per file; AES-GCM; Ed25519 signatures on bundles and plans | | |
| (d) Person or entity authentication | | Agent and console key pairs; TOFU registry; LAN token; plan binding | Review of `agent_trust: new` cases; token rotation schedule: ____ | |
| (e)(1) Transmission security | (2)(i) Integrity controls, (2)(ii) Encryption | Application-layer sealing and signatures on every transport; TLS 1.2+ required for non-loopback LAN binds | Certificate source for `serve`: ____ | |

## 6. Residual risks accepted

Copy the accepted risks from `docs/security/threat-model.md` section 7 that
apply to your deployment and add your own.

| # | Residual risk | Accepted by | Date | Compensating measure | Re-evaluate when |
|---|---|---|---|---|---|
| 1 | Regex redaction misses free-text names in logs | | | Local model only; operator preview; `--redact` literals | Presidio integration available |
| 2 | Shared LAN token | | | TLS; token file permissions; rotation every ____ | Per-agent request signing (PR 3) |
| 3 | Windows state directory ACLs inherited | | | Endpoint accounts restricted; FDE | PR 2 `icacls` hardening |
| 4 | | | | | |

## 7. Review schedule

| Trigger | Action | Owner |
|---|---|---|
| Annually (date: ____) | Full review of sections 1 to 6 | |
| New AI_IT minor release | Re-read the CHANGELOG `Security` and `BREAKING` items; update sections 2 and 5 | |
| New hosted provider or model | Re-do threat rows 3 and 9; confirm BAA | |
| Audit chain break alert | Incident procedure; record outcome in section 4 | |
| Lost or stolen media or device | Incident procedure; breach assessment under 164.402 | |
| Operator joins or leaves | Section 1 row 12; offboarding step | |
| Proposed Security Rule changes take effect | Map new required specifications (MFA, asset inventory, 72-hour restoration, vulnerability scanning) | |

---

**Sign-off**

Privacy officer: ______________________ Date: ________

Security officer: _____________________ Date: ________
