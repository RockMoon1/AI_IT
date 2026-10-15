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
4. Operator UI: the read-only local dashboard shipped in PR 2; the full
   console in the browser is designed under "UI phases" below.
5. Plan editing in the console before approval.
6. osquery query pack tuned per OS.

## UI phases

### UI phase 1 (PR 2): read-only local dashboard

`aiit.console.dashboard` renders the console directory as one self-contained
HTML page: cases, plans with their steps and approval state, execution
reports, agents, the audit chain verdict and the console id. It binds to
loopback only, has no login, serves only `GET` and `HEAD`, never writes, and
carries no script (`docs/architecture.md`, section 8). It exists so an operator
can watch a case while working in the terminal, and so the page layout, the
escaping rules and the "same data as the CLI" discipline are settled before
anything interactive is built on top of them.

### UI phase 2: the full console in the browser (design)

The goal is to do everything the CLI does from a browser, for more than one
operator, without weakening a single control the CLI enforces today. The
design, in the order the pieces will land:

1. **Local accounts and login.** Accounts live in `<data dir>/users.json`,
   created and disabled only from the CLI (`aiit-console user add|disable`),
   never from the browser. Passwords are hashed with PBKDF2-HMAC-SHA256 from
   the standard library `hashlib` (600 000 iterations, 16-byte random salt,
   per-record iteration count so it can be raised later). Argon2 would be the
   better primitive but it needs a compiled extra; the project's runtime
   dependencies stay stdlib + `cryptography` + `pydantic`, and the hash can be
   migrated on next login if that ever changes. Login failures are rate-limited
   per account and per address and every attempt is audited (`ui_login`,
   `ui_login_failed`). MFA is not built in: for anything beyond one trusted
   workstation the console sits behind a reverse proxy that enforces it, and
   the UI reads the proxy's authenticated user header only when explicitly
   configured to trust that proxy.
2. **Sessions and idle logoff.** A session is a random 256-bit cookie
   (`Secure`, `HttpOnly`, `SameSite=Strict`) that maps to a server-side record
   with the operator, the login time and the last request time. A session
   ends after 15 minutes idle (configurable down, not up, past 60 minutes),
   after 12 hours regardless, on logout, and when the account is disabled.
   Every expiry is audited with its reason. The HIPAA workstation-security
   checklist in `docs/compliance/hipaa.md` points at this control.
3. **Approval in the browser.** Approving a plan in the UI goes through
   `planner.approve`, the same function the CLI calls, with the same gates:
   lint warnings must be acknowledged explicitly, the lifetime cap applies,
   and the operator types `APPROVE` into a confirmation field that is checked
   server-side (the typed word is part of the request, not a client-side
   dialog). The signing key stays on the console; the browser never sees key
   material, only the signed plan's id. `approved_by` records the logged-in
   account, not the OS user, so the audit entry names a person.
4. **Every UI action is audited.** Each state-changing request writes the
   same audit action the CLI would (`ingest`, `plan_created`, `plan_approved`,
   `report`) plus `ui_action` with the account, the session id and the client
   address, and moves the signed checkpoint, so a UI-driven change is
   indistinguishable in strength from a CLI-driven one. Reads are not
   audited, as in the CLI.
5. **CSRF and request hygiene.** Every state-changing request is a `POST`
   with a per-session token in a hidden field, compared in constant time; a
   missing or wrong token is a `403` and an audited `ui_csrf_rejected`.
   `SameSite=Strict` cookies, an `Origin`/`Sec-Fetch-Site` check, the
   dashboard's Content-Security-Policy (no script until a feature needs one,
   then a per-response nonce), and no form or endpoint accepts a bundle path:
   uploads are the sealed `.aiit` bytes and go through `ingest_bundle`
   exactly as a LAN upload does.
6. **Framework as an optional extra.** The dashboard proves the stdlib server
   is enough for a read-only page; forms, sessions, uploads and a template
   layer are where it stops being enough. FastAPI (with `uvicorn` and
   `python-multipart`) goes behind an extras group, `pip install aiit[ui]`,
   so the default install, the agent and the offline wheelhouse stay
   stdlib + `cryptography` + `pydantic`; `aiit-console ui` prints a one-line
   install hint when the extra is missing. Templates are rendered with
   auto-escaping on and the same `html.escape` discipline as the dashboard
   for anything outside a template.
7. **TLS and binding.** Loopback by default; any other bind requires a
   certificate exactly like `serve`, and `--insecure-no-tls` does not exist
   for the UI (cookies and passwords must not cross a LAN in the clear).

**Why it is not in PR 2.** Each piece above is an authentication surface:
accounts, sessions, cookies, CSRF, an upload form and a signing action
reachable over HTTP. Getting any of them wrong turns the console into the
easiest way to sign a plan for an endpoint. PR 2's scope is the operator
workflow (providers, hosted-data defaults, platform hardening), and the
dashboard is what can be shipped with no new attack surface at all: loopback,
no login, no writes. The full console needs its own threat-model rows, its own
review and a release of its own, and it will reuse the dashboard's rendering
and escaping code rather than replace it.

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
