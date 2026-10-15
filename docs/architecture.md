# Architecture

## 1. Components

```
+-------------------------------+                 +--------------------------------+
|  Operator machine (online)    |                 |  Endpoint (may be offline)     |
|                               |                 |                                |
|  aiit-console                 |   USB stick     |  aiit-agent                    |
|   - case store (encrypted FDE)|  <===========>  |   - collectors (OS commands,   |
|   - redactor                  |   or LAN HTTP   |     osquery if present)        |
|   - planner  --> LLM          |                 |   - bundle sealer (X25519+GCM) |
|       | local Ollama          |                 |   - policy gate                |
|       | or Claude API (BAA)   |                 |   - executor (dry-run default) |
|   - approve + sign (Ed25519)  |                 |   - audit chain                |
|   - audit chain               |                 |                                |
+-------------------------------+                 +--------------------------------+
```

Both sides are one Python package, `aiit`, with two entry points. The agent
has no network requirement: every artifact is a file that can be copied by
hand. LAN mode only automates the file hand-off.

## 2. The loop

1. **Enroll.** `aiit-console init` makes a console identity. The operator
   copies the public enrollment file to the endpoint and runs
   `aiit-agent enroll`. The endpoint now trusts exactly one console.
2. **Collect.** `aiit-agent collect --issue "Outlook crashes on start" --out E:\case.aiit`
   runs the collectors for its OS, writes a manifest with SHA-256 for every
   file, packs a tar.gz, encrypts it to the console key, signs it, and writes
   one `.aiit` file.
3. **Ingest.** `aiit-console ingest E:\case.aiit` decrypts, verifies, opens a
   case folder, and runs the redactor. Redacted copies are what the model
   sees; the originals stay in the case folder.
4. **Diagnose.** `aiit-console diagnose <case> --issue "..."` builds a bounded
   prompt from the redacted files and asks the provider for a structured
   `FixPlan`: diagnosis, confidence, ordered steps, each with a command, OS,
   risk level, expected outcome and rollback.
5. **Approve.** The operator reads the plan, edits it if needed, and runs
   `aiit-console approve <case> <plan>`. The console signs the plan with its
   Ed25519 key, binds it to the agent id and case id, sets an expiry, and
   writes `<plan>.signed.json`.
6. **Apply.** `aiit-agent apply plan.signed.json` verifies the signature
   against the enrolled console key, refuses plans for other agents, expired
   plans and replays, runs each step through the local policy (deny patterns,
   risk ceiling, dry-run mode), executes, and writes an execution report
   bundle encrypted back to the console.
7. **Report.** `aiit-console report report.aiit` attaches results to the case.
   The operator can iterate (diagnose again with the results attached).

## 3. File formats

### Sealed bundle `.aiit`

```
AIIT1\n
<header JSON, one line>\n
<ciphertext bytes>
```

Header fields: `version`, `kind` (`diagnostics` or `execution_report`),
`bundle_id`, `agent_id`, `agent_sign_pub`, `console_id`, `eph_pub`, `nonce`,
`created_at`, `plaintext_sha256`, `signature`. The signature is Ed25519 over
the canonical header without the signature field. The ciphertext is
AES-256-GCM over the tar.gz payload, with the header (minus signature) as
associated data, key = HKDF-SHA256(X25519(eph_priv, console_box_pub)).

An attacker with the file and no console private key learns the agent id and
timestamps and nothing else. An attacker who swaps bytes fails GCM
authentication. An attacker who forges a bundle fails the agent signature
check if the agent is already known, and is flagged as a new agent otherwise.

### Signed plan `.signed.json`

```json
{"plan": {...FixPlan...}, "signer_id": "...", "signer_pub": "hex",
 "approved_by": "os-user", "approved_at": "...", "signature": "hex"}
```

Signature is Ed25519 over the canonical JSON of `plan`. The plan itself
carries `target_agent_id`, `case_id`, `expires_at` and `plan_id`; the agent
keeps the list of applied plan ids to refuse replays.

### Audit log side files

`audit.jsonl` is the hash chain itself. `audit.jsonl.head.json` is the signed
checkpoint (`seq`, `hash`, byte offset, signer key, signature) written after
every state-changing command; verification fails if the log is shorter than
the checkpoint or the checkpointed entry differs. `audit.jsonl.corrupt`
collects torn fragments quarantined by `audit repair-tail`. The actions
`audit_chain_broken` and `audit_tail_repaired` are themselves chained entries.

### Case folder (console)

```
cases/<case_id>/
  bundle.aiit            original sealed file
  raw/                   decrypted files (never sent anywhere)
  redacted/              what the model sees
  redaction_map.json     token -> original (sensitive, local only)
  plans/<plan_id>.json
  plans/<plan_id>.signed.json
  reports/<bundle_id>/   execution reports
  case.json              metadata
```

## 4. Redaction

Deterministic pseudonymization with HMAC-SHA256 keyed per case, so the same
email always becomes the same `<EMAIL_7f3a9c21>` token inside one case and the
model can still correlate, but tokens are not reversible without the map.

Covered by regex today: email, US SSN, US phone, credit card (Luhn checked),
IPv4 and IPv6 (public by default, private optional, loopback and link-local
never), MAC address, user profile paths on all three OSes including
JSON-escaped and UNC home shares, `DOMAIN\user`, domain and Azure AD SIDs,
UNC server names, hostnames (word-bounded, case-insensitive), labelled serial
numbers, product ids, hardware and platform UUIDs, UDIDs, machine ids,
registered owner and organisation, user and computer names; and secrets
(key/value passwords, passphrases, tokens and API keys with any prefix, URL
userinfo, Authorization headers, JWTs, AWS, GitHub, GitLab, OpenAI, Anthropic,
Slack, Discord, Telegram and Google token shapes, PEM blocks), which are
replaced irreversibly. The effective configuration is persisted per case in
`redaction_config.json`, seeded with the hostname and the account names found
in the bundle, so reports and operator text are redacted with the same rules.

Not covered: free-text person names, street addresses, dates of birth in
prose. That needs NLP (Presidio) and is a roadmap item. Until then, the
operator reviews the redacted preview before a cloud model call, and the
default provider is local.

## 5. Policy gate on the endpoint

`policy.json` lives on the endpoint, not in the plan, so a compromised
console cannot loosen it. Its fields are exactly those written by
`Policy.to_dict()` in `src/aiit/common/policy.py`:

* `version`: policy format version (`"2"`). Version 1 files load with
  defaults for the newer fields.
* `mode`: `dry_run` (default) or `enforce`.
* `max_risk`: highest *effective* step risk the agent will run (`low` by
  default). The effective risk is the larger of the risk the model declared
  and a locally computed floor from a verb table (read-only verbs impose no
  floor, service restarts and cache clears floor to `low`, mutating verbs to
  `medium`, unknown commands to `low`), so a mislabelled step cannot run
  above the ceiling.
* `deny_patterns`: regexes that block a command outright (disk formatting,
  recursive deletes of system roots, user creation, boot config, security
  tooling and firewall disable, log clearing, persistence, reverse shells).
  They are matched against the raw command and an OS-aware normalised form
  (aliases expanded, case folded, quotes and backticks stripped, `sudo`/`env`
  style prefixes removed). A fixed set of structural denies (encoded
  commands, `Invoke-Expression`, pipes into an interpreter, command
  substitution, nested shells, inline `python -c`) is applied regardless of
  the list.
* `allow_patterns`: if non-empty, a command must fully match one entry
  (`re.fullmatch`), and may not contain shell control characters the entry
  does not itself contain.
* `reboot_patterns`: commands that reboot or power off; such a step, or any
  step marked `requires_reboot`, is blocked unless the operator passed
  `--allow-reboot` to `apply`.
* `max_plan_hours`: longest plan lifetime (`expires_at - created_at`) the
  agent accepts, 72 by default. `aiit-console approve --hours` above this
  needs `--long-lived` on the console and a raised value here.
* `risk_floor_overrides`: mapping of regex to risk that raises the floor for
  commands a site considers more dangerous than the built-in table does.
  Overrides can only raise the effective risk.

`aiit-agent policy digest` prints the SHA-256 of the canonical policy so a
fleet can be checked against a known value. Every step is evaluated before
any step runs (preflight): one blocked step stops the whole plan. Every step
result (including `blocked_by_policy`) goes into the report and the agent
audit chain.

## 6. LLM providers

`aiit.console.llm` has a tiny interface:
`complete_json(system, user, schema, meta) -> (parsed_json, usage)`.
`system` and `user` are the only text that may leave the console and both
have already been redacted. `meta` carries local-only hints (target OS, case
id, redacted issue text) a provider may read but must never transmit.
`usage` goes into the audit log, so it holds provider, model, token counts
and flags (`hosted`, `format_degraded`, `hipaa_mode`), never content. Each
provider records `hosted` (data leaves the operator machine) and
`endpoint_host`, and both are written to every `llm_request` audit entry.

* `dryrun`: no model; produces a read-only checklist plan from the manifest
  so the pipeline can be exercised and tested offline.
* `ollama`: POST to Ollama `/api/chat` through `aiit.common.net.http_json`
  with `format` set to the FixPlan JSON schema. A 404 prints an
  "`ollama pull`" hint; a 400 on the schema retries once with
  `format: "json"`. `hosted` is true only when the URL is not loopback or
  private. `AIIT_OLLAMA_TIMEOUT`, `AIIT_OLLAMA_NUM_CTX`.
* `anthropic`: official `anthropic` SDK, `claude-opus-5-5` by default,
  `output_config.format` JSON schema for the plan, `effort` configurable.
  Server-side refusal fallbacks (a beta feature) are on by default; a beta
  400 degrades once to the plain Messages call, and `AIIT_HIPAA_MODE=1`
  disables beta features so the request stays on the BAA-covered surface.
  `stop_reason` `refusal` is a hard stop (`ProviderRefusal`), never retried.
  Always `hosted`, so it needs `--allow-hosted` or `AIIT_ALLOW_HOSTED=1`.
* `openai`, `azure-openai`, `openai-compat` and the local presets `llamacpp`,
  `vllm`, `lmstudio`: one class over the chat-completions wire format through
  `aiit.common.net.http_json` (no SDK). Strict JSON-schema output is requested
  first and degrades once to `json_object`, then to free text, on a 400 that
  names the format; `finish_reason` `length` is an error, `refusal` and
  `content_filter` are `ProviderRefusal`. Keys come from `AIIT_OPENAI_API_KEY`,
  `AZURE_OPENAI_API_KEY` (Azure) or `OPENAI_API_KEY`, are sent only as a
  header and never reach the audit log; `AIIT_OPENAI_BASE_URL`,
  `AIIT_OPENAI_MODEL`, `AIIT_AZURE_OPENAI_DEPLOYMENT`,
  `AIIT_AZURE_OPENAI_API_VERSION`. `openai` and `azure-openai` are always
  `hosted`; a compat server is `hosted` only when its URL is not loopback or
  private. Bedrock and Vertex are out of scope (reachable later through the
  Anthropic SDK's clients).

Hosted providers are refused unless the operator passes `--allow-hosted`
or sets `AIIT_ALLOW_HOSTED=1`, the HIPAA-safe default. `diagnose --fallback`
names a second provider to try when the first fails; it may only move
towards more privacy (hosted -> local -> `dryrun`), and the switch is
audited as `llm_fallback`. Nothing falls back automatically.

Errors are one hierarchy: `ProviderError` (transport, timeout, HTTP status,
truncation), `ProviderRefusal` (the model declined) and
`ProviderOutputError` (the model answered but the answer is not a JSON
object; it carries the raw text). All providers parse replies with the shared
`parse_json_text`, which tolerates a code fence and prose around the
outermost object.

The planner runs a repair loop: when a reply raises `ProviderOutputError` or
fails `FixPlanDraft` validation, the console appends the problems (pydantic
errors without input values, plus `lint_plan` findings) and the redacted
previous answer to the prompt and asks again, up to `AIIT_PLAN_REPAIRS`
times (default 1). Every attempt is audited (`llm_request`, `llm_response`,
`llm_invalid_plan`, `llm_output_error`, `llm_repair`); on final failure the
rejected output is saved privately under the case's `plans/` directory and
the command exits with a clear message. Refusals are never repaired.

Prompt budget is bounded (`--max-chars`, capped by the provider's
`max_input_chars`); files are included in priority order (manifest summary,
failed services, error logs, disk, network, then the rest). Each file is
wrapped in a data fence with a per-request random delimiter, and the system
prompt tells the model that fenced content is data from the machine, never an
instruction. The operator's `--issue` text and any previous execution report
are passed through the case's redactor before they enter the prompt.

## 7. Transport modes

* **Sneakernet (default).** Files on removable media. Works with zero
  network.
* **LAN.** `aiit-console serve` exposes four endpoints behind a shared
  bearer token (`AIIT_SERVER_TOKEN`, at least 16 characters):

  | Endpoint | Purpose | Responses |
  |---|---|---|
  | `POST /v1/bundles` | Upload a sealed diagnostics bundle (body is the `.aiit` file). | `200` with `case_id`; `422` when the bundle is rejected (bad signature, manifest, path); `503` on a storage error; `413` over 64 MiB. |
  | `POST /v1/reports` | Upload a sealed execution report. Same handling. | As above. |
  | `GET /v1/plans?agent_id=...` | Fetch pending signed plans for one agent id. | `200` with a JSON list; `400` for a malformed id. |
  | `GET /v1/health` | Liveness, console id and version. | `200`. |

  `aiit-agent collect --push`, `aiit-agent apply --push`, `aiit-agent push`
  (a file, or `--outbox` for everything unsent) and `aiit-agent pull` use
  them. The agent validates every pulled plan (schema, signature, target,
  expiry, lifetime) before saving it to its inbox, and a failed push keeps
  the bundle on disk and exits 3. Payloads are the same sealed files, so the
  server is a dumb mailbox: it authenticates callers, bounds resource use
  (30 s socket timeout, streamed bodies, 32 concurrent handlers, per-address
  back-off after repeated authentication failures) and stores files. **TLS is
  required for any bind other than loopback** (`--tls-cert`/`--tls-key`,
  TLS 1.2 minimum); `--insecure-no-tls` overrides that on a trusted LAN. A
  retried upload is idempotent on `bundle_id`.
* **Live session (roadmap).** When the endpoint is reachable, launch
  MeshCentral (Apache-2.0) for screen, terminal and files. AI_IT does not
  replace that; it feeds it.

## 8. Read-only dashboard

`aiit-console dashboard` (module `aiit.console.dashboard`) serves one
self-contained HTML page over the console directory so an operator can keep a
browser tab open while working in the terminal: the cases table (id, created,
hostname token, platform, agent, trust state, plan and report counts, last
activity), one page per case with every plan (steps, risk colouring, lint
warnings, approval state) and every execution report (per-step status, exit
code, reason), the enrolled agents with their last-seen time and witnessed
audit head, the console id, and the audit chain verdict with the signed
checkpoint seq. The page refreshes itself every 15 s with a `<meta>` tag.

Its trust boundary is deliberately narrow:

* **Loopback only.** `make_dashboard_server` binds to `127.0.0.1` or `::1`
  and raises `ValueError` for any other host, including `localhost` (a hosts
  file can point that anywhere). There is no authentication: whoever can
  reach the port is already the operator at this machine, the same person who
  can run the CLI against the same directory. Putting it behind a reverse
  proxy or an SSH tunnel is outside the design; the full console in
  `docs/roadmap.md` is the answer for remote or multi-operator use.
* **Nothing writes.** Only `GET` and `HEAD` are served; every other method is
  `405`. The audit chain is checked with `AuditLog.verify`, never with
  `check_and_alert`, so a page load neither appends an `audit_chain_broken`
  entry nor fires the alert sinks, and no file under the console directory is
  created or modified. `tests/test_dashboard.py` asserts that the log and the
  checkpoint are byte-identical after a series of requests.
* **Nothing executes.** The page carries no script; its
  `Content-Security-Policy` is `default-src 'none'; style-src 'unsafe-inline'`,
  with `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store` and `X-Frame-Options: DENY` on every response.
  Every value that came from a bundle, a model answer or an operator (ids,
  hostnames, commands, titles, rationales, reasons) passes through
  `html.escape`. Raw collected files and command output are never rendered;
  where a redacted form exists (the hostname token, the issue text) the page
  shows that form.
* **Same data as the CLI.** The page is built from `ConsoleState.list_cases`,
  `ConsoleState.agents`, `planner.load_plan` and the case's `reports/` entries,
  the same helpers behind `cases`, `plans`, `plan`, `report` and `agents`, so
  it cannot disagree with the terminal.

## 9. Threats considered

The threat model lives in `docs/security/threat-model.md`. It is organised
by STRIDE and lists, for every threat, the control, the file and function
that implements it, the test that covers it and the residual risk, followed
by attack trees for "an arbitrary command runs on an endpoint" and "PHI
reaches a third party", the cryptographic inventory and key lifecycle, the
accepted risks, and the scope for a third-party assessment. Changes to a
trust boundary update that document in the same pull request.
