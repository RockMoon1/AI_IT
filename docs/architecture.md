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
IPv4 (public by default, private optional), MAC address, user profile paths on
all three OSes, hostname, obvious secrets (passwords, tokens, bearer headers,
AWS and GitHub key shapes, PEM blocks) which are replaced irreversibly.

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
  Always `hosted`; from PR 2 it requires `AIIT_ALLOW_HOSTED=1`.

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

## 8. Threats considered

The threat model lives in `docs/security/threat-model.md`. It is organised
by STRIDE and lists, for every threat, the control, the file and function
that implements it, the test that covers it and the residual risk, followed
by attack trees for "an arbitrary command runs on an endpoint" and "PHI
reaches a third party", the cryptographic inventory and key lifecycle, the
accepted risks, and the scope for a third-party assessment. Changes to a
trust boundary update that document in the same pull request.
