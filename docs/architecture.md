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
console cannot loosen it:

* `mode`: `dry_run` (default) or `enforce`.
* `max_risk`: highest step risk the agent will run (`low` by default).
* `deny_patterns`: regexes that block a command outright (disk formatting,
  recursive deletes of system roots, user creation, boot config, firewall
  disable, reverse shells).
* `allow_patterns`: if non-empty, a command must match one.
* `require_reboot_flag`: steps marked `requires_reboot` are skipped unless
  the operator passed `--allow-reboot`.

Every step result (including `blocked_by_policy`) goes into the report and
the agent audit chain.

## 6. LLM providers

`aiit.console.llm` has a tiny interface: `complete_json(system, user, schema)`.

* `dryrun`: no model; produces a read-only checklist plan from the manifest
  so the pipeline can be exercised and tested offline.
* `ollama`: POST to the local Ollama `/api/chat` with `format` set to the
  FixPlan JSON schema.
* `anthropic`: official `anthropic` SDK, `claude-opus-5-5` by default,
  `output_config.format` JSON schema for the plan, `effort` configurable,
  server-side refusal fallbacks enabled by default on the Claude API, and a
  hard stop with a clear message when `stop_reason` is `refusal`.

Prompt budget is bounded (`--max-chars`); files are included in priority order
(manifest summary, failed services, error logs, disk, network, then the rest).

## 7. Transport modes

* **Sneakernet (default).** Files on removable media. Works with zero
  network.
* **LAN.** `aiit-console serve` exposes three endpoints protected by a shared
  token and optional TLS: upload bundle, fetch pending signed plans for an
  agent id, upload report. `aiit-agent push` and `aiit-agent pull` use them.
  Payloads are the same sealed files, so the server is a dumb mailbox.
* **Live session (roadmap).** When the endpoint is reachable, launch
  MeshCentral (Apache-2.0) for screen, terminal and files. AI_IT does not
  replace that; it feeds it.

## 8. Threats considered

| Threat | Control |
|---|---|
| Lost USB stick with a bundle | Encrypted to console key; signature prevents substitution. |
| Malicious plan file dropped on an endpoint | Ed25519 signature from the enrolled console only; bound to agent id, expiry, replay list. |
| Model proposes a destructive command | Operator approval, risk ceiling, deny patterns, dry-run default. |
| PHI leaks to a cloud model | Local model default; redaction before any provider; BAA requirement documented. |
| Secret committed to git | `.gitignore`, gitleaks pre-commit, CI scan, no secrets in config files. |
| Tampered audit trail | Hash-chained entries, `audit-verify`. |
| Compromised operator machine | Out of scope for the software; FDE, MFA and OS hardening are required by the deployment checklist. |
