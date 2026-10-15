# Changelog

All notable changes to AI_IT are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release may contain breaking changes; each one is marked
**BREAKING** with the step an operator has to take.

## [Unreleased]

PR 1, "Harden the core": closes every confirmed security hole, makes the
network and audit paths resilient, measures coverage on three operating
systems and four Python versions, and adds governance and threat-model
documentation. No new runtime dependencies, no change to the sealed bundle or
signed plan wire formats; existing bundles and plans remain readable.

### Security

- Policy engine: fixed deny-list bypasses (`powershell -enc`, mixed-case
  cmdlets, PowerShell aliases and backticks, `sudo`/`env`/`exec` prefixes,
  quoted paths, `curl ... | sudo bash`, `rm -r -f /`, `Remove-Item -Recurse
  C:\ -Force`). Commands are now matched against an OS-aware normalised form as
  well as the raw text, and a set of structural denies catches whole families
  (encoded commands, `Invoke-Expression`, `FromBase64String`, downloads to
  memory, pipes into any interpreter, command substitution, nested shells,
  `osascript`, inline `python -c`/`perl -e`/`node -e`, recursive deletes of a
  system root).
- Policy engine: the allow-list uses `re.fullmatch` instead of `re.search`, so
  an allowed prefix can no longer be chained with `;`, `&&` or `|`. Shell
  control characters are refused unless the matching allow entry contains them.
- Policy engine: a locally computed risk floor (`effective_risk = max(declared,
  floor)`) so a mislabelled "read_only" step that runs a mutating verb cannot
  slip under `max_risk`. Sites can tighten it with `risk_floor_overrides`.
- Policy engine: the floor is computed per separator-free segment and the
  maximum wins, so a read verb in front (`ls; chmod 777 /etc/x`) no longer
  hides a mutating command behind it. Output redirection and writer verbs
  (`tee`, `Out-File`, `Set-Content`) count as writes: temp and home targets
  floor to `low`, anything else to `medium`.
- Policy engine: writes to protected files and keys are structural denies at
  any `max_risk` (passwd, group, sudoers, ssh, PAM, cron, systemd and launchd
  units, shell profiles, `$PROFILE`, Startup folders, Run keys, Winlogon,
  LSA, Defender, boot and EFI, kernel modules, CA stores, System32 outside
  the usual cleanup targets); reads stay allowed. Credential stores (shadow,
  private keys, SAM/SECURITY hives, keychains, lsass, cloud and database
  credential files) are never touched, and `chmod` with a setuid/setgid bit
  is refused. `${HOME}`, `$env:USERPROFILE` and `%USERPROFILE%` count as home
  roots for the recursive-delete rule.
- Policy engine: many new deny families (Defender, firewall, BitLocker and
  event-log tampering, persistence keys, `find / -delete`, `iptables -F`,
  `nft flush`, sudoers, `passwd -d`, `diskutil secureErase`, `tmutil delete`,
  `sysadminctl -addUser`, `dscl . -create`, `socketfilterfw` off, `spctl
  --global-disable`, `nvram boot-args`); `poweroff`, `halt` and
  `Stop-Computer` now hit the reboot gate.
- Console ingest: path traversal through header and manifest ids and through
  manifest file paths is closed. Ids are validated against a strict pattern,
  member paths must be relative with no `..`, drive or backslash, every file
  write goes through `safe_join`, and the archive is unpacked into a temporary
  directory that is only renamed into place after the manifest, agent
  identity and every hash have been checked.
- Console report ingest: agent ownership and key pinning are checked before
  anything is unpacked, and a report that names another case inside the
  archive is refused.
- Bundle extraction limits: at most 2000 members, 8 MiB per member and
  256 MiB uncompressed; only regular files and directories are extracted;
  symlinks, devices, absolute paths and drive letters are rejected before
  anything is written.
- Subprocess environment is scrubbed for plan steps and collectors: only a
  short allow-list of variables is inherited, anything named like
  `AIIT_*`, `*_TOKEN`, `*_KEY`, `*_SECRET` or containing `PASS` is dropped,
  `PATH` is fixed to system directories and the current directory is removed
  from executable search. The key passphrase and the LAN token no longer
  reach command output.
- Windows: `powershell.exe` and every Windows collector binary are started by
  absolute `System32` path so a planted executable next to a plan on removable
  media is never picked up. Plan steps are fed to PowerShell on stdin as the
  exact bytes the policy evaluated (no `-EncodedCommand`, no `.ps1`). The
  child `PATH` is built from the real `SystemRoot` at call time (an earlier
  draft passed a literal `%SystemRoot%` that CreateProcess never expands, so
  no native tool could be found). A bare `powershell.exe` collector is
  normalised to the absolute, non-interactive form; other bare names that
  exist under System32 are started from there.
- Windows: the command bytes sent to PowerShell and the output read back use
  the console's OEM code page, so a non-ASCII path in a step is run as written
  and output is not mojibake; a step the code page cannot represent is
  refused with a clear reason instead of running altered. The child locale is
  pinned per platform (`C.UTF-8` on Linux, `en_US.UTF-8` on macOS, `C`
  elsewhere) so tools stop printing `setlocale` warnings into collected files.
- Planner: the operator's `--issue` text is redacted through the case's
  redactor before it reaches a model; previously it was sent verbatim.
  Collected files are wrapped in data fences with a per-request random
  delimiter and the system prompt declares fenced content to be data, not
  instructions.
- Redaction: a spaced `-p VALUE` is treated as a password unless the command
  is a known port/pid/path tool or the value is a number or path; credential
  flags of common clients (`sqlcmd -P`, `ldapsearch -w`, `redis-cli -a`,
  `smbclient -U user%pass`, `openssl pass:`, `schtasks /rp`, `/pass:`,
  `net use`, `curl -u user:pass`) are replaced irreversibly.
- Redaction: closed gaps for key/value secrets with underscores and
  `passphrase`, URL userinfo, `Authorization: Basic`, JWTs, `--password`
  flags, IPv6, JSON-escaped Windows user paths, `DOMAIN\user`, SIDs, UNC
  server names and labelled serial numbers, UUIDs, machine ids and registered
  owners; hostnames match on word boundaries. Usernames found in
  `local_users`, `computerinfo` and osquery `logged_in_users` are added as
  redaction literals automatically. Per-case redaction settings are persisted
  so reports and operator text are redacted with the same configuration.
- Network: one retrying HTTP helper (`aiit.common.net.http_json`) with bounded
  retries, jittered backoff, `Retry-After`, response size cap and a single
  error type, so a timeout or a proxy HTML page is an error message instead
  of a traceback.
- Audit log: tolerant of torn lines (a crash mid-append is reported as a
  break, never a traceback), appends under a cross-process file lock with
  `fsync`, signed checkpoints (`audit.jsonl.head.json`) that detect truncation
  below the last checkpoint, a console-side witness of each agent's audit head
  that records `audit_regression`, a chain check at the start of every command
  and on a timer while `serve` runs, and alert sinks (`AIIT_ALERT_CMD`,
  `AIIT_ALERT_SYSLOG`, `AIIT_ALERT_WEBHOOK`). CSV export guards against
  spreadsheet formula injection; HTML export escapes every value.
- Console ingest is idempotent on `bundle_id` (`bundles_index.json`), so a
  retried LAN upload cannot create a duplicate case.
- LAN server: 30 s socket timeout, guarded `Content-Length`, bodies streamed
  to a temp file with a 64 MiB cap, bounded concurrency, TLS 1.2 minimum with
  a handshake timeout, per-IP back-off after repeated authentication failures,
  constant-time token comparison, and server version taken from the package.
- `aiit-agent pull` validates and verifies every plan (schema, signature,
  target, expiry, lifetime) before saving it to the inbox.
- Signed plans: agents refuse a plan whose `created_at` is more than five
  minutes in the future or whose lifetime exceeds `max_plan_hours`.
- Agent `apply` evaluates every step against the policy before running any
  (preflight), keeps a write-ahead marker for `--resume`, and requires a typed
  `APPLY` in enforce mode and a typed `REPLAY` for `--force-replay`.
- Private files are written atomically (temp file, `fsync`, rename) with
  `0600` and `O_NOFOLLOW` where the platform supports it.
- Secret scanning: the synthetic fixtures in `tests/test_redact.py` and
  `tests/fixtures/redaction/` are built by concatenation and allow-listed by
  path in `.gitleaks.toml`, so the CI secret scan is green again.

### Added

PR 2, "Operators and platforms" (in progress on this branch):

- `aiit-console dashboard`: a read-only status page bound to loopback only
  (cases, plans with risk colouring, report results, agents, audit chain
  state), no authentication surface, nothing writes. The full browser console
  (login, idle logoff, approval in the browser) is designed in the roadmap.
- OpenAI-compatible provider: `--provider openai`, `azure-openai`,
  `openai-compat`, or the local presets `llamacpp`, `vllm`, `lmstudio`; one
  class over the chat-completions wire format with no SDK dependency, strict
  JSON-schema output with a degrade ladder, keys sent only as a header and
  never audited (`AIIT_OPENAI_BASE_URL`, `AIIT_OPENAI_MODEL`,
  `AIIT_OPENAI_API_KEY` or `OPENAI_API_KEY`, `AIIT_AZURE_OPENAI_DEPLOYMENT`,
  `AIIT_AZURE_OPENAI_API_VERSION`). Bedrock and Vertex stay out of scope.
- Hosted-provider gate: a provider that sends case data off the machine is
  refused unless `--allow-hosted` or `AIIT_ALLOW_HOSTED=1` is given. An
  explicit `--fallback <provider>` on `diagnose` is tried when the first
  provider fails; it may only move towards a more private provider
  (hosted -> local -> dryrun) and is audited as `llm_fallback`. A truncated
  model context is reported as a plan warning.
- Terminal output on both CLIs: colour that honours `NO_COLOR`, `FORCE_COLOR`
  and the Windows console, risk and status labels, a spinner while the model
  works, `--no-color`, `--json` on `report` and `aiit-agent status`. Errors
  print one line with a hint (traceback only with `--debug`); exit codes
  2 usage, 3 provider or network, 4 verification, 5 policy, 130 interrupted,
  1 for an operating-system error.
- Collectors for field testing: every collected file carries a `status`
  (`ok`, `nonzero`, `timeout`, `missing`, `denied`, `empty`, `invalid_json`)
  classified from the exit code, stderr markers and the output; stderr goes
  to a `<name>.stderr.txt` sidecar instead of being appended to JSON;
  collectors that need elevation are marked and a denied result says so;
  the manifest records whether the agent was elevated, the policy digest and
  mode, whether the agent is a frozen executable and which collector set and
  table produced the bundle. No collector runs through `sh -c` any more
  (head/tail are done in Python); narrower `ps` columns; hardware serials
  and UUIDs are dropped from macOS hardware output at collection time.
  Renamed or split collectors: Linux `apt_history` plus `dnf_history`,
  `crontab` plus `cron_d`; macOS `security` is now `gatekeeper`, `filevault`
  and `sip`.
- `aiit-agent selftest [--full] [--json|--markdown] [--seal OUT] [--strict]`:
  runs every collector for this OS and prints per-collector metadata only
  (status, exit code, duration, size, error class), never content or the
  hostname, for field-test reports. CI uploads the JSON report per runner.
- Endpoint key protection: state directories get a restrictive Windows ACL
  (`icacls /inheritance:r`, SYSTEM and Administrators for the agent, the
  current user for the console) and a pre-existing directory owned by
  someone else or writable by others is refused (`AIIT_ALLOW_LOOSE_STATE_DIR=1`
  turns that into a warning). The key passphrase comes from
  `AIIT_KEY_PASSPHRASE`, then `AIIT_KEY_PASSPHRASE_FILE`, then a terminal
  prompt (`AIIT_NO_PROMPT=1` disables it). `aiit-console init` and
  `aiit-agent enroll` print key fingerprints; `enroll --fingerprint` refuses
  a mismatch and without it a typed `ENROLL` is required (`--yes` for lab
  scripts). `aiit-agent status --json` reports both fingerprints.
- Packaging and release: `pyproject.toml` reads the version from the package,
  ships `py.typed`, declares a `release` extra; `packaging/` holds PyInstaller
  entry points and specs; `.github/workflows/release.yml` builds the wheel and
  sdist, one-file and one-folder binaries for Linux, Windows and macOS (arm64
  and x86_64) with a dry-run smoke loop, per-OS offline wheelhouse zips,
  `SHA256SUMS`, a build provenance attestation and a GitHub Release from the
  CHANGELOG section, then publishes to PyPI (or TestPyPI for pre-release
  tags) through trusted publishing. Binaries are unsigned for now. See
  `docs/release-process.md`.

- `aiit-agent push <file|--outbox>` to upload bundles or reports that were
  kept locally after a failed push; `AIIT_SERVER_TOKEN_FILE` as an
  alternative to the environment variable; on push failure the bundle is kept
  and the command exits 3.
- `aiit-console audit` and `aiit-agent audit` subcommand groups:
  `verify`, `export --format csv|jsonl|html`, `timeline`, `repair-tail`.
- Console settings: `--env-file` and `AIIT_ENV_FILE`.
- `Policy.digest()`, printed by `aiit-agent policy digest`, `enroll` and
  `apply`, for pinning a fleet policy.
- Planner repair loop: when the model returns unparseable or schema-invalid
  output the console feeds the validation errors back up to
  `AIIT_PLAN_REPAIRS` times (default 1), audits every attempt, and saves the
  rejected output privately on final failure. Refusals are never retried.
- Ollama provider: `AIIT_OLLAMA_TIMEOUT`, `AIIT_OLLAMA_NUM_CTX`, a "run
  `ollama pull`" hint on 404, and a fallback to `format: json` when the server
  rejects a schema.
- Anthropic provider: `AIIT_HIPAA_MODE=1` disables beta features (server-side
  refusal fallbacks) so requests stay on the BAA-covered surface; a beta 400
  degrades once to the plain Messages call; `AIIT_LLM_MAX_RETRIES` and
  `AIIT_LLM_TIMEOUT`.
- `audit_head` in bundle manifests and execution reports (the agent's last
  audit entry), consumed by the console witness.
- Shared primitives in `aiit.common.util`: `validate_id`, `safe_join`,
  `file_lock`, `atomic_write_bytes`.
- Process helper `aiit.agent.procs.run_capped` with output spooled to temp
  files, a hard output cap and process-group (POSIX) or process-tree
  (Windows) kill on timeout.
- CI: Python 3.13 and 3.14 in the matrix (3.10, 3.12, 3.13, 3.14 on Linux,
  Windows and macOS), coverage collection with a combined gate, `bandit`,
  `pip-audit` on a runtime-only install, an install-from-wheel job with an
  offline wheelhouse simulation, cancel-in-progress concurrency.
- CodeQL workflow (push, pull request and weekly), Dependabot for GitHub
  Actions and pip.
- Governance files: `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `SUPPORT.md`,
  `.github/CODEOWNERS`, issue templates (bug, feature, provider request),
  pull request template.
- `docs/security/threat-model.md` (STRIDE table with control, location, test
  and residual risk for every threat, attack trees, crypto inventory,
  accepted risks, assessment scope) and
  `docs/compliance/risk-analysis-template.md`.
- `scripts/run-tests.ps1` for Windows and `scripts/run-tests.sh --coverage`.
- Tests: `test_util`, `test_net`, `test_store`, `test_server`,
  `test_agent_cli`, `test_console_cli`, `test_audit`, `test_docs`, a
  table-driven policy bypass corpus, golden redaction fixtures, and a
  scripted `FakeHTTP` server in `tests/helpers.py`.

### Changed
- Console `approve` refuses a plan that carries lint warnings unless
  `--ack-warnings` is given (it used to print the warnings and sign anyway,
  even with `--yes`). `diagnose --hours` is capped by the policy's
  `max_plan_hours` unless `--long-lived` is given, and `approve --hours`
  re-dates both `created_at` and `expires_at` so the endpoint's lifetime
  check agrees with the console's.
- Console: an explicit `--env-file` or `AIIT_ENV_FILE` that does not exist is
  a usage error instead of being ignored. Previous execution reports are fed
  to the model in the order they were received. Harvested account names that
  are generic words (info, data, temp, backup, ...) are not added to the
  redaction literals, and literals are replaced as whole words only.
- Anthropic provider: an SDK too old for server-side fallbacks degrades to a
  plain request instead of crashing with a `TypeError`; one too old for
  `output_config` reports a clear `ProviderError`.
- Agent `push --outbox` pushes every bundle and reports each failure instead
  of stopping at the first one; it exits 3 at the end if any failed.
- An interrupted enforce run is refused on the next `apply` unless `--resume`
  (continue after the completed steps) or `--force-replay` (typed REPLAY,
  audited) is given; previously a note was printed and every step ran again.
- HTTP helper: `Retry-After` is honoured as sent up to 120 s; above that the
  request fails at once instead of hammering the server. Requests to loopback
  and private addresses bypass `http_proxy`/`https_proxy`, so a corporate
  proxy setting no longer breaks the LAN mailbox or a local Ollama.
- Audit: `check_and_alert` runs a full chain scan while the log is at most
  8 MiB and only switches to the incremental scan above that, so a same-length
  edit before the last checkpoint is caught at start-up. `audit repair-tail`
  re-signs the checkpoint when the identity is available; a stale checkpoint
  offset falls back to the full scan instead of alarming forever.
- Collectors run under the same scrubbed environment as plan steps, so the `env_names` collector now lists only that reduced set (no `AIIT_*`, token, key or passphrase variables reach a bundle).

- **BREAKING**: the console reads `.env` from its data directory
  (`<data dir>/.env`, default `~/.aiit/console/.env`) or from
  `--env-file` / `AIIT_ENV_FILE`, never from the current directory. A `.env`
  in the working directory is ignored with a note. Move your file:
  `cp .env ~/.aiit/console/.env` (or point `AIIT_ENV_FILE` at it). A group- or
  world-writable file is refused on POSIX.
- **BREAKING**: `aiit-console serve` refuses to bind to anything but loopback
  without `--tls-cert`/`--tls-key` unless `--insecure-no-tls` is passed
  explicitly. The default `--host 0.0.0.0` therefore needs TLS.
- **BREAKING**: the LAN server returns `422` when a bundle is rejected
  (bad signature, bad manifest, path escape) and `503` for storage errors;
  previously both were `400`. Clients that branch on the status code must be
  updated. `429` with `Retry-After` is returned after repeated
  authentication failures from one address.
- **BREAKING**: `audit` is a subcommand group on both CLIs
  (`audit verify|export|timeline|repair-tail`). `aiit-console audit-verify`
  is kept as an alias for `audit verify`.
- **BREAKING**: plan ids, agent ids, bundle ids, case ids and console ids are
  validated against `^[a-z]{1,16}-[0-9a-f]{12}$` everywhere they are read from
  a file, a header or the network. Ids minted by any released version match;
  hand-edited ids do not.
- **BREAKING**: agents refuse plans whose lifetime (`expires_at - created_at`)
  exceeds `max_plan_hours` (default 72) in `policy.json`.
  `aiit-console approve --hours` above 72 needs `--long-lived` and a raised
  `max_plan_hours` on the endpoint.
- `policy.json` version `2`: new fields `max_plan_hours` and
  `risk_floor_overrides`; version 1 files load with defaults. Every pattern is
  compiled on load and a bad regex is reported by name.
- `LLMProvider.complete_json(system, user, schema, meta)` takes a fourth
  `meta` argument (local-only hints: target OS, case id, redacted issue
  text) and providers raise `ProviderOutputError` carrying the raw text when
  the answer is not usable JSON; `parse_json_text` is shared by all
  providers.
- Every `llm_request` audit entry records `hosted` and `endpoint` so an
  auditor can see whether data left the operator machine.
- Ingest records `ingest_failed` and `ingest_duplicate`; the server records
  `serve_auth_fail` and `serve_ingest_error`.
- Agent exit codes: 2 usage, 3 network, 4 verification, 5 policy.
- `tests/test_e2e.py` runs the LAN loop through the hardened server.

### Fixed

- Read timeouts in the Ollama and Anthropic providers surfaced as a bare
  `TimeoutError` traceback instead of a `ProviderError` with a hint.
- A torn last line in `audit.jsonl` (power loss mid-append) made every later
  command crash; it is now reported as a break and `audit repair-tail` moves
  the fragment aside.
- `aiit-console report` accepted a report whose archive paths escaped the case
  directory.
- Docs drift: `docs/architecture.md` described a `require_reboot_flag` policy
  field, an old `complete_json` signature and three LAN endpoints;
  `docs/compliance/hipaa.md` linked a risk-analysis template that did not
  exist; `docs/research/open-source-landscape.md` promised an automatic
  dry-run fallback that was never implemented.

### Planned (lands in PR 2, listed here because it changes defaults)

- **BREAKING**: hosted providers (today `anthropic`, plus the planned
  OpenAI-compatible provider pointed at a non-private host) will require
  `AIIT_ALLOW_HOSTED=1` or `--allow-hosted`. This is the HIPAA-safe default:
  nothing leaves the operator machine unless an operator says so. Set the
  variable in the console `.env` before upgrading if you use `anthropic`.
- An explicit `--fallback dryrun` option for `diagnose` (never automatic,
  only towards a more private provider, always audited).
- Windows ACLs (`icacls`) on the agent and console state directories, a
  passphrase prompt and `AIIT_KEY_PASSPHRASE_FILE`, key fingerprint
  confirmation at enrollment.

## [0.1.0] - 2026-10-08

Initial release: the whole offline loop working end to end.

### Added

- `aiit-agent` for endpoints: `enroll`, `collect` (Windows, Linux and macOS
  collectors, osquery when present), `apply` (signature, target, expiry and
  replay checks, local policy with deny patterns, risk ceiling and dry-run
  default), `pull`, `status`, `policy`, `audit-verify`.
- `aiit-console` for the operator machine: `init`, `enrollment`, `ingest`
  (decrypt, verify, redact into a case folder), `cases`, `show`, `preview`,
  `diagnose` (dryrun, Ollama and Anthropic providers with structured output),
  `plans`, `plan`, `approve` (Ed25519-signed plans bound to agent, case and
  expiry), `report`, `agents`, `audit-verify`, `serve` (LAN mailbox with a
  shared token and optional TLS).
- Sealed bundle format `.aiit`: X25519 + HKDF-SHA256 + AES-256-GCM to the
  console key, Ed25519 agent signature over the header, SHA-256 per file in
  the manifest.
- Deterministic per-case redaction (HMAC-SHA256 tokens) for emails, SSNs,
  phones, cards, IPs, MACs, user paths, hostnames and obvious secrets.
- Hash-chained JSONL audit log on both sides.
- CI on Linux, Windows and macOS with gitleaks secret scanning; pre-commit
  hooks; Apache-2.0 license.
- Research and design documents: `docs/architecture.md`,
  `docs/compliance/hipaa.md`, `docs/research/open-source-landscape.md`,
  `docs/roadmap.md`.

[Unreleased]: https://github.com/RockMoon1/AI_IT/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RockMoon1/AI_IT/releases/tag/v0.1.0
