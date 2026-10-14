# AI_IT

Open source, HIPAA-minded AI IT support. An operator talks to an AI on a
connected machine; the machines being fixed can be completely offline. The
endpoint agent collects system facts, configs and logs into an encrypted
bundle, the console redacts it and asks a model (local Ollama by default, or
the Claude API under a BAA) for a structured fix plan, the operator approves
and signs the plan, and the agent runs it under a local policy with a
tamper-evident audit trail.

Status: phase 1 in progress. The full offline loop runs end to end in CI on
Linux, Windows and macOS (3 OS x 4 Python versions, coverage-gated). The real
Windows and macOS collectors pass a smoke test on GitHub runners; field tests on
real laptops are still needed. See `docs/roadmap.md` and `CHANGELOG.md`.

## Why another tool

No existing open source project covers offline endpoints, an approval-gated
AI planner, and PHI redaction together. The research behind that statement,
with licenses verified against each repository, is in
`docs/research/open-source-landscape.md`. The HIPAA analysis is in
`docs/compliance/hipaa.md`. The design is in `docs/architecture.md`.

## Quick start (sneakernet mode)

Every release on the [Releases page](https://github.com/RockMoon1/AI_IT/releases)
ships three ways to install, all of which work with no network:

| Asset | Use it when |
|---|---|
| `aiit-<version>-<os>-<arch>.tar.gz` (`.zip` on Windows) | The machine has no Python. Standalone `aiit-agent` and `aiit-console` for Linux x86_64, Windows x86_64, macOS arm64 and x86_64. Unsigned: verify `SHA256SUMS` first, see `docs/release-process.md`. |
| `aiit-<version>-wheelhouse-<os>-<arch>.zip` | The machine has Python 3.10 to 3.14 but no internet: the wheel plus every dependency, installed with `pip install --no-index`. |
| `aiit-<version>-py3-none-any.whl` | The machine has Python and can reach PyPI: `pip install aiit` fetches this same wheel. |

Each release also carries `SHA256SUMS` and a build-provenance attestation
(`gh attestation verify <file> --repo RockMoon1/AI_IT`).

Operator machine (online):

```bash
pip install aiit                      # or, from a checkout: pip install -e .
aiit-console init --label "clinic-helpdesk"
# prints the public enrollment file to copy to endpoints
cp .env.example ~/.aiit/console/.env   # settings live next to the console data, never in the repo
```

Endpoint (offline; copy the wheelhouse zip or the binary archive and the
enrollment file over on the same stick):

```bash
unzip aiit-<version>-wheelhouse-<os>-<arch>.zip -d wheelhouse
python -m pip install --no-index --find-links wheelhouse aiit
aiit-agent enroll console-enrollment.json
aiit-agent collect --issue "Outlook crashes on start since Monday" --out E:\case.aiit
```

Without Python, unpack the binary archive instead and run `aiit-agent` from
it (`onedir/aiit-agent/aiit-agent` is the faster-starting one-folder build);
the commands are the same.

Back on the operator machine:

```bash
aiit-console ingest E:\case.aiit                 # decrypt, verify, redact -> case id
aiit-console show case-xxxx                      # what was collected, redaction counts
aiit-console diagnose case-xxxx --issue "Outlook crashes on start"
aiit-console plan case-xxxx <plan_id>            # read it
aiit-console approve case-xxxx <plan_id> --out E:\   # sign; bound to that endpoint, expires in 24h
```

Endpoint:

```bash
aiit-agent apply E:\<plan_id>.signed.json         # dry run by default
aiit-agent policy set-mode enforce               # when you are ready to let it run commands
aiit-agent apply E:\<plan_id>.signed.json --out E:\report.aiit
```

Operator machine:

```bash
aiit-console report E:\report.aiit               # attach results to the case
aiit-console audit verify                        # hash chain intact? (also: audit export --format html --out audit.html)
```

LAN mode (`aiit-console serve --tls-cert ... --tls-key ...`, `aiit-agent collect --push`,
`aiit-agent push --outbox`, `aiit-agent pull`) moves the same files over HTTPS with a
shared token; nothing else changes. A bind on anything but loopback requires TLS
unless you pass `--insecure-no-tls` on a trusted LAN.

## Providers

| `AIIT_PROVIDER` | Where data goes | Notes |
|---|---|---|
| `ollama` (default) | Nowhere. Local model. | Install Ollama and pull a model; set `AIIT_OLLAMA_MODEL`. |
| `anthropic` | Anthropic API | Requires `pip install 'aiit[anthropic]'` and `ANTHROPIC_API_KEY`. For PHI, only with a signed BAA. Default model `claude-opus-5-5`, effort `high`, server-side refusal fallbacks on. |
| `dryrun` | Nowhere. No model. | Read-only checklist so you can test the pipeline. |

## Secrets never reach git

`.env`, keys, bundles, cases and signed plans are git-ignored. A gitleaks
pre-commit hook and a CI secret scan back that up. The console reads its `.env`
from its own data directory (or `--env-file`), never from the current directory.
See `SECURITY.md` and `docs/security/threat-model.md`.

## Development

```bash
python -m pip install -e ".[dev]"
pre-commit install
python -m unittest discover -s tests -t . -v      # or scripts/run-tests.sh --coverage
python -m bandit -r src -ll -ii -c pyproject.toml
```

License: Apache-2.0.
