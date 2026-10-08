# AI_IT

Open source, HIPAA-minded AI IT support. An operator talks to an AI on a
connected machine; the machines being fixed can be completely offline. The
endpoint agent collects system facts, configs and logs into an encrypted
bundle, the console redacts it and asks a model (local Ollama by default, or
the Claude API under a BAA) for a structured fix plan, the operator approves
and signs the plan, and the agent runs it under a local policy with a
tamper-evident audit trail.

Status: phase 0. The full offline loop works end to end on Linux in CI.
Windows and macOS collectors are written and need field testing. See
`docs/roadmap.md`.

## Why another tool

No existing open source project covers offline endpoints, an approval-gated
AI planner, and PHI redaction together. The research behind that statement,
with licenses verified against each repository, is in
`docs/research/open-source-landscape.md`. The HIPAA analysis is in
`docs/compliance/hipaa.md`. The design is in `docs/architecture.md`.

## Quick start (sneakernet mode)

Operator machine:

```bash
pip install -e .            # or: pip install aiit  (once published)
cp .env.example .env        # edit; .env is git-ignored
aiit-console init --label "clinic-helpdesk"
# prints the public enrollment file to copy to endpoints
```

Endpoint (can be offline; copy the wheel and the enrollment file over):

```bash
pip install aiit-0.1.0-py3-none-any.whl
aiit-agent enroll console-enrollment.json
aiit-agent collect --issue "Outlook crashes on start since Monday" --out E:\case.aiit
```

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
aiit-console audit-verify                        # hash chain intact?
```

LAN mode (`aiit-console serve`, `aiit-agent collect --push`, `aiit-agent pull`)
moves the same files over HTTP with a shared token; nothing else changes.

## Providers

| `AIIT_PROVIDER` | Where data goes | Notes |
|---|---|---|
| `ollama` (default) | Nowhere. Local model. | Install Ollama and pull a model; set `AIIT_OLLAMA_MODEL`. |
| `anthropic` | Anthropic API | Requires `pip install 'aiit[anthropic]'` and `ANTHROPIC_API_KEY`. For PHI, only with a signed BAA. Default model `claude-opus-5-5`, effort `high`, server-side refusal fallbacks on. |
| `dryrun` | Nowhere. No model. | Read-only checklist so you can test the pipeline. |

## Secrets never reach git

`.env`, keys, bundles, cases and signed plans are git-ignored. A gitleaks
pre-commit hook and a CI secret scan back that up. See `SECURITY.md`.

## Development

```bash
python -m pip install -e ".[dev]"
pre-commit install
python -m unittest discover -s tests -t . -v
```

License: Apache-2.0.
