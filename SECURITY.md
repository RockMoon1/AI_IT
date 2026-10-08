# Security Policy

## Reporting a vulnerability

Open a private security advisory on GitHub ("Security" tab, "Report a vulnerability")
or email the maintainer listed in the repository profile. Do not open a public issue
for an exploitable bug. We aim to acknowledge reports within 72 hours.

## What never goes in this repository

* API keys, tokens, passwords, private keys (`*.key`, `*.pem`), `.env` files.
* Diagnostic bundles (`*.aiit`), case folders, redaction maps, audit logs.
  These contain customer system data and may contain protected health
  information (PHI).
* Signed plans (`*.signed.json`): they are bound to a specific endpoint.

The `.gitignore`, the gitleaks pre-commit hook, and the CI secret scan exist
to enforce this. If a secret is ever committed: rotate it first, then purge
history (`git filter-repo`), then force-push. Deleting the file in a later
commit is not enough.

## Trust model (summary)

* Endpoints trust exactly one operator console, identified by its Ed25519
  signing key, imported at enrollment. The agent runs only plans carrying a
  valid signature from that key, addressed to its own agent id, not expired,
  and not previously applied.
* Diagnostic bundles are encrypted to the console's X25519 key before they
  leave the endpoint (sneakernet or LAN), and signed by the agent key.
* The LLM never gets raw data. The console redacts identifiers and secrets
  first and the agent-side policy can still block any command the model
  proposes.

See `docs/architecture.md` and `docs/compliance/hipaa.md` for the full model.
