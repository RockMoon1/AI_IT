# Security Policy

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `Main` branch | Yes | Where fixes land first. |
| 0.1.x | Yes, until 0.2.0 is released | Security fixes only. |
| Earlier | No | |

Only the latest minor release receives security fixes. Upgrade before
reporting an issue that a newer release may already address, and check
`CHANGELOG.md` for the `Security` sections.

## Reporting a vulnerability

Open a private security advisory on GitHub: repository **Security** tab,
**Report a vulnerability**. If you cannot use GitHub, contact the maintainer
listed in `GOVERNANCE.md` through their GitHub profile and ask for a private
channel. Do not open a public issue or discussion for an exploitable bug.

Please include: the version, the component (agent, console, server, a
specific module), the operating system, steps to reproduce with synthetic
data, and the impact you believe it has. Never attach a real bundle, case
folder, audit log, key or hostname; see `SUPPORT.md` for what must stay
private. If you need to demonstrate a redaction gap, build a synthetic input
like the fixtures under `tests/fixtures/redaction/`.

## What to expect

* **Acknowledgement within 72 hours** of the report reaching the maintainer.
* An initial assessment (confirmed, needs more information, or not a
  vulnerability) within 7 days.
* A fix on the security fast path described in `GOVERNANCE.md`, section 5,
  released out of band as a patch version.
* **Coordinated disclosure after 90 days** at the latest, or earlier when a
  fix is released. If a fix is not ready after 90 days we publish the advisory
  with mitigations anyway; please tell us if you plan to publish earlier so we
  can coordinate. Reporters are credited in the advisory unless they ask not
  to be.
* No bug bounty; this is a volunteer project.

## Scope

In scope:

* The `aiit` Python package: both command-line tools, the sealed bundle and
  signed plan formats, the LAN mailbox server, the policy engine and
  executor, the redaction layer, the audit log, the key handling and the
  provider adapters.
* The CI and release configuration in this repository (`.github/`,
  `pyproject.toml`, `scripts/`).
* The documentation, where it describes a control that the code does not
  actually implement.

Out of scope:

* Vulnerabilities in the operating system, in Ollama, in the Anthropic API or
  SDK, or in the `cryptography` and `pydantic` packages. Report those
  upstream; tell us if AI_IT needs a change to mitigate them.
* Attacks that require an already compromised operator machine or an
  already compromised endpoint account; these are discussed as residual risk
  in `docs/security/threat-model.md`, which also lists the accepted risks
  (section 7). A report that one of those is exploitable in a way the
  document does not describe is in scope.
* Denial of service by a party already on the operator's LAN beyond what the
  server's documented limits promise.
* Social engineering of operators.

## Safe harbour

Research conducted in good faith, on your own installations, with synthetic
data, within the scope above and reported privately will not lead to action
by the maintainers. Do not test against systems or data you do not own.

## What never goes in this repository

* API keys, tokens, passwords, private keys (`*.key`, `*.pem`), `.env` files.
* Diagnostic bundles (`*.aiit`), case folders, redaction maps, audit logs.
  These contain customer system data and may contain protected health
  information (PHI).
* Signed plans (`*.signed.json`): they are bound to a specific endpoint.

The `.gitignore`, the gitleaks pre-commit hook, and the CI secret scan exist
to enforce this. If a secret is ever committed: rotate it first, then purge
history (`git filter-repo`), then force-push. Deleting the file in a later
commit is not enough. Test fixtures that need a secret-shaped string build it
by concatenation so the scanners stay quiet without allow-listing real shapes.

## Trust model (summary)

* Endpoints trust exactly one operator console, identified by its Ed25519
  signing key, imported at enrollment. The agent runs only plans carrying a
  valid signature from that key, addressed to its own agent id, not expired,
  not older than `max_plan_hours`, and not previously applied.
* Diagnostic bundles are encrypted to the console's X25519 key before they
  leave the endpoint (sneakernet or LAN), and signed by the agent key.
* The LLM never gets raw data. The console redacts identifiers and secrets
  first, including the operator's own issue text, and the agent-side policy
  can still block any command the model proposes.
* The LAN mailbox is a dumb file store behind a shared token; a non-loopback
  bind requires TLS.

The full model, with every threat, its control, the code that implements it,
the test that covers it and the residual risk, is in
`docs/security/threat-model.md`. The compliance mapping is in
`docs/compliance/hipaa.md`.
