<!--
Thanks for the contribution. The checklist mirrors the hard constraints in
CONTRIBUTING.md and GOVERNANCE.md. Tick what applies; explain anything you
cannot tick. Pull requests that touch a trust boundary (crypto, policy,
redact, audit, executor, procs, server, bundle or plan formats) also need a
threat-model update and a failure-case test.
-->

## What and why

<!-- One or two paragraphs. Link the issue if there is one. -->

## How it was tested

<!-- Which test modules you ran locally and on which OS. -->

## Checklist

- [ ] Runtime dependencies are unchanged: Python stdlib + `cryptography` + `pydantic` only (no new imports from third-party packages; `dev` extras are fine).
- [ ] Code runs on Python 3.10 (no `match`, no `tomllib`, no 3.11+ typing features) and on Linux, macOS and Windows.
- [ ] Anything that executes on an endpoint goes through `aiit.common.policy.Policy.evaluate` and `aiit.agent.executor`; no second execution path was added.
- [ ] Anything that reaches a model goes through `aiit.common.redact` first, including operator-supplied text.
- [ ] No secrets, bundles, case folders, keys, audit logs or real hostnames in the diff, in tests or in fixtures. Credential-shaped test strings are built by concatenation.
- [ ] Tests use `unittest` only, fake servers instead of the network (`tests/helpers.FakeHTTP`), the cross-platform helpers (`echo_cmd`, `fail_cmd`, `sleep_cmd`), and OS-specific assertions are gated with `unittest.skipUnless`.
- [ ] CI is green on all three operating systems and every Python in the matrix, including the coverage gate and static analysis.
- [ ] Documentation updated where behaviour changed (`README.md`, `docs/architecture.md`, `.env.example` for any new `AIIT_*` variable).
- [ ] `CHANGELOG.md` has an entry under `Unreleased` in the right group (Security / Added / Changed / Fixed), marked `BREAKING` with a migration note if applicable.
- [ ] If a trust boundary changed: `docs/security/threat-model.md` updated and a test exercises the failure case.

## Breaking changes

<!-- "None", or the migration step an operator must take. -->
