# Contributing

Thank you for helping. This page covers the mechanics; `GOVERNANCE.md`
covers how decisions are made and `SECURITY.md` covers how to report a
vulnerability privately.

## Setup

```bash
git clone https://github.com/RockMoon1/AI_IT.git
cd AI_IT
python -m pip install -e ".[dev]"
pre-commit install
```

`dev` installs `pre-commit`, `coverage`, `bandit` and `pip-audit`. The
`anthropic` extra is only needed to exercise that provider by hand; the test
suite fakes it.

## Hard constraints

1. **Dependencies.** Runtime code uses the Python standard library plus
   `cryptography` and `pydantic`, nothing else. The agent must install on an
   offline laptop from a single wheel. Development tools go in the `dev`
   extra. A pull request that adds a runtime import from another package will
   be asked for the written case described in `GOVERNANCE.md`, section 3.
2. **Python versions and platforms.** Code runs on Python 3.10 through 3.14
   and on Linux, macOS and Windows. No `match` statements, no `tomllib`, no
   typing features newer than 3.10. Use `pathlib`, `os.replace`, and the
   helpers in `aiit.common.util` (`safe_join`, `file_lock`,
   `atomic_write_bytes`) rather than hand-rolled equivalents.
3. **One execution path.** Anything that runs a command on an endpoint goes
   through `aiit.common.policy.Policy.evaluate` and `aiit.agent.executor`
   (which uses `aiit.agent.procs.run_capped`). Do not add a second path, not
   even for collectors.
4. **One path to the model.** Anything that is sent to an LLM goes through
   `aiit.common.redact` first, including text typed by the operator.
5. **No secrets, no PHI.** Never commit keys, bundles, cases, audit logs,
   `.env` files or real hostnames. Secret-shaped strings in tests are built by
   concatenation (`"-----BEGIN " + "PRIVATE KEY-----"`), never written
   literally, so gitleaks and the pre-commit hook stay green.
6. **Trust boundaries.** A change to `crypto.py`, `policy.py`, `redact.py`,
   `audit.py`, `executor.py`, `procs.py`, `server.py` or the bundle and plan
   formats needs a matching row in `docs/security/threat-model.md` and a test
   that exercises the failure case.
7. **No em dashes** in code comments, docstrings or documentation; use commas,
   colons or parentheses.

## Tests

* **`unittest` only.** No pytest, no plugins. Test modules live in `tests/`
  and are named `test_<module>.py`; each imports `tests.helpers` first, which
  puts `src/` on the path.
* **Fakes, not the network.** Anything network-bound talks to
  `tests.helpers.FakeHTTP`, a scripted HTTP server:

  ```python
  from tests.helpers import FakeHTTP
  srv = FakeHTTP().start()
  srv.queue(503, {"error": "busy"})
  srv.queue(200, {"ok": True}, headers={"X-Test": "1"}, delay=0.1)
  ...  # point the code at srv.url
  srv.requests  # list of recorded requests (method, path, headers, body)
  srv.stop()
  ```

  Providers are driven with `ScriptedProvider` (see
  `tests/test_planner_providers.py`); the Anthropic SDK is replaced with a
  fake module through `mock.patch.dict(sys.modules)`. Retry logic takes an
  injectable `sleep` so tests never wait.
* **Cross-platform snippets.** Shell commands in tests come from
  `tests.helpers.echo_cmd(text)`, `fail_cmd(code)` and `sleep_cmd(seconds)`,
  which produce PowerShell on Windows and `sh` elsewhere. Gate anything
  OS-specific with `unittest.skipUnless(os.name == "nt", ...)` or
  `skipUnless(sys.platform == "darwin", ...)`; every test must pass on the
  `ubuntu-latest`, `windows-latest` and `macos-latest` runners.
* **Hostile inputs.** Build hostile bundles with the real `bundle.pack_dir`
  and `bundle.write_bundle` (pattern in `tests/test_store.py`); add policy
  bypasses to the corpus in `tests/test_policy.py`; add redaction cases to the
  golden fixtures under `tests/fixtures/redaction/` with the planted values
  listed in the matching `.planted.json`.
* **Coverage.** CI combines coverage from every OS and Python and enforces a
  minimum (`COV_MIN` in `.github/workflows/ci.yml`, 70 today, rising with
  each pull request towards 85). New code is expected to arrive with tests
  that cover its error branches, not just the happy path.
* **Docs are tested too.** `tests/test_docs.py` checks that every
  `aiit-agent ...` / `aiit-console ...` example in `README.md` and `docs/`
  names a real subcommand, that every `AIIT_*` variable read by the code is
  listed in `.env.example`, and that `CHANGELOG.md` has an `Unreleased`
  section.

### Running the tests

Everything, on Linux or macOS:

```bash
scripts/run-tests.sh                 # or: PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
scripts/run-tests.sh --coverage      # same, with a coverage report
```

On Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run-tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\run-tests.ps1 -Coverage
```

or, without the script, from the repository root:

```powershell
$env:PYTHONPATH = "src"; python -m unittest discover -s tests -t . -v
```

A single module, for example while working on the policy engine:

```bash
PYTHONPATH=src python3 -m unittest tests.test_policy -v
```

A single test case or method:

```bash
PYTHONPATH=src python3 -m unittest tests.test_policy.AllowListTests -v
PYTHONPATH=src python3 -m unittest tests.test_policy.AllowListTests.test_non_matching_command_refused -v
```

The real Windows and macOS collectors run only when
`AIIT_RUN_REAL_COLLECTORS=1` is set (CI sets it on those runners); everything
else is hermetic.

Static checks that CI also runs:

```bash
python -m bandit -r src -ll -ii -c pyproject.toml
python -m pip_audit --strict
pre-commit run --all-files
```

## Pull requests

* One topic per pull request; keep commits in a reviewable order.
* Fill in the template; the checklist mirrors the constraints above.
* Add a line to `CHANGELOG.md` under `Unreleased`, in the right group
  (`Security`, `Added`, `Changed`, `Fixed`). Mark anything an operator must
  act on as **BREAKING** with the migration step.
* Update `README.md`, `docs/architecture.md` and `.env.example` when behaviour
  or configuration changes.
* Write docstrings for public functions: what they do, what they raise, and
  any security property they are responsible for.
* Expect review from the code owner for the trust-boundary files
  (`.github/CODEOWNERS`).

## Licensing

Contributions are accepted under Apache-2.0. Do not copy code from AGPL or
source-available projects (RustDesk, Tactical RMM) into this tree; integrate
with them over their network APIs instead. See
`docs/research/open-source-landscape.md` for the license table.
