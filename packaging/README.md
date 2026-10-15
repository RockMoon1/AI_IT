# packaging/

Everything that turns the `aiit` package into release files. The release itself is
driven by `.github/workflows/release.yml`; the owner's checklist is
`docs/release-process.md`.

| File | Purpose |
|---|---|
| `entry_agent.py`, `entry_console.py` | PyInstaller entry points. Each imports the installed package and calls the same `main` the pip console scripts call, nothing more. |
| `aiit-agent.spec`, `aiit-console.spec` | PyInstaller build recipes. One spec builds either layout: one-folder by default, single file with `AIIT_PYI_ONEFILE=1`. |
| `release_notes.py` | Standard-library helper the workflow runs: checks that the tag, `__version__` and `CHANGELOG.md` agree, and renders the GitHub Release body from the matching changelog section. |

Do not add an `__init__.py` here. The directory is named `packaging`, and a package of
that name on `sys.path` (the repository root is on it whenever `python -m build` or
`pyinstaller` runs from the root) would shadow the `packaging` library that `build`,
`pip` and PyInstaller import. Without `__init__.py` Python prefers the real library.

## Build the binaries locally

```bash
python -m pip install ".[release]"                      # build, twine, pyinstaller; never runtime deps
pyinstaller --clean --noconfirm packaging/aiit-agent.spec                      # dist/aiit-agent/   (one folder)
AIIT_PYI_ONEFILE=1 pyinstaller --clean --noconfirm packaging/aiit-console.spec # dist/aiit-console  (one file)
```

The spec reads the installed `aiit`, so reinstall after a source change. Frozen
programs have `sys.frozen == True` and `sys._MEIPASS` set by PyInstaller; that flag is
what tells a binary apart from a wheel install (the bundle manifest's `aiit_frozen`).
The one-folder layout starts faster and is friendlier to antivirus software; the
single file is the one to carry on a USB stick.

What is deliberately not in a frozen build: the `anthropic` extra (a binary has no
`pip`; the `dryrun` and `ollama` providers work, the `anthropic` provider needs a wheel
install) and `tkinter`. The binaries are unsigned; see `docs/release-process.md`.

## Smoke test a frozen build

The same dry-run loop the workflow runs on every platform, with the binaries instead
of the console scripts (`aiit-console init`, `aiit-agent enroll`, `collect --quick`,
`ingest`, `diagnose --provider dryrun`, `approve --yes`, `apply --dry-run --yes`,
`report`, `audit verify`). It lives in the `Smoke test` step of
`.github/workflows/release.yml`; copy the commands from there to run them by hand.
