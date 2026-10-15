# Release process

How a version of AI_IT gets from `Main` to the Releases page and PyPI, what the
owner has to set up once, what to check afterwards, and how to withdraw a bad
release. The mechanics live in `.github/workflows/release.yml` and
`packaging/`; this page is the human side.

## What a release contains

Pushing a tag `vX.Y.Z` builds, tests and publishes, in this order:

| Job | Runs on | Produces |
|---|---|---|
| `dist` | ubuntu | `aiit-X.Y.Z-py3-none-any.whl` and `aiit-X.Y.Z.tar.gz`. Refuses to continue unless the tag, `__version__` and `CHANGELOG.md` agree. Installs the wheel in a fresh venv and runs the whole test suite against it (`AIIT_TEST_INSTALLED=1`). |
| `binaries` | ubuntu-22.04, windows-latest, macos-14 (arm64), macos-15-intel (x86_64) | `aiit-X.Y.Z-<os>-<arch>.tar.gz` (`.zip` on Windows): single-file and one-folder PyInstaller builds of both tools, smoke-tested with the full dry-run loop before they are packed. |
| `wheelhouse` | the same four runners | `aiit-X.Y.Z-wheelhouse-<os>-<arch>.zip`: the wheel plus every dependency wheel for CPython 3.10 to 3.14 on that platform, for `pip install --no-index --find-links`. Installed with no index on the runner as a check. |
| `release` | ubuntu | `SHA256SUMS`, a build-provenance attestation for every asset, and the GitHub Release whose body is the matching `CHANGELOG.md` section plus the asset table and the verification and unsigned-binary notes. `-rc`, `-beta` and `-alpha` tags are marked pre-release. |
| `pypi` | ubuntu, environment `pypi` | The wheel and sdist on PyPI, through trusted publishing. Final versions only. |
| `testpypi` | ubuntu, environment `testpypi` | The same on TestPyPI, for pre-release tags only. |

`binaries` and `wheelhouse` wait for `dist`; `release` waits for all three;
`pypi`/`testpypi` wait for `release`, so nothing reaches PyPI unless the
GitHub Release with its checksums and attestations exists. A manual run of
the workflow (Actions, Release, Run workflow, on a branch) does everything up
to and including `wheelhouse` and keeps the results as workflow artifacts; it
never publishes. Use it to rehearse.

Runner notes: the Linux binaries are built on ubuntu-22.04 on purpose, because
a PyInstaller binary needs a glibc at least as new as its build host (2.35
covers Ubuntu 22.04+, Debian 12+, RHEL 9+). GitHub retired the `macos-13`
image in December 2025; `macos-15-intel` is the x86_64 macOS runner. There is
no Linux aarch64 or Windows arm64 build yet; those endpoints use the wheelhouse.

## One-time setup (owner)

Everything below is a click in a web UI; nothing is stored in the repository
and no API token exists anywhere. Trusted publishing lets PyPI accept uploads
from this exact repository, workflow file and environment, authenticated by
GitHub's OpenID Connect token.

### 1. PyPI and TestPyPI accounts

1. Create an account on <https://pypi.org> and on <https://test.pypi.org>
   (separate accounts; TestPyPI is a different site). Enable two-factor
   authentication on both; PyPI requires it for project owners.
2. Check that the name `aiit` is free on both sites. If it is taken, change
   `name` in `pyproject.toml` (for example `ai-it`) before the first release;
   the workflow's `aiit-*.whl` globs and the archive names follow from it.

### 2. Register `aiit` as a pending trusted publisher

Because the project does not exist on PyPI yet, it is created by the first
trusted upload. On <https://pypi.org/manage/account/publishing/> add a
**pending publisher** with exactly:

| Field | Value |
|---|---|
| PyPI project name | `aiit` |
| Owner | `RockMoon1` |
| Repository name | `AI_IT` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Repeat on <https://test.pypi.org/manage/account/publishing/> with environment
name `testpypi`. After the first successful upload the pending publisher turns
into the project's publisher automatically; you can see it under the project's
*Publishing* settings.

### 3. GitHub environments

On <https://github.com/RockMoon1/AI_IT/settings/environments> create two
environments, `pypi` and `testpypi`. For each:

* **Deployment branches and tags**: *Selected branches and tags*, add the tag
  rule `v*`. This stops any other ref from reaching the publish job.
* **Required reviewers** (optional, recommended for `pypi`): add yourself. The
  `pypi` job then pauses with a *Review deployments* button until you approve
  it, which is the last moment to stop a release before it becomes permanent
  on PyPI. Leave `testpypi` without reviewers so rc tags publish unattended.
* No secrets. The environment exists only so that trusted publishing and the
  reviewer gate can be bound to it.

### 4. Nothing else

Build-provenance attestations need no setup on a public repository. The
GitHub Release is created with the workflow's own `GITHUB_TOKEN`; the
workflow file grants `contents: write` to that one job. Dependabot already
watches the action versions (`.github/dependabot.yml`).

## Cutting a release

The version is written in exactly one place, `src/aiit/__init__.py`;
`pyproject.toml` reads it at build time and the workflow refuses a tag that
does not match it. Tags are `vX.Y.Z`; pre-releases are `vX.Y.Z-rcN` with
`__version__ = "X.Y.ZrcN"` (PEP 440 has no hyphen, the tag has one; the
workflow normalises both before comparing).

1. On a branch off `Main`:
   * Set `__version__` in `src/aiit/__init__.py`.
   * In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`,
     add a fresh empty `## [Unreleased]` above it (the docs test requires it),
     and update the link references at the bottom of the file. The release
     body is this section, verbatim, so read it as an operator would.
   * Update the supported-versions table in `SECURITY.md`.
   * Commit as `Release X.Y.Z`, open the pull request, let CI go green on all
     three operating systems, merge to `Main`.
2. Rehearse once if anything in `packaging/` or the workflow changed since
   the last release: Actions, *Release*, *Run workflow* on `Main`. Download
   the `binaries-*` artifacts and run one on a real machine.
3. Tag the merge commit on `Main` and push the tag:

   ```bash
   git checkout Main && git pull
   git tag -a vX.Y.Z -m "aiit X.Y.Z"
   git push origin vX.Y.Z
   ```

4. Watch the run. If `pypi` has required reviewers, approve it when the
   GitHub Release looks right (step 5 below can be done before approving,
   except the PyPI install).

For a release candidate: `__version__ = "X.Y.Zrc1"`, tag `vX.Y.Z-rc1`. The
CHANGELOG section for an rc is optional; without one the notes are taken from
`[Unreleased]`. The GitHub Release is marked pre-release and the wheel goes to
TestPyPI, not PyPI. Install it with
`pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ aiit==X.Y.Zrc1`.

## What to verify after the run

1. The Releases page shows `vX.Y.Z` with eleven assets: wheel, sdist, four
   binary archives, four wheelhouse zips, `SHA256SUMS`. The body starts with
   the CHANGELOG section and ends with the unsigned-binary notice.
2. On any machine with the GitHub CLI:

   ```bash
   gh release download vX.Y.Z --repo RockMoon1/AI_IT --pattern 'SHA256SUMS' --pattern 'aiit-X.Y.Z-py3-none-any.whl'
   sha256sum -c SHA256SUMS --ignore-missing
   gh attestation verify aiit-X.Y.Z-py3-none-any.whl --repo RockMoon1/AI_IT
   ```

3. `python -m venv /tmp/r && /tmp/r/bin/pip install aiit==X.Y.Z` in a fresh
   venv, then `/tmp/r/bin/aiit-console --version` prints `aiit-console X.Y.Z`
   and `/tmp/r/bin/aiit-agent status` runs. PyPI shows the project page with
   the README rendered and the links from `[project.urls]`.
4. One wheelhouse zip, unpacked on a machine with no network:
   `python -m pip install --no-index --find-links . aiit` succeeds.
5. One binary archive on a real endpoint of that platform (not a runner):
   unpack, then `./aiit-agent status` and `./aiit-console --version`. Expect
   the SmartScreen or Gatekeeper warning described below.
6. `SECURITY.md` lists the new version as supported.

## When something fails

* A job failed before `release` ran: nothing was published. Fix the cause on
  `Main`. If the fix changes what ships, bump the patch version and tag again;
  if it only changes the workflow or the runner matrix, delete the tag
  (`git push --delete origin vX.Y.Z`, then `git tag -d vX.Y.Z`), re-tag the
  same commit after the workflow fix is merged, and push it again.
* `release` failed part-way (the GitHub Release exists but `pypi` did not run
  or failed): re-run the failed jobs from the Actions page; the artifacts of
  the run are reused. A PyPI version that was uploaded cannot be replaced, so
  if `pypi` succeeded and the release is wrong, the fix is a new patch version.
* The `pypi` job says the publisher is not trusted: the pending publisher's
  five fields in step 2 above must match exactly, including `release.yml` and
  the environment name.

## Yanking a bad release

* **PyPI**: on <https://pypi.org/manage/project/aiit/releases/> choose the
  version, *Options*, *Yank*, and give the reason (it is shown to users).
  A yanked version stays downloadable for anyone who pins it exactly, but
  `pip install aiit` and range specifiers skip it. Never delete a PyPI
  release; it breaks reproducible installs and the version number can never
  be reused. Yank, then publish the fixed patch version.
* **GitHub Release**: edit the release, tick *Set as a pre-release* and add a
  line at the top of the notes saying what is wrong and which version fixes
  it; delete the binary assets if they are the problem. Keep the tag: people
  may have fetched it, and the attestation log already references it.
* A security issue follows `SECURITY.md` and `GOVERNANCE.md` section 5: the
  fixed patch release and the advisory go out together.

## Unsigned binaries

The PyInstaller builds are not code-signed and not notarised. In practice:

* **Windows**: SmartScreen shows *Windows protected your PC* on first run of
  an unknown unsigned executable (*More info*, *Run anyway*). Some endpoint
  protection products quarantine unsigned single-file PyInstaller binaries
  outright; the one-folder layout (`onedir/` inside the archive) is treated
  more leniently. A fleet can allow-list the file hash from `SHA256SUMS`.
* **macOS**: Gatekeeper refuses a downloaded unsigned, un-notarised binary
  with *cannot be opened because the developer cannot be verified*. After
  verifying the checksum, `xattr -d com.apple.quarantine aiit-agent` removes
  the quarantine flag; or allow it under *System Settings*, *Privacy &
  Security*.
* **Linux**: no signature check; `chmod +x` if the archive tool dropped the bit.

What users get instead today: the `SHA256SUMS` file and the build-provenance
attestation (`gh attestation verify FILE --repo RockMoon1/AI_IT`), which
proves the file was built by this workflow from this repository at that tag.
The release body says all of this; so does `README.txt` inside each archive.
Where Python is available, the wheel or the wheelhouse is the better choice.

The path to signed binaries, when there is budget and a legal entity to hold
the certificates:

1. **Windows Authenticode**: an OV or EV code-signing certificate on a
   hardware token or in a cloud signing service (Azure Trusted Signing is the
   cheapest option for an open source project with a verified identity). Sign
   in the `binaries` job with `signtool sign /tr <timestamp url> /td sha256 /fd sha256`
   (or the Azure action) after PyInstaller and before the smoke test. EV
   removes the SmartScreen warning immediately; OV builds reputation over time.
2. **macOS notarisation**: an Apple Developer ID (paid Apple Developer
   Program). Set `codesign_identity` in both spec files (PyInstaller signs with
   the hardened runtime), then `xcrun notarytool submit` the archive with an
   App Store Connect API key stored as environment secrets, and `xcrun stapler
   staple` the result. Both archs need it.
3. **Sigstore for everything else**: `cosign sign-blob` with keyless signing
   from the workflow's OIDC identity gives Linux users the same proof as the
   attestation in a more widely tooled form. Lowest priority: the attestation
   already covers it.

## Follow-ups

* Pin the third-party actions (`pypa/gh-action-pypi-publish`, and the
  `actions/*` set if wanted) to commit SHAs rather than major tags; Dependabot
  updates SHA pins too. Major tags are used today so the first releases are
  not blocked on an audit of each action's history.
* Linux aarch64 and Windows arm64 binaries once GitHub's arm runners are in
  the matrix.
* MSI and PKG installers (roadmap phase 1), on top of the signing work above.
* A software bill of materials attached to the release.
