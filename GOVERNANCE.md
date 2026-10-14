# Governance

This document describes who decides what in the AI_IT project, how those
people are chosen, and how releases and security fixes are handled. It is
deliberately short because the project is small. It will grow when the project
does.

## 1. Current structure

AI_IT is a single-maintainer project. The maintainer is the GitHub user
**RockMoon1**, who owns the repository, the release process, the security
contact, and the final say on every change. `.github/CODEOWNERS` reflects this:
every path is owned by `@RockMoon1`.

A single maintainer is a known weakness (bus factor of one). The mitigations
are: every design decision is written down in `docs/`, every release step is
scripted in CI, and the path to adding maintainers below is intentionally
simple.

## 2. Roles

| Role | Who | Can |
|---|---|---|
| Maintainer | @RockMoon1 | Merge, release, triage, moderate, hold the security contact, add or remove maintainers. |
| Contributor | Anyone who has had a pull request merged | Propose changes, review pull requests (non-binding), take part in discussions. |
| User | Anyone running the software | Open issues and discussions, report vulnerabilities privately. |

## 3. Decision process

1. Small changes (bug fixes, documentation, test additions, dependency bumps)
   are decided by the maintainer reviewing the pull request. A green CI run on
   all three operating systems is a precondition, never a substitute, for
   review.
2. Changes that alter a trust boundary (anything under
   `src/aiit/common/crypto.py`, `policy.py`, `redact.py`, `audit.py`,
   `src/aiit/agent/executor.py`, `src/aiit/agent/procs.py`,
   `src/aiit/console/server.py`, or the bundle and plan formats) must come with
   an update to `docs/security/threat-model.md` describing the new or changed
   threat row, and a test that exercises the failure case. The maintainer may
   ask for a short design note in the pull request before reviewing code.
3. Changes to the dependency footprint are presumed rejected. The runtime
   dependency set is the Python standard library plus `cryptography` and
   `pydantic`. A proposal to add a runtime dependency needs a written case
   explaining why the standard library cannot do the job, an assessment of the
   dependency's maintenance and license, and a plan for offline installation
   on endpoints.
4. When contributors disagree, the discussion happens on the pull request or
   issue, in the open. If no consensus forms, the maintainer decides and
   records the reasoning in the thread. Decisions can be revisited by opening a
   new issue with new information.
5. Decisions that affect HIPAA posture (what leaves the operator machine, what
   is logged, what is redacted) default to the more private option. A feature
   that sends more data to a third party must be opt-in and audited.

## 4. Adding and removing maintainers

A contributor may be invited to become a maintainer when all of the following
hold:

* At least six months of regular contributions, including reviews of other
  people's pull requests.
* At least one merged change in a trust-boundary file, with the matching
  threat-model and test updates.
* Demonstrated care with the project's constraints (no new dependencies, no
  secrets in git, cross-platform tests, no PHI in issues).
* Agreement to the Code of Conduct and to the coordinated disclosure process
  in `SECURITY.md`.

The existing maintainers propose the invitation in a public issue and the
candidate accepts in that issue. Once there is more than one maintainer,
adding another requires the agreement of all current maintainers, and
`CODEOWNERS` is updated in the same pull request.

A maintainer who has been inactive for twelve months is moved to emeritus
status, which keeps the credit and removes the permissions. A maintainer may
step down at any time by opening an issue. Removal for Code of Conduct
violations follows the enforcement guidelines in `CODE_OF_CONDUCT.md`.

## 5. Security-fix fast path

Security reports arrive privately (see `SECURITY.md`). For a confirmed
vulnerability:

1. The maintainer opens a private security advisory on GitHub and works on the
   fix in the advisory's private fork, not on a public branch.
2. The fix must still pass the full three-OS test matrix, but review by a second
   person is not required when there is only one maintainer. The advisory text
   records what was reviewed and how.
3. A release is cut as soon as the fix is ready, outside the regular cadence,
   as a patch version. The CHANGELOG entry goes under `Security`.
4. The advisory is published with the release, crediting the reporter unless
   they ask otherwise.
5. If the issue affects data already collected by users (for example, a
   redaction gap that let identifiers reach a model), the advisory says so
   plainly and gives the steps an operator should take.

## 6. Release cadence

* Versions follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.
  While the major version is 0, a minor release may contain breaking changes;
  every breaking change is listed under `BREAKING` in `CHANGELOG.md` with the
  migration step.
* Minor releases ship roughly every six weeks when there is something to ship.
  There is no fixed train; a release is cut when the `Unreleased` section of
  the changelog has settled and CI is green on all supported platforms.
* Patch releases ship for bug fixes at any time.
* Security releases ship out of band, as soon as the fix is ready.
* Each release is a git tag `vX.Y.Z` on `Main`, a GitHub Release whose notes
  are the matching CHANGELOG section, and (from PR 2 onwards) wheels and
  binaries built by the release workflow.
* Supported versions are listed in `SECURITY.md`. In short: the latest minor
  release receives security fixes; older minors do not.

## 7. Changing this document

Edits to `GOVERNANCE.md` go through a pull request like any other change. While
there is one maintainer, that maintainer decides. Once there are several, a
change to sections 3, 4 or 5 requires agreement from all of them.
