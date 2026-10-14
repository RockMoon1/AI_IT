# Getting support

AI_IT is maintained by volunteers. There is no SLA. Questions that follow this
guide get answered faster because they contain what we need and nothing we
must not see.

## Where to ask

| I want to... | Go to |
|---|---|
| Ask how to do something, discuss a design idea, share a field report | GitHub Discussions (once the maintainer enables them; until then, open an issue with the `question` label) |
| Report a bug | A GitHub issue using the **Bug report** template |
| Request a feature | A GitHub issue using the **Feature request** template |
| Request support for another model server or API | A GitHub issue using the **Provider request** template |
| Report a security vulnerability | **Never an issue.** Use the private advisory form described in `SECURITY.md`. |

Blank issues are disabled; the templates ask for exactly what we need.

## What to include

For a bug, the template walks you through it. The short version:

* The operating system and edition of the machine the problem happened on
  (for example "Windows 11 Pro 23H2", "macOS 14.5", "Ubuntu 24.04"), and
  whether it was the endpoint (`aiit-agent`) or the operator machine
  (`aiit-console`).
* How you installed AI_IT (wheel, `pip install -e .`, binary) and the version
  (`aiit-console --version`, or `pip show aiit`).
* The exact command you ran, with any paths and ids replaced by placeholders.
* What you expected and what happened instead, including the error line
  printed by the tool. Run the command again with `--debug` to get a
  traceback and include that.
* For provider problems: the provider name, the model name, and whether the
  model server is local or hosted. Not the API key.

## What never to attach

Diagnostic bundles contain system data from real machines, and in a clinic
that can include protected health information. The redaction layer exists so
that data stays on the operator machine; please do not undo that by pasting it
into a public tracker. Do **not** attach or paste:

* Bundles (`*.aiit`), case folders, `raw/` or `redacted/` directories,
  `redaction_map.json`, `redaction.key`.
* Audit logs (`audit.jsonl`, `audit.jsonl.head.json`), exported audit CSV or
  HTML.
* Signed plans (`*.signed.json`), enrollment files, anything from a `keys/`
  directory, `.env` files, tokens or passphrases.
* Hostnames, usernames, IP addresses, serial numbers, email addresses, or
  anything that identifies a patient, a staff member, or a device.
* Collector output, event logs or application logs from a real machine, even
  "just one line". Describe the shape of the data instead ("a 300-entry JSON
  array of application errors") or reproduce the issue with the synthetic
  fixtures under `tests/fixtures/`.

If a maintainer needs more detail than can be shared publicly, they will say
so and suggest a private channel. If you accidentally post sensitive data,
edit the post immediately and ask a maintainer to purge the edit history.

## Self-help

* `docs/architecture.md` explains the loop, the file formats and the trust
  model.
* `docs/security/threat-model.md` explains what each control defends against
  and what it does not.
* `docs/compliance/hipaa.md` explains the compliance posture and the
  deployment checklist.
* `aiit-console audit verify` and `aiit-agent audit verify` tell you whether
  an audit chain is intact; `aiit-console audit timeline <case>` shows what
  happened to one case.
* `--provider dryrun` lets you exercise the whole pipeline with no model and
  no network, which is the fastest way to tell whether a problem is in AI_IT
  or in the model server.
