# Redaction golden fixtures

Synthetic collector output with planted identifiers and fake secrets. Every
value here was typed by hand; none belongs to a real person, machine or
account. Secret-shaped strings are assembled from obviously fake parts.

Each `<name>.<ext>` has a sidecar `<name>.planted.json`:

* `must_not_survive`: strings that must be absent (case-insensitive) from the
  redacted output,
* `must_survive`: strings that must still be present verbatim,
* `secrets`: subset of `must_not_survive` that must also be absent from the
  reversible token map,
* `config`: optional `RedactionConfig.to_dict()` overrides used by the test.

The directory is allow-listed in `.gitleaks.toml`.
