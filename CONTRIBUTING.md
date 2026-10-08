# Contributing

1. Fork and clone. `python -m pip install -e ".[dev]"` then `pre-commit install`.
2. Run tests: `python -m unittest discover -s tests -t . -v`.
3. Keep the dependency footprint small. The agent must install on an
   offline laptop from a single wheel plus `cryptography` and `pydantic`.
4. Anything that executes on an endpoint goes through
   `aiit.common.policy` and `aiit.agent.executor`. Do not add a second path.
5. Anything that is sent to an LLM goes through `aiit.common.redact` first.
6. Never commit secrets, bundles, cases, or keys. CI will reject them.

Licensing: contributions are accepted under Apache-2.0. Do not copy code from
AGPL or source-available projects (RustDesk, Tactical RMM) into this tree;
integrate with them over their network APIs instead. See
`docs/research/open-source-landscape.md` for the license table.
