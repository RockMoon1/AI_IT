"""Docs and examples must not drift from the code."""
import re
import unittest
from pathlib import Path

from . import helpers
from aiit.agent.cli import build_parser as agent_parser
from aiit.console.cli import build_parser as console_parser

ROOT = helpers.ROOT
DOC_FILES = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
ENV_EXEMPT = {"AIIT_TEST_INSTALLED"}


def _subcommands(parser):
    for action in parser._actions:
        if hasattr(action, "choices") and action.choices:
            return set(action.choices.keys())
    return set()


class DocDriftTests(unittest.TestCase):
    def test_every_cli_example_names_a_real_subcommand(self):
        known = {"aiit-agent": _subcommands(agent_parser()), "aiit-console": _subcommands(console_parser())}
        seen = 0
        for doc in DOC_FILES:
            for line in doc.read_text(encoding="utf-8").splitlines():
                # an option value never starts with "-", which keeps the option group unambiguous (no catastrophic backtracking)
                m = re.match(r"^\s*(?:\$\s*)?(aiit-(?:agent|console))\s+(?:--[\w-]+(?:=\S+|\s+[^-\s]\S*)?\s+)*([a-z][\w-]*)", line)
                if not m:
                    continue
                tool, sub = m.group(1), m.group(2)
                seen += 1
                self.assertIn(sub, known[tool], f"{doc.name}: `{line.strip()}` uses unknown subcommand {sub!r}")
        self.assertGreater(seen, 10)

    def test_env_vars_in_code_and_env_example_agree(self):
        # Every AIIT_* string literal counts as a read, so indirect readers such as
        # ollama._env_float("AIIT_OLLAMA_TIMEOUT", ...) are covered, not only os.environ.get("...").
        used = set()
        for py in (ROOT / "src").rglob("*.py"):
            used.update(re.findall(r"[\"'](AIIT_[A-Z0-9_]+)[\"']", py.read_text(encoding="utf-8")))
        documented = set(re.findall(r"^#?\s*(AIIT_[A-Z0-9_]+)\s*=", (ROOT / ".env.example").read_text(encoding="utf-8"), re.M))
        self.assertIn("AIIT_OLLAMA_TIMEOUT", used)
        self.assertGreater(len(used), 15)
        missing = sorted(used - documented - ENV_EXEMPT)
        self.assertEqual(missing, [], f"document these in .env.example: {missing}")
        stale = sorted(documented - used - ENV_EXEMPT)
        self.assertEqual(stale, [], f"documented in .env.example but nothing in src reads them: {stale}")

    def test_changelog_has_unreleased_section(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [Unreleased]", text)


if __name__ == "__main__":
    unittest.main()
