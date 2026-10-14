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
                m = re.match(r"^\s*(?:\$\s*)?(aiit-(?:agent|console))\s+(?:--[\w-]+(?:\s+\S+)?\s+)*([a-z][\w-]*)", line)
                if not m:
                    continue
                tool, sub = m.group(1), m.group(2)
                seen += 1
                self.assertIn(sub, known[tool], f"{doc.name}: `{line.strip()}` uses unknown subcommand {sub!r}")
        self.assertGreater(seen, 10)

    def test_every_env_var_is_documented(self):
        used = set()
        for py in (ROOT / "src").rglob("*.py"):
            used.update(re.findall(r"environ(?:\.get)?\(\s*[\"'](AIIT_[A-Z0-9_]+)[\"']", py.read_text(encoding="utf-8")))
            used.update(re.findall(r"environ\[\s*[\"'](AIIT_[A-Z0-9_]+)[\"']\s*\]", py.read_text(encoding="utf-8")))
        documented = set(re.findall(r"^#?\s*(AIIT_[A-Z0-9_]+)\s*=", (ROOT / ".env.example").read_text(encoding="utf-8"), re.M))
        missing = sorted(used - documented - ENV_EXEMPT)
        self.assertEqual(missing, [], f"document these in .env.example: {missing}")

    def test_changelog_has_unreleased_section(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [Unreleased]", text)


if __name__ == "__main__":
    unittest.main()
