"""Packaging: one version source, declared entry points, thin PyInstaller entry scripts, release helper."""
import importlib
import importlib.metadata
import importlib.util
import os
import re
import runpy
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from . import helpers
import aiit

ROOT = helpers.ROOT
PACKAGING = ROOT / "packaging"
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PEP440_RELEASE = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")


def _table(name: str) -> str:
    """The lines of one pyproject table (no tomllib on 3.10, and the shape is simple enough for a regex)."""
    m = re.search(rf"^\[{re.escape(name)}\]\n(.*?)(?=^\[|\Z)", PYPROJECT, re.M | re.S)
    return m.group(1) if m else ""


def _release_notes():
    """packaging/release_notes.py as a module. Not importable by name: `packaging` is also the PyPI library."""
    spec = importlib.util.spec_from_file_location("aiit_release_notes", PACKAGING / "release_notes.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _dist_version():
    try:
        return importlib.metadata.version("aiit")
    except importlib.metadata.PackageNotFoundError:
        return None


class VersionTests(unittest.TestCase):
    def test_version_is_a_pep440_release_string(self):
        self.assertRegex(aiit.__version__, PEP440_RELEASE)

    def test_pyproject_reads_the_version_from_the_package(self):
        self.assertIn('dynamic = ["version"]', _table("project"))
        self.assertNotRegex(_table("project"), r"^version\s*=", "version must not be written in pyproject.toml too")
        self.assertIn('version = {attr = "aiit.__version__"}', _table("tool.setuptools.dynamic"))
        self.assertEqual(_release_notes().read_version(ROOT), aiit.__version__)

    def test_installed_metadata_agrees_with_the_package(self):
        dist = _dist_version()
        if dist is None:
            if os.environ.get("AIIT_TEST_INSTALLED"):
                self.fail("AIIT_TEST_INSTALLED is set but no aiit distribution metadata was found")
            self.skipTest("aiit is not installed (plain PYTHONPATH=src run)")
        self.assertEqual(dist, aiit.__version__)


class EntryPointTests(unittest.TestCase):
    EXPECTED = {"aiit-agent": "aiit.agent.cli:main", "aiit-console": "aiit.console.cli:main"}

    def test_console_scripts_are_declared_and_resolve(self):
        declared = dict(re.findall(r'^([\w-]+)\s*=\s*"([^"]+)"', _table("project.scripts"), re.M))
        self.assertEqual(declared, self.EXPECTED)
        for target in declared.values():
            module, attr = target.split(":")
            self.assertTrue(callable(getattr(importlib.import_module(module), attr)))

    def test_installed_entry_points_match(self):
        if _dist_version() is None:
            self.skipTest("aiit is not installed")
        eps = {ep.name: ep.value for ep in importlib.metadata.entry_points(group="console_scripts") if ep.name in self.EXPECTED}
        self.assertEqual(eps, self.EXPECTED)

    def test_py_typed_is_shipped(self):
        self.assertTrue((ROOT / "src" / "aiit" / "py.typed").exists())
        self.assertIn('aiit = ["py.typed"]', _table("tool.setuptools.package-data"))
        self.assertTrue(Path(aiit.__file__).with_name("py.typed").is_file(), "py.typed missing next to the imported package")

    def test_release_tooling_is_an_extra_not_a_dependency(self):
        deps = re.search(r"^dependencies = \[(.*?)\]", _table("project"), re.M | re.S).group(1)
        self.assertEqual(sorted(re.findall(r'"([A-Za-z0-9_-]+)', deps)), ["cryptography", "pydantic"])
        extras = _table("project.optional-dependencies")
        self.assertRegex(extras, r"(?m)^dev = \[")
        release = re.search(r'^release = \[(.*?)\]', extras, re.M).group(1)
        for tool in ("build", "twine", "pyinstaller"):
            self.assertIn(f'"{tool}', release)
        self.assertEqual(_table("build-system").count("pyinstaller"), 0)


class FrozenEntryScriptTests(unittest.TestCase):
    CASES = (("entry_agent.py", "aiit.agent.cli.main", "aiit.console.cli.main"),
             ("entry_console.py", "aiit.console.cli.main", "aiit.agent.cli.main"))

    def test_entry_scripts_call_exactly_their_main(self):
        for script, wanted, other in self.CASES:
            with self.subTest(script=script), mock.patch(wanted) as want, mock.patch(other) as not_want:
                runpy.run_path(str(PACKAGING / script), run_name="__main__")
                want.assert_called_once_with()
                not_want.assert_not_called()

    def test_entry_scripts_do_nothing_when_imported(self):
        for script, wanted, _ in self.CASES:
            with self.subTest(script=script), mock.patch(wanted) as want:
                runpy.run_path(str(PACKAGING / script), run_name="not_main")
                want.assert_not_called()

    def test_specs_build_the_matching_entry_script(self):
        for tool, script in (("agent", "entry_agent.py"), ("console", "entry_console.py")):
            spec = (PACKAGING / f"aiit-{tool}.spec").read_text(encoding="utf-8")
            self.assertIn(script, spec)
            self.assertIn(f'NAME = "aiit-{tool}"', spec)
            self.assertIn("AIIT_PYI_ONEFILE", spec)
        self.assertFalse((PACKAGING / "__init__.py").exists(), "packaging/__init__.py would shadow the `packaging` library")


class ReleaseNotesTests(unittest.TestCase):
    SAMPLE = (
        "# Changelog\n\n## [Unreleased]\n\n### Added\n- next thing\n\n"
        "## [0.2.0-rc1] - 2026-11-01\n\n- rc notes\n\n"
        "## [0.1.0] - 2026-10-08\n\n- first\n\n"
        "[Unreleased]: https://example.org/compare/v0.1.0...HEAD\n[0.1.0]: https://example.org/tag/v0.1.0\n"
    )

    def setUp(self):
        self.rn = _release_notes()

    def test_normalize_tags_and_versions(self):
        n = self.rn.normalize
        self.assertEqual(n("v0.2.0"), "0.2.0")
        self.assertEqual(n("v0.2.0-rc1"), "0.2.0rc1")
        self.assertEqual(n("0.2.0rc1"), "0.2.0rc1")
        self.assertEqual(n("v0.2.0-beta.2"), "0.2.0b2")
        self.assertEqual(n("1.0.0-alpha1"), "1.0.0a1")
        self.assertEqual(n("0.3.0.dev4"), "0.3.0.dev4")
        self.assertEqual(n("v1.2.3.post1"), "1.2.3.post1")
        for bad in ("Unreleased", "v", "latest", ""):
            with self.assertRaises(ValueError):
                n(bad)
        self.assertTrue(self.rn.is_prerelease("v0.2.0-rc1"))
        self.assertTrue(self.rn.is_prerelease("0.3.0.dev1"))
        self.assertFalse(self.rn.is_prerelease("0.2.0"))

    def test_sections_drop_link_references(self):
        secs = self.rn.sections(self.SAMPLE)
        self.assertEqual(list(secs), ["Unreleased", "0.2.0-rc1", "0.1.0"])
        self.assertEqual(secs["0.1.0"], "- first")
        self.assertNotIn("example.org", secs["0.1.0"])

    def test_find_section_matches_normalised_labels_and_falls_back_for_prereleases(self):
        self.assertEqual(self.rn.find_section(self.SAMPLE, "0.1.0"), ("0.1.0", "- first"))
        self.assertEqual(self.rn.find_section(self.SAMPLE, "0.2.0rc1"), ("0.2.0-rc1", "- rc notes"))
        label, body = self.rn.find_section(self.SAMPLE, "0.2.0rc2")
        self.assertEqual(label, "Unreleased")
        self.assertIn("next thing", body)
        with self.assertRaises(LookupError):
            self.rn.find_section(self.SAMPLE, "0.2.0")

    def test_real_changelog_has_the_sections_the_workflow_needs(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("Unreleased", self.rn.sections(text))
        label, body = self.rn.find_section(text, "0.1.0")
        self.assertEqual(label, "0.1.0")
        self.assertIn("Initial release", body)

    def test_check_rejects_a_tag_that_does_not_match_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "aiit").mkdir(parents=True)
            (root / "src" / "aiit" / "__init__.py").write_text('__version__ = "0.2.0"\n', encoding="utf-8")
            (root / "CHANGELOG.md").write_text("## [Unreleased]\n\n## [0.2.0] - 2026-12-01\n\n- shipped\n", encoding="utf-8")
            facts = self.rn.check("v0.2.0", root)
            self.assertEqual(facts, {"version": "0.2.0", "prerelease": "false", "notes_section": "0.2.0"})
            self.assertEqual(self.rn.check(None, root)["version"], "0.2.0")
            for bad_tag in ("v0.2.1", "0.2.0", "v0.2.0-rc1"):
                with self.subTest(tag=bad_tag), self.assertRaises(SystemExit):
                    self.rn.check(bad_tag, root)
            (root / "CHANGELOG.md").write_text("## [Unreleased]\n\n## [0.2.0] - 2026-12-01\n\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                self.rn.check("v0.2.0", root)   # empty section
            (root / "src" / "aiit" / "__init__.py").write_text('__version__ = "0.2.0rc1"\n', encoding="utf-8")
            (root / "CHANGELOG.md").write_text("## [Unreleased]\n\n- in progress\n", encoding="utf-8")
            self.assertEqual(self.rn.check("v0.2.0-rc1", root), {"version": "0.2.0rc1", "prerelease": "true", "notes_section": "Unreleased"})

    def test_release_body_lists_assets_and_says_the_binaries_are_unsigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "aiit").mkdir(parents=True)
            (root / "src" / "aiit" / "__init__.py").write_text('__version__ = "0.2.0"\n', encoding="utf-8")
            (root / "CHANGELOG.md").write_text("## [0.2.0] - 2026-12-01\n\n### Added\n- a feature\n", encoding="utf-8")
            assets = root / "assets"
            assets.mkdir()
            for name in ("aiit-0.2.0-py3-none-any.whl", "aiit-0.2.0.tar.gz", "aiit-0.2.0-linux-x86_64.tar.gz",
                         "aiit-0.2.0-windows-x86_64.zip", "aiit-0.2.0-wheelhouse-macos-arm64.zip", "SHA256SUMS"):
                (assets / name).write_bytes(b"x" * 2048)
            body = self.rn.release_body("v0.2.0", assets, root)
        self.assertTrue(body.startswith("### Added\n- a feature"))
        for name in ("aiit-0.2.0-py3-none-any.whl", "aiit-0.2.0-linux-x86_64.tar.gz", "SHA256SUMS"):
            self.assertIn(f"`{name}`", body)
        self.assertIn("Standalone `aiit-agent` and `aiit-console` for windows x86_64", body)
        self.assertIn("Offline wheelhouse for macos arm64", body)
        self.assertIn("not code-signed or notarised", body)
        self.assertIn("gh attestation verify", body)
        self.assertIn("pip install aiit==0.2.0", body)

    def test_release_body_marks_prerelease_notes_taken_from_unreleased(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "aiit").mkdir(parents=True)
            (root / "src" / "aiit" / "__init__.py").write_text('__version__ = "0.2.0rc1"\n', encoding="utf-8")
            (root / "CHANGELOG.md").write_text("## [Unreleased]\n\n- in progress\n", encoding="utf-8")
            body = self.rn.release_body("v0.2.0-rc1", None, root)
        self.assertTrue(body.startswith("Pre-release 0.2.0rc1."))
        self.assertIn("- in progress", body)
        self.assertNotIn("## Assets", body)

    def test_cli_version_and_section(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.rn.main(["version"])
        self.assertEqual(out.getvalue().strip(), aiit.__version__)


class WorkflowTests(unittest.TestCase):
    """Text-level checks (PyYAML is not a dependency); the YAML itself is validated in CI by being run."""

    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_wires_the_packaging_files(self):
        for needle in ("packaging/release_notes.py check", "packaging/release_notes.py body", "packaging/aiit-$tool.spec",
                       "AIIT_PYI_ONEFILE=1", "AIIT_PYI_ONEFILE=0", "AIIT_TEST_INSTALLED=1",
                       "pypa/gh-action-pypi-publish@release/v1", "actions/attest-build-provenance@",
                       "name: pypi", "name: testpypi", "id-token: write", "sha256sum", "--prerelease"):
            self.assertIn(needle, self.text, needle)

    def test_publish_jobs_only_run_for_pushed_tags(self):
        jobs = re.findall(r"^  (\w+):\n(.*?)(?=^  \w+:\n|\Z)", self.text[self.text.index("jobs:"):], re.M | re.S)
        jobs = dict(jobs)
        self.assertEqual(list(jobs), ["dist", "binaries", "wheelhouse", "release", "pypi", "testpypi"])
        for job in ("release", "pypi", "testpypi"):
            self.assertIn("github.event_name == 'push' && github.ref_type == 'tag'", jobs[job], job)
        self.assertIn("needs.dist.outputs.prerelease == 'false'", jobs["pypi"])
        self.assertIn("needs.dist.outputs.prerelease == 'true'", jobs["testpypi"])
        self.assertIn("test.pypi.org/legacy/", jobs["testpypi"])
        self.assertNotIn("test.pypi.org/legacy/", jobs["pypi"])

    def test_smoke_loop_names_real_subcommands(self):
        from aiit.agent.cli import build_parser as agent_parser
        from aiit.console.cli import build_parser as console_parser
        known = {"AGENT": {a for a in agent_parser()._actions if a.choices for a in a.choices},
                 "CONSOLE": {a for a in console_parser()._actions if a.choices for a in a.choices}}
        seen = 0
        for tool, sub in re.findall(r'"\$(AGENT|CONSOLE)" --data-dir \S+ ([a-z][\w-]*)', self.text):
            seen += 1
            self.assertIn(sub, known[tool], f"{tool} {sub}")
        self.assertGreaterEqual(seen, 10)


if __name__ == "__main__":
    unittest.main()
