"""Collector run classification, stderr sidecars, keep_lines and output filters, plus the real quick set.

The fake collectors exercise every ``FileEntry.status`` with tiny commands on
all three platforms. ``RealQuickSetTests`` runs the real quick set for this OS:
structural invariants are checked everywhere, and on a GitHub-hosted runner the
set of collectors allowed to fail is pinned by ``EXPECTED_FAILURES`` so a
collector that silently stops working on a runner turns CI red.
"""
import json
import ntpath
import os
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from . import helpers  # noqa: F401  (puts src/ on the path and scrubs AIIT_* from the environment)
from aiit.agent import collectors
from aiit.agent.collectors import (
    FAILURE_STATUSES, LINUX, MACOS, OUTPUT_FILTERS, STATUSES, TRUNCATED_MARK, WINDOWS, Collector, classify, collect_all,
    collector_table_sha256, error_class, is_elevated, keep_lines, run_one, selftest_rows, status_counts,
)
from aiit.common.schema import FileEntry
from aiit.common.util import current_os, sha256_file

NT = os.name == "nt"


def _ps(script: str) -> list[str]:
    return ["powershell.exe", "-NoProfile", "-Command", script]


def _sh(script: str) -> list[str]:
    return ["sh", "-c", script]


def _cmd(ps_script: str, sh_script: str) -> list[str]:
    return _ps(ps_script) if NT else _sh(sh_script)


# One fake per status, plus a warning-with-good-output case, a valid JSON case and a keep_lines case.
FAKES: dict[str, Collector] = {
    "ok": Collector("echo", "sys", _cmd("Write-Output 'hello world'", "echo 'hello world'"), "txt", 60),
    "nonzero": Collector("nonzero", "sys", _cmd("Write-Output partial; exit 3", "echo partial; exit 3"), "txt", 60),
    "timeout": Collector("slow", "sys", _ps("Start-Sleep -Seconds 30") if NT else ["sleep", "30"], "txt", 3 if NT else 1),
    "missing": Collector("missing", "logs", ["definitely-not-a-real-command-xyz"], "txt", 5),
    "denied": Collector("denied", "sys", _cmd("[Console]::Error.WriteLine('Access is denied.'); exit 1", "echo 'Permission denied' >&2; exit 1"),
                        "txt", 60, requires_admin=True),
    "invalid_json": Collector("badjson", "sys", _cmd("Write-Output '{not json'", "echo '{not json'"), "json", 60),
    "empty": Collector("empty", "sys", ["cmd.exe", "/c", "exit", "0"] if NT else ["true"], "txt", 60),
    "warn": Collector("warn", "sys", _cmd("Write-Output out; [Console]::Error.WriteLine('careful')", "echo out; echo careful >&2"), "txt", 60),
    "json_ok": Collector("goodjson", "sys", _cmd("Write-Output '{\"a\": 1}'", "echo '{\"a\": 1}'"), "json", 60),
    "head3": Collector("ten", "sys", _ps("1..10") if NT else ["seq", "1", "10"], "txt", 60, keep_lines=("head", 3)),
}


class FakeCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        # elevation is pinned to "not elevated" so the denied annotation is deterministic on every runner
        with mock.patch.object(collectors, "is_elevated", return_value=False):
            cls.results = {key: run_one(c, cls.root) for key, c in FAKES.items()}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def primary(self, key: str) -> FileEntry:
        entries = self.results[key]
        self.assertFalse(entries[0].collector.endswith(".stderr"))
        return entries[0]

    def sidecar(self, key: str) -> FileEntry | None:
        extra = [e for e in self.results[key] if e.collector.endswith(".stderr")]
        return extra[0] if extra else None

    def test_every_status_is_classified(self):
        expected = {"ok": "ok", "nonzero": "nonzero", "timeout": "timeout", "missing": "missing", "denied": "denied",
                    "invalid_json": "invalid_json", "empty": "empty", "warn": "ok", "json_ok": "ok", "head3": "ok"}
        got = {key: self.primary(key).status for key in expected}
        self.assertEqual(got, expected)
        self.assertEqual(self.primary("ok").exit_code, 0)
        self.assertIsNone(self.primary("ok").error)
        self.assertEqual(self.primary("nonzero").exit_code, 3)
        self.assertEqual(self.primary("nonzero").error, "exit 3")
        self.assertTrue(self.primary("timeout").error.startswith("timeout after "), self.primary("timeout").error)
        self.assertIsNone(self.primary("timeout").exit_code)
        self.assertEqual(self.primary("missing").error, "command not found: definitely-not-a-real-command-xyz")
        self.assertIsNone(self.primary("missing").exit_code)
        self.assertEqual(self.primary("denied").exit_code, 1)
        self.assertIn("denied", self.primary("denied").error.lower())
        self.assertIn("(needs administrator/root; the agent is not elevated)", self.primary("denied").error)
        self.assertIn("output is not valid JSON", self.primary("invalid_json").error)
        self.assertIsNone(self.primary("empty").error)
        self.assertIsNone(self.primary("warn").error)  # a warning next to good output is not an error

    def test_files_and_sidecars(self):
        for key, entries in self.results.items():
            for e in entries:
                p = self.root / e.path
                self.assertTrue(p.exists(), e.path)
                self.assertEqual(sha256_file(p), e.sha256, e.path)
                self.assertEqual(p.stat().st_size, e.size, e.path)
                if not NT:
                    self.assertEqual(p.stat().st_mode & 0o777, 0o600, e.path)
        self.assertEqual((self.root / "sys/echo.txt").read_text().split(), ["hello", "world"])
        self.assertIsNone(self.sidecar("ok"))
        # stderr is a sidecar with its own entry, never appended to the output file
        warn = self.sidecar("warn")
        self.assertIsNotNone(warn)
        self.assertEqual((warn.path, warn.collector, warn.status, warn.error), ("sys/warn.stderr.txt", "warn.stderr", "ok", None))
        self.assertEqual((self.root / "sys/warn.txt").read_text().split(), ["out"])
        self.assertEqual((self.root / "sys/warn.stderr.txt").read_text().split(), ["careful"])
        self.assertNotIn("--- stderr ---", (self.root / "sys/warn.txt").read_text())
        self.assertEqual(self.sidecar("denied").path, "sys/denied.stderr.txt")
        self.assertEqual(self.sidecar("nonzero"), None)
        # JSON outputs stay parseable; invalid JSON is kept as written
        self.assertEqual(json.loads((self.root / "sys/goodjson.json").read_text()), {"a": 1})
        self.assertIn("{not json", (self.root / "sys/badjson.json").read_text())
        # an empty result is an empty file; a failed start records the reason in the file
        self.assertEqual((self.root / "sys/empty.txt").read_bytes(), b"")
        self.assertIn("command not found", (self.root / "logs/missing.txt").read_text())
        self.assertIn("[timeout]", (self.root / "sys/slow.txt").read_text())

    def test_keep_lines_applied_to_output(self):
        self.assertEqual((self.root / "sys/ten.txt").read_text().split(), ["1", "2", "3"])
        self.assertEqual(keep_lines("a\nb\nc\nd\n", ("head", 2)), "a\nb\n")
        self.assertEqual(keep_lines("a\nb\nc\nd\n", ("tail", 2)), "c\nd\n")
        self.assertEqual(keep_lines("a\nb\n", ("tail", 5)), "a\nb\n")
        self.assertEqual(keep_lines("a\nb\n", None), "a\nb\n")
        with self.assertRaises(ValueError):
            keep_lines("a\n", ("middle", 1))

    def test_not_elevated_annotation_only_when_not_elevated(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(collectors, "is_elevated", return_value=True):
            e = run_one(FAKES["denied"], Path(d))[0]
        self.assertEqual(e.status, "denied")
        self.assertNotIn("not elevated", e.error)

    def test_entries_round_trip_and_old_manifests_default_to_ok(self):
        for entries in self.results.values():
            for e in entries:
                self.assertEqual(FileEntry.model_validate(e.model_dump()), e)
                self.assertIn(e.status, STATUSES)
        old = {"path": "sys/x.txt", "sha256": "0" * 64, "size": 1, "collector": "x", "exit_code": 1, "error": "exit 1"}
        self.assertEqual(FileEntry.model_validate(old).status, "ok")
        with self.assertRaises(ValueError):
            FileEntry.model_validate({**old, "status": "exploded"})

    def test_selftest_rows_are_metadata_only(self):
        entries = [e for es in self.results.values() for e in es]
        rows = selftest_rows(entries, current_os())
        self.assertEqual(len(rows), len(FAKES))
        keys = {"name", "category", "requires_admin", "status", "exit_code", "duration_ms", "size", "stderr_size", "error_class"}
        for r in rows:
            self.assertEqual(set(r), keys, r)
        by = {r["name"]: r for r in rows}
        self.assertEqual(by["warn"]["stderr_size"], self.sidecar("warn").size)
        self.assertEqual(by["echo"]["stderr_size"], 0)
        self.assertEqual(by["denied"]["error_class"], "access is denied" if NT else "permission denied")
        self.assertEqual(by["nonzero"]["error_class"], "exit 3")
        self.assertEqual(by["missing"]["error_class"], "command not found")
        self.assertEqual(by["badjson"]["error_class"], "json decode error")
        self.assertEqual(by["empty"]["error_class"], "no output")
        self.assertIsNone(by["echo"]["error_class"])
        self.assertEqual(status_counts(entries), {"ok": 4, "nonzero": 1, "timeout": 1, "missing": 1, "denied": 1, "empty": 1, "invalid_json": 1})


class ClassifyTests(unittest.TestCase):
    """The pure classifier, table driven (no subprocess)."""

    def test_table(self):
        cases = [
            # (ext, exit_code, stdout, stderr) -> (status, error contains)
            (("txt", 0, "fine\n", ""), ("ok", None)),
            (("json", 0, '{"a": [1, 2]}\n', ""), ("ok", None)),
            (("txt", 0, "data\n", "warning: Permission denied on /x\n"), ("ok", None)),  # good output wins over a warning
            (("txt", 1, "", "cat: /root/x: Permission denied\n"), ("denied", "Permission denied")),
            (("txt", 0, "", "The requested operation requires elevation.\n"), ("denied", "requires elevation")),
            (("txt", 1, "", "Get-X : Access is denied.\n"), ("denied", "Access is denied")),
            (("txt", 1, "", "dmesg: read kernel buffer failed: Operation not permitted\n"), ("denied", "Operation not permitted")),
            (("txt", 1, "", "Get-Thing : Attempted to perform an unauthorized operation.\n"), ("denied", "unauthorized")),
            (("txt", 127, "", "bash: foo: command not found\n"), ("missing", "command not found")),
            (("txt", 127, "", "sh: 1: foo: not found\n"), ("missing", "not found")),
            (("txt", 1, "", "The term 'Get-BitLockerVolume' is not recognized as the name of a cmdlet, function, script file, or operable program.\n"),
             ("missing", "is not recognized")),
            (("txt", 1, "", "'foo' is not recognized as an internal or external command,\n"), ("missing", "not recognized")),
            (("txt", 2, "partial\n", ""), ("nonzero", "exit 2")),
            (("txt", 2, "partial\n", "something broke\n"), ("nonzero", "exit 2: something broke")),
            (("txt", 0, "", ""), ("empty", None)),
            (("txt", 0, "  \n", "Hint: You are currently not seeing messages from other users and the system.\n"), ("empty", "Hint:")),
            (("json", 0, "", ""), ("empty", None)),
            (("json", 0, "{bad\n", ""), ("invalid_json", "not valid JSON")),
            (("json", 0, "[1, 2, \n... " + TRUNCATED_MARK + "\n", ""), ("invalid_json", "(output truncated)")),
            (("json", 0, "﻿{\"bom\": true}", ""), ("ok", None)),
        ]
        for args, (status, needle) in cases:
            got_status, got_error = classify(*args)
            self.assertEqual(got_status, status, args)
            if needle is None:
                self.assertIsNone(got_error, args)
            else:
                self.assertIn(needle, got_error, args)

    def test_error_class_never_carries_content(self):
        def entry(status, error=None, exit_code=None):
            return FileEntry(path="sys/x.txt", sha256="0" * 64, size=1, collector="x", status=status, error=error, exit_code=exit_code)
        self.assertEqual(error_class(entry("denied", "cat: /home/jdoe/secret.txt: Permission denied")), "permission denied")
        self.assertEqual(error_class(entry("denied", "Get-X : Access is denied. (needs administrator/root; the agent is not elevated)")), "access is denied")
        self.assertEqual(error_class(entry("denied", "cannot start /opt/jdoe/tool: Permission denied")), "permission denied")
        self.assertEqual(error_class(entry("nonzero", "exit 3: jdoe failed", 3)), "exit 3")
        self.assertEqual(error_class(entry("missing", "command not found: /home/jdoe/bin/x")), "command not found")
        self.assertEqual(error_class(entry("timeout", "timeout after 5s")), "timeout")
        self.assertEqual(error_class(entry("empty", "Hint: jdoe")), "no output (stderr present)")
        self.assertEqual(error_class(entry("empty")), "no output")
        self.assertEqual(error_class(entry("invalid_json", "output is not valid JSON: Expecting value: line 1")), "json decode error")
        self.assertEqual(error_class(entry("invalid_json", "output is not valid JSON (output truncated): x")), "json decode error (output truncated)")
        self.assertIsNone(error_class(entry("ok")))


class OutputFilterTests(unittest.TestCase):
    def test_env_names_keeps_names_only(self):
        self.assertEqual(OUTPUT_FILTERS["env_names"]("PATH=/usr/bin\nSECRET_TOKEN=abc\nnoequals\nA=1\n"), "A\nPATH\nSECRET_TOKEN\n")
        self.assertEqual(OUTPUT_FILTERS["env_names"](""), "")

    def test_hardware_ids_dropped_from_profiler_json_and_text(self):
        doc = {"SPHardwareDataType": [{"machine_name": "Mac mini", "serial_number": "C02XXXXXX", "platform_UUID": "1111-2222",
                                       "provisioning_UDID": "0000-1111", "nested": {"boot_volume_uuid": "x", "chip_type": "M2"}}],
               "SPSoftwareDataType": [{"os_version": "macOS 14.6", "kernel_version": "Darwin 23.6.0"}]}
        out = json.loads(OUTPUT_FILTERS["drop_hardware_ids"](json.dumps(doc)))
        self.assertEqual(out, {"SPHardwareDataType": [{"machine_name": "Mac mini", "nested": {"chip_type": "M2"}}],
                               "SPSoftwareDataType": [{"os_version": "macOS 14.6", "kernel_version": "Darwin 23.6.0"}]})
        text = "Model Name: Mac mini\nSerial Number (system): C02XXXXXX\nHardware UUID: 1111-2222\nChip: Apple M2\n"
        self.assertEqual(OUTPUT_FILTERS["drop_hardware_ids"](text), "Model Name: Mac mini\nChip: Apple M2\n")


class CollectorTableTests(unittest.TestCase):
    def test_posix_tables_start_tools_directly(self):
        for c in LINUX + MACOS:
            self.assertNotIn(c.argv[0], ("sh", "bash", "zsh", "dash"), c.name)
            self.assertFalse(any(tok in ("|", "||", "&&", ";") or tok.startswith("2>") for tok in c.argv), c.name)
            if c.keep_lines:
                self.assertIn(c.keep_lines[0], ("head", "tail"), c.name)
                self.assertGreater(c.keep_lines[1], 0, c.name)
            if c.output_filter:
                self.assertIn(c.output_filter, OUTPUT_FILTERS, c.name)
        self.assertEqual([c for c in LINUX if c.name == "processes_top"][0].argv[:4], ["ps", "-e", "-o", "pid,ppid,user,%cpu,%mem,etime,comm"])
        self.assertEqual([c for c in MACOS if c.name == "processes_top"][0].argv, ["ps", "-A", "-r", "-o", "pid,ppid,user,%cpu,%mem,etime,comm"])
        self.assertEqual([c.output_filter for c in MACOS if c.name == "hardware"], ["drop_hardware_ids"])
        self.assertEqual([c.keep_lines for c in MACOS if c.name == "log_errors_30m"], [("tail", 500)])

    def test_windows_table_is_absolute_and_admin_collectors_are_marked(self):
        for c in WINDOWS:
            self.assertTrue(ntpath.isabs(c.argv[0]), c.name)
        admin = {c.name for c in WINDOWS if c.requires_admin}
        self.assertTrue({"defender", "bitlocker", "system_errors_7d", "application_errors_7d", "drivers", "connections"} <= admin, admin)
        self.assertTrue({"dmesg_err", "journal_errors", "journal_boot"} <= {c.name for c in LINUX if c.requires_admin})
        self.assertIn("log_errors_30m", {c.name for c in MACOS if c.requires_admin})

    def test_names_unique_and_table_digest_stable(self):
        for table in (WINDOWS, LINUX, MACOS):
            names = [c.name for c in table]
            self.assertEqual(len(names), len(set(names)))
        digests = {os_name: collector_table_sha256(os_name) for os_name in ("windows", "linux", "macos")}
        for d in digests.values():
            self.assertRegex(d, r"^[0-9a-f]{64}$")
        self.assertEqual(len(set(digests.values())), 3)
        self.assertEqual(collector_table_sha256("linux"), digests["linux"])

    def test_is_elevated_is_bool_or_none(self):
        self.assertIn(is_elevated(), (True, False, None))
        if not NT:
            self.assertEqual(is_elevated(), os.geteuid() == 0)


# Collectors of the real quick set that may report a failure status on a
# GitHub-hosted runner, with the reason. Everything else must be ok or empty.
EXPECTED_FAILURES: dict[str, dict[str, str]] = {
    "linux": {
        "dmesg_err": "ubuntu runner sets kernel.dmesg_restrict=1; the runner user cannot read the ring buffer (denied)",
        "journal_errors": "journal visibility depends on the runner user's group membership (adm/systemd-journal)",
        "journal_boot": "journal visibility depends on the runner user's group membership (adm/systemd-journal)",
    },
    "macos": {
        "gatekeeper": "spctl --status reports 'assessments disabled' with a non-zero exit on runner images",
        "log_errors_30m": "log show over 30 minutes of a busy runner can exceed its timeout; needs root for the system scope",
    },
    "windows": {
        "bitlocker": "the BitLocker feature is not installed on Windows Server runner images (cmdlet not recognized)",
        "defender": "Windows Defender is removed or its service stopped on runner images",
        "disks": "Get-PhysicalDisk returns nothing or errors on some Azure VM generations (provisional)",
        "computerinfo": "Get-ComputerInfo takes 20-60 s on a cold runner and may hit its 90 s timeout (provisional)",
    },
}
ON_GITHUB_RUNNER = os.environ.get("GITHUB_ACTIONS") == "true"


class RealQuickSetTests(unittest.TestCase):
    """Runs the real quick set once for this OS (no osquery)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.entries = collect_all(cls.root, quick=True, include_osquery=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_invariants(self):
        primary = [e for e in self.entries if not e.collector.endswith(".stderr")]
        sidecars = {e.path: e for e in self.entries if e.collector.endswith(".stderr")}
        self.assertGreater(len(primary), 5)
        self.assertEqual(len({e.collector for e in primary}), len(primary))
        for e in self.entries:
            p = self.root / e.path
            self.assertTrue(p.exists(), e.path)
            self.assertEqual(sha256_file(p), e.sha256, e.path)
            self.assertEqual(p.stat().st_size, e.size, e.path)
            self.assertIn(e.status, STATUSES)
        for e in primary:
            ext = e.path.rsplit(".", 1)[-1]
            if e.status == "ok":
                self.assertIn(e.exit_code, (0, None), e.path)
                self.assertIsNone(e.error, e.path)
                self.assertGreater(e.size, 0, e.path)
                if ext == "json":
                    json.loads((self.root / e.path).read_text(encoding="utf-8"))
            elif e.status == "empty":
                self.assertEqual(e.size, 0, e.path)
            elif e.status == "nonzero":
                self.assertNotIn(e.exit_code, (0, None), e.path)
                self.assertTrue(e.error.startswith("exit "), e.error)
            elif e.status == "timeout":
                self.assertTrue(e.error.startswith("timeout after "), e.error)
            else:
                self.assertIsNotNone(e.error, e.path)
            category, _, name = e.path.partition("/")
            stderr_path = f"{category}/{e.collector}.stderr.txt"
            if (self.root / stderr_path).exists():
                self.assertIn(stderr_path, sidecars, "every stderr sidecar on disk is listed in the manifest")
                self.assertEqual(sidecars[stderr_path].collector, f"{e.collector}.stderr")
        self.assertGreater(len([e for e in primary if e.status == "ok"]), 3, [(e.path, e.status, e.error) for e in primary])

    @unittest.skipUnless(ON_GITHUB_RUNNER and current_os() in EXPECTED_FAILURES, "collector outcomes are pinned only on GitHub-hosted runners")
    def test_pinned_outcomes_on_github_runner(self):
        allowed = EXPECTED_FAILURES[current_os()]
        rows = selftest_rows(self.entries, current_os())
        unexpected = [(r["name"], r["status"], r["error_class"]) for r in rows if r["status"] in FAILURE_STATUSES and r["name"] not in allowed]
        self.assertEqual(unexpected, [], "collectors failing on this runner that are not in EXPECTED_FAILURES")


if __name__ == "__main__":
    unittest.main()
