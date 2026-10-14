"""Console ingest is a trust boundary: hostile bundles must fail closed and leave nothing behind."""
import json
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from . import helpers
from aiit.common.crypto import CryptoError, Identity
from aiit.common.redact import RedactionConfig
from aiit.common.util import read_json
from aiit.console.store import _harvest_usernames


def leftovers(state):
    return sorted(p.name for p in state.cases_dir.glob(".tmp-*")) if state.cases_dir.exists() else []


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = helpers.make_console(self.root / "console")
        self.agent = helpers.agent_identity()
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def bundle(self, **kw):
        self.n += 1
        return helpers.seal_diagnostics(self.state, self.agent, self.root / f"b{self.n}.aiit", **kw)

    def assert_rejected(self, path, needle):
        before = len(self.state.list_cases())
        with self.assertRaises(CryptoError) as cm:
            self.state.ingest_bundle(path)
        self.assertIn(needle, str(cm.exception))
        self.assertEqual(len(self.state.list_cases()), before)
        self.assertEqual(leftovers(self.state), [])
        self.assertEqual(self.state.audit.entries()[-1]["action"], "ingest_failed")

    def test_happy_path_and_duplicate(self):
        p = self.bundle(files={"sys/echo.txt": "user jdoe@example.org on 11.22.33.44\n"}, issue="printer offline for jdoe@example.org")
        case_id, manifest, case = self.state.ingest_bundle(p)
        self.assertEqual(case["agent_trust"], "new")
        red = (self.state.cases_dir / case_id / "redacted" / "sys" / "echo.txt").read_text()
        self.assertNotIn("jdoe@example.org", red)
        self.assertNotIn("11.22.33.44", red)
        cfg = read_json(self.state.cases_dir / case_id / "redaction_config.json")
        self.assertIn("lab-pc-07", cfg["redact_hostnames"])
        idx = read_json(self.state.bundles_index_file)
        self.assertEqual(idx[manifest.bundle_id]["case_id"], case_id)
        again_id, _, _ = self.state.ingest_bundle(p)
        self.assertEqual(again_id, case_id)
        self.assertEqual(len(self.state.list_cases()), 1)
        self.assertEqual(self.state.audit.entries()[-1]["action"], "ingest_duplicate")

    def test_missing_manifest(self):
        def drop(root):
            (root / "manifest.json").unlink()
        self.assert_rejected(self.bundle(tamper=drop), "no manifest.json")

    def test_manifest_agent_mismatch(self):
        def swap(m):
            m["agent_id"] = "agent-ffffffffffff"
            return m
        self.assert_rejected(self.bundle(manifest_override=swap), "do not match the sealed header")

    def test_modified_file_hash(self):
        def edit(root):
            (root / "sys" / "echo.txt").write_text("changed after hashing")
        self.assert_rejected(self.bundle(tamper=edit), "hash mismatch")

    def test_manifest_lists_missing_file(self):
        def drop(root):
            (root / "sys" / "echo.txt").unlink()
        self.assert_rejected(self.bundle(tamper=drop), "not in the bundle")

    def test_manifest_path_escape_rejected(self):
        def escape(m):
            m["files"][0]["path"] = "/etc/hosts"
            return m
        self.assert_rejected(self.bundle(manifest_override=escape), "failed validation")

    def test_key_pinning_on_agent_id_reuse(self):
        self.state.ingest_bundle(self.bundle())
        impostor = Identity.generate(self.agent.id, with_box=False)
        p = helpers.seal_diagnostics(self.state, impostor, self.root / "imp.aiit")
        self.assert_rejected(p, "different signing key")

    def test_extra_literals_and_harvested_usernames_persist(self):
        users = json.dumps([{"Name": "jsmith", "Enabled": True}, {"Name": "Guest", "Enabled": False}])
        p = self.bundle(files={"sys/local_users.json": users, "sys/log.txt": "Jane Doe logged in; profile C:\\Users\\jsmith\\x"})
        case_id, _, _ = self.state.ingest_bundle(p, RedactionConfig(extra_literals=["Jane Doe"]))
        cfg = read_json(self.state.cases_dir / case_id / "redaction_config.json")
        self.assertIn("Jane Doe", cfg["extra_literals"])
        self.assertIn("jsmith", cfg["extra_literals"])
        self.assertNotIn("Guest", cfg["extra_literals"])
        red = (self.state.cases_dir / case_id / "redacted" / "sys" / "log.txt").read_text()
        self.assertNotIn("Jane Doe", red)
        self.assertNotIn("jsmith", red)

    def test_harvested_usernames_skip_generic_names_and_are_word_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            raw = Path(d)
            (raw / "sys").mkdir()
            (raw / "sys" / "local_users.json").write_text(json.dumps(
                [{"Name": "mark"}, {"Name": "info"}, {"Name": "Backup"}, {"Name": "jsmith"}, {"Name": "bob"}, {"Name": "1001"}]))
            # real account names stay; generic words, short names and numbers are dropped
            self.assertEqual(_harvest_usernames(raw), ["jsmith", "mark"])
        users = json.dumps([{"Name": "mark"}, {"Name": "info"}])
        log = "information about bookmarks: marker=on; user mark logged in; remark by Mark"
        p = self.bundle(files={"sys/local_users.json": users, "sys/log.txt": log})
        case_id, _, _ = self.state.ingest_bundle(p)
        cfg = read_json(self.state.cases_dir / case_id / "redaction_config.json")
        self.assertIn("mark", cfg["extra_literals"])
        self.assertNotIn("info", cfg["extra_literals"])
        red = (self.state.cases_dir / case_id / "redacted" / "sys" / "log.txt").read_text(encoding="utf-8")
        # the account is tokened as a whole word only; unrelated words keep their letters
        self.assertTrue(red.startswith("information about bookmarks: marker=on; user <NAME_"), red)
        self.assertTrue(red.endswith("logged in; remark by Mark"), red)


class ReportIngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = helpers.make_console(self.root / "console")
        self.agent = helpers.agent_identity()
        self.case_id, _, _ = self.state.ingest_bundle(helpers.seal_diagnostics(self.state, self.agent, self.root / "d.aiit"))
        self.plan_id = "plan-000000000001"
        self.ok = [{"step_id": "s1", "title": "t", "status": "dry_run"}]

    def tearDown(self):
        self.tmp.cleanup()

    def reports_tmp(self):
        rd = self.state.cases_dir / self.case_id / "reports"
        return sorted(p.name for p in rd.glob(".tmp-*")) if rd.exists() else []

    def test_report_attaches_and_duplicate_is_idempotent(self):
        p = helpers.seal_report(self.state, self.agent, self.root / "r.aiit", self.case_id, self.plan_id, self.ok)
        cid, manifest, case = self.state.ingest_bundle(p)
        self.assertEqual(cid, self.case_id)
        self.assertEqual(manifest.kind, "execution_report")
        self.assertEqual(case["reports"][0]["summary"], {"dry_run": 1})
        cid2, _, case2 = self.state.ingest_bundle(p)
        self.assertEqual(cid2, self.case_id)
        self.assertEqual(len(case2["reports"]), 1)

    def test_unknown_case(self):
        p = helpers.seal_report(self.state, self.agent, self.root / "r.aiit", "case-ffffffffffff", self.plan_id, self.ok)
        with self.assertRaises(CryptoError) as cm:
            self.state.ingest_bundle(p)
        self.assertIn("unknown case", str(cm.exception))

    def test_wrong_agent_is_refused_before_unpacking(self):
        other = helpers.agent_identity("agent-000000000002")
        p = helpers.seal_report(self.state, other, self.root / "r.aiit", self.case_id, self.plan_id, self.ok)
        # Make the ordering observable: if the ownership check ever moved below the unpack, this
        # AssertionError (which ingest_bundle does not catch) fails the test instead of the cleaned-up
        # temp dir hiding the difference.
        with mock.patch("aiit.console.store.unpack_to", side_effect=AssertionError("unpack_to must not run for a foreign report")) as up:
            with self.assertRaises(CryptoError) as cm:
                self.state.ingest_bundle(p)
        up.assert_not_called()
        self.assertIn("different agent", str(cm.exception))
        self.assertEqual(self.reports_tmp(), [])
        self.assertFalse(any((self.state.cases_dir / self.case_id / "reports").glob("r-*")))

    def test_report_for_another_case_inside_is_refused(self):
        def swap(rep):
            rep["case_id"] = "case-eeeeeeeeeeee"
            return rep
        p = helpers.seal_report(self.state, self.agent, self.root / "r.aiit", self.case_id, self.plan_id, self.ok, report_override=swap)
        with self.assertRaises(CryptoError):
            self.state.ingest_bundle(p)
        self.assertEqual(self.reports_tmp(), [])


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# State directory protection and fingerprints (appended; kept below the __main__
# guard on purpose so parallel appends to this file do not collide; discovery
# loads the whole module).
# ---------------------------------------------------------------------------
import io  # noqa: E402
import os  # noqa: E402
from contextlib import redirect_stderr  # noqa: E402

from aiit.agent.state import AgentState  # noqa: E402
from aiit.common import util as _util  # noqa: E402
from aiit.common.crypto import fingerprint  # noqa: E402
from aiit.common.schema import Enrollment  # noqa: E402
from aiit.console.store import ConsoleState  # noqa: E402


class StateDirAndFingerprintTests(unittest.TestCase):
    def test_console_root_is_created_as_the_console_owner(self):
        with tempfile.TemporaryDirectory() as d:
            calls = []
            real = _util.ensure_private_dir

            def spy(path, **kw):
                calls.append((Path(path), kw))
                return real(path, **kw)

            with mock.patch("aiit.console.store.ensure_private_dir", spy):
                st = ConsoleState(Path(d) / "console")
            self.assertEqual(calls[0], (Path(d) / "console", {"owner": "console"}))
            self.assertIsNone(st.identity_fingerprint())
            st.init(label="fp")
            fp = st.identity_fingerprint()
            self.assertEqual(fp, fingerprint(st.public_sign_key()))
            self.assertEqual(fp, st.identity().fingerprint)
            self.assertRegex(fp, r"^(?:[0-9a-f]{4} ){15}[0-9a-f]{4}$")
            # the public enrollment file carries the same key, so the endpoint can check it
            enr = Enrollment.model_validate(read_json(st.enrollment_file))
            self.assertEqual(fingerprint(enr.console_sign_pub), fp)

    def test_agent_exposes_its_own_and_the_console_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            console = helpers.make_console(Path(d) / "console")
            calls = []
            real = _util.ensure_private_dir

            def spy(path, **kw):
                calls.append((Path(path), kw))
                return real(path, **kw)

            with mock.patch("aiit.agent.state.ensure_private_dir", spy):
                agent = AgentState(Path(d) / "agent")
            self.assertEqual(calls, [(Path(d) / "agent", {"owner": "agent"})])
            self.assertIsNone(agent.identity_fingerprint())
            self.assertIsNone(agent.console_fingerprint())
            ident = agent.enroll(Enrollment.model_validate(read_json(console.enrollment_file)))
            self.assertEqual(agent.identity_fingerprint(), ident.fingerprint)
            self.assertEqual(agent.console_fingerprint(), console.identity_fingerprint())
            self.assertNotEqual(agent.identity_fingerprint(), agent.console_fingerprint())

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_group_writable_existing_console_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "console"
            root.mkdir()
            os.chmod(root, 0o770)  # deliberately loose: this is the misconfiguration under test
            with self.assertRaises(PermissionError) as cm:
                ConsoleState(root)
            self.assertIn("chmod 700", str(cm.exception))
            with mock.patch.dict(os.environ, {"AIIT_ALLOW_LOOSE_STATE_DIR": "1"}), redirect_stderr(io.StringIO()):
                ConsoleState(root)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
