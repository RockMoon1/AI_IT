import codecs
import io
import multiprocessing
import os
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
from contextlib import redirect_stderr
from pathlib import Path

from aiit.agent.procs import windows_system32
from aiit.common import util
from aiit.common.util import atomic_write_bytes, ensure_private_dir, new_id, safe_join, sddl_write_principals, validate_id, write_json

ICACLS = windows_system32("icacls.exe")
WHOAMI = windows_system32("whoami.exe")
ME = "S-1-5-21-1111-2222-3333-1001"
OTHER = "S-1-5-21-1111-2222-3333-1002"
TIGHT_AGENT = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
TIGHT_USER = f"D:P(A;OICI;FA;;;{ME})"
# What %ProgramData%\aiit\agent inherits by default: Users may list, add files and subfolders.
LOOSE_PROGRAMDATA = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;LC;;;BU)(A;CIIOID;DC;;;BU)(A;OICIIOID;FA;;;CO)"
READ_ONLY_USERS = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"


def _locked_append(args):
    path, lock_path, token = args
    from aiit.common.util import file_lock as fl
    with fl(Path(lock_path)):
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"start-{token}\n")
            time.sleep(0.05)
            f.write(f"end-{token}\n")


class FakeWindowsTools:
    """Stands in for util.windows_tool_runner: records every argv, answers whoami and icacls."""

    def __init__(self, sddl=TIGHT_AGENT, sid=ME, rc=0, whoami_rc=0, whoami_out=None):
        self.calls = []
        self.sddl, self.sid, self.rc, self.whoami_rc, self.whoami_out = sddl, sid, rc, whoami_rc, whoami_out

    def __call__(self, argv):
        self.calls.append(list(argv))
        if argv[0] == WHOAMI:
            out = self.whoami_out if self.whoami_out is not None else f'"lab\\operator","{self.sid}"\r\n'
            return self.whoami_rc, out
        if argv[0] == ICACLS and "/save" in argv:
            if self.rc == 0:
                body = f"state\r\n{self.sddl}\r\n".encode("utf-16-le")
                Path(argv[argv.index("/save") + 1]).write_bytes(codecs.BOM_UTF16_LE + body)
            return self.rc, "Successfully processed 1 files; Failed processing 0 files\r\n"
        if argv[0] == ICACLS:
            return self.rc, "processed file\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n"
        raise AssertionError(f"unexpected tool call {argv}")

    @property
    def grants(self):
        return [c for c in self.calls if c[0] == ICACLS and "/grant:r" in c]


class IdTests(unittest.TestCase):
    def test_minted_ids_validate(self):
        for prefix in ("console-", "agent-", "case-", "plan-", "b-", "r-", "in-"):
            validate_id(new_id(prefix))

    def test_bad_ids_rejected(self):
        for bad in ["", "case", "case-", "case-123", "CASE-0123456789ab", "case-0123456789ab/x", "../x", "case-0123456789abcd", None, 5]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                validate_id(bad)


class SafeJoinTests(unittest.TestCase):
    def test_contained_paths(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            self.assertEqual(safe_join(base, "a", "b.txt"), (base / "a" / "b.txt").resolve())
            self.assertEqual(safe_join(base, "sys/a.txt"), (base / "sys" / "a.txt").resolve())

    def test_escapes_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            for bad in [["../x"], ["a", "..", "..", "x"], ["/etc/hosts"], [""], ["a\x00b"]]:
                with self.assertRaises(ValueError, msg=repr(bad)):
                    safe_join(base, *bad)
            if os.name == "nt":
                with self.assertRaises(ValueError):
                    safe_join(base, "C:\\Windows")


class AtomicWriteTests(unittest.TestCase):
    def test_no_temp_left_and_content_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.json"
            write_json(p, {"a": 1})
            write_json(p, {"a": 2}, private=True)
            self.assertEqual(p.read_text(encoding="utf-8").strip(), '{\n  "a": 2\n}')
            leftovers = [x for x in Path(d).iterdir() if x.name.endswith(".tmp")]
            self.assertEqual(leftovers, [])
            if os.name != "nt":
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_failed_write_leaves_old_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.bin"
            atomic_write_bytes(p, b"old")
            with self.assertRaises(TypeError):
                atomic_write_bytes(p, "not-bytes")  # type: ignore[arg-type]
            self.assertEqual(p.read_bytes(), b"old")
            self.assertEqual([x for x in Path(d).iterdir() if x.name.endswith(".tmp")], [])


class FileLockTests(unittest.TestCase):
    def test_threads_are_serialized(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "log.txt"
            lock = Path(d) / "log.txt"
            def worker(i):
                _locked_append((str(target), str(lock), f"t{i}"))
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            lines = target.read_text().splitlines()
            self.assertEqual(len(lines), 8)
            for i in range(0, 8, 2):
                self.assertEqual(lines[i].split("-")[0], "start")
                self.assertEqual(lines[i + 1].split("-")[1], lines[i].split("-")[1])

    def test_processes_are_serialized(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "log.txt"
            ctx = multiprocessing.get_context("spawn")
            with ctx.Pool(3) as pool:
                pool.map(_locked_append, [(str(target), str(target), f"p{i}") for i in range(3)])
            lines = target.read_text().splitlines()
            self.assertEqual(len(lines), 6)
            for i in range(0, 6, 2):
                self.assertEqual(lines[i + 1].split("-")[1], lines[i].split("-")[1])


class _PrivateDirBase(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(util.LOOSE_STATE_DIR_ENV, None)
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def allow_loose(self):
        os.environ[util.LOOSE_STATE_DIR_ENV] = "1"


@unittest.skipIf(os.name == "nt", "POSIX file modes")
class PrivateDirPosixTests(_PrivateDirBase):
    def mode(self, p):
        return p.stat().st_mode & 0o777

    def test_fresh_dirs_are_0700(self):
        for owner in (None, "agent", "console"):
            p = ensure_private_dir(self.root / "deep" / f"{owner}", owner=owner)
            self.assertTrue(p.is_dir())
            self.assertEqual(self.mode(p), 0o700, owner)

    def test_readable_existing_dir_is_tightened_not_refused(self):
        d = self.root / "agent"
        d.mkdir()
        os.chmod(d, 0o755)
        self.assertEqual(ensure_private_dir(d, owner="agent"), d)
        self.assertEqual(self.mode(d), 0o700)

    def test_group_or_world_writable_existing_dir_is_refused(self):
        for mode, needle in ((0o770, "group-writable"), (0o707, "world-writable"), (0o777, "group- and world-writable")):
            d = self.root / f"d{mode:o}"
            d.mkdir()
            os.chmod(d, mode)  # deliberately loose: this is the misconfiguration under test
            with self.assertRaises(PermissionError, msg=oct(mode)) as cm:
                ensure_private_dir(d, owner="console")
            msg = str(cm.exception)
            self.assertIn(needle, msg)
            self.assertIn(f"chmod 700 {d}", msg)
            self.assertIn("AIIT_CONSOLE_DIR", msg)
            self.assertIn(util.LOOSE_STATE_DIR_ENV, msg)
            self.assertEqual(self.mode(d), mode)  # refused means untouched

    def test_dir_owned_by_another_account_is_refused(self):
        d = self.root / "agent"
        d.mkdir()
        os.chmod(d, 0o700)
        with mock.patch.object(util.os, "geteuid", return_value=d.stat().st_uid + 1):
            with self.assertRaises(PermissionError) as cm:
                ensure_private_dir(d, owner="agent")
        self.assertIn("owned by uid", str(cm.exception))
        self.assertIn("chown", str(cm.exception))
        self.assertIn("AIIT_AGENT_DIR", str(cm.exception))

    def test_override_warns_and_still_tightens(self):
        d = self.root / "agent"
        d.mkdir()
        os.chmod(d, 0o770)
        self.allow_loose()
        err = io.StringIO()
        with redirect_stderr(err):
            ensure_private_dir(d, owner="agent")
        self.assertIn("group-writable", err.getvalue())
        self.assertIn(util.LOOSE_STATE_DIR_ENV, err.getvalue())
        self.assertEqual(self.mode(d), 0o700)

    def test_subdirectory_without_owner_is_never_refused(self):
        d = self.root / "reports"
        d.mkdir()
        os.chmod(d, 0o777)
        ensure_private_dir(d)
        self.assertEqual(self.mode(d), 0o700)

    def test_unknown_owner(self):
        with self.assertRaises(ValueError):
            ensure_private_dir(self.root / "x", owner="service")


class PrivateDirWindowsPathTests(_PrivateDirBase):
    """The Windows branch, driven on every OS through the injectable tool runner."""

    def setUp(self):
        super().setUp()
        for name, value in (("_is_windows", lambda: True), ("windows_is_elevated", lambda: True)):
            p = mock.patch.object(util, name, value)
            p.start()
            self.addCleanup(p.stop)
        util.windows_current_user_sid.cache_clear()
        self.addCleanup(util.windows_current_user_sid.cache_clear)

    def use(self, fake):
        p = mock.patch.object(util, "windows_tool_runner", fake)
        p.start()
        self.addCleanup(p.stop)
        return fake

    def test_fresh_agent_dir_gets_system_and_administrators(self):
        fake = self.use(FakeWindowsTools())
        d = ensure_private_dir(self.root / "agent", owner="agent")
        self.assertTrue(d.is_dir())
        self.assertEqual(fake.calls, [[ICACLS, str(d), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]])

    def test_fresh_console_dir_gets_the_current_user_sid(self):
        fake = self.use(FakeWindowsTools())
        d = ensure_private_dir(self.root / "console", owner="console")
        self.assertEqual(fake.calls, [[WHOAMI, "/user", "/fo", "csv", "/nh"],
                                      [ICACLS, str(d), "/inheritance:r", "/grant:r", f"*{ME}:(OI)(CI)F"]])

    def test_console_falls_back_to_username_when_whoami_fails(self):
        fake = self.use(FakeWindowsTools(whoami_rc=1, whoami_out="ERROR: no token\r\n"))
        os.environ["USERNAME"] = "operator"
        d = ensure_private_dir(self.root / "console", owner="console")
        self.assertEqual(fake.grants, [[ICACLS, str(d), "/inheritance:r", "/grant:r", "operator:(OI)(CI)F"]])

    def test_whoami_table_output_is_parsed_too(self):
        self.use(FakeWindowsTools(whoami_out=f"\r\nUSER INFORMATION\r\n----------------\r\n\r\nUser Name    SID\r\n============ {'=' * 44}\r\nlab\\operator {ME.lower()}\r\n"))
        self.assertEqual(util.windows_current_user_sid(), ME)

    def test_icacls_failure_fails_closed_unless_overridden(self):
        fake = self.use(FakeWindowsTools(rc=5))
        with self.assertRaises(PermissionError) as cm:
            ensure_private_dir(self.root / "agent", owner="agent")
        self.assertIn("icacls exited 5", str(cm.exception))
        self.assertIn("/inheritance:r", str(cm.exception))
        self.allow_loose()
        err = io.StringIO()
        with redirect_stderr(err):
            ensure_private_dir(self.root / "agent2", owner="agent")
        self.assertIn("icacls exited 5", err.getvalue())
        self.assertEqual(len(fake.grants), 2)

    def test_agent_dir_needs_an_elevated_process(self):
        fake = self.use(FakeWindowsTools())
        with mock.patch.object(util, "windows_is_elevated", lambda: False):
            with self.assertRaises(PermissionError) as cm:
                ensure_private_dir(self.root / "agent", owner="agent")
            self.assertIn("elevated", str(cm.exception))
            self.assertFalse((self.root / "agent").exists() and fake.grants)
            self.allow_loose()
            err = io.StringIO()
            with redirect_stderr(err):
                d = ensure_private_dir(self.root / "agent", owner="agent")
            self.assertIn("elevated", err.getvalue())
            self.assertEqual(fake.grants, [[ICACLS, str(d), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
                                            "*S-1-5-32-544:(OI)(CI)F", f"*{ME}:(OI)(CI)F"]])

    def test_existing_tight_dirs_pass_without_regranting(self):
        for owner, sddl in (("agent", TIGHT_AGENT), ("console", TIGHT_AGENT), ("agent", TIGHT_USER), ("console", TIGHT_USER),
                            ("agent", READ_ONLY_USERS)):
            with self.subTest(owner=owner, sddl=sddl):
                util.windows_current_user_sid.cache_clear()
                fake = self.use(FakeWindowsTools(sddl=sddl))
                d = self.root / f"{owner}-{len(sddl)}"
                d.mkdir()
                ensure_private_dir(d, owner=owner)
                self.assertEqual(fake.grants, [])
                self.assertEqual([c[:3] for c in fake.calls if c[0] == ICACLS], [[ICACLS, str(d), "/save"]])

    def test_existing_loose_dir_is_refused_with_the_fix(self):
        for owner, sddl, needle in (("agent", LOOSE_PROGRAMDATA, "Users (S-1-5-32-545)"),
                                    ("console", f"D:P(A;OICI;FA;;;{ME})(A;OICI;FA;;;{OTHER})", OTHER),
                                    ("console", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)", "Authenticated Users")):
            with self.subTest(owner=owner, needle=needle):
                util.windows_current_user_sid.cache_clear()
                fake = self.use(FakeWindowsTools(sddl=sddl))
                d = self.root / f"{owner}-{needle[:4]}"
                d.mkdir()
                with self.assertRaises(PermissionError) as cm:
                    ensure_private_dir(d, owner=owner)
                msg = str(cm.exception)
                self.assertIn(needle, msg)
                self.assertIn(f'{ICACLS} "{d}" /inheritance:r /grant:r', msg)
                self.assertIn("*S-1-5-18:(OI)(CI)F" if owner == "agent" else f"*{ME}:(OI)(CI)F", msg)
                self.assertIn(f"AIIT_{owner.upper()}_DIR", msg)
                self.assertEqual(fake.grants, [])
                self.allow_loose()
                err = io.StringIO()
                with redirect_stderr(err):
                    ensure_private_dir(d, owner=owner)
                self.assertIn(needle, err.getvalue())
                os.environ.pop(util.LOOSE_STATE_DIR_ENV)

    def test_unreadable_acl_is_refused(self):
        self.use(FakeWindowsTools(rc=2))
        d = self.root / "agent"
        d.mkdir()
        with self.assertRaises(PermissionError) as cm:
            ensure_private_dir(d, owner="agent")
        self.assertIn("cannot read the ACL", str(cm.exception))

    def test_subdirectory_without_owner_runs_no_tool(self):
        fake = self.use(FakeWindowsTools())
        ensure_private_dir(self.root / "state" / ".tmp-case")
        self.assertEqual(fake.calls, [])


class SddlTests(unittest.TestCase):
    def test_write_principals(self):
        self.assertEqual(sddl_write_principals(TIGHT_AGENT), [("S-1-5-18", 0x1F01FF), ("S-1-5-32-544", 0x1F01FF)])
        self.assertEqual([s for s, _ in sddl_write_principals(LOOSE_PROGRAMDATA)],
                         ["S-1-5-18", "S-1-5-32-544", "S-1-5-32-545", "S-1-5-32-545", "S-1-3-0"])
        self.assertEqual(sddl_write_principals(READ_ONLY_USERS)[2:], [])
        self.assertEqual(sddl_write_principals("D:(D;;FA;;;WD)(A;;FR;;;WD)"), [])  # deny and read-only: no writers
        self.assertEqual(sddl_write_principals("D:(A;;0x2;;;WD)"), [("S-1-1-0", 2)])  # add file
        self.assertEqual(sddl_write_principals("D:(A;;SD;;;IU)"), [("S-1-5-4", 0x10000)])  # delete
        self.assertEqual(sddl_write_principals("D:(A;;WDWO;;;LA)"), [("LA", 0xC0000)])  # write DAC + owner
        self.assertEqual(sddl_write_principals("D:(A;;QQ;;;BU)"), [("S-1-5-32-545", util._SDDL_WRITE_MASK)])  # unknown: assume write
        self.assertEqual(sddl_write_principals("O:BAG:BAD:P(A;OICI;FA;;;SY)S:(AU;SA;FA;;;WD)"), [("S-1-5-18", 0x1F01FF)])
        self.assertEqual(sddl_write_principals("not an sddl"), [])

    def test_icacls_save_decoding(self):
        text = "state\r\nD:P(A;OICI;FA;;;SY)\r\n"
        for data in (codecs.BOM_UTF16_LE + text.encode("utf-16-le"), text.encode("utf-16-le"), text.encode("utf-8")):
            self.assertIn("D:P(A;OICI;FA;;;SY)", util._decode_icacls_save(data))


class WindowsToolRunnerTests(unittest.TestCase):
    def test_runs_under_the_scrubbed_environment(self):
        with mock.patch.dict(os.environ, {"AIIT_SERVER_TOKEN": "must-not-reach-the-child"}):
            rc, out = util._run_windows_tool([sys.executable, "-c", "import os,sys; sys.stdout.write(os.environ.get('AIIT_SERVER_TOKEN', 'absent'))"])
        self.assertEqual((rc, out.strip()), (0, "absent"))

    def test_missing_tool_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = util._run_windows_tool([str(Path(d) / "no-such-tool.exe"), "/x"])
        self.assertEqual(rc, -1)
        self.assertIn("FileNotFoundError", out)


@unittest.skipUnless(os.name == "nt", "real icacls")
class RealIcaclsTests(unittest.TestCase):
    def test_console_dir_restricted_checked_and_loose_dir_refused(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            root = Path(d)
            c = ensure_private_dir(root / "console", owner="console")
            sid = util.windows_current_user_sid()
            self.assertRegex(sid or "", r"^S-1-5-")
            writers = {s for s, _ in sddl_write_principals(util.windows_dir_sddl(c))}
            self.assertTrue(writers and writers <= {sid, "LA"}, writers)
            ensure_private_dir(c, owner="console")  # re-open passes the check
            (c / "probe.txt").write_text("ok", encoding="utf-8")  # and the account can still use it
            loose = root / "loose"
            loose.mkdir()
            rc, out = util.windows_tool_runner([ICACLS, str(loose), "/grant", "*S-1-1-0:(OI)(CI)M"])
            self.assertEqual(rc, 0, out)
            with self.assertRaises(PermissionError) as cm:
                ensure_private_dir(loose, owner="console")
            self.assertIn("Everyone", str(cm.exception))
            err = io.StringIO()
            with mock.patch.dict(os.environ, {util.LOOSE_STATE_DIR_ENV: "1"}), redirect_stderr(err):
                ensure_private_dir(loose, owner="console")
            self.assertIn("Everyone", err.getvalue())

    def test_agent_dir_is_system_and_administrators_only(self):
        if not util.windows_is_elevated():
            self.skipTest("needs an elevated process")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            a = ensure_private_dir(Path(d) / "agent", owner="agent")
            writers = {s for s, _ in sddl_write_principals(util.windows_dir_sddl(a))}
            self.assertEqual(writers, {util.WINDOWS_SID_SYSTEM, util.WINDOWS_SID_ADMINISTRATORS})
            ensure_private_dir(a, owner="agent")
            (a / "probe.txt").write_text("ok", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
