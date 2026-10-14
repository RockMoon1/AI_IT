import multiprocessing
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from aiit.common.util import atomic_write_bytes, new_id, safe_join, validate_id, write_json


def _locked_append(args):
    path, lock_path, token = args
    from aiit.common.util import file_lock as fl
    with fl(Path(lock_path)):
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"start-{token}\n")
            time.sleep(0.05)
            f.write(f"end-{token}\n")


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


if __name__ == "__main__":
    unittest.main()
