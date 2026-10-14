import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from aiit.common.bundle import MAX_MEMBERS, pack_dir, read_bundle, read_bundle_header, unpack_to, write_bundle
from aiit.common.crypto import CryptoError, Identity


class BundleTests(unittest.TestCase):
    def test_pack_unpack_and_sealed_file(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "src"
            (src / "sys").mkdir(parents=True)
            (src / "manifest.json").write_text("{}")
            (src / "sys" / "a.txt").write_text("alpha")
            data = pack_dir(src)
            dest = Path(d) / "dest"
            names = unpack_to(data, dest)
            self.assertEqual(sorted(names), ["manifest.json", "sys/a.txt"])
            self.assertEqual((dest / "sys" / "a.txt").read_text(), "alpha")

            console = Identity.generate("console-aaaaaaaaaaaa", with_box=True)
            agent = Identity.generate("agent-bbbbbbbbbbbb", with_box=False)
            out = Path(d) / "b.aiit"
            hdr = write_bundle(out, data, console.box_pub_hex, agent, kind="diagnostics", bundle_id="b-cccccccccccc", console_id="console-aaaaaaaaaaaa")
            self.assertEqual(read_bundle_header(out)["bundle_id"], "b-cccccccccccc")
            hdr2, pt = read_bundle(out, console)
            self.assertEqual(pt, data)
            self.assertEqual(hdr2["signature"], hdr["signature"])
            with self.assertRaises(CryptoError):
                read_bundle(out, Identity.generate("console-dddddddddddd", with_box=True))
            # ids that could become path components are rejected before decryption
            bad = Path(d) / "bad.aiit"
            write_bundle(bad, data, console.box_pub_hex, agent, kind="diagnostics", bundle_id="../../etc", console_id="console-aaaaaaaaaaaa")
            with self.assertRaises(CryptoError):
                read_bundle(bad, console)

    @staticmethod
    def _tar_with(members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, payload, kind in members:
                info = tarfile.TarInfo(name)
                if kind == "sym":
                    info.type = tarfile.SYMTYPE
                    info.linkname = payload.decode()
                    tar.addfile(info)
                else:
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
        return buf.getvalue()

    def test_rejects_hostile_archives(self):
        hostile = {
            "dotdot": [("../evil.txt", b"x", "file")],
            "absolute": [("/tmp/evil.txt", b"x", "file")],
            "drive": [("D:evil.txt", b"x", "file")],
            "backslash": [("sys\\evil.txt", b"x", "file")],
            "symlink": [("link", b"/etc/passwd", "sym")],
        }
        for label, members in hostile.items():
            with tempfile.TemporaryDirectory() as d:
                out = Path(d) / "out"
                with self.assertRaises(CryptoError, msg=label):
                    unpack_to(self._tar_with(members), out)
                self.assertEqual(sorted(p.name for p in out.rglob("*")), [], label)

    def test_rejects_too_many_members_and_bombs(self):
        with tempfile.TemporaryDirectory() as d:
            many = [(f"f{i}.txt", b"x", "file") for i in range(MAX_MEMBERS + 1)]
            with self.assertRaises(CryptoError):
                unpack_to(self._tar_with(many), Path(d) / "a")
            from unittest import mock
            with mock.patch("aiit.common.bundle.MAX_MEMBER_BYTES", 10):
                with self.assertRaises(CryptoError):
                    unpack_to(self._tar_with([("big.txt", b"x" * 11, "file")]), Path(d) / "b")
            with mock.patch("aiit.common.bundle.MAX_TOTAL_BYTES", 15):
                with self.assertRaises(CryptoError):
                    unpack_to(self._tar_with([("a.txt", b"x" * 10, "file"), ("b.txt", b"x" * 10, "file")]), Path(d) / "c")


if __name__ == "__main__":
    unittest.main()
