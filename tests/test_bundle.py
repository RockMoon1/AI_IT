import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from . import helpers  # noqa: F401
from aiit.common.bundle import pack_dir, read_bundle, read_bundle_header, unpack_to, write_bundle
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

            console = Identity.generate("console-x", with_box=True)
            agent = Identity.generate("agent-y", with_box=False)
            out = Path(d) / "b.aiit"
            hdr = write_bundle(out, data, console.box_pub_hex, agent, kind="diagnostics", bundle_id="b-1", console_id="console-x")
            self.assertEqual(read_bundle_header(out)["bundle_id"], "b-1")
            hdr2, pt = read_bundle(out, console)
            self.assertEqual(pt, data)
            self.assertEqual(hdr2["signature"], hdr["signature"])
            with self.assertRaises(CryptoError):
                read_bundle(out, Identity.generate("console-z", with_box=True))

    def test_rejects_path_traversal(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo("../evil.txt")
            payload = b"x"
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(CryptoError):
                unpack_to(buf.getvalue(), Path(d) / "out")


if __name__ == "__main__":
    unittest.main()
