import os
import tempfile
import unittest
from pathlib import Path

from aiit.common.crypto import CryptoError, Identity, open_sealed, seal, sign_object, verify_object


class CryptoTests(unittest.TestCase):
    def test_identity_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            ident = Identity.generate("console-1", with_box=True)
            ident.save(Path(d))
            loaded = Identity.load(Path(d))
            self.assertEqual(loaded.id, "console-1")
            self.assertEqual(loaded.sign_pub_hex, ident.sign_pub_hex)
            self.assertEqual(loaded.box_pub_hex, ident.box_pub_hex)

    def test_identity_passphrase(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["AIIT_KEY_PASSPHRASE"] = "unit-test-passphrase"
            try:
                ident = Identity.generate("agent-1", with_box=False)
                ident.save(Path(d))
                self.assertIn(b"ENCRYPTED", (Path(d) / "sign.key").read_bytes())
                self.assertEqual(Identity.load(Path(d)).sign_pub_hex, ident.sign_pub_hex)
                os.environ.pop("AIIT_KEY_PASSPHRASE")
                with self.assertRaises(CryptoError):
                    Identity.load(Path(d))
            finally:
                os.environ.pop("AIIT_KEY_PASSPHRASE", None)

    def test_sign_verify_object_is_canonical(self):
        ident = Identity.generate("c", with_box=False)
        obj = {"b": 2, "a": [1, 2, {"z": "x"}]}
        sig = sign_object(ident, obj)
        self.assertTrue(verify_object(ident.sign_pub_hex, {"a": [1, 2, {"z": "x"}], "b": 2}, sig))
        self.assertFalse(verify_object(ident.sign_pub_hex, {"a": [1, 2, {"z": "x"}], "b": 3}, sig))
        self.assertFalse(verify_object(Identity.generate("o", with_box=False).sign_pub_hex, obj, sig))

    def test_seal_open_and_tamper_detection(self):
        console = Identity.generate("console", with_box=True)
        agent = Identity.generate("agent", with_box=False)
        pt = os.urandom(5000) + b"hello"
        hdr, ct = seal(pt, console.box_pub_hex, {"kind": "diagnostics", "bundle_id": "b1"}, agent)
        self.assertEqual(hdr["agent_id"], "agent")
        self.assertEqual(open_sealed(hdr, ct, console), pt)
        bad = bytearray(ct)
        bad[10] ^= 0xFF
        with self.assertRaises(CryptoError):
            open_sealed(hdr, bytes(bad), console)
        h2 = dict(hdr)
        h2["bundle_id"] = "b2"
        with self.assertRaises(CryptoError):
            open_sealed(h2, ct, console)
        with self.assertRaises(CryptoError):
            open_sealed(hdr, ct, Identity.generate("other", with_box=True))
        with self.assertRaises(CryptoError):
            open_sealed(hdr, ct, agent)


if __name__ == "__main__":
    unittest.main()
