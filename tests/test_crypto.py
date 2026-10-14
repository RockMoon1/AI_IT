import base64
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from aiit.common import crypto
from aiit.common.crypto import (CryptoError, Identity, fingerprint, fingerprint_matches, key_file_is_encrypted,
                                open_sealed, passphrase_source, public_key_bytes, seal, sign_object, verify_object)

PASSPHRASE_VARS = (crypto.PASSPHRASE_ENV, crypto.PASSPHRASE_FILE_ENV, crypto.NO_PROMPT_ENV)
# SHA-256 of 32 zero bytes, grouped: the fingerprint of an all-zero raw public key.
ZERO_KEY_FINGERPRINT = "6668 7aad f862 bd77 6c8f c18b 8e9f 8e20 0897 1485 6ee2 33b3 902a 591d 0d5f 2925"


class _Tty:
    def isatty(self):
        return True


class _NoTty:
    def isatty(self):
        return False


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


class PassphraseTests(unittest.TestCase):
    """_passphrase(): AIIT_KEY_PASSPHRASE, then AIIT_KEY_PASSPHRASE_FILE, then a terminal prompt, then None."""

    def setUp(self):
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for k in PASSPHRASE_VARS:
            os.environ.pop(k, None)
        crypto.set_passphrase_prompt(False)
        self.addCleanup(crypto.set_passphrase_prompt, False)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pw_file = self.root / "key.passphrase"
        self.pw_file.write_bytes(b"from-file-line-one\r\nsecond line is ignored\n")
        self._private(self.pw_file)

    @staticmethod
    def _private(path):
        if os.name != "nt":
            os.chmod(path, 0o600)

    def test_env_beats_file_beats_prompt_beats_none(self):
        asked = mock.Mock(return_value="from-prompt")
        with mock.patch.object(sys, "stdin", _Tty()), mock.patch.object(crypto.getpass, "getpass", asked):
            crypto.set_passphrase_prompt(True)
            os.environ[crypto.PASSPHRASE_ENV] = "from-env"
            os.environ[crypto.PASSPHRASE_FILE_ENV] = str(self.pw_file)
            self.assertEqual(crypto._passphrase(), b"from-env")
            self.assertEqual(passphrase_source(), "env")
            os.environ.pop(crypto.PASSPHRASE_ENV)
            self.assertEqual(crypto._passphrase(), b"from-file-line-one")  # first line, CRLF stripped
            self.assertEqual(passphrase_source(), "file")
            asked.assert_not_called()
            os.environ.pop(crypto.PASSPHRASE_FILE_ENV)
            self.assertIsNone(passphrase_source())
            self.assertEqual(crypto._passphrase(), b"from-prompt")
            self.assertEqual(crypto._passphrase(), b"from-prompt")  # remembered for the process
            self.assertEqual(asked.call_count, 1)
            crypto.set_passphrase_prompt(True)  # forgets the answer
            os.environ[crypto.NO_PROMPT_ENV] = "1"
            self.assertIsNone(crypto._passphrase())
            os.environ.pop(crypto.NO_PROMPT_ENV)
            crypto.set_passphrase_prompt(False)  # library default: never prompt
            self.assertIsNone(crypto._passphrase())
            self.assertEqual(asked.call_count, 1)
        with mock.patch.object(sys, "stdin", _NoTty()), mock.patch.object(crypto.getpass, "getpass", asked):
            crypto.set_passphrase_prompt(True)
            self.assertIsNone(crypto._passphrase())  # stdin is a pipe: no prompt
        with mock.patch.object(sys, "stdin", None), mock.patch.object(crypto.getpass, "getpass", asked):
            crypto.set_passphrase_prompt(True)
            self.assertIsNone(crypto._passphrase())  # pythonw / no stdin at all
        self.assertEqual(asked.call_count, 1)

    def test_empty_env_value_counts_as_unset(self):
        os.environ[crypto.PASSPHRASE_ENV] = ""
        os.environ[crypto.PASSPHRASE_FILE_ENV] = str(self.pw_file)
        self.assertEqual(crypto._passphrase(), b"from-file-line-one")
        self.assertEqual(passphrase_source(), "file")

    def test_prompt_confirmation(self):
        with mock.patch.object(sys, "stdin", _Tty()):
            crypto.set_passphrase_prompt(True)
            with mock.patch.object(crypto.getpass, "getpass", side_effect=["typed-once", "typed-twice"]):
                with self.assertRaises(CryptoError) as cm:
                    crypto._passphrase(confirm=True)
            self.assertIn("do not match", str(cm.exception))
            crypto.set_passphrase_prompt(True)
            with mock.patch.object(crypto.getpass, "getpass", side_effect=["typed-same", "typed-same"]) as g:
                self.assertEqual(crypto._passphrase(confirm=True), b"typed-same")
                self.assertEqual(g.call_count, 2)
                self.assertEqual(crypto._passphrase(), b"typed-same")
                self.assertEqual(g.call_count, 2)
            crypto.set_passphrase_prompt(True)
            with mock.patch.object(crypto.getpass, "getpass", side_effect=[""]) as g:
                self.assertIsNone(crypto._passphrase(confirm=True))  # empty answer: unencrypted, no repeat
                self.assertEqual(g.call_count, 1)

    def test_passphrase_file_problems(self):
        os.environ[crypto.PASSPHRASE_FILE_ENV] = str(self.root / "missing.passphrase")
        with self.assertRaises(CryptoError) as cm:
            crypto._passphrase()
        self.assertIn("missing.passphrase", str(cm.exception))
        empty = self.root / "empty"
        empty.write_bytes(b"\n\nnot the first line\n")
        self._private(empty)
        os.environ[crypto.PASSPHRASE_FILE_ENV] = str(empty)
        with self.assertRaises(CryptoError) as cm:
            crypto._passphrase()
        self.assertIn("empty", str(cm.exception))
        os.environ[crypto.PASSPHRASE_FILE_ENV] = self.tmp.name  # a directory
        with self.assertRaises(CryptoError):
            crypto._passphrase()

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_passphrase_file_accessible_by_others_is_refused(self):
        os.environ[crypto.PASSPHRASE_FILE_ENV] = str(self.pw_file)
        for mode in (0o644, 0o604, 0o602, 0o601):
            os.chmod(self.pw_file, mode)  # deliberately loose: this is the misconfiguration under test
            with self.assertRaises(CryptoError, msg=oct(mode)) as cm:
                crypto._passphrase()
            self.assertIn("chmod 600", str(cm.exception))
        for mode in (0o600, 0o640, 0o400):
            os.chmod(self.pw_file, mode)
            self.assertEqual(crypto._passphrase(), b"from-file-line-one", oct(mode))

    def test_identity_roundtrip_with_file_passphrase(self):
        keys = self.root / "keys"
        os.environ[crypto.PASSPHRASE_FILE_ENV] = str(self.pw_file)
        ident = Identity.generate("console-000000000001", with_box=True)
        ident.save(keys)
        self.assertTrue(key_file_is_encrypted(keys / "sign.key"))
        self.assertTrue(key_file_is_encrypted(keys / "box.key"))
        self.assertEqual(Identity.load(keys).box_pub_hex, ident.box_pub_hex)
        os.environ.pop(crypto.PASSPHRASE_FILE_ENV)
        with self.assertRaises(CryptoError) as cm:
            Identity.load(keys)
        self.assertIn(crypto.PASSPHRASE_FILE_ENV, str(cm.exception))
        os.environ[crypto.PASSPHRASE_ENV] = "not-the-file-passphrase"
        with self.assertRaises(CryptoError) as cm:
            Identity.load(keys)
        self.assertIn("wrong passphrase", str(cm.exception))

    def test_prompted_once_for_both_console_keys(self):
        keys = self.root / "keys"
        with mock.patch.object(sys, "stdin", _Tty()), mock.patch.object(crypto.getpass, "getpass", return_value="typed-at-init") as g:
            crypto.set_passphrase_prompt(True)
            ident = Identity.generate("console-000000000001", with_box=True)
            ident.save(keys)
            self.assertEqual(g.call_count, 2)  # passphrase and its confirmation, not once per key file
            self.assertTrue(key_file_is_encrypted(keys / "box.key"))
            crypto.set_passphrase_prompt(True)
            g.reset_mock()
            self.assertEqual(Identity.load(keys).sign_pub_hex, ident.sign_pub_hex)
            self.assertEqual(g.call_count, 1)  # asked once, reused for box.key

    def test_unencrypted_key_loads_when_a_passphrase_is_configured_later(self):
        keys = self.root / "keys"
        ident = Identity.generate("agent-000000000001", with_box=False)
        ident.save(keys)
        self.assertFalse(key_file_is_encrypted(keys / "sign.key"))
        os.environ[crypto.PASSPHRASE_ENV] = "configured-afterwards"
        self.assertEqual(Identity.load(keys).sign_pub_hex, ident.sign_pub_hex)


class FingerprintTests(unittest.TestCase):
    def test_known_answer_and_input_formats(self):
        raw = bytes(32)
        self.assertEqual(fingerprint(raw), ZERO_KEY_FINGERPRINT)
        self.assertEqual(fingerprint(bytearray(raw)), ZERO_KEY_FINGERPRINT)
        self.assertEqual(fingerprint(raw.hex()), ZERO_KEY_FINGERPRINT)
        self.assertEqual(fingerprint(raw.hex().upper()), ZERO_KEY_FINGERPRINT)
        self.assertEqual(fingerprint(base64.b64encode(raw).decode()), ZERO_KEY_FINGERPRINT)
        self.assertEqual(fingerprint(base64.urlsafe_b64encode(raw).decode().rstrip("=")), ZERO_KEY_FINGERPRINT)
        self.assertRegex(fingerprint(raw), r"^(?:[0-9a-f]{4} ){15}[0-9a-f]{4}$")
        self.assertEqual(public_key_bytes(raw.hex()), raw)

    def test_identity_keys(self):
        ident = Identity.generate("c", with_box=True)
        fp = ident.fingerprint
        self.assertEqual(fp, fingerprint(ident.sign_pub_hex))
        self.assertEqual(fp, fingerprint(ident.sign_priv))
        self.assertEqual(fp, fingerprint(ident.sign_priv.public_key()))
        self.assertEqual(fp, fingerprint(crypto.ed25519_pub_from_hex(ident.sign_pub_hex)))
        self.assertNotEqual(fp, fingerprint(ident.box_pub_hex))
        self.assertNotEqual(fp, Identity.generate("d", with_box=False).fingerprint)

    def test_bad_inputs(self):
        for bad in ("", "zz", "ab" * 31, bytes(31), bytes(33), 12, None, "not base64 at all!!", b"x" * 64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                fingerprint(bad)

    def test_matching_is_tolerant_but_exact(self):
        fp = ZERO_KEY_FINGERPRINT
        self.assertTrue(fingerprint_matches(fp, fp))
        self.assertTrue(fingerprint_matches(fp.upper(), fp))
        self.assertTrue(fingerprint_matches(fp.replace(" ", ""), fp))
        self.assertTrue(fingerprint_matches(fp.replace(" ", ":"), fp))
        self.assertTrue(fingerprint_matches("  " + fp.replace(" ", " - ") + "\n", fp))
        self.assertTrue(fingerprint_matches("sha256:" + fp, fp))
        self.assertFalse(fingerprint_matches(fp[:-1] + "6", fp))
        self.assertFalse(fingerprint_matches(fp[:39], fp))  # a prefix is not a match
        self.assertFalse(fingerprint_matches(fp + "0", fp))
        self.assertFalse(fingerprint_matches("", fp))
        self.assertFalse(fingerprint_matches(fp, ""))
        self.assertFalse(fingerprint_matches(fp, Identity.generate("x", with_box=False).fingerprint))


if __name__ == "__main__":
    unittest.main()
