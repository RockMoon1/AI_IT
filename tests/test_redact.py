import unittest

from . import helpers  # noqa: F401
from aiit.common.redact import RedactionConfig, Redactor, luhn_ok

KEY = b"k" * 32


class RedactTests(unittest.TestCase):
    def test_email_tokens_are_consistent_and_mapped(self):
        r = Redactor(KEY)
        text = "mail from alice@example.org and again alice@example.org, cc bob@example.org"
        out = r.redact(text)
        self.assertNotIn("alice@example.org", out)
        self.assertEqual(out.count("<EMAIL_"), 3)
        tokens = [t for t in out.split() if t.startswith("<EMAIL_")]
        self.assertEqual(tokens[0].rstrip(","), tokens[1].rstrip(","))
        self.assertEqual(r.stats.counts["EMAIL"], 3)
        self.assertIn("alice@example.org", r.map.values())
        # same key -> same token; different key -> different token
        self.assertEqual(Redactor(KEY).redact("alice@example.org"), Redactor(KEY).redact("alice@example.org"))
        self.assertNotEqual(Redactor(KEY).redact("alice@example.org"), Redactor(b"z" * 32).redact("alice@example.org"))

    def test_user_paths_and_hostnames(self):
        r = Redactor(KEY, RedactionConfig(redact_hostnames=["CLINIC-LAPTOP-07"]))
        text = r"C:\Users\jdoe\AppData and C:\Users\Public\x and /home/jdoe/.config on clinic-laptop-07"
        out = r.redact(text)
        self.assertNotIn("jdoe", out)
        self.assertIn(r"C:\Users\Public", out)           # built-in profile names are kept
        self.assertNotIn("clinic-laptop-07", out.lower())
        self.assertIn("<HOST_", out)
        self.assertEqual(out.count("<USER_"), 2)

    def test_ip_policy(self):
        text = "gw 192.168.1.1 lo 127.0.0.1 ext 11.22.33.44 link 169.254.3.4"
        out = Redactor(KEY).redact(text)
        self.assertIn("192.168.1.1", out)                # private kept by default
        self.assertIn("127.0.0.1", out)
        self.assertIn("169.254.3.4", out)
        self.assertNotIn("11.22.33.44", out)             # public redacted
        out2 = Redactor(KEY, RedactionConfig(redact_private_ips=True)).redact(text)
        self.assertNotIn("192.168.1.1", out2)
        self.assertIn("127.0.0.1", out2)

    def test_mac_phone_ssn_card(self):
        r = Redactor(KEY)
        text = "mac 00:1A:2B:3C:4D:5E tel (555) 010-2345 ssn 123-45-6789 card 4111 1111 1111 1111 notcard 1234 5678 9012 3456"
        out = r.redact(text)
        self.assertIn("<MAC_", out)
        self.assertIn("<PHONE_", out)
        self.assertIn("<SSN_", out)
        self.assertIn("<CARD_", out)
        self.assertIn("1234 5678 9012 3456", out)        # fails Luhn, so it stays
        self.assertTrue(luhn_ok("4111111111111111"))
        self.assertFalse(luhn_ok("1234567890123456"))

    def test_secrets_are_irreversible(self):
        r = Redactor(KEY)
        aws_like = "AKIA" + "Q" * 16
        pem = "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"
        text = f"password=hunter2x token: abcd1234efgh Authorization: Bearer {'t' * 24} key {aws_like}\n{pem}"
        out = r.redact(text)
        self.assertNotIn("hunter2x", out)
        self.assertNotIn("abcd1234efgh", out)
        self.assertNotIn(aws_like, out)
        self.assertNotIn("MIIabc", out)
        self.assertIn("<SECRET_REDACTED>", out)
        self.assertFalse(any("hunter2x" in v for v in r.map.values()))
        self.assertGreaterEqual(r.stats.counts["SECRET"], 4)

    def test_extra_literals_and_mrn_dob(self):
        r = Redactor(KEY, RedactionConfig(extra_literals=["Pat Example"]))
        out = r.redact("Patient Pat Example MRN: 00123456 DOB: 1980-02-03 crashed viewer")
        self.assertNotIn("Pat Example", out)
        self.assertIn("<NAME_", out)
        self.assertIn("<MRN_", out)
        self.assertIn("<DOB_", out)
        self.assertNotIn("00123456", out)


if __name__ == "__main__":
    unittest.main()
