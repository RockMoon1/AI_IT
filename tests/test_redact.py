"""Tests for aiit.common.redact.

Secret-shaped strings are assembled by concatenation so neither this file nor
the gitleaks scan ever sees a credential-looking literal.
"""
import json
import unittest
from pathlib import Path

from aiit.common.redact import RedactionConfig, Redactor, SECRET_TOKEN, luhn_ok

KEY = b"k" * 32
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "redaction"
FIXTURE_FILES = [
    "windows_computerinfo.json",
    "macos_spsoftware.json",
    "linux_ps_aux.txt",
    "windows_ipconfig.txt",
]

PEM_BEGIN = "-----BEGIN " + "PRIVATE KEY-----"
PEM_END = "-----END " + "PRIVATE KEY-----"


def _map_contains(r: Redactor, needle: str) -> bool:
    return any(needle in v for v in r.map.values())


class LegacyBehaviourTests(unittest.TestCase):
    """The cases from the original suite, kept so existing behaviour holds."""

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
        pem = PEM_BEGIN + "\nMIIabc\n" + PEM_END
        bearer = "Bearer " + "t" * 24
        text = "password=hun" + "ter2x token: abcd1234" + "efgh Authorization: " + bearer + " key " + aws_like + "\n" + pem
        out = r.redact(text)
        self.assertNotIn("hun" + "ter2x", out)
        self.assertNotIn("abcd1234" + "efgh", out)
        self.assertNotIn(aws_like, out)
        self.assertNotIn("MIIabc", out)
        self.assertNotIn("t" * 24, out)
        self.assertIn(SECRET_TOKEN, out)
        self.assertFalse(_map_contains(r, "hun" + "ter2x"))
        self.assertGreaterEqual(r.stats.counts["SECRET"], 4)
        self.assertEqual(r.map, {})                      # nothing reversible was produced

    def test_extra_literals_and_mrn_dob(self):
        r = Redactor(KEY, RedactionConfig(extra_literals=["Pat Example"]))
        out = r.redact("Patient Pat Example MRN: 00123456 DOB: 1980-02-03 crashed viewer")
        self.assertNotIn("Pat Example", out)
        self.assertIn("<NAME_", out)
        self.assertIn("<MRN_", out)
        self.assertIn("<DOB_", out)
        self.assertNotIn("00123456", out)


class DeterminismTests(unittest.TestCase):
    def test_same_key_same_token_different_key_different_token(self):
        a = Redactor(KEY).redact("alice@example.org")
        b = Redactor(KEY).redact("alice@example.org")
        c = Redactor(b"z" * 32).redact("alice@example.org")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertRegex(a, r"^<EMAIL_[0-9a-f]{8}>$")

    def test_same_user_across_forms_shares_one_token(self):
        r = Redactor(KEY)
        out = r.redact(r"C:\Users\jsmith\x CLINIC\jsmith /home/jsmith https://jsmith@git.example.com")
        tokens = {t for t in out.replace("\\", " ").replace("/", " ").replace("@", " ").split() if t.startswith("<USER_")}
        self.assertEqual(len(tokens), 1, out)
        self.assertNotIn("jsmith", out)

    def test_token_method_records_map_and_stats(self):
        r = Redactor(KEY)
        tok = r.token("HOST", "box")
        self.assertEqual(r.map[tok], "box")
        self.assertEqual(r.stats.counts["HOST"], 1)
        self.assertEqual(r.stats.total(), 1)


class SecretTests(unittest.TestCase):
    def assert_secret(self, text: str, *values: str, keep: tuple = ()):
        r = Redactor(KEY)
        out = r.redact(text)
        for v in values:
            self.assertNotIn(v, out, f"{v!r} survived in {out!r}")
            self.assertFalse(_map_contains(r, v), f"{v!r} leaked into the reversible map")
        for k in keep:
            self.assertIn(k, out, f"{k!r} missing from {out!r}")
        self.assertIn(SECRET_TOKEN, out)
        self.assertGreaterEqual(r.stats.counts.get("SECRET", 0), len(values))
        return out

    def test_env_style_keys_with_underscores(self):
        tok = "abc" + "DEF" + "0123456789" + "xyz"
        self.assert_secret("AIIT_SERVER_TOKEN=" + tok, tok, keep=("AIIT_SERVER_TOKEN=",))
        self.assert_secret('DB_PASSWORD="hun' + 'ter2"', "hun" + "ter2", keep=("DB_PASSWORD=",))
        self.assert_secret("AIIT_KEY_PASSPHRASE: corr" + "ect-horse", "corr" + "ect-horse")
        self.assert_secret("SMTP_PASSWD=" + "p" + "assw0rd", "p" + "assw0rd")
        self.assert_secret("client_secret = " + "s3cr" + "3tvalue", "s3cr" + "3tvalue")
        self.assert_secret("private_key_pem: " + "MIIE" + "vQIBADANBg", "MIIE" + "vQIBADANBg")
        self.assert_secret("credential=" + "cred" + "1234", "cred" + "1234")
        self.assert_secret("basic_auth: " + "user" + ":pw1234", "user" + ":pw1234")

    def test_json_and_xml_and_cli_forms(self):
        self.assert_secret('{"password": "hun' + 'ter2", "user": "x"}', "hun" + "ter2", keep=('"password": "', '"user": "x"'))
        self.assert_secret('{"api_key": "AK' + '-1234-5678"}', "AK" + "-1234-5678")
        self.assert_secret('<add key="ApiKey" value="zz' + 'z-111" />', "zz" + "z-111", keep=('key="ApiKey"',))
        self.assert_secret('<add name="password" value="pw' + '-222" />', "pw" + "-222")
        self.assert_secret("Set-Thing -Password 'Tr0' + 'ub4dor' -User jsmith".replace("' + '", ""), "Tr0" + "ub4dor")
        self.assert_secret("Connect -Passphrase " + "open" + "sesame -Verbose", "open" + "sesame", keep=("-Verbose",))
        self.assert_secret("mysql -u appuser --password " + "Tr0ub" + "4dor -h db", "Tr0ub" + "4dor", keep=("-h db",))
        self.assert_secret("mysql -u appuser --password=" + "Tr0ub" + "4dor appdb", "Tr0ub" + "4dor")
        self.assert_secret("mysql -u root -p'" + "Tr0ub" + "4dor' appdb", "Tr0ub" + "4dor", keep=("appdb",))
        self.assert_secret("mysqldump -u root -p" + "Tr0ub" + "4dor appdb", "Tr0ub" + "4dor")
        # -p followed by a space is a port, pid or path for the usual tools
        out = Redactor(KEY).redact("ssh -p 2222 host; mkdir -p dir; find . -print")
        self.assertEqual(out, "ssh -p 2222 host; mkdir -p dir; find . -print")

    def test_spaced_dash_p_is_a_password_for_other_tools(self):
        pw = "MyDb" + "Pass"
        self.assert_secret("-p " + pw, pw)
        self.assert_secret("someclient -p " + pw + " --host x", pw, keep=("--host x",))
        self.assert_secret("sshpass -p " + pw + " ssh bob@h", pw, keep=("ssh",))
        self.assert_secret("mongosh -u bob -p " + pw + " --host h", pw, keep=("-u bob",))
        self.assert_secret("psexec \\\\h -u bob -p " + pw + " cmd", pw)
        self.assert_secret("certutil -p " + pw + " -importpfx x.pfx", pw)
        self.assert_secret("useradd -p '" + pw + "' bob", pw, keep=("bob",))
        for untouched in [
            "mkdir -p /var/log/app", "mkdir -p buildcache", "docker run -p 8080:80 nginx", "ps -p 1234",
            "ls -p /var/log", "cp -p a b", "tar -p -xf x.tgz", "grep -P 'x+' file", "wget -P downloads http://x",
            "scp -P 2222 a b:", "mysql -u root -P 3306 -h db",
        ]:
            self.assertEqual(Redactor(KEY).redact(untouched), untouched)

    def test_tool_specific_credential_flags(self):
        pw = "S3cr" + "et!x"
        self.assert_secret("sqlcmd -S srv -U sa -P " + pw + " -Q 'select 1'", pw, keep=("-U sa",))
        self.assert_secret("cmdkey /add:srv /user:bob /pass:" + pw, pw, keep=("/user:bob",))
        self.assert_secret("net use Z: \\\\srv\\share " + pw + " /user:dom\\bob", pw, keep=("/user:dom",))
        self.assert_secret("net use \\\\srv\\share /user:dom\\bob " + pw, pw, keep=("/user:dom",))
        self.assert_secret("curl -u admin:" + pw + " https://x", pw, keep=("admin:",))
        self.assert_secret("redis-cli -a " + pw + " ping", pw, keep=("ping",))
        self.assert_secret("smbclient //srv/share -U bob%" + pw, pw, keep=("bob%",))
        self.assert_secret("openssl pkcs12 -export -passout pass:" + pw + " -out x.p12", pw, keep=("-out x.p12",))
        self.assert_secret("schtasks /create /tn x /ru bob /rp " + pw + " /tr x.exe", pw, keep=("/ru bob",))
        self.assert_secret("ldapsearch -D cn=admin -w " + pw + " -b dc=x", pw, keep=("-b dc=x",))

    def test_kv_false_positives_are_limited(self):
        r = Redactor(KEY)
        out = r.redact('PWD=/opt/app author=someone "password": null tokens=12')
        self.assertIn("PWD=/opt/app", out)
        self.assertIn("author=someone", out)
        self.assertIn('"password": null', out)
        self.assertIn("tokens=12", out)
        self.assertNotIn(SECRET_TOKEN, out)

    def test_url_userinfo_is_irreversible_and_runs_before_email(self):
        r = Redactor(KEY)
        url = "postgres://admin:hun" + "ter22@db.example.net:5432/clinic"
        out = r.redact("dsn " + url)
        self.assertEqual(out, "dsn postgres://" + SECRET_TOKEN + "@db.example.net:5432/clinic")
        self.assertNotIn("hun" + "ter22", out)
        self.assertNotIn("<EMAIL_", out)
        self.assertFalse(_map_contains(r, "hun" + "ter22"))
        self.assertFalse(_map_contains(r, "admin"))
        self.assertEqual(r.stats.counts["SECRET"], 1)
        # a bare user in a URL is an identifier, not a secret
        r2 = Redactor(KEY)
        out2 = r2.redact("git clone https://jsmith@git.example.com/repo.git")
        self.assertIn("https://<USER_", out2)
        self.assertNotIn("jsmith", out2)
        self.assertIn("jsmith", r2.map.values())

    def test_authorization_headers_and_jwt(self):
        basic = "QWxh" + "ZGRpbjpvcGVuIHNlc2FtZQ=="
        self.assert_secret("Authorization: Basic " + basic, basic, keep=("Authorization: Basic ",))
        self.assert_secret("Proxy-Authorization: " + "abcdef" + "ghijkl", "abcdef" + "ghijkl")
        jwt = "eyJ" + "hbGciOiJub25lIn0" + "." + "eyJzdWIiOiJ4In0" + "." + "ZmFrZS1zaWc"
        self.assert_secret("token " + jwt + " end", jwt, keep=("token ", " end"))
        self.assert_secret("Authorization: Bearer " + jwt, jwt)
        out = Redactor(KEY).redact("Authorization: Bearer " + jwt)
        self.assertEqual(out.count(SECRET_TOKEN), 1)

    def test_vendor_token_shapes(self):
        self.assert_secret("k=" + "sk-proj-" + "A" * 30, "sk-proj-" + "A" * 30)
        self.assert_secret("k=" + "sk-svcacct-" + "B" * 30, "sk-svcacct-" + "B" * 30)
        self.assert_secret("k=" + "sk-admin-" + "C" * 30, "sk-admin-" + "C" * 30)
        self.assert_secret("k=" + "sk-ant-" + "D" * 30, "sk-ant-" + "D" * 30)
        hex32 = "0123456789abcdef" * 2
        self.assert_secret("api-key " + hex32, hex32)
        self.assert_secret("Ocp-Apim-Subscription-Key: " + hex32, hex32)
        self.assert_secret("slack " + "xoxb-" + "1234567890-abcdefghij", "xoxb-" + "1234567890-abcdefghij")
        self.assert_secret("slack " + "xapp-1-" + "A1B2C3D4E5-abcdef", "xapp-1-" + "A1B2C3D4E5-abcdef")
        discord = "M" + "A" * 24 + "." + "B" * 6 + "." + "C" * 28
        self.assert_secret("discord " + discord, discord)
        telegram = "123456789" + ":" + "A" * 35
        self.assert_secret("telegram " + telegram, telegram)
        aws_secret = "wJal" + "r" * 36
        self.assert_secret("aws_secret_access_key = " + aws_secret, aws_secret, keep=("aws_secret_access_key =",))
        self.assert_secret("AWS_SECRET_ACCESS_KEY " + aws_secret, aws_secret)
        self.assert_secret("AWS_ACCESS_KEY_ID=" + "AKIA" + "EXAMPLE" + "000000000", "AKIA" + "EXAMPLE" + "000000000")
        self.assert_secret("gh " + "ghp_" + "x" * 36, "ghp_" + "x" * 36)
        self.assert_secret("gh " + "github_pat_" + "y" * 30, "github_pat_" + "y" * 30)

    def test_pem_block_multiline(self):
        pem = PEM_BEGIN + "\nMIIEvQIBADANBg\nkqhkiG9w0BAQEF\n" + PEM_END
        out = self.assert_secret("before\n" + pem + "\nafter", "MIIEvQIBADANBg", keep=("before", "after"))
        self.assertNotIn("kqhkiG9w0BAQEF", out)
        self.assertEqual(out.count(SECRET_TOKEN), 1)      # one block, one replacement

    def test_secret_count_is_not_double_bumped(self):
        r = Redactor(KEY)
        r.redact("password=" + "hun" + "ter2x")
        self.assertEqual(r.stats.counts["SECRET"], 1)


class IPv6Tests(unittest.TestCase):
    TEXT = ("global 2600:1f18:1234:5678::9 ula fd12:3456:789a::1 lo ::1 ll fe80::1%12 "
            "doc 2001:db8::1 bracket [2600:1f18::2]:443 mac 00:1A:2B:3C:4D:5E time 10:30:45 c: drive")

    def test_default_policy_matches_ipv4(self):
        r = Redactor(KEY)
        out = r.redact(self.TEXT)
        self.assertNotIn("2600:1f18:1234:5678::9", out)
        self.assertNotIn("2600:1f18::2", out)
        self.assertIn("[<IP_", out)
        self.assertIn("fd12:3456:789a::1", out)         # ULA is private: kept by default
        self.assertIn("::1 ", out)
        self.assertIn("fe80::1%12", out)
        self.assertIn("10:30:45", out)
        self.assertIn("c: drive", out)
        self.assertEqual(r.stats.counts["IP"], 2)
        self.assertEqual(r.stats.counts["MAC"], 1)

    def test_private_policy_and_opt_out(self):
        out = Redactor(KEY, RedactionConfig(redact_private_ips=True)).redact(self.TEXT)
        self.assertNotIn("fd12:3456:789a::1", out)
        self.assertIn("::1 ", out)
        self.assertIn("fe80::1%12", out)
        out2 = Redactor(KEY, RedactionConfig(redact_ipv6=False)).redact(self.TEXT)
        self.assertIn("2600:1f18:1234:5678::9", out2)
        out3 = Redactor(KEY, RedactionConfig(redact_public_ips=False)).redact(self.TEXT)
        self.assertIn("2600:1f18:1234:5678::9", out3)

    def test_ipconfig_style_scope_and_suffix(self):
        out = Redactor(KEY).redact("IPv6 Address. . . : 2600:1f18:1234:5678:a1b2:c3d4:e5f6:7890(Preferred)")
        self.assertRegex(out, r": <IP_[0-9a-f]{8}>\(Preferred\)$")


class WindowsIdentifierTests(unittest.TestCase):
    def test_json_escaped_user_paths(self):
        r = Redactor(KEY)
        text = r'"C:\\Users\\jsmith\\AppData\\Local" "C:\Users\jsmith\Desktop" "C:/Users/jsmith/x" "C:\\Users\\Public\\x"'
        out = r.redact(text)
        self.assertNotIn("jsmith", out)
        self.assertIn(r"C:\\Users\\<USER_", out)
        self.assertIn(r"C:\Users\<USER_", out)
        self.assertIn("C:/Users/<USER_", out)
        self.assertIn(r"\\AppData\\Local", out)
        self.assertIn(r"C:\\Users\\Public\\x", out)
        self.assertEqual(r.stats.counts["USER"], 3)
        self.assertEqual(len({t for t in r.map if t.startswith("<USER_")}), 1)

    def test_domain_user_gating(self):
        r = Redactor(KEY)
        text = (r"CLINIC\jsmith CLINIC\\jsmith clinic\jsmith NT AUTHORITY\SYSTEM BUILTIN\Administrators "
                r"NT SERVICE\MSSQLSERVER CLINIC\Administrator CLINIC\Guest NT AUTHORITY\LOCAL SERVICE "
                r"C:\Windows\System32\drivers HKLM\SOFTWARE")
        out = r.redact(text)
        self.assertNotIn("jsmith", out)
        self.assertIn(r"CLINIC\<USER_", out)
        self.assertIn(r"CLINIC\\<USER_", out)
        self.assertIn(r"clinic\<USER_", out)
        self.assertIn(r"NT AUTHORITY\SYSTEM", out)
        self.assertIn(r"BUILTIN\Administrators", out)
        self.assertIn(r"NT SERVICE\MSSQLSERVER", out)
        self.assertIn(r"CLINIC\Administrator", out)
        self.assertIn(r"CLINIC\Guest", out)
        self.assertIn(r"NT AUTHORITY\LOCAL SERVICE", out)
        self.assertIn(r"C:\Windows\System32\drivers", out)
        self.assertIn(r"HKLM\SOFTWARE", out)
        self.assertEqual(r.stats.counts["USER"], 3)
        # JSON escape sequences in ordinary strings are not domain users
        self.assertEqual(Redactor(KEY).redact(r'"line one\nline two\tend"'), r'"line one\nline two\tend"')
        # opt-out
        out2 = Redactor(KEY, RedactionConfig(redact_domain_users=False)).redact(r"CLINIC\jsmith")
        self.assertEqual(out2, r"CLINIC\jsmith")

    def test_sids(self):
        r = Redactor(KEY)
        text = "user S-1-5-21-3623811015-3361044348-30300820-1013 domain S-1-5-21-3623811015-3361044348-30300820 admins S-1-5-32-544 system S-1-5-18 ls S-1-5-19 ns S-1-5-20 aad S-1-12-1-1234567890-1234567890-1234567890-1234567890"
        out = r.redact(text)
        self.assertNotIn("S-1-5-21-", out)
        self.assertNotIn("S-1-12-1-", out)
        self.assertIn("S-1-5-32-544", out)
        self.assertIn("S-1-5-18", out)
        self.assertIn("S-1-5-19", out)
        self.assertIn("S-1-5-20", out)
        self.assertEqual(r.stats.counts["SID"], 3)
        self.assertNotIn("PHONE", r.stats.counts)
        self.assertNotIn("CARD", r.stats.counts)
        out2 = Redactor(KEY, RedactionConfig(redact_sids=False)).redact(text)
        self.assertIn("S-1-5-21-3623811015-3361044348-30300820-1013", out2)

    def test_unc_paths(self):
        r = Redactor(KEY)
        text = r'\\clinic-fs-01\shares\radiology "\\\\CLINIC-DC-01" "\\\\clinic-fs-01\\home" \\localhost\c$ \\127.0.0.1\x \\?\C:\x C:\\Users\\jsmith\\AppData'
        out = r.redact(text)
        self.assertNotIn("clinic-fs-01", out.lower())
        self.assertNotIn("clinic-dc-01", out.lower())
        self.assertIn(r"\\<HOST_", out)
        self.assertIn(r"\\\\<HOST_", out)
        self.assertIn(r"\shares\radiology", out)
        self.assertIn(r"\\localhost\c$", out)
        self.assertIn(r"\\127.0.0.1\x", out)
        self.assertIn(r"\\?\C:\x", out)
        self.assertIn(r"\\AppData", out)                 # a tokened user path is not a UNC server
        self.assertEqual(r.stats.counts["HOST"], 3)      # clinic-fs-01 twice (same token), CLINIC-DC-01 once
        self.assertEqual(len({t for t in r.map if t.startswith("<HOST_")}), 2)
        out2 = Redactor(KEY, RedactionConfig(redact_unc=False)).redact(r"\\clinic-fs-01\share")
        self.assertEqual(out2, r"\\clinic-fs-01\share")


class LabelledValueTests(unittest.TestCase):
    def test_serials_uuids_and_ids_only_when_labelled(self):
        r = Redactor(KEY)
        text = json.dumps({
            "BiosSeralNumber": "7XY2ZQ3",
            "OsSerialNumber": "00330-80000-00000-AAOEM",
            "WindowsProductId": "00330-80000-00000-AA123",
            "serial_number": "C02ZX1ABCD12",
            "platform_UUID": "6F1A2B3C-4D5E-6F70-8192-A3B4C5D6E7F8",
            "provisioning_UDID": "00008112-000A1B2C3D4E5F67",
            "IOPlatformUUID": "11111111-2222-3333-4444-555555555555",
            "machine_id": "9f8e7d6c5b4a39281716151413121110",
            "other_guid": "2A1B3C4D-5E6F-7081-92A3-B4C5D6E7F8A9",
            "ProductName": "Windows 10 Pro",
        })
        out = r.redact(text)
        for planted in ("7XY2ZQ3", "00330-80000-00000-AAOEM", "00330-80000-00000-AA123", "C02ZX1ABCD12",
                        "6F1A2B3C-4D5E-6F70-8192-A3B4C5D6E7F8", "00008112-000A1B2C3D4E5F67",
                        "11111111-2222-3333-4444-555555555555", "9f8e7d6c5b4a39281716151413121110"):
            self.assertNotIn(planted, out, planted)
        self.assertIn("2A1B3C4D-5E6F-7081-92A3-B4C5D6E7F8A9", out)   # unlabelled GUIDs are left alone
        self.assertIn("Windows 10 Pro", out)
        self.assertEqual(r.stats.counts["SERIAL"], 4)
        self.assertEqual(r.stats.counts["UUID"], 4)
        json.loads(out)                                   # output is still valid JSON
        out2 = Redactor(KEY, RedactionConfig(redact_serials=False)).redact(text)
        self.assertIn("7XY2ZQ3", out2)
        self.assertIn("6F1A2B3C-4D5E-6F70-8192-A3B4C5D6E7F8", out2)

    def test_text_layouts(self):
        r = Redactor(KEY)
        text = ("Serial Number (system): C02ZX1ABCD12\n"
                "Hardware UUID: 6F1A2B3C-4D5E-6F70-8192-A3B4C5D6E7F8\n"
                "Volume Serial Number is 1234-ABCD\n"
                "Registered Owner: Jane Smith\n"
                "Registered Organization: Example Clinic\n"
                "Computer Name: Janes-MacBook-Pro\n"
                "Host Name . . . . . . . . . . . . : CLINIC-PC-07\n"
                "Primary Dns Suffix  . . . . . . . : clinic.local\n"
                "Connection-specific DNS Suffix  . :\n"
                "Description . . . . . . . . . . . : Intel(R) Ethernet\n"
                "Model Name: MacBook Air\n")
        out = r.redact(text)
        for planted in ("C02ZX1ABCD12", "6F1A2B3C", "1234-ABCD", "Jane Smith", "Example Clinic",
                        "Janes-MacBook-Pro", "CLINIC-PC-07", "clinic.local"):
            self.assertNotIn(planted, out, planted)
        self.assertIn("Intel(R) Ethernet", out)
        self.assertIn("MacBook Air", out)
        self.assertIn("Connection-specific DNS Suffix  . :\n", out)
        self.assertIn("<ORG_", out)
        self.assertIn("<NAME_", out)

    def test_user_name_with_account_and_propagation(self):
        r = Redactor(KEY)
        text = ('{"user_name": "Jane Smith (jsmith)", "CsUserName": "CLINIC\\\\jsmith", "CsName": "CLINIC-PC-07", '
                '"note": "Jane Smith logged on at clinic-pc-07 as jsmith"}')
        out = r.redact(text)
        self.assertNotIn("Jane Smith", out)
        self.assertNotIn("jsmith", out)
        self.assertNotIn("clinic-pc-07", out.lower())
        self.assertIn("<NAME_", out)
        self.assertIn("(<USER_", out)
        self.assertEqual(len({t for t in r.map if t.startswith("<USER_")}), 1)
        self.assertEqual(len({t for t in r.map if t.startswith("<HOST_")}), 1)
        json.loads(out)

    def test_boolean_and_empty_values_are_not_tokened(self):
        out = Redactor(KEY).redact('{"CsPartOfDomain": true, "CsDomain": "WORKGROUP", "hostname": "", "logged_in_users": []}')
        self.assertIn('"CsPartOfDomain": true', out)
        self.assertIn('"CsDomain": "WORKGROUP"', out)
        self.assertNotIn("<HOST_", out)
        self.assertNotIn("<USER_", out)


class HostnameTests(unittest.TestCase):
    def test_word_boundaries_and_case(self):
        r = Redactor(KEY, RedactionConfig(redact_hostnames=["lab", "CLINIC-PC-07"]))
        out = r.redact("label lab labs lab.example.com LAB on clinic-pc-07 and clinic-pc-071 and xclinic-pc-07")
        self.assertIn("label", out)
        self.assertIn("labs", out)
        self.assertIn("clinic-pc-071", out)
        self.assertIn("xclinic-pc-07", out)
        self.assertNotIn(" lab ", out)
        self.assertNotIn("lab.example.com", out)
        self.assertNotIn("LAB", out)
        self.assertNotIn(" clinic-pc-07 ", out)
        self.assertEqual(r.stats.counts["HOST"], 4)
        self.assertEqual(len({t for t in r.map if t.startswith("<HOST_")}), 2)  # case-insensitive, one token each

    def test_short_hostnames_are_ignored(self):
        out = Redactor(KEY, RedactionConfig(redact_hostnames=["pc", ""])).redact("pc on the pc")
        self.assertEqual(out, "pc on the pc")


class ConfigTests(unittest.TestCase):
    def test_to_dict_from_dict_round_trip(self):
        cfg = RedactionConfig(redact_private_ips=True, redact_mac=False, redact_hostnames=["a-host", "b.local"],
                              extra_literals=["Pat Example"], redact_ipv6=False, redact_domain_users=False,
                              redact_sids=False, redact_unc=False, redact_serials=False)
        d = cfg.to_dict()
        self.assertEqual(json.loads(json.dumps(d)), d)
        self.assertEqual(RedactionConfig.from_dict(d), cfg)
        self.assertIsNot(RedactionConfig.from_dict(d).redact_hostnames, cfg.redact_hostnames)
        for key in ("redact_public_ips", "redact_private_ips", "redact_mac", "redact_hostnames", "extra_literals",
                    "redact_ipv6", "redact_domain_users", "redact_sids", "redact_unc", "redact_serials"):
            self.assertIn(key, d)

    def test_from_dict_is_tolerant(self):
        self.assertEqual(RedactionConfig.from_dict(None), RedactionConfig())
        self.assertEqual(RedactionConfig.from_dict({}), RedactionConfig())
        cfg = RedactionConfig.from_dict({"unknown": 1, "redact_hostnames": "single", "extra_literals": None, "redact_mac": 0})
        self.assertEqual(cfg.redact_hostnames, ["single"])
        self.assertEqual(cfg.extra_literals, [])
        self.assertFalse(cfg.redact_mac)
        self.assertTrue(cfg.redact_ipv6)

    def test_defaults(self):
        cfg = RedactionConfig()
        self.assertTrue(cfg.redact_ipv6 and cfg.redact_domain_users and cfg.redact_sids and cfg.redact_unc and cfg.redact_serials)
        self.assertTrue(cfg.redact_public_ips and cfg.redact_mac)
        self.assertFalse(cfg.redact_private_ips)


class GoldenFixtureTests(unittest.TestCase):
    """Each fixture is real-shaped collector output with planted values; the
    sidecar lists what must disappear and what must stay."""

    def _run(self, name: str):
        text = (FIXTURES / name).read_text(encoding="utf-8")
        side = json.loads((FIXTURES / (name.rsplit(".", 1)[0] + ".planted.json")).read_text(encoding="utf-8"))
        self.assertTrue(side["must_not_survive"], "fixture plants nothing")
        self.assertTrue(side["must_survive"], "fixture keeps nothing")
        r = Redactor(KEY, RedactionConfig.from_dict(side.get("config")))
        out = r.redact(text)
        return side, r, out

    def test_fixture_files_exist(self):
        for name in FIXTURE_FILES:
            self.assertTrue((FIXTURES / name).is_file(), name)
            self.assertTrue((FIXTURES / (name.rsplit(".", 1)[0] + ".planted.json")).is_file(), name)

    def test_golden(self):
        for name in FIXTURE_FILES:
            with self.subTest(fixture=name):
                side, r, out = self._run(name)
                low = out.lower()
                survived = [v for v in side["must_not_survive"] if v.lower() in low]
                self.assertEqual(survived, [], f"{name}: planted values survived")
                missing = [v for v in side["must_survive"] if v not in out]
                self.assertEqual(missing, [], f"{name}: benign values were damaged")
                leaked = [v for v in side.get("secrets", []) if _map_contains(r, v)]
                self.assertEqual(leaked, [], f"{name}: secrets leaked into the reversible map")
                self.assertGreater(r.stats.total(), 0)

    def test_json_fixtures_stay_valid_json(self):
        for name in FIXTURE_FILES:
            if not name.endswith(".json"):
                continue
            with self.subTest(fixture=name):
                _, _, out = self._run(name)
                json.loads(out)

    def test_fixtures_are_deterministic(self):
        for name in FIXTURE_FILES:
            with self.subTest(fixture=name):
                _, _, a = self._run(name)
                _, _, b = self._run(name)
                self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
