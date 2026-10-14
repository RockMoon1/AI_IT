"""LAN mailbox: authentication, limits, error mapping, TLS and idempotency."""
import http.client
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
import urllib.error
import urllib.request
from pathlib import Path

from . import helpers
from aiit.console import server as server_mod
from aiit.console.server import make_server

TOKEN = "unit-test-token-0123456789abcdef"


def _selfsigned(dirpath: Path):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = dirpath / "cert.pem", dirpath / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class ServerBase(unittest.TestCase):
    tls = False

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = helpers.make_console(self.root / "console")
        self.agent = helpers.agent_identity()
        if self.tls:
            cert, key = _selfsigned(self.root)
            self.srv = make_server(self.state, "127.0.0.1", 0, TOKEN, str(cert), str(key))
            self.ctx = ssl.create_default_context(cafile=str(cert))
            self.scheme = "https"
        else:
            self.srv = make_server(self.state, "127.0.0.1", 0, TOKEN)
            self.ctx = None
            self.scheme = "http"
        self.port = self.srv.server_address[1]
        self.url = f"{self.scheme}://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def request(self, method, path, body=None, token=TOKEN, headers=None):
        req = urllib.request.Request(self.url + path, data=body, method=method, headers=headers or {})
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=10, context=self.ctx) as resp:
                return resp.status, json.loads(resp.read() or b"null"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null"), dict(e.headers)


class PlainServerTests(ServerBase):
    def test_health_and_404(self):
        status, body, _ = self.request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.request("GET", "/nope")[0], 404)
        self.assertEqual(self.request("POST", "/nope", b"x")[0], 404)

    def test_auth_failures_and_backoff(self):
        self.assertEqual(self.request("GET", "/v1/health", token=None)[0], 401)
        for _ in range(server_mod.AUTH_FAIL_LIMIT - 1):
            self.assertEqual(self.request("GET", "/v1/health", token="wrong-token-wrong-token")[0], 401)
        status, _, hdrs = self.request("GET", "/v1/health", token=TOKEN)
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", hdrs)
        self.assertLessEqual(sum(1 for e in self.state.audit.entries() if e["action"] == "serve_auth_fail"), 3)

    def test_bad_content_lengths(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/v1/bundles")
        conn.putheader("Authorization", f"Bearer {TOKEN}")
        conn.putheader("Content-Length", "abc")
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 400)
        conn.close()
        status, _, _ = self.request("POST", "/v1/bundles", b"")
        self.assertEqual(status, 400)
        with mock.patch.object(server_mod, "MAX_BODY", 10):
            status, body, _ = self.request("POST", "/v1/bundles", b"x" * 11)
        self.assertEqual(status, 413)

    def test_garbage_body_is_422_and_audited(self):
        status, body, _ = self.request("POST", "/v1/bundles", b"not a bundle at all")
        self.assertEqual(status, 422)
        self.assertEqual(self.state.audit.entries()[-1]["action"], "serve_ingest_error")
        self.assertEqual(list(self.state.inbox.glob("*.aiit")), [])

    def test_bundle_upload_is_idempotent(self):
        p = helpers.seal_diagnostics(self.state, self.agent, self.root / "d.aiit")
        s1, b1, _ = self.request("POST", "/v1/bundles", p.read_bytes())
        s2, b2, _ = self.request("POST", "/v1/bundles", p.read_bytes())
        self.assertEqual((s1, s2), (200, 200))
        self.assertEqual(b1["case_id"], b2["case_id"])
        self.assertEqual(len(self.state.list_cases()), 1)

    def test_plans_requires_valid_agent_id(self):
        self.assertEqual(self.request("GET", "/v1/plans")[0], 400)
        self.assertEqual(self.request("GET", "/v1/plans?agent_id=../x")[0], 400)
        status, body, _ = self.request("GET", f"/v1/plans?agent_id={self.agent.id}")
        self.assertEqual((status, body), (200, []))

    def test_slow_client_does_not_block_others(self):
        slow = socket.create_connection(("127.0.0.1", self.port))
        slow.sendall(b"POST /v1/bundles HTTP/1.1\r\nHost: x\r\n")  # never finishes the headers
        t0 = time.time()
        status, _, _ = self.request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertLess(time.time() - t0, 5)
        slow.close()

    def test_storage_errors_map_to_503(self):
        p = helpers.seal_diagnostics(self.state, self.agent, self.root / "d.aiit")
        with mock.patch.object(type(self.state), "ingest_bundle", side_effect=OSError(28, "No space left on device")):
            status, body, _ = self.request("POST", "/v1/bundles", p.read_bytes())
        self.assertEqual(status, 503)  # retryable for the agent, unlike 500
        self.assertIn("storage", body["error"])
        self.assertNotIn("No space left", json.dumps(body))  # the OS detail goes to the audit log, not the wire
        last = self.state.audit.entries()[-1]
        self.assertEqual(last["action"], "serve_ingest_error")
        self.assertIn("OSError", last["details"]["error"])
        self.assertEqual(list(self.state.inbox.glob("*.aiit")), [])
        self.assertEqual(self.request("POST", "/v1/bundles", p.read_bytes())[0], 200)  # same bundle once the disk is back

    def test_incomplete_upload_is_400_and_leaves_no_temp_file(self):
        conn = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        head = f"POST /v1/bundles HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 100000\r\n\r\n"
        conn.sendall(head.encode("ascii") + b"x" * 10)
        conn.shutdown(socket.SHUT_WR)  # the client goes away after 10 of the promised 100000 bytes
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        conn.close()
        self.assertRegex(data.split(b"\r\n", 1)[0].decode("ascii", "replace"), r"^HTTP/1\.[01] 400 ")
        self.assertIn(b"incomplete upload", data)
        self.assertEqual(sorted(self.state.inbox.glob("in-*")), [])
        self.assertEqual(sorted(self.state.inbox.glob("*.aiit")), [])
        self.assertEqual(self.request("GET", "/v1/health")[0], 200)

    def test_bounded_concurrency_refuses_instead_of_queueing(self):
        srv = make_server(self.state, "127.0.0.1", 0, TOKEN, max_concurrent=1)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        hog = socket.create_connection(("127.0.0.1", port))  # holds the only slot; it never sends a request line
        try:
            time.sleep(0.3)
            req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/health", headers={"Authorization": f"Bearer {TOKEN}"})
            t0 = time.time()
            with self.assertRaises((urllib.error.URLError, http.client.HTTPException, OSError)):
                urllib.request.urlopen(req, timeout=25)  # closed without a response once the 5 s slot wait expires
            self.assertLess(time.time() - t0, 20)
            hog.close()  # frees the slot; the next request is served normally
            deadline = time.time() + 10
            status = None
            while time.time() < deadline:
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        status = resp.status
                    break
                except (urllib.error.URLError, http.client.HTTPException, OSError):
                    time.sleep(0.2)
            self.assertEqual(status, 200)
        finally:
            hog.close()
            srv.shutdown()
            srv.server_close()


class TlsServerTests(ServerBase):
    tls = True

    def test_health_over_tls(self):
        status, body, _ = self.request("GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_plain_http_to_tls_port_fails_fast(self):
        t0 = time.time()
        with self.assertRaises(Exception):
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/v1/health", timeout=5)
        self.assertLess(time.time() - t0, 15)
        self.assertEqual(self.request("GET", "/v1/health")[0], 200)


class MakeServerTests(unittest.TestCase):
    def test_token_and_bind_rules(self):
        with tempfile.TemporaryDirectory() as d:
            st = helpers.make_console(Path(d))
            with self.assertRaises(ValueError):
                make_server(st, "127.0.0.1", 0, "short")
            with self.assertRaises(ValueError):
                make_server(st, "0.0.0.0", 0, TOKEN)
            with self.assertRaises(ValueError):
                make_server(st, "127.0.0.1", 0, TOKEN, tls_cert="only-cert")
            srv = make_server(st, "0.0.0.0", 0, TOKEN, insecure_no_tls=True)
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
