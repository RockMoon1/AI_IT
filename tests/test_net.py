import os
import unittest
import unittest.mock as mock
import urllib.error
import urllib.request

from . import helpers
from aiit.common import net
from aiit.common.net import RETRY_AFTER_MAX, HttpStatusError, NetError, http_json, is_loopback_or_private


class HttpJsonTests(unittest.TestCase):
    def setUp(self):
        self.srv = helpers.FakeHTTP().start()
        self.sleeps: list[float] = []
        self.sleep = self.sleeps.append

    def tearDown(self):
        self.srv.stop()

    def test_retries_503_then_succeeds(self):
        self.srv.queue(503, "down").queue(200, {"ok": 1})
        out = http_json("GET", self.srv.url + "/x", retries=3, sleep=self.sleep)
        self.assertEqual(out, {"ok": 1})
        self.assertEqual(len(self.sleeps), 1)
        self.assertEqual(len(self.srv.requests), 2)

    def test_honours_retry_after(self):
        self.srv.queue(429, {"err": "slow"}, headers={"Retry-After": "0"}).queue(200, {"ok": 2})
        self.assertEqual(http_json("GET", self.srv.url, retries=2, sleep=self.sleep)["ok"], 2)
        self.assertEqual(self.sleeps, [0.0])
        # a window longer than max_backoff is waited out as asked, not clipped to max_backoff
        self.srv.queue(429, {"err": "slow"}, headers={"Retry-After": "60"}).queue(200, {"ok": 3})
        self.assertEqual(http_json("GET", self.srv.url, retries=2, max_backoff=8.0, sleep=self.sleep)["ok"], 3)
        self.assertEqual(self.sleeps, [0.0, 60.0])

    def test_retry_after_above_ceiling_fails_at_once(self):
        self.srv.queue(429, {"err": "go away"}, headers={"Retry-After": "600"}).queue(200, {"ok": 1})
        with self.assertRaises(HttpStatusError) as cm:
            http_json("GET", self.srv.url, retries=3, sleep=self.sleep)
        self.assertEqual(cm.exception.status, 429)
        self.assertIn("Retry-After 600s", str(cm.exception))
        self.assertIn(f"exceeds {int(RETRY_AFTER_MAX)}s", str(cm.exception))
        self.assertEqual(self.sleeps, [])
        self.assertEqual(len(self.srv.requests), 1)
        # exactly the ceiling is still honoured
        self.srv.replies.clear()
        self.srv.queue(503, "busy", headers={"Retry-After": str(int(RETRY_AFTER_MAX))}).queue(200, {"ok": 4})
        self.assertEqual(http_json("GET", self.srv.url, retries=1, sleep=self.sleep)["ok"], 4)
        self.assertEqual(self.sleeps, [RETRY_AFTER_MAX])

    def test_400_is_not_retried(self):
        self.srv.queue(400, {"error": "bad"})
        with self.assertRaises(HttpStatusError) as cm:
            http_json("POST", self.srv.url, body={"a": 1}, retries=3, sleep=self.sleep)
        self.assertEqual(cm.exception.status, 400)
        self.assertIn("bad", cm.exception.body_snippet)
        self.assertEqual(len(self.srv.requests), 1)
        self.assertEqual(self.srv.requests[0]["body"], b'{"a": 1}')

    def test_exhausted_retries_raise_status_error(self):
        for _ in range(3):
            self.srv.queue(502, "gateway")
        with self.assertRaises(HttpStatusError):
            http_json("GET", self.srv.url, retries=2, sleep=self.sleep)
        self.assertEqual(len(self.srv.requests), 3)

    def test_timeout_becomes_neterror_not_timeouterror(self):
        self.srv.queue(200, {"late": True}, delay=1.5)
        with self.assertRaises(NetError) as cm:
            http_json("GET", self.srv.url, timeout=0.3, retries=0, sleep=self.sleep)
        self.assertNotIsInstance(cm.exception, HttpStatusError)

    def test_html_body_is_neterror(self):
        self.srv.queue(200, "<html>proxy login</html>")
        with self.assertRaises(NetError):
            http_json("GET", self.srv.url, retries=0)

    def test_oversized_response_rejected(self):
        self.srv.queue(200, {"blob": "x" * 5000})
        with self.assertRaises(NetError):
            http_json("GET", self.srv.url, retries=0, max_response=1000)

    def test_connection_refused_is_neterror(self):
        with self.assertRaises(NetError):
            http_json("GET", "http://127.0.0.1:9/", retries=1, timeout=2, sleep=self.sleep)

    def test_raw_body_and_headers(self):
        self.srv.queue(200, {"got": True})
        http_json("POST", self.srv.url + "/v1/bundles", raw_body=b"\x00\x01", headers={"Authorization": "Bearer t"}, retries=0)
        req = self.srv.requests[0]
        self.assertEqual(req["body"], b"\x00\x01")
        self.assertEqual(req["headers"]["content-type"], "application/octet-stream")
        self.assertEqual(req["headers"]["authorization"], "Bearer t")

    def test_non_http_schemes_are_refused_before_any_io(self):
        with mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("must not open")), \
                mock.patch.object(net._direct_opener, "open", side_effect=AssertionError("must not open")):
            for url in ("file:///etc/passwd", "ftp://127.0.0.1/x", "gopher://x/", "data:application/json,{}",
                        "FILE:///C:/Windows/win.ini", "/relative/path", ""):
                with self.assertRaises(NetError, msg=url) as cm:
                    http_json("GET", url, retries=3, sleep=self.sleep)
                self.assertNotIsInstance(cm.exception, HttpStatusError, url)
                self.assertIn("unsupported URL scheme", str(cm.exception))
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.srv.requests, [])

    def test_private_targets_bypass_environment_proxy(self):
        env = {"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
               "HTTPS_PROXY": "http://127.0.0.1:9"}
        with mock.patch.dict(os.environ, env):
            for name in ("no_proxy", "NO_PROXY"):
                os.environ.pop(name, None)
            # the default opener would hand this to the dead proxy ...
            with self.assertRaises(urllib.error.URLError):
                urllib.request.build_opener().open(self.srv.url + "/v1/health", timeout=2)
            # ... http_json talks to the loopback server directly
            self.srv.queue(200, {"ok": True})
            self.assertEqual(http_json("GET", self.srv.url + "/v1/health", retries=0, timeout=5), {"ok": True})
        self.assertEqual(self.srv.requests[-1]["path"], "/v1/health")

    def test_public_targets_keep_the_default_opener(self):
        with mock.patch.object(net, "is_loopback_or_private", return_value=False), \
                mock.patch.object(urllib.request, "urlopen", side_effect=urllib.error.URLError("nope")) as default, \
                mock.patch.object(net._direct_opener, "open", side_effect=AssertionError("direct opener used")):
            with self.assertRaises(NetError):
                http_json("GET", "https://console.example.org/v1/plans", retries=0, sleep=self.sleep)
        self.assertEqual(default.call_count, 1)

    def test_private_detection(self):
        self.assertTrue(is_loopback_or_private("http://127.0.0.1:11434"))
        self.assertTrue(is_loopback_or_private("http://localhost:11434/v1"))
        self.assertTrue(is_loopback_or_private("http://192.168.1.20:8080"))
        self.assertFalse(is_loopback_or_private("https://11.22.33.44/v1"))


if __name__ == "__main__":
    unittest.main()
