import unittest

from . import helpers
from aiit.common.net import HttpStatusError, NetError, http_json, is_loopback_or_private


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

    def test_private_detection(self):
        self.assertTrue(is_loopback_or_private("http://127.0.0.1:11434"))
        self.assertTrue(is_loopback_or_private("http://localhost:11434/v1"))
        self.assertTrue(is_loopback_or_private("http://192.168.1.20:8080"))
        self.assertFalse(is_loopback_or_private("https://11.22.33.44/v1"))


if __name__ == "__main__":
    unittest.main()
