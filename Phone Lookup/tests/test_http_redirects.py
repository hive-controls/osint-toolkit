import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from phone_lookup.http import get_json, post_json

SECRET_HEADERS = {
    "X-API-Key": "leakcheck-secret",
    "DeHashed-Api-Key": "dehashed-secret",
    "apikey": "numverify-secret",
    "Authorization": "Bearer leakradar-secret",
}


class _Recorder(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.received.append(
            {"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body}
        )
        payload = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _record


class _Redirector(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _redirect(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(self.server.status_code)
        self.send_header("Location", self.server.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = _redirect


def _start(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class RedirectLeakTests(unittest.TestCase):
    def setUp(self):
        self.target = _start(_Recorder)
        self.target.received = []
        self.origin = _start(_Redirector)
        self.origin.target = f"http://127.0.0.1:{self.target.server_port}/landing"
        self.addCleanup(self._stop)

    def _stop(self):
        for server in (self.origin, self.target):
            server.shutdown()
            server.server_close()

    def _origin_url(self):
        return f"http://127.0.0.1:{self.origin.server_port}/api"

    def _assert_refused(self, status, body, expected_status):
        self.assertEqual(self.target.received, [])
        self.assertEqual(status, expected_status)
        self.assertIs(body["ok"], False)
        self.assertEqual(body["error"], "unexpected-redirect")
        self.assertEqual(body["status"], expected_status)
        self.assertEqual(body["location_host"], "127.0.0.1")
        serialized = json.dumps(body)
        for secret in ("leakcheck-secret", "dehashed-secret", "numverify-secret", "leakradar-secret"):
            self.assertNotIn(secret, serialized)

    def test_get_302_does_not_forward_api_key_headers(self):
        self.origin.status_code = 302
        status, body = get_json(self._origin_url(), headers=dict(SECRET_HEADERS))
        self._assert_refused(status, body, 302)

    def test_post_302_does_not_forward_api_key_headers(self):
        self.origin.status_code = 302
        status, body = post_json(
            self._origin_url(), json_body={"query": "x"}, headers=dict(SECRET_HEADERS)
        )
        self._assert_refused(status, body, 302)

    def test_post_307_does_not_replay_body_or_headers(self):
        self.origin.status_code = 307
        status, body = post_json(
            self._origin_url(), json_body={"phone": "+12025550123"}, headers=dict(SECRET_HEADERS)
        )
        self._assert_refused(status, body, 307)


if __name__ == "__main__":
    unittest.main()
