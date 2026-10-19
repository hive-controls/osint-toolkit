import base64
import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from osint_profiler.store import Store
from osint_profiler.web import create_server

class API(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.server = create_server(self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.token = self.get("/api/session")["data"]["token"]

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.tmp.cleanup()

    def get(self, path, headers=None):
        with self.opener.open(urllib.request.Request(self.base+path, headers=headers or {})) as response:
            return json.load(response)

    def post(self, action, args, token=None, origin=None):
        headers = {"Content-Type": "application/json", "X-Profiler-Token": token if token is not None else self.token, "Origin": origin or self.base}
        request = urllib.request.Request(self.base + "/api/action", json.dumps({"action": action, "args": args}).encode(), headers)
        with self.opener.open(request) as response:
            return json.load(response)["data"]

    def test_create_import_claim_roundtrip(self):
        self.post("create_case", {"case_id": "api-case", "question": "An evidence question"})
        a = self.post("add_entity", {"case_id": "api-case", "label": "Persona A"})["id"]
        b = self.post("add_entity", {"case_id": "api-case", "label": "Persona B"})["id"]
        relation = self.post("add_relation", {"case_id": "api-case", "source": a, "target": b, "kind": "same_entity"})["id"]
        upload = {"filename": "test.txt", "data": base64.b64encode(b"Evidence").decode(), "case_id": "api-case"}
        artifact = self.post("import_upload", upload)["id"]
        self.post("attach_evidence", {"case_id": "api-case", "relation_id": relation, "artifact_id": artifact, "note": "Operator evidence"})
        data = self.get("/api/case/api-case")["data"]
        self.assertEqual(len(data["groups"]), 1)
        self.assertEqual(data["relations"][0]["evidence"][0]["note"], "Operator evidence")

    def test_host_origin_and_token_restrictions(self):
        for action in (lambda: self.get("/api/bootstrap", {"Host": "evil.example"}),
                       lambda: self.post("list_cases", {}, token="wrong"),
                       lambda: self.post("list_cases", {}, origin="http://evil.example")):
            with self.assertRaises(urllib.error.HTTPError) as caught: action()
            self.assertEqual(caught.exception.code, 403)
            caught.exception.close()

    def test_no_filesystem_action_and_html_download(self):
        with self.assertRaises(urllib.error.HTTPError) as caught: self.post("import_path", {"path": "C:/Windows/win.ini"})
        caught.exception.close()
        self.store.create_case("web", "Test")
        art = self.store.import_bytes(b"<script>alert(1)</script>", "untrusted.html", "web")["id"]
        with self.opener.open(f"{self.base}/api/artifact?case=web&id={art}&preview=1") as response:
            self.assertEqual(response.headers.get_content_type(), "application/octet-stream")
            self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_plan_requires_explicit_confirmation(self):
        self.store.create_case("scan", "Test")
        plan = self.post("plan_scan", {"case_id": "scan", "tool": "maigret", "target": "synthetic"})
        with self.assertRaises(urllib.error.HTTPError) as caught: self.post("start_scan", {"plan_id": plan["plan_id"]})
        caught.exception.close()
        self.assertEqual(self.store.summary("scan")["jobs"], [])

if __name__ == "__main__": unittest.main()
