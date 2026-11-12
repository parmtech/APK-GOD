import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from apk_god.ai import AIError, enrich_report, payload_preview, validate_ai_response


def report():
    return {
        "input": {"filename": "private-app.apk", "sha256": "a" * 64},
        "inspection": {"strings": ["do-not-send-raw-string"], "source": "do-not-send-source"},
        "evidence": {"findings": [{"id": "F-identity", "title": "Package identity", "statement": "org.secret.customer", "basis": "static-observed"},
                                  {"id": "F-media", "title": "Media capability", "statement": "Contains media calls; password=hidden-secret and https://u:pw@private.invalid/x?token=secret", "basis": "inferred", "evidence": [{"excerpt": "do-not-send-excerpt"}]}],
                     "coverage": {"classes_indexed": 4, "runtime_executed": False, "private_key": "do-not-send-coverage-secret"},
                     "api_observations": [{"body": "do-not-send-body"}], "source_index": [{"path": "do-not-send-source-path"}]}}


class Provider:
    def __init__(self):
        self.requests = []
        self.response = {"summary": "Media behavior needs runtime confirmation.", "findings": [{"title": "Possible playback", "explanation": "Media calls are present.", "uncertainty": "Execution was not tested.", "evidence_ids": ["F-media"]}]}
        self.status = 200
        self.redirect = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append({"path": self.path, "headers": dict(self.headers), "json": json.loads(data)})
                self.send_response(owner.status)
                if owner.redirect:
                    self.send_header("Location", owner.redirect)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"choices": [{"message": {"content": json.dumps(owner.response)}}]}).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class AITests(unittest.TestCase):
    def test_preview_omits_sensitive_inputs_and_redacts_likely_secrets(self):
        payload = payload_preview(report())
        raw = json.dumps(payload)
        for value in ["private-app", "do-not-send", "org.secret", "hidden-secret", "private.invalid", "u:pw"]:
            self.assertNotIn(value, raw)
        self.assertEqual([x["id"] for x in payload["findings"]], ["F-media"])
        self.assertIn("[redacted]", raw)
        self.assertFalse(payload["coverage"]["runtime_executed"])

    def test_live_local_provider_only_gets_projection_report_is_immutable(self):
        provider = Provider()
        try:
            document = report()
            before = copy.deepcopy(document)
            result = enrich_report(document, endpoint=provider.endpoint, model="local-fixture", api_key="local-test-key")
            self.assertEqual(document, before)
            self.assertEqual(len(provider.requests), 1)
            request = provider.requests[0]
            self.assertEqual(request["path"], "/v1/chat/completions")
            self.assertEqual(request["headers"]["Authorization"], "Bearer local-test-key")
            self.assertNotIn("local-test-key", json.dumps(request["json"]))
            self.assertEqual(json.loads(request["json"]["messages"][1]["content"]), payload_preview(document))
            self.assertEqual(result["basis"], "ai-inferred")
            self.assertFalse(result["findings"][0]["verified"])
            self.assertNotIn("local-test-key", json.dumps(result))
        finally:
            provider.close()

    def test_unknown_evidence_is_rejected(self):
        value = {"summary": "Something happened.", "findings": [{"title": "Claim", "explanation": "Claim detail", "uncertainty": "None", "evidence_ids": ["invented-id"]}]}
        with self.assertRaisesRegex(AIError, "unknown evidence"):
            validate_ai_response(json.dumps(value), {"F-media"})

    def test_endpoint_credentials_and_insecure_remote_are_rejected(self):
        for endpoint in ["http://example.com/v1", "https://user:password@example.com/v1", "https://example.com/v1?key=secret", "file:///tmp/model"]:
            with self.subTest(endpoint=endpoint), self.assertRaises(AIError):
                enrich_report(report(), endpoint=endpoint, model="fixture")

    def test_redirect_does_not_send_credentials_to_second_server(self):
        first, second = Provider(), Provider()
        try:
            first.status = 307
            first.redirect = second.endpoint + "/chat/completions"
            with self.assertRaisesRegex(AIError, "HTTP 307"):
                enrich_report(report(), endpoint=first.endpoint, model="fixture", api_key="SECRET")
            self.assertEqual(len(first.requests), 1)
            self.assertEqual(second.requests, [])
        finally:
            first.close()
            second.close()

    def test_no_implicit_model_or_endpoint_and_no_source_fallback(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(AIError):
                enrich_report(report())
        with self.assertRaises(AIError):
            payload_preview({"inspection": {"source": "There is source but no findings"}})

    def test_model_response_is_validated_before_return(self):
        provider = Provider()
        try:
            provider.response["findings"][0]["evidence_ids"] = ["F-madeup"]
            with self.assertRaisesRegex(AIError, "unknown evidence"):
                enrich_report(report(), endpoint=provider.endpoint, model="fixture")
        finally:
            provider.close()


if __name__ == "__main__":
    unittest.main()
