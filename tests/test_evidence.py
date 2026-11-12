import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apk_god.evidence import build_evidence, import_har, sanitize_url


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def inspection(self):
        return {
            "package": {"package_name": "org.example.fixture"},
            "components": [{"type": "activity", "name": "org.example.fixture.Main", "exported": True}],
            "permissions": ["android.permission.INTERNET"],
            "dex": [{"path": "classes.dex"}],
            "native_libraries": [{"path": "lib/arm64-v8a/libsample.so", "abi": "arm64-v8a"}],
            "urls": [{"url": "https://user:pw@example.invalid/api/items?token=secret#hidden", "source": "classes.dex", "offset": 212}],
        }

    def engine(self):
        class_name = "Lorg/example/fixture/Main;"
        method = class_name + "->onCreate()V"
        callee = "Landroid/media/MediaPlayer;->start()V"
        return {"classes": [{"name": class_name, "superclass": "Landroid/app/Activity;", "source": "classes.dex"}],
                "methods": [{"id": method, "class": class_name, "name": "onCreate", "source": "classes.dex", "offset": 100}],
                "calls": [{"caller": method, "callee": callee, "source": "classes.dex", "offset": 20, "offset_kind": "instruction-byte-offset-within-method"},
                          {"caller": method, "callee": callee, "source": "classes.dex", "offset": 30}],
                "cfg": [{"method": method, "source": "classes.dex", "blocks": [{"id": "b0", "start": 0, "end": 32, "successors": []}]}],
                "coverage": {"status": "partial"}, "source_index": []}

    def test_cross_references_have_stable_ids_and_exact_offsets(self):
        first = build_evidence(self.inspection(), [self.engine()], self.root)
        second = build_evidence(self.inspection(), [self.engine()], self.root)
        self.assertEqual(first, second)
        edges = first["graph"]["edges"]
        call = [x for x in edges if x["relation"] == "static_call"]
        self.assertEqual(len(call), 1)
        self.assertEqual([r["offset"] for r in call[0]["evidence"]], [20, 30])
        self.assertEqual(call[0]["evidence"][0]["offset_kind"], "instruction-byte-offset-within-method")
        self.assertTrue(any(x["relation"] == "class_name_match" for x in edges))
        self.assertEqual(call[0]["basis"], "static-observed")
        media = first["functionality"][0]
        self.assertEqual(media["id"], "media_playback")
        self.assertEqual(media["basis"], "inferred")
        self.assertFalse(media["runtime_verified"])
        self.assertFalse(first["coverage"]["runtime_executed"])
        self.assertFalse(first["coverage"]["complete_functionality_claimed"])

    def test_manifest_permission_is_not_runtime_behavior(self):
        result = build_evidence(self.inspection(), [], self.root)
        self.assertFalse(result["functionality"])
        self.assertTrue(any(x["title"] == "DEX semantics unavailable" and x["basis"] == "unknown" for x in result["findings"]))
        self.assertEqual(result["endpoint_candidates"][0]["url"], "https://example.invalid/api/items")
        dump = json.dumps(result)
        self.assertNotIn("secret", dump)
        self.assertNotIn("user:pw", dump)

    def test_har_metadata_redacted_deduplicated_and_matched(self):
        entries = []
        for token, status in [("one-secret", 200), ("two-secret", 304)]:
            entries.append({"request": {"url": f"https://user:password@example.invalid/api/items?token={token}&q=PRIVATE", "method": "GET", "headers": [{"name": "Authorization", "value": "Bearer auth-secret"}], "postData": {"text": "request-body-secret"}},
                            "response": {"status": status, "headers": [{"name": "Set-Cookie", "value": "cookie-secret"}], "content": {"mimeType": "application/json; charset=utf-8", "text": "response-body-secret"}}, "startedDateTime": "private-timestamp"})
        path = self.root / "private-filename.har"
        path.write_text(json.dumps({"log": {"entries": entries}}))
        result = build_evidence(self.inspection(), [self.engine()], self.root, path)
        observations = result["api_observations"]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["count"], 2)
        self.assertEqual(observations[0]["statuses"], [200, 304])
        self.assertEqual(observations[0]["query_parameters"], ["q", "token"])
        self.assertTrue(observations[0]["matches_static_url"])
        self.assertFalse(observations[0]["independently_replayed"])
        dump = json.dumps(result)
        for secret in ["one-secret", "two-secret", "PRIVATE", "password", "auth-secret", "request-body-secret", "cookie-secret", "response-body-secret", "private-timestamp", "private-filename"]:
            self.assertNotIn(secret, dump)

    def test_sensitive_url_paths_and_invalid_urls(self):
        self.assertEqual(sanitize_url("https://name:pass@example.invalid/token/SENSITIVE?x=secret"), "https://example.invalid/token/[redacted]")
        self.assertEqual(sanitize_url("https://example.invalid/user/1234567"), "https://example.invalid/user/[redacted]")
        self.assertIsNone(sanitize_url("file:///etc/passwd"))
        self.assertIsNone(sanitize_url("https://host:wrong/path"))

    def test_har_malformed_and_bounded(self):
        path = self.root / "bad.har"
        path.write_text('{"entries": []}')
        with self.assertRaisesRegex(ValueError, "log.entries"):
            import_har(path)
        result = build_evidence(self.inspection(), [], self.root, path)
        self.assertFalse(result["coverage"]["har_imported"])
        self.assertEqual(result["api_observations"], [])
        self.assertTrue(any(x["title"] == "Traffic import unavailable" for x in result["findings"]))
        path.write_bytes(b"a" * 200)
        with patch("apk_god.evidence.MAX_HAR_BYTES", 100):
            with self.assertRaisesRegex(ValueError, "limit"):
                import_har(path)

    def test_source_index_rejects_escape_missing_and_symlinks(self):
        safe = self.root / "sources" / "Main.java"
        safe.parent.mkdir()
        safe.write_text("class Main {}\n")
        outside = self.root.parent / (self.root.name + "-outside")
        outside.write_text("secret")
        try:
            (self.root / "link.java").symlink_to(outside)
            engine = self.engine()
            engine["source_index"] = [{"path": "sources/Main.java", "language": "java", "lines": 1, "source": "classes.dex", "kind": "reconstructed"},
                                      {"path": "../" + outside.name}, {"path": "link.java"}, {"path": "missing.java"}]
            result = build_evidence(self.inspection(), engine, self.root)
            self.assertEqual([x["path"] for x in result["source_index"]], ["sources/Main.java"])
            self.assertTrue(any("unsafe" in x for x in result["limitations"]))
        finally:
            outside.unlink()

    def test_graph_limit_is_explicit_and_has_no_dangling_edges(self):
        with patch("apk_god.evidence.MAX_GRAPH_NODES", 3):
            result = build_evidence(self.inspection(), self.engine(), self.root)
        nodes = {x["id"] for x in result["graph"]["nodes"]}
        self.assertTrue(result["graph"]["truncated"])
        for edge in result["graph"]["edges"]:
            self.assertIn(edge["source"], nodes)
            self.assertIn(edge["target"], nodes)


if __name__ == "__main__":
    unittest.main()
