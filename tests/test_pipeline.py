import importlib.util
import io
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from apk_god.analysis import analyze, public_url
from apk_god.report import render_html
from apk_god.server import make_server


def sample_bytes(extra_entries=()):
    stream = io.BytesIO()
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
      package="org.example.apkgod.fixture" android:versionName="1.0" android:versionCode="1">
      <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
      <uses-permission android:name="android.permission.INTERNET"/>
      <application android:label="Synthetic fixture">
       <activity android:name=".MainActivity" android:exported="true"/>
      </application></manifest>"""
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("assets/config.json", '{"url":"https://example.invalid/api/items?token=secret-value"}')
        for name, content in extra_entries:
            archive.writestr(name, content)
    return stream.getvalue()


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.apk = cls.root / "sample.apk"
        cls.apk.write_bytes(sample_bytes())
        cls.output = cls.root / "output"
        cls.result = analyze(cls.apk, cls.output, profile="quick", timeout=60)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_embedded_report_transaction_exports_and_no_overwrite(self):
        result = self.result
        self.assertEqual(result["inspection"]["package"]["package_name"], "org.example.apkgod.fixture")
        self.assertNotIn("strings", result["inspection"])
        for name in ["report.html", "report.md", "rewrite-spec.md", "analysis.json", "evidence-graph.json", "source-bundle.zip"]:
            self.assertTrue((self.output / name).is_file(), name)
        self.assertNotIn("secret-value", (self.output / "analysis.json").read_text())
        self.assertTrue(result["engine_runs"])
        self.assertEqual(result["tool_runs"], [])
        self.assertTrue(all(x["mode"] == "embedded-library" for x in result["libraries"]))
        self.assertFalse(result["evidence"]["coverage"]["runtime_executed"])
        self.assertFalse(result["evidence"]["coverage"]["complete_functionality_claimed"])
        self.assertEqual(result["inspection"]["signatures"]["verification"], "not-performed")
        self.assertFalse((self.output / ".analysis-lock").exists())
        self.assertFalse((self.output / ".worker-result.json").exists())
        with self.assertRaises(ValueError):
            analyze(self.apk, self.output)

    def test_source_bundle_and_graph_are_consistent_with_report(self):
        exported = json.loads((self.output / "evidence-graph.json").read_text())
        self.assertEqual(exported, self.result["evidence"]["graph"])
        self.assertTrue(any(x["path"] == "source/AndroidManifest.xml" for x in self.result["evidence"]["source_index"]))
        with zipfile.ZipFile(self.output / "source-bundle.zip") as archive:
            self.assertIn("source/AndroidManifest.xml", archive.namelist())
            self.assertTrue(all(not x.endswith(".apk") for x in archive.namelist()))
            self.assertEqual(json.loads(archive.read("analysis.json")), self.result)
            self.assertIn(b"org.example.apkgod.fixture", archive.read("source/AndroidManifest.xml"))

    def test_invalid_or_unsafe_packages_never_receive_complete_report(self):
        for label, payload in [("invalid", b"not a zip"), ("traversal", sample_bytes([("../outside.txt", "should never be written")]))]:
            with self.subTest(label=label):
                apk = self.root / (label + ".apk")
                apk.write_bytes(payload)
                output = self.root / (label + "-output")
                with self.assertRaises(ValueError):
                    analyze(apk, output, profile="quick", timeout=60)
                self.assertFalse((output / "analysis.json").exists())
                self.assertFalse((output / ".analysis-lock").exists())
                self.assertFalse((self.root / "outside.txt").exists())

    def test_html_escapes_package_and_findings(self):
        malicious = '<script>alert("injected")</script>'
        document = {"input": {"filename": malicious, "sha256": "0" * 64},
                    "created_at": "test", "generator": {"version": "0.2"},
                    "inspection": {"package": {"package_name": malicious}},
                    "evidence": {"findings": [{"title": malicious, "statement": malicious, "basis": malicious}]},
                    "tool_runs": [], "limitations": [malicious]}
        output = render_html(document)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)

    def test_url_redaction_and_external_launcher_rejection(self):
        result = public_url("https://name:password@example.invalid:443/search?token=SECRET&x=VALUE#private")
        for secret in ["password", "name:", "SECRET", "VALUE", "private"]:
            self.assertNotIn(secret, result)
        self.assertEqual(public_url("https://example.invalid:wrong/"), "[unparseable URL]")
        destination = self.root / "external-launcher-attempt"
        with self.assertRaisesRegex(ValueError, "External tool launchers"):
            analyze(self.apk, destination, selected_tools=["jadx"])
        self.assertFalse(destination.exists())


REAL_APK = Path(os.environ.get("APK_GOD_TEST_APK", str(Path(__file__).resolve().parents[2] / "reference-fixtures" / "hello-world.apk")))


@unittest.skipUnless(REAL_APK.is_file() and importlib.util.find_spec("androguard"), "Optional local real-DEX fixture or embedded Androguard unavailable; no download is attempted.")
class RealPackageIntegrationTests(unittest.TestCase):
    def test_binary_manifest_dex_reconstruction_through_worker_and_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "analysis"
            result = analyze(REAL_APK, output, profile="quick", timeout=90)
            engine = result["engine_analysis"]
            self.assertTrue(result["inspection"]["package"]["package_name"])
            self.assertGreater(len(engine["methods"]), 0)
            self.assertGreater(len(engine["calls"]), 0)
            self.assertGreater(len(engine["cfg"]), 0)
            self.assertGreater(engine["coverage"]["classes_decompiled"], 0)
            java = [x for x in result["evidence"]["source_index"] if x["language"] == "java"]
            self.assertTrue(java, engine.get("warnings"))
            with zipfile.ZipFile(output / "source-bundle.zip") as bundle:
                self.assertIn(java[0]["path"], bundle.namelist())
                self.assertRegex(bundle.read(java[0]["path"]).decode("utf-8"), r"\b(class|interface|enum)\b")
            self.assertFalse(result["evidence"]["coverage"]["runtime_executed"])


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.server = make_server(0, cls.root)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_address[1])
        with urllib.request.urlopen(cls.base + "/api/session", timeout=5) as response:
            cls.token = json.load(response)["token"]
        cls.job = cls.upload_and_wait(sample_bytes())
        if cls.job["status"] != "completed":
            raise AssertionError(cls.job)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temp.cleanup()

    @classmethod
    def upload_and_wait(cls, payload):
        request = urllib.request.Request(cls.base + "/api/analyze?profile=quick", data=payload, method="POST",
            headers={"X-APK-GOD-Token": cls.token, "X-APK-GOD-Filename": "fixture.apk"})
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 202:
                raise AssertionError("Analysis submission must be asynchronous")
            job_id = json.load(response)["id"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            with urllib.request.urlopen(cls.base + "/api/jobs/" + job_id, timeout=5) as response:
                job = json.load(response)
            if job["status"] != "running":
                return job
            time.sleep(0.05)
        raise AssertionError("Dashboard analysis did not finish before its test deadline")

    def get(self, suffix):
        return urllib.request.urlopen(self.base + suffix, timeout=10)

    def test_ui_capabilities_and_identity(self):
        with self.get("/") as response:
            self.assertIn(b"Start an analysis", response.read())
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        with self.get("/api/capabilities") as response:
            info = json.load(response)
            self.assertFalse(info["external_tool_launchers"])
            self.assertFalse(info["network_required_for_static_analysis"])
            self.assertTrue(any(x["id"] == "bytecode" for x in info["capabilities"]))
        with self.get("/api/about") as response:
            self.assertEqual(json.load(response)["name"], "APK-GOD")

    def test_downloaded_report_source_and_bundle(self):
        prefix = "/api/jobs/" + self.job["id"] + "/"
        with self.get(prefix + "analysis.json") as response:
            self.assertEqual(json.load(response)["input"]["sha256"], self.job["sha256"])
        with self.get(prefix + "source/AndroidManifest.xml") as response:
            self.assertEqual(response.headers.get_content_type(), "text/plain")
            self.assertIn(b"org.example.apkgod.fixture", response.read())
        with self.get(prefix + "source-bundle.zip") as response:
            self.assertEqual(response.headers.get_content_type(), "application/zip")
            with zipfile.ZipFile(io.BytesIO(response.read())) as bundle:
                self.assertIn("evidence-graph.json", bundle.namelist())
                self.assertNotIn("input.apk", bundle.namelist())

    def test_history_survives_server_restart(self):
        restored = make_server(0, self.root)
        worker = threading.Thread(target=restored.serve_forever, daemon=True)
        worker.start()
        try:
            base = "http://127.0.0.1:" + str(restored.server_address[1])
            with urllib.request.urlopen(base + "/api/jobs", timeout=5) as response:
                items = json.load(response)["jobs"]
            matching = [x for x in items if x["id"] == self.job["id"]]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0]["status"], "completed")
            with urllib.request.urlopen(base + "/api/session", timeout=5) as response:
                self.assertNotEqual(json.load(response)["token"], self.token)
        finally:
            restored.shutdown()
            restored.server_close()
            worker.join(timeout=2)

    def test_failed_upload_reports_failure_without_downloads(self):
        job = self.upload_and_wait(b"This is not an APK")
        self.assertEqual(job["status"], "failed")
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.get("/api/jobs/" + job["id"] + "/analysis.json")
        self.assertEqual(error.exception.code, 404)

    def test_session_origin_and_host_guards(self):
        cases = [urllib.request.Request(self.base + "/api/analyze", data=sample_bytes(), method="POST"),
                 urllib.request.Request(self.base + "/api/session", headers={"Origin": "https://attacker.invalid"}),
                 urllib.request.Request(self.base + "/api/session", headers={"Host": "attacker.invalid"})]
        for request in cases:
            with self.subTest(request=request.full_url), self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(error.exception.code, 403)

    def test_source_routes_cannot_escape_or_serve_original_apk(self):
        prefix = "/api/jobs/" + self.job["id"] + "/"
        for path in ["input.apk", "source/%2e%2e/analysis.json", "source/%2Fetc%2Fpasswd", "source/does-not-exist.java"]:
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as error:
                self.get(prefix + path)
            self.assertEqual(error.exception.code, 404)
        target = self.root / self.job["id"] / "output" / "source" / "external-link.txt"
        try:
            target.symlink_to(self.root / self.job["id"] / "input.apk")
        except (OSError, NotImplementedError):
            return
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.get(prefix + "source/external-link.txt")
            self.assertEqual(error.exception.code, 403)
        finally:
            target.unlink()


if __name__ == "__main__":
    unittest.main()
