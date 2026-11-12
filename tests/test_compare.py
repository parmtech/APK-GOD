import copy
import json
import tempfile
import unittest
from pathlib import Path

from apk_god.compare import compare_reports, load_report


def report(package="org.example.one"):
    return {"input": {"filename": "fixture.apk", "sha256": "a" * 64},
            "inspection": {"package": {"package_name": package, "version_code": "1"},
                           "permissions": ["android.permission.INTERNET"],
                           "components": [{"type": "activity", "name": "org.example.Main", "exported": False}],
                           "urls": [{"url": "https://example.invalid/v1/items"}]},
            "engine_analysis": {"classes": [{"name": "Lorg/example/Main;"}],
                                "methods": [{"id": "Lorg/example/Main;->load()V"}],
                                "coverage": {"truncated": False}}}


class CompareTests(unittest.TestCase):
    def test_package_permissions_methods_and_endpoints_change(self):
        before, after = report(), report("org.example.two")
        after["inspection"]["package"]["version_code"] = "2"
        after["inspection"]["permissions"].append("android.permission.CAMERA")
        after["engine_analysis"]["methods"] = [{"id": "Lorg/example/Main;->capture()V"}]
        after["inspection"]["urls"] = [{"url": "https://example.invalid/v2/items"}]
        result = compare_reports(before, after)
        self.assertFalse(result["same_package"])
        self.assertEqual(result["identity_changes"]["version_code"], {"before": "1", "after": "2"})
        self.assertEqual(result["permissions"]["added"], ["android.permission.CAMERA"])
        self.assertEqual(result["methods"]["added"], ["Lorg/example/Main;->capture()V"])
        self.assertEqual(result["methods"]["removed"], ["Lorg/example/Main;->load()V"])
        self.assertEqual(result["endpoint_candidates"]["added"], ["https://example.invalid/v2/items"])

    def test_class_identity_uses_its_actual_descriptor(self):
        before = report()
        after = copy.deepcopy(before)
        after["engine_analysis"]["classes"].append({"name": "Lorg/example/Camera;"})
        self.assertEqual(compare_reports(before, after)["classes"]["added"], ["Lorg/example/Camera;"])

    def test_partial_coverage_preserved_without_claiming_runtime_equivalence(self):
        before = report()
        after = copy.deepcopy(before)
        after["engine_analysis"]["coverage"] = {"truncated": True, "limit_reasons": ["method limit"]}
        after["engine_analysis"]["methods"] = []
        result = compare_reports(before, after)
        self.assertTrue(result["coverage_after"]["truncated"])
        self.assertTrue(any("coverage" in x for x in result["limitations"]))
        self.assertTrue(any("runtime" in x for x in result["limitations"]))

    def test_report_loading_supports_output_folder_and_rejects_unrelated_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "analysis.json"
            path.write_text(json.dumps(report()))
            self.assertEqual(load_report(directory), report())
            path.write_text('{"some_other_file": true}')
            with self.assertRaises(ValueError):
                load_report(path)


if __name__ == "__main__":
    unittest.main()
