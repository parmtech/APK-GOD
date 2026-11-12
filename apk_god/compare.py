"""Deterministic semantic differences between two APK-GOD reports."""
from __future__ import annotations
import json
from pathlib import Path


def load_report(path: str | Path) -> dict:
    source = Path(path)
    if source.is_dir():
        source /= "analysis.json"
    if source.stat().st_size > 128 * 1024**2:
        raise ValueError("Report exceeds 128 MiB.")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not {"inspection", "input"} <= data.keys():
        raise ValueError("Expected an APK-GOD analysis.json report.")
    return data


def _set_diff(before, after):
    left, right = set(before), set(after)
    return {"added": sorted(right - left), "removed": sorted(left - right), "unchanged_count": len(left & right)}


def compare_reports(before: dict, after: dict) -> dict:
    a, b = before.get("inspection", {}), after.get("inspection", {})
    ae, be = before.get("engine_analysis", {}), after.get("engine_analysis", {})
    def identity(item):
        if isinstance(item, str):
            return item
        return str(item.get("id") or item.get("signature") or item.get("full_name") or
                   (str(item.get("class", item.get("class_name", ""))) + "->" + str(item.get("name", "")) + str(item.get("descriptor", ""))))
    def class_identity(item):
        return item if isinstance(item, str) else str(item.get("name") or item.get("descriptor") or item.get("id") or "")
    def call_identity(item):
        return str(item.get("caller", "")) + " -> " + str(item.get("callee", ""))
    oldpkg, newpkg = a.get("package", {}), b.get("package", {})
    return {
        "schema_version": 1, "before": before["input"], "after": after["input"],
        "same_package": oldpkg.get("package_name") == newpkg.get("package_name"),
        "identity_changes": {key: {"before": oldpkg.get(key), "after": newpkg.get(key)}
                             for key in sorted(set(oldpkg) | set(newpkg)) if oldpkg.get(key) != newpkg.get(key)},
        "permissions": _set_diff(a.get("permissions", []), b.get("permissions", [])),
        "components": _set_diff((str(x.get("type")) + ":" + str(x.get("name")) for x in a.get("components", [])),
                                (str(x.get("type")) + ":" + str(x.get("name")) for x in b.get("components", []))),
        "classes": _set_diff((class_identity(x) for x in ae.get("classes", [])), (class_identity(x) for x in be.get("classes", []))),
        "methods": _set_diff((identity(x) for x in ae.get("methods", [])), (identity(x) for x in be.get("methods", []))),
        "calls": _set_diff((call_identity(x) for x in ae.get("calls", [])), (call_identity(x) for x in be.get("calls", []))),
        "endpoint_candidates": _set_diff((x.get("url", "") for x in a.get("urls", [])), (x.get("url", "") for x in b.get("urls", []))),
        "limitations": ["Only recorded static evidence is compared. Missing or truncated coverage can look like removals.",
                        "This comparison does not establish equivalence of runtime behavior or backend services."],
        "coverage_before": ae.get("coverage", {}), "coverage_after": be.get("coverage", {}),
    }
