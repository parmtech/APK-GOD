"""Validate the feature ledger and render its human-readable matrix."""
from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "feature_ledger.json"
MATRIX = ROOT / "docs" / "FEATURE_MATRIX.md"
STATUSES = {"proposed", "implemented-unverified", "verified-with-limits", "blocked", "not-implemented"}


def render(data: dict) -> str:
    lines = [
        "# Feature acceptance inventory — APK-GOD 0.2", "",
        "**Draft 0.1 — 12 November 2026.** This inventory scopes capabilities promised or explicitly planned in this repository. It is not an exhaustive feature catalog of the twenty upstream projects and does not establish a completion percentage.", "",
        "## Reading the inventory", "",
        "The machine-readable source is [`feature_ledger.json`](feature_ledger.json). Reference IDs join to exact source-study commits in [`SOURCE_REVIEW.md`](SOURCE_REVIEW.md); those commits identify reviewed snapshots, not released versions or dependency pins. The source review sampled entrypoints, and some upstream repositories were only partly materialized. `platform_scope` distinguishes Android work from broader JVM/native work.", "",
        "`verified-with-limits` means the named bounded slice has test evidence; `implemented-unverified` means the needed target behavior is not verified; `blocked` records a target/environment gap; `proposed` is scoped but not complete; `not-implemented` means absent. Future procedures are not existing tests. Add automated fixture tests before upgrading a status.", "",
        "## Twenty reference projects", "",
        "| ID | Reference snapshot | Feature / pass criterion | Module | Fixture and acceptance case | Evidence | Platform | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in data["features"]:
        sha = f["reference_version"].removeprefix("commit:")[:12]
        lines.append(f"| {f['id']} | {f['reference_id']} (`{sha}`) | {f['feature']}; {f['expected_output_semantics']} | `{f['planned_apkgod_module']}` | {f['fixture']}; {f['acceptance_case']} | {f['evidence_location']} | {f['platform_scope']} | `{f['status']}` |")
    lines += ["", "## APK-GOD product features", "",
        "These records describe first-party promises and are not attributed to an upstream project.", "",
        "| ID | Version | Feature / pass criterion | Module | Fixture and acceptance case | Evidence | Platform | Status |",
        "|---|---|---|---|---|---|---|---|"]
    for f in data["product_features"]:
        lines.append(f"| {f['id']} | {f['reference_version']} | {f['feature']}; {f['expected_output_semantics']} | `{f['planned_apkgod_module']}` | {f['fixture']}; {f['acceptance_case']} | {f['evidence_location']} | {f['platform_scope']} | `{f['status']}` |")
    lines += ["", "## Provenance and evidence rules", "",
        "- Prefer original APK-GOD modules and direct embedded APIs. External CLI launchers do not satisfy the product architecture. Preserve third-party provenance and terms; do not include upstream scanner rules without review.",
        "- Keep static evidence, runtime observations, imported HAR data, symbolic paths, inference, and optional AI output distinct. A manifest declaration is not runtime behavior; a model witness is not execution; readable output is not recovered original source.",
        "- Every record names its expected action, input/target bounds, output semantics, module, fixture, acceptance case, evidence location, and platform scope.", "",
        "## Open scope questions", ""]
    for q in data["scope_questions"]:
        lines.append(f"- **{q['id']}** {q['question']} {q['reason']}")
    lines += ["", "## M00 gate state", "",
        "This inventory names scoped features across all twenty source snapshots plus first-party APK-GOD features. **M00 remains the first open gate:** unresolved families need explicit scope decisions, and future acceptance procedures still need stable owned fixtures and automated tests. Do not advance to M01 as the next gate until M00 acceptance is closed; independent M01 work may proceed in parallel only when separately requested/authorized. No coverage percentage or full-parity claim is supported.", ""]
    return "\n".join(lines)


def validate(data: dict) -> None:
    refs = data["references"]
    if len(refs) != 20 or len({r["id"] for r in refs}) != 20:
        raise ValueError("The source reference catalog must contain exactly 20 unique projects.")
    ref_versions = {r["id"]: r["version"] for r in refs}
    source_rows = {}
    for line in (ROOT / "docs" / "SOURCE_REVIEW.md").read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if len(cells) < 2:
            continue
        match = re.search(r"\[([0-9a-f]{40})\]", cells[1])
        if match:
            source_rows[cells[0]] = "commit:" + match.group(1)
    if any(source_rows.get(name) != version for name, version in ref_versions.items()):
        raise ValueError("A reference version does not match docs/SOURCE_REVIEW.md")
    fields = set(data["feature_fields"])
    all_rows = data["features"] + data["product_features"]
    if not all_rows or len({x["id"] for x in all_rows}) != len(all_rows):
        raise ValueError("Feature IDs must be unique across both catalogs.")
    for f in all_rows:
        missing = fields - f.keys()
        if missing or any(f.get(k) in (None, "") for k in fields):
            raise ValueError(f"{f.get('id')}: missing required fields {sorted(missing)}")
        if f["status"] not in STATUSES:
            raise ValueError(f"{f['id']}: invalid status {f['status']}")
        if f["reference_id"] == "APK-GOD":
            if f["reference_version"] != "project:0.2.0":
                raise ValueError(f"{f['id']}: invalid first-party version")
        elif f["reference_id"] not in ref_versions or f["reference_version"] != ref_versions[f["reference_id"]]:
            raise ValueError(f"{f['id']}: reference/version does not join")
        if f["candidate_scope"] == "unresolved" and not f.get("scope_question_id"):
            raise ValueError(f"{f['id']}: unresolved scope needs a question ID")
        for path, class_name, method in re.findall(
            r"(tests/[A-Za-z0-9_./-]+\.py)::([A-Za-z_][A-Za-z0-9_]*)::(test_[A-Za-z0-9_]*)",
            f["evidence_location"],
        ):
            test_path = ROOT / path
            if not test_path.is_file():
                raise ValueError(f"{f['id']}: evidence file does not exist: {path}")
            tree = ast.parse(test_path.read_text(encoding="utf-8"))
            cls = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name), None)
            if cls is None or not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == method for n in cls.body):
                raise ValueError(f"{f['id']}: pytest node does not exist: {path}::{class_name}::{method}")
    covered = {f["reference_id"] for f in data["features"]}
    if covered != set(ref_versions):
        raise ValueError(f"Every reference needs a feature; missing {sorted(set(ref_versions)-covered)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if the Markdown matrix is stale.")
    args = parser.parse_args()
    data = json.loads(LEDGER.read_text(encoding="utf-8"))
    validate(data)
    rendered = render(data)
    if args.check:
        if not MATRIX.exists() or MATRIX.read_text(encoding="utf-8") != rendered:
            print("FEATURE_MATRIX.md is stale; run python scripts/render_feature_matrix.py")
            return 1
    else:
        MATRIX.write_text(rendered, encoding="utf-8")
    print(f"Validated {len(data['features'])} reference features across 20 projects and {len(data['product_features'])} APK-GOD product features.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
