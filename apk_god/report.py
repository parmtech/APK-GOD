"""Readable, self-contained reports. All APK-controlled content is escaped."""
from __future__ import annotations
import html
import json
from pathlib import Path
from urllib.parse import quote


def esc(value):
    if value is None:
        value = "Unknown"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return html.escape(str(value), quote=True)


def md(value):
    return str(value if value is not None else "Unknown").replace("|", r"\|").replace("\n", " ").replace("\r", " ")


def table(headers, rows):
    head = "".join("<th>" + esc(h) + "</th>" for h in headers)
    body = "".join("<tr>" + "".join("<td>" + esc(c) + "</td>" for c in row) + "</tr>" for row in rows)
    return '<div class="scroll"><table><thead><tr>' + head + "</tr></thead><tbody>" + body + "</tbody></table></div>"


def render_markdown(doc):
    inspection, evidence = doc["inspection"], doc["evidence"]
    package = inspection.get("package", {})
    lines = [
        "# APK GOD — evidence report", "",
        "## Target", "",
        "- File: " + md(doc["input"]["filename"]),
        "- SHA-256: " + md(doc["input"]["sha256"]),
        "- Package: " + md(package.get("package_name")),
        "- Version: " + md(package.get("version_name")),
        "- Created: " + md(doc["created_at"]), "",
        "## What the evidence means", "",
        "- **static-observed**: present in the package or reconstructed source; not proof it executed.",
        "- **runtime-imported**: present in a supplied capture; not independently collected by this run.",
        "- **inferred**: an interpretation that needs validation.",
        "- **unknown**: evidence is missing.", "",
        "## Findings", "",
    ]
    for item in evidence.get("findings", []):
        lines += [
            "### " + md(item.get("id", "")) + " · " + md(item.get("title", "Finding")), "",
            "**Basis:** " + md(item.get("basis", "unknown")) + " · **Support:** " + md(item.get("confidence", "unknown")), "",
            md(item.get("statement", "")), "",
        ]
        for source in item.get("evidence", []):
            lines.append("- Evidence: " + md(source.get("source", "")) + " — " + md(source.get("locator", "")))
        lines.append("")
    lines += ["## Embedded engine results", "", "| Engine | Status | Details |", "|---|---|---|"]
    for run in doc.get("engine_runs", []):
        lines.append("| " + md(run.get("id")) + " | " + md(run.get("status")) + " | " + md(run.get("message", "")) + " |")
    if not doc.get("engine_runs"):
        lines += ["", "No embedded engine results were recorded."]
    engine = doc.get("engine_analysis", {})
    lines += ["", "## Code coverage", "", "```json", json.dumps(engine.get("coverage", {}), indent=2), "```", "",
              "## Measured performance", "", md(json.dumps(doc.get("performance", {}))), ""]
    lines += ["", "## Components", "", "| Type | Name | Exported |", "|---|---|---|"]
    for component in inspection.get("components", []):
        lines.append("| " + md(component.get("type")) + " | " + md(component.get("name")) + " | " + md(component.get("exported")) + " |")
    lines += ["", "## API observations", ""]
    for item in evidence.get("api_observations", []):
        lines.append("- " + md(json.dumps(item, ensure_ascii=False)))
    if not evidence.get("api_observations"):
        lines.append("No traffic capture supplied. Static URL strings alone do not establish an API contract.")
    lines += ["", "## Limits and unanswered questions", ""]
    lines += ["- " + md(x) for x in dict.fromkeys(doc.get("limitations", []) + evidence.get("limitations", []) + inspection.get("warnings", []))]
    lines += ["", "## Reconstructed source index", "", "| File | Language | Lines |", "|---|---|---|"]
    for item in evidence.get("source_index", [])[:500]:
        lines.append("| " + md(item.get("path")) + " | " + md(item.get("language")) + " | " + md(item.get("lines")) + " |")
    return "\n".join(lines) + "\n"


def render_html(doc):
    inspection, evidence = doc["inspection"], doc["evidence"]
    package = inspection.get("package", {})
    body = [
        '<header><p class="eyebrow">APK GOD / LOCAL ANALYSIS</p><h1>Understand the app.<br><span>Follow the evidence.</span></h1>',
        "<p>" + esc(doc["input"]["filename"]) + " · " + esc(package.get("package_name")) + "</p></header>",
        '<section class="metrics">',
    ]
    for count, label in [
        (len(inspection.get("files", [])), "Package entries"),
        (len(inspection.get("dex", [])), "DEX files"),
        (len(inspection.get("native_libraries", [])), "Native libraries"),
        (len(evidence.get("findings", [])), "Evidence findings"),
    ]:
        body.append('<div class="metric"><strong>' + esc(count) + "</strong><span>" + label + "</span></div>")
    body += [
        "</section>",
        '<section class="notice"><b>Read the labels.</b> Static code can describe a possible behavior without proving it ran. '
        "Imported traffic was supplied by the analyst. Inferences and missing backend evidence remain explicit.</section>",
        '<nav><a href="analysis.json">JSON report</a><a href="source-bundle.zip">Source bundle</a><a href="evidence-graph.json">Evidence graph</a><a href="report.md">Markdown report</a><a href="rewrite-spec.md">Engineering brief</a></nav>',
        '<section><h2>Package identity</h2>',
        table(["Field", "Value"], [
            ("SHA-256", doc["input"]["sha256"]),
            ("Version name", package.get("version_name")),
            ("Version code", package.get("version_code")),
            ("Minimum SDK", package.get("min_sdk")),
            ("Target SDK", package.get("target_sdk")),
            ("APK v2 integrity", inspection.get("signatures", {}).get("verification", "not-performed")),
            ("Signer trust", inspection.get("signatures", {}).get("signer_trust", "not-assessed")),
        ]), "</section>",
        "<section><h2>Functionality and evidence</h2>",
    ]
    for item in evidence.get("findings", []):
        basis = item.get("basis", "unknown")
        css = basis if basis in {"static-observed", "runtime-imported", "inferred", "unknown"} else "unknown"
        body += [
            '<article class="finding"><div class="finding-top"><span class="badge ' + css + '">' + esc(basis) + "</span>",
            '<span class="muted">' + esc(item.get("id")) + " · " + esc(item.get("confidence", "unknown")) + "</span></div>",
            "<h3>" + esc(item.get("title", "Finding")) + "</h3><p>" + esc(item.get("statement", "")) + "</p>",
        ]
        refs = item.get("evidence", [])
        if refs:
            body += ["<details><summary>Evidence references</summary><ul>"]
            for ref in refs[:30]:
                body.append("<li><code>" + esc(ref.get("source", "")) + "</code> " + esc(ref.get("locator", "")))
                if ref.get("excerpt"):
                    body.append("<pre>" + esc(ref["excerpt"]) + "</pre>")
                body.append("</li>")
            body.append("</ul></details>")
        body.append("</article>")
    if not evidence.get("findings"):
        body.append("<p>No supported findings were produced.</p>")
    engine = doc.get("engine_analysis", {})
    body += ["</section>", "<section><h2>Embedded engine results</h2>"]
    body.append(table(["Engine", "Status", "Details"], [
        (r.get("id"), r.get("status"), r.get("message", "")) for r in doc.get("engine_runs", [])
    ]) if doc.get("engine_runs") else "<p>No embedded engine results recorded.</p>")
    body += ["<p class=\"muted\">Analysis status: " + esc(engine.get("status", "unknown")) +
             ". Library availability, command completion and complete behavioral understanding are different measurements.</p>",
             "</section><section><h2>Classes and readable source</h2>"]
    body.append('<div class="scroll"><table><thead><tr><th>Class</th><th>DEX</th><th>Methods</th><th>Source</th></tr></thead><tbody>')
    for item in engine.get("classes", [])[:1000]:
        links = []
        for key, label in (("source_path", "Java-like source"), ("disassembly_path", "DEX listing")):
            path = item.get(key)
            # Artifact paths were generated and validated, but never trust a
            # supplied report to turn an arbitrary scheme into a hyperlink.
            if isinstance(path, str) and path.startswith("source/") and ".." not in Path(path).parts and "\\" not in path:
                links.append('<a href="' + esc(quote(path, safe="/")) + '">' + label + '</a>')
        body.append("<tr><td><code>" + esc(item.get("name")) + "</code></td><td>" + esc(item.get("source")) +
                    "</td><td>" + esc(item.get("methods")) + "</td><td>" + " · ".join(links) + "</td></tr>")
    body += ["</tbody></table></div><p class=\"muted\">Showing up to 1,000 indexed classes. Exported source is reconstructed and may not compile; the JSON report contains the full recorded index.</p>",
             "</section><section><h2>Native libraries</h2>",
             table(["Library", "Architecture", "Symbols", "Instructions", "Status"], [
                 (x.get("source"), x.get("architecture"), len(x.get("symbols", [])), x.get("instruction_count", 0), x.get("status"))
                 for x in engine.get("native", [])]),
             "<p class=\"muted\">Native output is structural evidence and bounded instruction decoding. Function reachability and native high-level decompilation are not established by a linear listing.</p>"]
    body += ["</section>", "<section><h2>Components</h2>", table(["Type", "Name", "Exported"], [
        (x.get("type"), x.get("name"), x.get("exported")) for x in inspection.get("components", [])
    ]), "</section>", "<section><h2>Declared permissions</h2><div class=\"chips\">"]
    body += ["<code>" + esc(p) + "</code>" for p in inspection.get("permissions", [])]
    body += ["</div></section>", "<section><h2>API observations</h2>"]
    for item in evidence.get("api_observations", []):
        body.append("<pre>" + esc(json.dumps(item, indent=2, ensure_ascii=False)) + "</pre>")
    if not evidence.get("api_observations"):
        body.append("<p>No runtime traffic supplied. A URL found in code is a candidate, not a confirmed request.</p>")
    body += ["</section>", "<section><h2>Coverage and unanswered questions</h2><ul>"]
    body += ["<li>" + esc(x) + "</li>" for x in dict.fromkeys(doc.get("limitations", []) + evidence.get("limitations", []) + inspection.get("warnings", []))]
    body += ["</ul><details><summary>Evidence coverage</summary><pre>" + esc(evidence.get("coverage", {})) + "</pre></details>",
             "<details open><summary>Engine coverage and bounds</summary><pre>" + esc(json.dumps(engine.get("coverage", {}), indent=2)) + "</pre></details>",
             "<details><summary>Measured performance</summary><pre>" + esc(doc.get("performance", {})) + "</pre></details></section>"]
    body += ["<section><h2>Source index</h2>", table(["File", "Language", "Lines"], [
        (x.get("path"), x.get("language"), x.get("lines")) for x in evidence.get("source_index", [])[:500]
    ]), "</section>", '<footer>APK GOD ' + esc(doc["generator"]["version"]) + " · " + esc(doc["created_at"]) + "</footer>"]
    css = """
    :root{color-scheme:dark;--bg:#10131b;--panel:#191e2a;--text:#eaf0fa;--muted:#a5b3cb;--line:#303b50;--accent:#adabff}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.65 system-ui,sans-serif}
    main{max-width:1100px;margin:auto;padding:48px 28px}h1{font-size:clamp(34px,6vw,64px);line-height:1.12;letter-spacing:-2px;margin:16px 0 24px}
    h1 span{color:var(--accent)}h2{font-size:24px;margin:0 0 20px}h3{font-size:19px;margin:14px 0 8px}
    .eyebrow{letter-spacing:2px;font-size:12px;color:var(--accent);font-weight:700}section{margin:36px 0}
    .metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.metric{padding:20px;background:var(--panel);border:1px solid var(--line);border-radius:12px}
    .metric strong{display:block;font-size:30px}.metric span,.muted,footer{color:var(--muted);font-size:13px}
    .notice{border-left:3px solid var(--accent);padding:18px 24px;background:var(--panel);border-radius:0 10px 10px 0}
    nav{display:flex;flex-wrap:wrap;gap:14px}a{color:#c5c4ff}nav a{padding:9px 16px;border:1px solid var(--line);border-radius:8px;text-decoration:none}
    .finding{background:var(--panel);border:1px solid var(--line);padding:22px;border-radius:12px;margin:14px 0}
    .finding-top{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.badge{font-size:12px;padding:3px 10px;border-radius:20px;background:#29354a}
    .static-observed{color:#b4d8ff}.runtime-imported{color:#9ae7cd;background:#183b35}.inferred{color:#ffe0a1;background:#42351f}.unknown{color:#c0c6d2}
    .scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;color:var(--muted);background:var(--panel)}
    td,th{padding:12px;border-bottom:1px solid var(--line);vertical-align:top}td{overflow-wrap:anywhere}
    code,pre{font-family:ui-monospace,monospace;font-size:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0d1017;border-radius:8px;padding:14px}
    .chips{display:flex;flex-wrap:wrap;gap:8px}.chips code{padding:6px 10px;background:var(--panel);border-radius:5px;overflow-wrap:anywhere}
    details{margin-top:14px}summary{cursor:pointer;color:var(--accent)}footer{border-top:1px solid var(--line);padding-top:20px;margin-top:40px}
    @media(max-width:600px){main{padding:24px 16px}.metrics{grid-template-columns:repeat(2,1fr)}h1{letter-spacing:-1px}.finding{padding:16px}}
    """
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>APK GOD evidence report</title><style>' + css + "</style></head><body><main>" + "".join(body) + "</main></body></html>"


def write_reports(doc, output_dir):
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    (root / "report.html").write_text(render_html(doc), encoding="utf-8")
    (root / "report.md").write_text(render_markdown(doc), encoding="utf-8")
    evidence = doc["evidence"]
    lines = [
        "# APK GOD — rewrite handoff", "",
        "This is an evidence-based engineering brief, not recovered original source.", "",
        "## Scope", "",
        "Implementations should reproduce only behavior justified by the evidence and independently validated requirements.",
        "Backend internals, missing screens, dynamic downloads, authentication rules and third-party services may be unknown.", "",
        "## Observed components", "",
    ]
    for c in doc["inspection"].get("components", []):
        lines.append("- " + md(c.get("type")) + ": " + md(c.get("name")))
    lines += ["", "## Findings to translate into requirements", ""]
    for f in evidence.get("findings", []):
        lines.append("- [" + md(f.get("id")) + "] (" + md(f.get("basis")) + ") " + md(f.get("statement")))
    lines += ["", "## Imported API contract evidence", ""]
    for item in evidence.get("api_observations", []):
        lines.append("- " + md(json.dumps(item, ensure_ascii=False)))
    if not evidence.get("api_observations"):
        lines.append("No runtime API contract supplied. Do not invent endpoints, request schemas or server business rules.")
    lines += ["", "## Validation still required", ""]
    lines += ["- " + md(x) for x in dict.fromkeys(doc["limitations"] + evidence.get("limitations", []))]
    lines += ["", "## Acceptance criteria for a future rewrite", "",
              "- Trace every implemented feature to a finding or an approved requirement.",
              "- Verify screen flows and error states on a test device.",
              "- Confirm API contracts using authorized test traffic and backend specifications.",
              "- Keep inferred backend architecture separate from verified implementation facts.", ""]
    (root / "rewrite-spec.md").write_text("\n".join(lines), encoding="utf-8")
