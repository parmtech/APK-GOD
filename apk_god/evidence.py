"""Correlate APK structures without confusing static evidence with execution.

This module has no network access and never executes extracted application code.
All graph relationships are derived from supplied parser output or an explicitly
imported HAR. Unknown behavior remains unknown, including backend internals.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

MAX_HAR_BYTES = 16 * 1024 * 1024
MAX_HAR_ENTRIES = 20_000
MAX_GRAPH_NODES = 30_000
MAX_GRAPH_EDGES = 60_000
MAX_SOURCE_FILES = 10_000
MAX_ITEMS = 25_000
MAX_TEXT = 2048


def _text(value, limit: int = MAX_TEXT) -> str:
    """A bounded scalar, never implicit serialization of arbitrary objects."""
    if not isinstance(value, (str, int, float, bool)):
        return ""
    return str(value).replace("\x00", "")[:limit]


def _records(value, maximum: int = MAX_ITEMS):
    return [x for x in value[:maximum] if isinstance(x, dict)] if isinstance(value, list) else []


def _integer(value, default=None):
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return default


def _identifier(value: str, prefix: str) -> str:
    return prefix + "-" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:20]


def redact_path(path: str) -> str:
    """Remove common credential and identifier path segments, without inventing routes."""
    parts, result = path.split("/"), []
    hide_next = False
    for raw in parts[:100]:
        value = unquote(raw)
        sensitive = (
            hide_next
            or bool(re.fullmatch(r"[0-9]{5,}", value))
            or bool(re.fullmatch(r"[a-fA-F0-9]{24,}", value))
            or bool(re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value))
            or bool(re.fullmatch(r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", value))
            or bool(re.fullmatch(r"[^/@\s]+@[^/@\s]+", value))
            or len(value) > 96
        )
        result.append("[redacted]" if sensitive else raw[:160])
        hide_next = value.casefold() in {"token", "password", "secret", "apikey", "api-key", "api_key", "access_token", "auth", "session"}
    return "/".join(result) or "/"


def sanitize_url(value) -> str | None:
    """Keep endpoint structure only; omit userinfo, query, fragment and likely secrets."""
    if not isinstance(value, str) or len(value) > 16_384:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            return None
        if any(ord(c) < 33 for c in parsed.hostname):
            return None
        host = parsed.hostname.casefold()
        if ":" in host:
            host = "[" + host + "]"
        if parsed.port is not None:
            host += ":" + str(parsed.port)
        return urlunsplit((parsed.scheme.lower(), host, redact_path(parsed.path), "", ""))
    except (ValueError, UnicodeError):
        return None


def _query_names(value) -> list[str]:
    """Only ordinary parameter names are retained; never values or opaque keys."""
    if not isinstance(value, str) or len(value) > 16_384:
        return []
    try:
        pairs = parse_qsl(urlsplit(value).query, max_num_fields=200, keep_blank_values=True)
    except (ValueError, UnicodeError):
        return []
    return sorted({name for name, _ in pairs if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,63}", name)})[:100]


def _ref(source, locator="", *, offset=None, offset_kind=None, excerpt=None) -> dict:
    item = {"source": _text(source, 500), "locator": _text(locator, 800)}
    number = _integer(offset)
    if number is not None and number >= 0:
        item["offset"] = number
        if offset_kind in {"dex-code-item-byte-offset", "instruction-byte-offset-within-method", "file-byte-offset"}:
            item["offset_kind"] = offset_kind
    if excerpt:
        item["excerpt"] = _text(excerpt, 500)
    return item


def import_har(path: str | Path) -> dict:
    """Import only bounded HTTP metadata; do not retain headers, cookies or bodies.

    Path templates are not guessed. Redacted path segments may group multiple
    requests; each observation explicitly says it came from a supplied capture.
    """
    file = Path(path)
    if not file.is_file():
        raise ValueError("HAR input must be a file.")
    with file.open("rb") as handle:
        raw = handle.read(MAX_HAR_BYTES + 1)
    if len(raw) > MAX_HAR_BYTES:
        raise ValueError("HAR exceeds the 16 MiB metadata import limit.")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("HAR is not a valid bounded JSON document.") from exc
    log = doc.get("log") if isinstance(doc, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("HAR must contain log.entries as an array.")
    observations: dict[tuple[str, str], dict] = {}
    skipped = 0
    for index, entry in enumerate(entries[:MAX_HAR_ENTRIES]):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            skipped += 1
            continue
        request = entry["request"]
        response = entry.get("response", {})
        response = response if isinstance(response, dict) else {}
        endpoint = sanitize_url(request.get("url"))
        method = _text(request.get("method"), 32).upper()
        if not endpoint or not re.fullmatch(r"[A-Z]{1,20}", method):
            skipped += 1
            continue
        key = (method, endpoint)
        item = observations.setdefault(key, {
            "method": method, "url": endpoint, "basis": "runtime-imported",
            "count": 0, "statuses": [], "mime_types": [], "query_parameters": [],
            "evidence": [], "independently_replayed": False,
        })
        item["count"] += 1
        status = _integer(response.get("status"))
        if status is not None and 0 <= status <= 599 and status not in item["statuses"]:
            item["statuses"].append(status)
        content = response.get("content", {})
        mime = content.get("mimeType") if isinstance(content, dict) else None
        if isinstance(mime, str):
            mime = mime.split(";", 1)[0].strip().lower()
            if re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", mime) and mime not in item["mime_types"]:
                item["mime_types"].append(mime)
        item["query_parameters"] = sorted(set(item["query_parameters"] + _query_names(request.get("url"))))[:100]
        if len(item["evidence"]) < 20:
            item["evidence"].append(_ref("imported-network.har", f"log.entries[{index}]"))
    for item in observations.values():
        item["statuses"].sort()
        item["mime_types"].sort()
    return {
        "observations": list(observations.values()),
        "entries_total": len(entries), "entries_considered": min(len(entries), MAX_HAR_ENTRIES),
        "entries_skipped": skipped, "truncated": len(entries) > MAX_HAR_ENTRIES,
        "privacy": "URL credentials, query values, fragments, headers, cookies, request bodies, response bodies and timestamps were omitted. Likely sensitive path segments were redacted.",
    }


class _Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], dict] = {}
        self.truncated = False

    def node(self, kind: str, label, **attributes) -> str | None:
        label = _text(label, 1200)
        if not label:
            return None
        node_id = _identifier(kind + "\0" + label, kind)
        if node_id not in self.nodes:
            if len(self.nodes) >= MAX_GRAPH_NODES:
                self.truncated = True
                return None
            self.nodes[node_id] = {"id": node_id, "kind": kind, "label": label, **attributes}
        return node_id

    def edge(self, source, target, relation: str, evidence=None, basis="static-observed"):
        if source not in self.nodes or target not in self.nodes:
            return
        key = (source, target, relation)
        if key not in self.edges:
            if len(self.edges) >= MAX_GRAPH_EDGES:
                self.truncated = True
                return
            self.edges[key] = {"source": source, "target": target, "relation": relation, "basis": basis, "evidence": []}
        if isinstance(evidence, dict) and evidence not in self.edges[key]["evidence"] and len(self.edges[key]["evidence"]) < 10:
            self.edges[key]["evidence"].append(evidence)

    def export(self):
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values()), "truncated": self.truncated}


def _source_index(runs: list[dict], output: Path, warnings: list[str]) -> list[dict]:
    root = output.resolve()
    indexed = {}
    for run in runs:
        for item in _records(run.get("source_index"), MAX_SOURCE_FILES):
            name = _text(item.get("path"), 1000).replace("\\", "/")
            parsed = PurePosixPath(name)
            if not name or parsed.is_absolute() or ".." in parsed.parts or re.match(r"^[A-Za-z]:", name):
                warnings.append("An unsafe source index path was omitted.")
                continue
            file = root / name
            try:
                if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(root):
                    warnings.append("A missing or unsafe source index artifact was omitted.")
                    continue
                record = {
                    "path": name, "language": _text(item.get("language"), 80),
                    "lines": max(_integer(item.get("lines"), 0), 0),
                    "source": _text(item.get("source"), 500),
                    "kind": _text(item.get("kind"), 80), "size_bytes": file.stat().st_size,
                }
                indexed[name] = record
            except OSError:
                warnings.append("A source artifact could not be read for indexing.")
            if len(indexed) >= MAX_SOURCE_FILES:
                warnings.append("Source index reached its file limit.")
                return list(indexed.values())
    return list(indexed.values())


_FEATURE_RULES = (
    ("network_requests", "Network requests", ("Ljava/net/", "Lokhttp3/", "Lretrofit2/", "Lorg/apache/http/")),
    ("media_playback", "Media playback", ("Landroid/media/MediaPlayer;", "Lcom/google/android/exoplayer2/", "Landroidx/media3/")),
    ("web_content", "Embedded web content", ("Landroid/webkit/WebView;",)),
    ("local_storage", "Local storage", ("Landroid/content/SharedPreferences", "Landroid/database/sqlite/", "Landroidx/room/")),
    ("cryptography", "Cryptographic operations", ("Ljavax/crypto/", "Ljava/security/MessageDigest;", "Landroid/security/keystore/")),
    ("location", "Location access", ("Landroid/location/", "Lcom/google/android/gms/location/")),
    ("notifications", "Notifications", ("Landroid/app/NotificationManager;", "Landroidx/core/app/NotificationManagerCompat;")),
    ("background_work", "Background work", ("Landroidx/work/", "Landroid/app/job/JobScheduler;")),
    ("camera", "Camera access", ("Landroid/hardware/Camera", "Landroid/hardware/camera2/", "Landroidx/camera/")),
    ("dynamic_code", "Dynamic class loading", ("Ldalvik/system/DexClassLoader;", "Ldalvik/system/InMemoryDexClassLoader;")),
)


def build_evidence(inspection: dict, runs, output: str | Path, har_path: str | Path | None = None) -> dict:
    """Create deterministic links, capability hypotheses and honest coverage.

    ``runs`` accepts an embedded-engine summary or a list of summaries. External
    CLI success flags are not used as evidence of any application functionality.
    """
    summaries = [runs] if isinstance(runs, dict) else _records(runs or [], 100)
    warnings: list[str] = []
    graph, findings, functionality = _Graph(), [], []

    def finding(key, title, statement, basis, refs, confidence="direct"):
        value = {"id": _identifier(key, "F"), "title": title, "statement": statement, "basis": basis,
                 "confidence": confidence, "evidence": refs[:40]}
        findings.append(value)
        return value["id"]

    package = inspection.get("package") if isinstance(inspection.get("package"), dict) else {}
    package_name = _text(package.get("package_name"), 500)
    package_node = graph.node("package", package_name or "Unresolved package")
    if package_name:
        finding("identity", "Package identity", "The manifest identifies the package as " + package_name + ".",
                "static-observed", [_ref("AndroidManifest.xml", "manifest/@package")])
    else:
        finding("identity", "Package identity unresolved", "The available parser output did not resolve a package name.",
                "unknown", [], "unknown")

    signatures = inspection.get("signatures", {})
    verification = signatures.get("verification") if isinstance(signatures, dict) else None
    if verification in {"v2-valid", "v2-invalid"}:
        statement = ("The APK v2 signatures and protected-content digests passed the implemented cryptographic checks. "
                     if verification == "v2-valid" else
                     "The APK did not pass the implemented v2 integrity checks: " + _text(signatures.get("reason"), 1000) + ". ")
        statement += "This does not assess publisher trust, v1/v3/v4 schemes, or complete Android installation acceptance."
        finding("v2-signatures", "APK v2 integrity: " + verification, statement, "static-observed",
                [_ref("APK signing block", "APK Signature Scheme v2 / protected-content digest")], "cryptographic-check")
        for signer in _records(signatures.get("signers"), 32):
            fingerprint = _text(signer.get("certificate_sha256"), 128)
            if fingerprint:
                signer_node = graph.node("signer", fingerprint)
                graph.edge(package_node, signer_node, "v2_signer", _ref("APK signing block", "certificate SHA-256"))
    elif verification:
        finding("v2-signatures", "APK v2 integrity not established", _text(signatures.get("reason"), 1000) +
                " Missing v2 evidence is not proof that the APK is unsigned; other schemes may be present.",
                "unknown", [_ref("APK signing block", "APK Signature Scheme v2")], "unknown")

    components = _records(inspection.get("components"))
    component_names = {}
    for index, component in enumerate(components):
        name, kind = _text(component.get("name"), 600), _text(component.get("type"), 80)
        if not name:
            continue
        node = graph.node("component", name, component_type=kind, exported=component.get("exported") if isinstance(component.get("exported"), (bool, str)) else None)
        full_name = (package_name + name if name.startswith(".") else
                     package_name + "." + name if "." not in name and package_name else name)
        component_names[name] = node
        component_names[full_name] = node
        graph.edge(package_node, node, "declares", _ref("AndroidManifest.xml", kind + "/@android:name=" + name))
    if components:
        counts = Counter(_text(c.get("type"), 80) or "component" for c in components)
        finding("components", "Declared Android entry points", "The manifest declares " + ", ".join(f"{n} {kind}" for kind, n in sorted(counts.items())) + ". Declared activities do not prove all screen flows are reachable.",
                "static-observed", [_ref("AndroidManifest.xml", "manifest/application")])
    permissions = sorted({_text(p, 300) for p in inspection.get("permissions", [])[:1000] if isinstance(p, str)}) if isinstance(inspection.get("permissions"), list) else []
    for permission in permissions:
        node = graph.node("permission", permission)
        graph.edge(package_node, node, "requests_permission", _ref("AndroidManifest.xml", "uses-permission/@android:name=" + permission))
    if permissions:
        finding("permissions", "Requested permissions", f"The manifest requests {len(permissions)} distinct permissions. A request is not evidence that permission was granted or used.",
                "static-observed", [_ref("AndroidManifest.xml", "uses-permission")])

    classes, methods, calls, cfg = [], [], [], []
    for run in summaries:
        classes.extend(_records(run.get("classes")))
        methods.extend(_records(run.get("methods")))
        calls.extend(_records(run.get("calls")))
        cfg.extend(_records(run.get("cfg")))
        for warning in run.get("warnings", [])[:100] if isinstance(run.get("warnings"), list) else []:
            if isinstance(warning, str):
                warnings.append(_text(warning, 1000))
    for sequence in (classes, methods, calls, cfg):
        if len(sequence) > MAX_ITEMS:
            del sequence[MAX_ITEMS:]
            warnings.append("Evidence indexing reached its item limit; totals describe indexed evidence only.")

    class_nodes, method_nodes = {}, {}
    for cls in classes:
        name = _text(cls.get("name"), 1000)
        if not name:
            continue
        node = graph.node("class", name)
        class_nodes[name] = node
        graph.edge(package_node, node, "contains_class", _ref(cls.get("source", "DEX"), name))
        dotted = name[1:-1].replace("/", ".") if name.startswith("L") and name.endswith(";") else name
        component = component_names.get(dotted)
        if component:
            graph.edge(component, node, "class_name_match", _ref(cls.get("source", "DEX"), name))
        superclass = _text(cls.get("superclass"), 1000)
        if superclass:
            parent = graph.node("class", superclass)
            graph.edge(node, parent, "extends", _ref(cls.get("source", "DEX"), name))
    for method in methods:
        identity = _text(method.get("id"), 1200)
        if not identity:
            continue
        node = graph.node("method", identity, external=bool(method.get("external", False)))
        method_nodes[identity] = node
        classname = _text(method.get("class"), 1000)
        parent = class_nodes.get(classname) or graph.node("class", classname)
        graph.edge(parent, node, "declares_method", _ref(method.get("source", "DEX"), identity, offset=method.get("offset"), offset_kind=method.get("offset_kind")))
    for call in calls:
        caller, callee = _text(call.get("caller"), 1200), _text(call.get("callee"), 1200)
        if not caller or not callee:
            continue
        start = method_nodes.get(caller) or graph.node("method", caller)
        end = method_nodes.get(callee) or graph.node("method", callee)
        graph.edge(start, end, "static_call", _ref(call.get("source", "DEX"), caller + " -> " + callee, offset=call.get("offset"), offset_kind=call.get("offset_kind")))
    if classes or methods:
        finding("dex-structures", "DEX structure and static references", f"Indexed {len(classes)} class records, {len(methods)} method records, {len(calls)} static call records and {len(cfg)} method control-flow graphs. Static references do not establish execution order across components or all runtime targets.",
                "static-observed", [_ref(c.get("source", "DEX"), c.get("name", "class")) for c in classes[:8]])
    elif inspection.get("dex"):
        finding("dex-unresolved", "DEX semantics unavailable", "DEX files are present but no class or method analysis was supplied. Application behavior cannot be inferred from a DEX filename.", "unknown", [], "unknown")

    for key, title, prefixes in _FEATURE_RULES:
        matching = [call for call in calls if _text(call.get("callee")).startswith(prefixes)]
        if not matching:
            continue
        refs = [_ref(c.get("source", "DEX"), _text(c.get("caller")) + " -> " + _text(c.get("callee")), offset=c.get("offset"), offset_kind=c.get("offset_kind")) for c in matching[:20]]
        fid = finding("feature:" + key, title + " — static capability hypothesis",
            f"{len(matching)} indexed call references are consistent with {title.lower()}. These calls may be unreachable, belong to a bundled library, or depend on runtime conditions; this is not a claim that the behavior occurred.", "inferred", refs, "static-indicators")
        functionality.append({"id": key, "name": title, "basis": "inferred", "finding_ids": [fid],
                              "static_call_count": len(matching), "runtime_verified": False})

    endpoint_candidates, endpoint_nodes = [], {}
    seen_urls = set()
    for item in _records(inspection.get("urls"), 5000):
        safe = sanitize_url(item.get("url"))
        source = _text(item.get("source"), 600)
        offset = _integer(item.get("offset"))
        key = (safe, source, offset)
        if not safe or key in seen_urls:
            continue
        seen_urls.add(key)
        reference = _ref(source, "URL string", offset=offset, offset_kind="file-byte-offset")
        endpoint_candidates.append({"url": safe, "basis": "static-observed", "evidence": [reference], "request_confirmed": False})
        node = graph.node("endpoint", safe)
        endpoint_nodes[safe] = node
        file_node = graph.node("file", source)
        graph.edge(file_node, node, "contains_url_string", reference)
    if endpoint_candidates:
        finding("static-endpoints", "URL strings in the package", f"Found {len(endpoint_candidates)} indexed URL occurrences. A URL string can be unused, documentation, or a library constant; it does not prove an API call or reveal server implementation.",
                "static-observed", [x["evidence"][0] for x in endpoint_candidates[:20]])

    har_meta, api_observations = None, []
    if har_path is not None:
        try:
            har_meta = import_har(har_path)
            api_observations = har_meta.pop("observations")
        except (OSError, ValueError) as exc:
            warnings.append("Traffic import failed: " + _text(str(exc), 500))
            finding("traffic-import-failed", "Traffic import unavailable", "The supplied HAR could not be imported. No runtime network conclusions were produced.", "unknown", [], "unknown")
        else:
            capture_node = graph.node("capture", "imported-network.har")
            for observation in api_observations:
                node = endpoint_nodes.get(observation["url"]) or graph.node("endpoint", observation["url"])
                for reference in observation["evidence"]:
                    graph.edge(capture_node, node, "recorded_request", reference, basis="runtime-imported")
                observation["matches_static_url"] = observation["url"] in endpoint_nodes
            finding("traffic-imported", "Imported HTTP observations", f"The supplied HAR contains {sum(o['count'] for o in api_observations)} accepted request records grouped into {len(api_observations)} method/endpoint observations. Their capture origin and association with this APK were not independently verified.",
                    "runtime-imported", [_ref("imported-network.har", "log.entries")], "supplied-capture")
            if har_meta["truncated"]:
                warnings.append("HAR import reached its request limit; later entries were not analyzed.")
    else:
        warnings.append("No HAR was supplied. No runtime network behavior was observed by this analysis.")

    natives = _records(inspection.get("native_libraries"), 5000)
    for native in natives:
        path = _text(native.get("path"), 1000)
        node = graph.node("native_library", path, abi=_text(native.get("abi"), 80))
        graph.edge(package_node, node, "contains_native_library", _ref(path, "archive entry"))
    if natives:
        finding("native-libraries", "Native library inventory", f"The APK contains {len(natives)} indexed native libraries. Library presence alone does not identify all native behavior, downloaded modules, or runtime loading.", "static-observed", [_ref(n.get("path"), "archive entry") for n in natives[:20]])
    sources = _source_index(summaries, Path(output), warnings)
    if sources:
        finding("reconstructed-sources", "Reconstructed source artifacts", f"Indexed {len(sources)} generated source/disassembly artifacts. Decompiled text is a reconstruction and is not guaranteed to compile or match the original source.", "static-observed", [_ref(s["path"], s["kind"]) for s in sources[:20]])

    finding("backend-unknown", "Backend implementation remains unknown", "APK structures and supplied HTTP metadata cannot establish private server source, database schema, authorization logic, or hidden business rules. Those require backend evidence.", "unknown", [], "unknown")
    limitations = [
        "The graph records static declarations and call references, not a complete runtime execution trace.",
        "Reflection, obfuscation, downloaded code, native indirection and runtime configuration can hide behavior.",
        "Source reconstruction and functionality hypotheses require validation against an authorized test build.",
        "An imported capture is not independently bound to this APK or verified as a successful transaction.",
    ]
    limitations.extend(dict.fromkeys(warnings))
    if graph.truncated:
        limitations.append("The evidence graph reached its size limit and is incomplete.")
    engine_coverage = [r.get("coverage") for r in summaries if isinstance(r.get("coverage"), dict)]
    return {
        "schema_version": 2, "findings": findings, "functionality": functionality,
        "api_observations": api_observations, "endpoint_candidates": endpoint_candidates,
        "source_index": sources, "graph": graph.export(),
        "coverage": {
            "manifest_identity_resolved": bool(package_name), "components_indexed": len(components),
            "permissions_indexed": len(permissions), "classes_indexed": len(classes),
            "methods_indexed": len(methods), "static_calls_indexed": len(calls), "cfg_methods_indexed": len(cfg),
            "native_libraries_indexed": len(natives), "source_artifacts_indexed": len(sources),
            "runtime_executed": False, "har_imported": har_meta is not None,
            "har": har_meta, "backend_source_available": False, "complete_functionality_claimed": False,
            "engine_coverage": engine_coverage, "graph_truncated": graph.truncated,
        },
        "limitations": limitations,
    }
