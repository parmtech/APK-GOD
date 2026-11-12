"""Integrated APK analysis using direct, embedded library interfaces.

Androguard owns DEX decoding, cross references and DAD reconstruction. APK GOD
owns bounds, normalization, provenance, file exports and coverage accounting.
No executable discovery or external tool command is involved in this module.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import re
import struct
import time
import zipfile
import zlib
from pathlib import Path

from .inspect_apk import DEX_NAME, decode_xml, inspect_apk, read_member, validate_archive
from .native import analyze_native, reconstruct_native

PROFILES = {
    "quick": {"dex_bytes": 16 * 1024**2, "total_dex_bytes": 32 * 1024**2,
              "classes": 1000, "methods": 6000, "calls": 20_000, "instructions": 30_000,
              "instructions_per_method": 500, "decompile_classes": 50, "source_bytes": 4 * 1024**2,
              "native_libraries": 8, "native_instructions": 3000, "seconds": 45},
    "standard": {"dex_bytes": 48 * 1024**2, "total_dex_bytes": 96 * 1024**2,
                 "classes": 5000, "methods": 30_000, "calls": 100_000, "instructions": 200_000,
                 "instructions_per_method": 3000, "decompile_classes": 500, "source_bytes": 32 * 1024**2,
                 "native_libraries": 32, "native_instructions": 20_000, "seconds": 180},
    "deep": {"dex_bytes": 96 * 1024**2, "total_dex_bytes": 256 * 1024**2,
             "classes": 20_000, "methods": 120_000, "calls": 500_000, "instructions": 1_000_000,
             "instructions_per_method": 10_000, "decompile_classes": 3000, "source_bytes": 128 * 1024**2,
             "native_libraries": 128, "native_instructions": 100_000, "seconds": 600},
}


def _version(distribution: str):
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def _method_id(method) -> str:
    return f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}"


def _class_basename(name: str) -> str:
    short = name.rstrip(";").split("/")[-1][:70]
    safe = re.sub(r"[^A-Za-z0-9_$-]", "_", short) or "class"
    return hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:12] + "_" + safe


def _write_source(output: Path, relative: str, text: str, source: str,
                  language: str, kind: str) -> dict:
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")
    return {"path": relative, "language": language, "lines": text.count("\n") + bool(text and not text.endswith("\n")),
            "source": source, "kind": kind, "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()}


def _validate_dex(raw: bytes) -> dict:
    if len(raw) < 112 or raw[:4] != b"dex\n" or raw[7] != 0:
        raise ValueError("Invalid or truncated DEX header.")
    version = raw[4:7].decode("ascii", "replace")
    if version not in {"035", "036", "037", "038", "039", "040"}:
        raise ValueError(f"DEX version {version} is outside the embedded parser's supported range.")
    file_size, header_size, endian_tag = struct.unpack_from("<III", raw, 32)
    if file_size != len(raw) or header_size != 112 or endian_tag != 0x12345678:
        raise ValueError("DEX size, header size, or byte order is unsupported/inconsistent.")
    # Validate fixed-size tables before handing counts to an embedded parser.
    for count_offset, entry_size, hard_cap in ((56, 4, 1_000_000), (64, 4, 65536),
                                             (72, 12, 65536), (80, 8, 65536),
                                             (88, 8, 65536), (96, 32, 65536)):
        count, offset = struct.unpack_from("<II", raw, count_offset)
        if count > hard_cap or (count and (offset < 112 or offset + count * entry_size > len(raw))):
            raise ValueError("DEX table bounds or count limit exceeded.")
    return {"version": version, "sha256": hashlib.sha256(raw).hexdigest(),
            "header_sha1_matches": hashlib.sha1(raw[32:]).digest() == raw[12:32],
            "header_adler32_matches": (zlib.adler32(raw[12:]) & 0xffffffff) == struct.unpack_from("<I", raw, 8)[0]}


def analyze_engines(apk_path: str | Path, output_dir: str | Path, profile: str = "standard",
                    *, inspection: dict | None = None) -> dict:
    if profile not in PROFILES:
        raise ValueError("Choose quick, standard, or deep analysis.")
    apk, output = Path(apk_path), Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    limits = dict(PROFILES[profile])
    started = time.monotonic()
    inspection = inspection if inspection is not None else inspect_apk(apk)
    result = {"id": "embedded-analysis", "status": "completed", "profile": profile,
              "engines": [], "source_index": [], "classes": [], "methods": [], "calls": [], "cfg": [],
              "native": [], "dex": [], "resources": [], "warnings": [],
              "native_reconstruction": {"status": "not-requested", "library_limit": 2,
                                        "functions_per_library_limit": 10, "libraries": [],
                                        "automatic_symbolic_exploration": False},
              "coverage": {"limits": limits, "truncated": False, "limit_reasons": [],
                           "dex_entries_total": len(inspection.get("dex", [])), "dex_entries_parsed": 0,
                           "classes_total": 0, "methods_total": 0, "instructions_exported": 0,
                           "classes_decompiled": 0, "source_bytes_written": 0},
              "versions": {name: _version(name) for name in ("androguard", "lief", "capstone")}}
    coverage = result["coverage"]

    def limited(reason):
        coverage["truncated"] = True
        if reason not in coverage["limit_reasons"]:
            coverage["limit_reasons"].append(reason)
        result["status"] = "partial"

    def time_left():
        if time.monotonic() - started > limits["seconds"]:
            limited("Profile processing time budget reached between library calls.")
            return False
        return True

    def save(relative, text, source, language, kind):
        size = len(text.encode("utf-8", "replace"))
        if coverage["source_bytes_written"] + size > limits["source_bytes"]:
            limited("Source export byte limit reached.")
            return None
        record = _write_source(output, relative, text, source, language, kind)
        result["source_index"].append(record)
        coverage["source_bytes_written"] += size
        return record

    manifest = inspection.get("manifest_xml")
    if manifest:
        save("source/AndroidManifest.xml", manifest, "AndroidManifest.xml", "xml", "decoded-resource")
    result["engines"].append({"id": "manifest", "status": "completed" if manifest else "partial",
                              "message": "Manifest decoded in process." if manifest else "Manifest decoding unavailable or failed."})
    if not manifest:
        result["status"] = "partial"
    with zipfile.ZipFile(apk) as archive:
        entries = validate_archive(archive)
        # Decode bounded XML resources and exported string tables directly.
        resource_count = 0
        for entry in entries:
            if not time_left():
                break
            if not entry.filename.startswith("res/") or not entry.filename.endswith(".xml"):
                continue
            if resource_count >= (100 if profile == "quick" else 1000):
                limited("Decoded XML resource limit reached.")
                break
            resource_count += 1
            if entry.file_size > 2 * 1024**2:
                limited("An XML resource exceeded the per-member decoding limit.")
                continue
            _, text, warning = decode_xml(read_member(archive, entry, 2 * 1024**2))
            if text:
                # The archive path passed traversal/symlink validation. A hash
                # avoids Windows reserved basenames and path length surprises.
                slug = hashlib.sha256(entry.filename.encode()).hexdigest()[:20]
                saved = save(f"source/resources/{slug}.xml", text, entry.filename, "xml", "decoded-resource")
                if saved:
                    result["resources"].append({"source": entry.filename, "path": saved["path"]})
            elif warning:
                result["warnings"].append(f"{entry.filename}: {warning}")
                result["status"] = "partial"
        if "resources.arsc" in archive.namelist() and time_left():
            try:
                from androguard.core.axml import ARSCParser
                from loguru import logger
                logger.disable("androguard")
                raw_arsc = read_member(archive, "resources.arsc", 32 * 1024**2)
                resources = ARSCParser(raw_arsc)
                exported = 0
                for package in resources.get_packages_names():
                    for locale in resources.get_locales(package):
                        if exported >= 100 or not time_left():
                            limited("Resource string-table export limit reached.")
                            break
                        data = resources.get_string_resources(package, locale)
                        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
                        slug = hashlib.sha256((package + locale).encode()).hexdigest()[:20]
                        saved = save(f"source/resources/strings_{slug}.xml", text, "resources.arsc", "xml", "decoded-resource")
                        if saved:
                            result["resources"].append({"source": "resources.arsc", "package": package,
                                                        "locale": locale.replace("\x00", ""), "path": saved["path"]})
                        exported += 1
            except ImportError:
                result["warnings"].append("Embedded Androguard is missing; compiled resource tables were not decoded.")
                result["status"] = "partial"
            except Exception as exc:
                result["warnings"].append(f"Compiled resource-table decoding failed ({type(exc).__name__}).")
                result["status"] = "partial"
        result["engines"].append({"id": "resources", "status": "completed" if result["resources"] else "not-applicable",
                                  "counts": {"decoded_exports": len(result["resources"])},
                                  "message": "Direct XML and resource-table decoding; export limits are recorded in coverage."})

        dex_entries = [e for e in entries if DEX_NAME.fullmatch(e.filename)]
        parsed = []
        analysis = None
        dex_started = time.monotonic()
        if dex_entries:
            try:
                from androguard.core.dex import DEX
                from androguard.core.analysis.analysis import Analysis
                from androguard.decompiler.decompiler import DecompilerDAD
                from loguru import logger
                logger.disable("androguard")
                analysis = Analysis()
                total_read = 0
                for entry in dex_entries:
                    if not time_left():
                        break
                    if entry.file_size > limits["dex_bytes"] or total_read + entry.file_size > limits["total_dex_bytes"]:
                        limited(f"DEX byte limit prevented parsing {entry.filename}.")
                        continue
                    try:
                        raw = read_member(archive, entry, limits["dex_bytes"])
                        total_read += len(raw)
                        metadata = _validate_dex(raw)
                        vm = DEX(raw)
                        analysis.add(vm)
                        parsed.append((entry.filename, vm))
                        metadata.update(source=entry.filename, status="completed", classes=len(vm.get_classes()),
                                        methods=len(list(vm.get_encoded_methods())))
                        coverage["classes_total"] += metadata["classes"]
                        coverage["methods_total"] += metadata["methods"]
                        result["dex"].append(metadata)
                        coverage["dex_entries_parsed"] += 1
                        if not metadata["header_sha1_matches"] or not metadata["header_adler32_matches"]:
                            result["warnings"].append(f"{entry.filename}: DEX header digest/checksum does not match the bytes.")
                    except Exception as exc:
                        result["dex"].append({"source": entry.filename, "status": "failed", "reason": type(exc).__name__})
                        result["warnings"].append(f"{entry.filename}: DEX decoding failed ({type(exc).__name__}).")
                        result["status"] = "partial"
                if parsed and time_left():
                    analysis.create_xref()
                else:
                    analysis = None
            except ImportError:
                result["warnings"].append("Embedded Androguard is not installed; DEX code analysis was not performed.")
                result["status"] = "partial"
            except Exception as exc:
                result["warnings"].append(f"DEX cross-reference construction failed ({type(exc).__name__}).")
                result["status"] = "partial"
                analysis = None
        if parsed and analysis is not None:
            package = inspection.get("package", {}).get("package_name") or ""
            preferred = "L" + package.replace(".", "/") + "/" if package else None
            class_work = []
            for source, vm in parsed:
                vm.set_decompiler(DecompilerDAD(vm, analysis))
                for item in vm.get_classes():
                    class_work.append((source, item))
            # Export application classes before bundled dependencies under caps.
            class_work.sort(key=lambda x: (not (preferred and x[1].get_name().startswith(preferred)), x[0], x[1].get_name()))
            for source, cls in class_work:
                if not time_left():
                    break
                if len(result["classes"]) >= limits["classes"]:
                    limited("Class export limit reached.")
                    break
                name = cls.get_name()
                class_record = {"name": name, "superclass": cls.get_superclassname(), "source": source,
                                "methods": len(cls.get_methods()), "interfaces": list(cls.get_interfaces())}
                result["classes"].append(class_record)
                dalvik = [f"# APK GOD decoded DEX instructions — {source}", f".class {name}",
                          f".super {cls.get_superclassname()}", "# This text is an inspection listing, not guaranteed reassemblable smali."]
                for method in cls.get_methods():
                    if not time_left():
                        break
                    if len(result["methods"]) >= limits["methods"]:
                        limited("Method export limit reached.")
                        break
                    method_id = _method_id(method)
                    record = {"id": method_id, "class": name, "name": method.get_name(),
                              "descriptor": method.get_descriptor(), "access": method.get_access_flags_string(),
                              "source": source, "offset": int(method.get_code_off()),
                              "offset_kind": "dex-code-item-byte-offset", "instructions": []}
                    result["methods"].append(record)
                    dalvik.append(f"\n.method {record['access']} {record['name']}{record['descriptor']}")
                    count = 0
                    try:
                        for offset, instruction in method.get_instructions_idx():
                            if count >= limits["instructions_per_method"] or coverage["instructions_exported"] >= limits["instructions"]:
                                record["instructions_truncated"] = True
                                limited("DEX instruction export limit reached.")
                                break
                            text = instruction.get_output()
                            item = {"offset": int(offset), "offset_kind": "instruction-byte-offset-within-method",
                                    "opcode": instruction.get_name(), "operands": text[:4096]}
                            record["instructions"].append(item)
                            dalvik.append(f"  {offset:06x}: {item['opcode']} {item['operands']}")
                            count += 1
                            coverage["instructions_exported"] += 1
                        method_analysis = analysis.get_method(method)
                        if method_analysis is not None:
                            for _, callee, call_offset in sorted(method_analysis.get_xref_to(), key=lambda x: (x[2], _method_id(x[1].get_method()))):
                                if len(result["calls"]) >= limits["calls"]:
                                    limited("Call-reference export limit reached.")
                                    break
                                result["calls"].append({"caller": method_id, "callee": _method_id(callee.get_method()),
                                                         "source": source, "offset": int(call_offset),
                                                         "offset_kind": "instruction-byte-offset-within-method",
                                                         "external": bool(callee.is_external())})
                            blocks = []
                            for index, block in enumerate(method_analysis.get_basic_blocks().gets()):
                                if index >= 2000:
                                    limited("Basic-block limit reached for an individual method.")
                                    break
                                blocks.append({"id": int(block.get_start()), "start": int(block.get_start()),
                                               "end": int(block.get_end()),
                                               "successors": sorted({int(edge[2].get_start()) for edge in block.get_next()})})
                            if blocks:
                                result["cfg"].append({"method": method_id, "source": source, "blocks": blocks,
                                                      "offset_kind": "instruction-byte-offset-within-method", "end_exclusive": True})
                    except Exception as exc:
                        record["analysis_error"] = type(exc).__name__
                        result["status"] = "partial"
                    dalvik.append(".end method")
                basename = _class_basename(name)
                dex_folder = source.removesuffix(".dex")
                saved = save(f"source/dalvik/{dex_folder}/{basename}.dalvik", "\n".join(dalvik) + "\n", source, "dalvik", "disassembly")
                if saved:
                    class_record["disassembly_path"] = saved["path"]
                if coverage["classes_decompiled"] < limits["decompile_classes"] and time_left():
                    try:
                        source_text = cls.get_source()
                        if source_text:
                            source_text = ("// Reconstructed by embedded Androguard DAD. Not original source; may not compile.\n"
                                           + source_text)
                            saved = save(f"source/java/{dex_folder}/{basename}.java", source_text, source, "java", "reconstructed")
                            if saved:
                                class_record["source_path"] = saved["path"]
                                coverage["classes_decompiled"] += 1
                    except Exception as exc:
                        class_record["decompilation_error"] = type(exc).__name__
                        result["warnings"].append(f"Java-like reconstruction failed for {name[:200]} ({type(exc).__name__}).")
                        result["status"] = "partial"
                else:
                    limited("Java-like class reconstruction limit reached.")
            if len(result["methods"]) < coverage["methods_total"]:
                limited("Some method definitions were not exported under the selected limits.")
        if dex_entries and coverage["dex_entries_parsed"] < len(dex_entries):
            result["status"] = "partial"
        result["engines"].append({"id": "dex", "status": ("not-applicable" if not dex_entries else
                                  "completed" if analysis is not None and not coverage["truncated"] else "partial"),
                                  "duration_seconds": round(time.monotonic() - dex_started, 3),
                                  "counts": {"classes": len(result["classes"]), "methods": len(result["methods"]),
                                             "calls": len(result["calls"]), "decompiled_classes": coverage["classes_decompiled"]},
                                  "message": "Embedded DEX parsing, static call references, basic blocks and Java-like reconstruction."})
        native_entries = [e for e in entries if e.filename.startswith("lib/") and e.filename.endswith(".so")]
        native_instruction_count = 0
        reconstruction = result["native_reconstruction"]
        if profile == "deep":
            reconstruction["status"] = "not-applicable" if not native_entries else "pending"
        for index, entry in enumerate(native_entries):
            if index >= limits["native_libraries"] or not time_left():
                limited("Native-library analysis limit reached.")
                break
            try:
                raw = read_member(archive, entry, 64 * 1024**2)
                remaining_source = max(0, limits["source_bytes"] - coverage["source_bytes_written"])
                instruction_budget = min(limits["native_instructions"] - native_instruction_count,
                                         remaining_source // 256)
                if instruction_budget <= 0:
                    limited("Native instruction/source export budget reached.")
                item = analyze_native(raw, entry.filename, output,
                                      max_instructions=max(0, instruction_budget), max_symbols=20_000)
                native_instruction_count += item.get("instruction_count", 0)
                result["native"].append(item)
                native_sources = item.pop("source_index", [])
                result["source_index"].extend(native_sources)
                for exported in native_sources:
                    coverage["source_bytes_written"] += (output / exported["path"]).stat().st_size
                if item["status"] != "completed":
                    result["status"] = "partial"
                if profile == "deep" and len(reconstruction["libraries"]) < reconstruction["library_limit"] and time_left():
                    remaining_source = max(0, limits["source_bytes"] - coverage["source_bytes_written"])
                    if remaining_source == 0:
                        limited("No shared source-export budget remains for native C-like reconstruction.")
                    else:
                        reconstructed = reconstruct_native(raw, entry.filename, output, max_functions=10,
                                                           source_byte_limit=remaining_source)
                        reconstruction["libraries"].append(reconstructed)
                        generated = reconstructed.get("source_index", [])
                        result["source_index"].extend(generated)
                        for exported in generated:
                            coverage["source_bytes_written"] += (output / exported["path"]).stat().st_size
                        item["reconstruction"] = {
                            "status": reconstructed["status"],
                            "functions_reconstructed": reconstructed.get("coverage", {}).get("functions_reconstructed", 0),
                            "source_paths": [x["path"] for x in generated],
                        }
                        if reconstructed["status"] not in {"completed", "not-applicable"}:
                            result["status"] = "partial"
            except Exception as exc:
                result["native"].append({"source": entry.filename, "status": "failed", "warnings": [type(exc).__name__]})
                result["status"] = "partial"
        result["engines"].append({"id": "native", "status": "not-applicable" if not native_entries else
                                  "completed" if len(result["native"]) == len(native_entries)
                                  and all(x["status"] == "completed" for x in result["native"]) else "partial",
                                  "counts": {"libraries": len(result["native"]), "total_libraries": len(native_entries)},
                                  "message": "Embedded ELF metadata, symbols, dependencies and bounded native disassembly; no native decompilation."})
        if profile == "deep" and native_entries:
            results = reconstruction["libraries"]
            if not results:
                reconstruction["status"] = "not-run"
                limited("Native C-like reconstruction did not run within the available time/source budget.")
            elif all(x["status"] == "unavailable" for x in results):
                reconstruction["status"] = "unavailable"
            elif any(x["status"] != "completed" for x in results) or len(results) < len(native_entries):
                reconstruction["status"] = "partial"
            else:
                reconstruction["status"] = "completed"
            if len(native_entries) > reconstruction["library_limit"]:
                limited("Deep native C-like reconstruction is limited to two libraries per APK.")
            result["engines"].append({
                "id": "native-reconstruction", "status": reconstruction["status"],
                "counts": {"libraries_attempted": len(results), "total_libraries": len(native_entries),
                           "functions_reconstructed": sum(x.get("coverage", {}).get("functions_reconstructed", 0) for x in results)},
                "message": "Embedded native C-like reconstruction in deep mode; no automatic symbolic exploration.",
            })
    coverage.update(classes_exported=len(result["classes"]), methods_exported=len(result["methods"]),
                    calls_exported=len(result["calls"]), cfg_methods_exported=len(result["cfg"]),
                    native_libraries_analyzed=len(result["native"]), native_instructions_exported=native_instruction_count)
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    result["message"] = "Direct embedded-library analysis. Coverage and unsupported operations remain explicit."
    return result
