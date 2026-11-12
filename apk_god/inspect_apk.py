"""Bounded, in-process APK inventory and Android manifest decoding.

No archive member is extracted or executed. Binary XML is decoded through the
embedded Androguard library; the dependency-free path still inventories ZIPs
and reads text manifests. All names and strings remain untrusted evidence.
"""
from __future__ import annotations

import hashlib
import re
import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

MAX_APK_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_SCAN_TOTAL = 32 * 1024 * 1024
MAX_URLS = 3000
ANDROID = "{http://schemas.android.com/apk/res/android}"
DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z")
URL_RE = re.compile(rb"(?:https?|wss?)://[^\s\x00-\x20<>\"'\\]{3,2048}", re.I)


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_archive(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Check resource limits and reject ambiguous/dangerous archive names."""
    entries = archive.infolist()
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"APK contains more than {MAX_ENTRIES:,} entries.")
    total = 0
    names: set[str] = set()
    for info in entries:
        name = info.filename
        normal = name.replace("\\", "/")
        parts = PurePosixPath(normal).parts
        if (not name or "\x00" in name or name != normal or normal.startswith("/")
                or re.match(r"^[A-Za-z]:", normal) or ".." in parts):
            raise ValueError("APK contains an unsafe archive path.")
        # Duplicate entries have different meanings to different ZIP readers.
        if normal in names:
            raise ValueError("APK contains duplicate archive entry names.")
        names.add(normal)
        if stat.S_ISLNK(info.external_attr >> 16):
            raise ValueError("APK contains a symbolic-link archive member.")
        if info.flag_bits & 1:
            raise ValueError("Encrypted ZIP members are not supported.")
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError(f"APK member exceeds {MAX_MEMBER_BYTES // 1024**2} MiB analysis limit.")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("APK uncompressed size exceeds the 1 GiB analysis limit.")
        if info.file_size > 8 * 1024 * 1024 and info.file_size / max(info.compress_size, 1) > 1000:
            raise ValueError("APK contains a member with an excessive compression ratio.")
    return entries


def read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo | str,
                limit: int = MAX_MEMBER_BYTES) -> bytes:
    """Read at most limit bytes, also defending against inconsistent ZIP metadata."""
    entry = archive.getinfo(info) if isinstance(info, str) else info
    if entry.file_size > limit:
        raise ValueError(f"Archive member exceeds the {limit:,}-byte read limit.")
    with archive.open(entry) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Decompressed member exceeds its read limit.")
    if len(data) != entry.file_size:
        raise ValueError("Decompressed member size does not match ZIP metadata.")
    return data


def decode_xml(raw: bytes) -> tuple[ET.Element | None, str | None, str | None]:
    """Return a stdlib XML tree, serialized XML and a decoding warning."""
    if len(raw) > MAX_MANIFEST_BYTES:
        return None, None, "XML member exceeds the decoding size limit."
    trimmed = raw.lstrip(b"\xef\xbb\xbf\x00 \r\n\t")
    try:
        if trimmed.startswith(b"<"):
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ValueError("XML declarations with document types or entities are not supported.")
            tree = ET.fromstring(raw)
        else:
            try:
                from androguard.core.axml import AXMLPrinter
                from loguru import logger
                logger.disable("androguard")
            except ImportError:
                return None, None, "Binary Android XML requires the embedded Androguard dependency."
            printer = AXMLPrinter(raw)
            if not printer.is_valid():
                return None, None, "Binary Android XML could not be decoded."
            serialized = printer.get_xml(pretty=False)
            if not serialized:
                return None, None, "Binary Android XML decoder produced no document."
            tree = ET.fromstring(serialized)
        text = ET.tostring(tree, encoding="unicode")
        return tree, text, None
    except Exception as exc:
        return None, None, f"XML decoding failed ({type(exc).__name__}); manifest fields remain unknown."


def _boolean(value: str | None):
    if value is None:
        return None
    if value.lower() in {"true", "1", "0xffffffff"}:
        return True
    if value.lower() in {"false", "0", "0x0"}:
        return False
    return value  # A resource reference cannot be treated as a boolean.


def _component_name(package: str, name: str) -> str:
    if name.startswith("."):
        return package + name
    if name and "." not in name and package:
        return package + "." + name
    return name


def _manifest_fields(root: ET.Element | None) -> dict:
    result = {"package": {}, "permissions": [], "components": [], "application": {}, "features": []}
    if root is None or root.tag.split("}")[-1] != "manifest":
        return result
    package = root.get("package", "")
    sdk = root.find("uses-sdk")
    result["package"] = {
        "package_name": package or None,
        "version_name": root.get(ANDROID + "versionName"),
        "version_code": root.get(ANDROID + "versionCode"),
        "min_sdk": sdk.get(ANDROID + "minSdkVersion") if sdk is not None else None,
        "target_sdk": sdk.get(ANDROID + "targetSdkVersion") if sdk is not None else None,
    }
    result["permissions"] = sorted({
        e.get(ANDROID + "name") for e in root
        if e.tag in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
        and e.get(ANDROID + "name")
    })
    result["features"] = [{"name": e.get(ANDROID + "name"), "required": _boolean(e.get(ANDROID + "required"))}
                          for e in root.findall("uses-feature")]
    app = root.find("application")
    if app is None:
        return result
    result["application"] = {
        "name": _component_name(package, app.get(ANDROID + "name", "")) or None,
        "label": app.get(ANDROID + "label"),
        "debuggable": _boolean(app.get(ANDROID + "debuggable")),
        "allow_backup": _boolean(app.get(ANDROID + "allowBackup")),
        "uses_cleartext_traffic": _boolean(app.get(ANDROID + "usesCleartextTraffic")),
        "network_security_config": app.get(ANDROID + "networkSecurityConfig"),
    }
    for element in app:
        if element.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        filters = []
        for intent in element.findall("intent-filter"):
            filters.append({
                "actions": [x.get(ANDROID + "name") for x in intent.findall("action")],
                "categories": [x.get(ANDROID + "name") for x in intent.findall("category")],
                "data": [{key.removeprefix(ANDROID): val for key, val in x.attrib.items()}
                         for x in intent.findall("data")],
            })
        result["components"].append({
            "type": element.tag,
            "name": _component_name(package, element.get(ANDROID + "name", "")),
            "exported": _boolean(element.get(ANDROID + "exported")),
            "exported_basis": "explicit" if ANDROID + "exported" in element.attrib else "not-explicitly-declared",
            "enabled": _boolean(element.get(ANDROID + "enabled")),
            "permission": element.get(ANDROID + "permission"),
            "authorities": element.get(ANDROID + "authorities"),
            "intent_filters": filters,
            "source": "AndroidManifest.xml",
        })
    return result


def inspect_apk(path: str | Path) -> dict:
    apk = Path(path)
    if not apk.is_file():
        raise ValueError("Input must be an APK file.")
    if apk.stat().st_size > MAX_APK_BYTES:
        raise ValueError("APK exceeds the 512 MiB analysis limit.")
    result = {"sha256": _sha_file(apk), "files": [], "dex": [], "native_libraries": [],
              "urls": [], "warnings": [], "strings": [], "resources": [],
              "signatures": {"verification": "not-performed", "v1_entries": []}}
    try:
        with zipfile.ZipFile(apk) as archive:
            entries = validate_archive(archive)
            if "AndroidManifest.xml" not in archive.namelist():
                raise ValueError("ZIP does not contain AndroidManifest.xml; it is not an APK.")
            manifest = read_member(archive, "AndroidManifest.xml", MAX_MANIFEST_BYTES)
            tree, xml, warning = decode_xml(manifest)
            result.update(_manifest_fields(tree))
            result["manifest_xml"] = xml
            if warning:
                result["warnings"].append(warning)
            scanned = 0
            candidates = 0
            seen_urls: set[tuple[str, str]] = set()
            for info in entries:
                name = info.filename
                result["files"].append({"path": name, "name": name, "size_bytes": info.file_size,
                                        "compressed_bytes": info.compress_size, "crc32": f"{info.CRC:08x}"})
                if info.is_dir():
                    continue
                if DEX_NAME.fullmatch(name):
                    with archive.open(info) as handle:
                        header = handle.read(112)
                    valid_magic = len(header) >= 8 and header[:4] == b"dex\n" and header[7] == 0
                    record = {"path": name, "size_bytes": info.file_size,
                              "version": header[4:7].decode("ascii", "replace") if valid_magic else None,
                              "header_valid": valid_magic and len(header) >= 112}
                    if valid_magic and len(header) >= 112:
                        record.update({"declared_size_bytes": struct.unpack_from("<I", header, 32)[0],
                                       "declared_class_count": struct.unpack_from("<I", header, 96)[0],
                                       "declared_method_count": struct.unpack_from("<I", header, 88)[0]})
                    result["dex"].append(record)
                if name.startswith("lib/") and name.endswith(".so"):
                    result["native_libraries"].append({"path": name, "abi": name.split("/")[1] if "/" in name else None,
                                                       "size_bytes": info.file_size})
                if name.startswith("res/") or name == "resources.arsc":
                    result["resources"].append({"path": name, "size_bytes": info.file_size})
                if name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")):
                    result["signatures"]["v1_entries"].append(name)
                if not (name.endswith((".dex", ".xml", ".json", ".properties", ".txt", ".html", ".js", ".yml", ".yaml", ".so"))):
                    continue
                candidates += 1
                if scanned >= MAX_SCAN_TOTAL or len(result["urls"]) >= MAX_URLS:
                    continue
                allowance = min(MAX_SCAN_BYTES, MAX_SCAN_TOTAL - scanned)
                with archive.open(info) as handle:
                    chunk = handle.read(allowance)
                scanned += len(chunk)
                for match in URL_RE.finditer(chunk):
                    url = match.group().decode("utf-8", "replace").rstrip(").,;]}")
                    key = (url, name)
                    if key not in seen_urls:
                        result["urls"].append({"url": url, "source": name, "offset": match.start()})
                        seen_urls.add(key)
                    if len(result["urls"]) >= MAX_URLS:
                        break
            result["coverage"] = {"archive_entries": len(entries), "url_scan_bytes": scanned,
                                  "url_scan_member_limit_bytes": MAX_SCAN_BYTES,
                                  "url_scan_total_limit_bytes": MAX_SCAN_TOTAL,
                                  "url_candidate_entries": candidates,
                                  "url_scan_complete": not any(
                                      x.file_size > MAX_SCAN_BYTES for x in entries if not x.is_dir()
                                      and x.filename.endswith((".dex", ".xml", ".json", ".properties", ".txt", ".html", ".js", ".yml", ".yaml", ".so")))
                                      and scanned < MAX_SCAN_TOTAL and len(result["urls"]) < MAX_URLS}
            if not result["coverage"]["url_scan_complete"]:
                result["warnings"].append("URL scan was bounded; strings beyond documented byte/member limits were not scanned.")
    except zipfile.BadZipFile as exc:
        raise ValueError("Input is not a valid APK/ZIP archive.") from exc
    result["warnings"].append("Signing entries are inventoried; APK signature validity and signer trust were not verified.")
    return result
