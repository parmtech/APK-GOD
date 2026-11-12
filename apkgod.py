#!/usr/bin/env python3
"""APK-GOD: dependency-free, offline APK inventory (no execution of APK code)."""
import argparse, hashlib, json, re, zipfile
from pathlib import Path
from datetime import datetime, timezone

def inspect(path):
    p = Path(path)
    if not p.is_file() or not zipfile.is_zipfile(p):
        raise ValueError("Input must be a valid APK/ZIP file")
    result = {"schema_version": 1, "file": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
              "analyzed_at": datetime.now(timezone.utc).isoformat(), "findings": {}, "limitations": []}
    with zipfile.ZipFile(p) as z:
        entries = z.infolist()
        names = [e.filename for e in entries]
        result["findings"]["entry_count"] = len(entries)
        result["findings"]["dex_files"] = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
        result["findings"]["native_libraries"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
        result["findings"]["assets"] = [n for n in names if n.startswith("assets/")][:500]
        result["findings"]["manifest_present"] = "AndroidManifest.xml" in names
        result["findings"]["total_uncompressed_bytes"] = sum(e.file_size for e in entries)
        result["findings"]["signing_files"] = [n for n in names if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
        result["findings"]["suspicious_archive_paths"] = [n for n in names if n.startswith("/") or ".." in Path(n).parts]
    result["limitations"] = [
        "Manifest permissions and component names require Android binary XML decoding.",
        "DEX source reconstruction requires a decompiler such as JADX.",
        "No runtime, network, backend, or security claims are inferred from this inventory.",
        "APK contents do not reveal private server source code."
    ]
    return result

def main():
    parser = argparse.ArgumentParser(description="Offline APK inventory")
    parser.add_argument("apk", help="APK path")
    parser.add_argument("-o", "--output", help="JSON report destination")
    args = parser.parse_args()
    report = json.dumps(inspect(args.apk), indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(args.output)
    else:
        print(report)

if __name__ == "__main__":
    main()
