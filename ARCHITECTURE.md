# APK-GOD

**APK-GOD** is an evidence-first Android application analysis workbench. It aims to orchestrate multiple open-source tools and optional AI-assisted interpretation.

## Status

**Early foundation only.** The initial offline inventory script works without third-party packages; the 20-tool integration, dynamic analysis, source reconstruction, AI, and backend inference are planned, **not implemented**.

## Run the first analyzer

```bash
python3 apkgod.py /path/to/app.apk -o report.json
```

This produces a JSON inventory of DEX files, native libraries, assets, signing-file hints, SHA-256, and archive metadata. It **does not** decompile code or recover backend source.

## Architecture roadmap

1. **Evidence store:** APK hashes, provenance, tool versions, reproducible runs.
2. **Static adapters:** JADX, Apktool, APKiD, Androguard, MobSF, dex2jar, smali/baksmali, Bytecode Viewer, Quark Engine.
3. **Native adapters:** Ghidra, radare2, Cutter/Rizin, LIEF, LLDB, angr.
4. **Authorized runtime adapters:** Frida, Objection, drozer, mitmproxy, apk-mitm; run in isolated test devices and with permission.
5. **Reconstruction:** component/call graphs, resource mapping, pseudocode exports, buildability checks.
6. **Optional AI:** explain findings, generate architecture hypotheses and source skeletons; distinguish observations from inference.

## Reporting principles

Each finding should include its evidence, tool/version, confidence, and whether it was directly observed or inferred. No claim of universal APK recovery or guaranteed backend reconstruction.

## Responsible use

Analyze apps you own or are authorized to test. Do not execute untrusted APKs on your primary computer.
