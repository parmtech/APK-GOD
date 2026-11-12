"""Discover embedded libraries, never launch third-party tool executables."""
from __future__ import annotations

import importlib.util
from importlib import metadata


LIBRARIES = (
    ("androguard", "androguard", "DEX, binary manifest, resources, references and DAD reconstruction", "Apache-2.0"),
    ("lief", "lief", "Native binary structures and ELF symbols", "Apache-2.0"),
    ("capstone", "capstone", "Native instruction decoding", "BSD-3-Clause"),
    ("frida", "frida", "Explicit runtime observation using the embedded instrumentation API", "wxWindows"),
    ("angr", "angr", "Native control flow, C-like reconstruction and bounded symbolic models", "BSD-2-Clause"),
)


def detect_tools() -> list[dict]:
    """Compatibility name for library readiness; installation is not validation."""
    result = []
    for module, distribution, role, license_id in LIBRARIES:
        present = importlib.util.find_spec(module) is not None
        try:
            version = metadata.version(distribution) if present else None
        except metadata.PackageNotFoundError:
            version = None
        result.append({"id": module, "name": module, "role": role,
                       "mode": "embedded-library", "available": present,
                       "status": "installed" if present else "missing",
                       "version": version, "license": license_id,
                       "tested": False})
    return result


def capabilities() -> list[dict]:
    installed = {x["id"]: x["available"] for x in detect_tools()}
    items = [
        ("package", "Package inspection", "Archive inventory, hashes and bounded string discovery", None),
        ("signatures", "APK v2 integrity", "Check v2 protected content and signer signatures; trust is separate", None),
        ("manifest", "Manifest and resources", "Binary XML, permissions, components and resource strings", "androguard"),
        ("bytecode", "DEX exploration", "Classes, methods, instructions, references and control flow", "androguard"),
        ("reconstruction", "Readable source", "Java-like reconstruction with per-class failures preserved", "androguard"),
        ("native", "Native analysis", "ELF structure, imports, exports and symbol metadata", "lief"),
        ("instructions", "Native instructions", "Bounded disassembly with address evidence", "capstone"),
        ("symbolic", "Native reconstruction", "C-like source and bounded symbolic path exploration", "angr"),
        ("evidence", "Functionality map", "Correlate package and code evidence without inventing execution", None),
        ("traffic", "Network evidence", "Import a HAR capture and compare endpoint structures", None),
        ("diff", "Version comparison", "Compare packages, permissions, methods and call relationships", None),
        ("runtime", "Runtime observation", "Process and module evidence from an explicitly selected test process", "frida"),
        ("ai", "Optional AI explanation", "Send a redacted evidence summary only when requested", None),
        ("reports", "Engineering exports", "HTML, JSON, Markdown, graph and source bundle", None),
    ]
    return [{"id": ident, "name": name, "description": desc,
             "status": ("requires-device" if ident == "runtime" and installed.get(provider) else
                        "available" if provider is None or installed.get(provider) else "needs-library"),
             "provider": provider or "APK-GOD", "execution": "in-process-library" if provider else "built-in"}
            for ident, name, desc, provider in items]


def doctor() -> dict:
    return {"libraries": detect_tools(), "capabilities": capabilities(),
            "external_tool_launchers": False, "network_required_for_static_analysis": False,
            "runtime_requires_configured_device": True,
            "readiness_note": "Installed libraries are not proof of complete APK coverage or tool parity."}
