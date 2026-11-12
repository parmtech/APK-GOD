"""APK-GOD analysis transactions using embedded libraries in bounded workers."""
from __future__ import annotations

import json
import multiprocessing
import os
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import __version__
from .tools import capabilities, detect_tools

MAX_RESULT_BYTES = 128 * 1024 * 1024
PROFILES = {"quick", "standard", "deep"}


def public_url(value: str) -> str:
    try:
        p = urlsplit(value)
        if p.scheme not in {"http", "https", "ws", "wss"} or not p.hostname:
            return "[unparseable URL]"
        host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
        if p.port:
            host += f":{p.port}"
        query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(p.query, keep_blank_values=True)])
        return urlunsplit((p.scheme, host, p.path, query, ""))
    except (TypeError, ValueError):
        return "[unparseable URL]"


def _worker(apk: str, output: str, profile: str, cpu_seconds: int):
    """Separate our own parser process; no third-party CLI or APK code is run."""
    root = Path(output)
    try:
        if os.name == "posix":
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 2))
            # A generous virtual-memory ceiling still bounds hostile parsers.
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
        try:
            from loguru import logger
            logger.disable("androguard")
        except ImportError:
            pass
        from .inspect_apk import inspect_apk
        from .engines import analyze_engines
        started = time.perf_counter()
        inspection = inspect_apk(Path(apk))
        engines = analyze_engines(Path(apk), root, profile=profile, inspection=inspection)
        value = {"inspection": inspection, "engines": engines,
                 "duration_seconds": round(time.perf_counter() - started, 4)}
        if os.name == "posix":
            value["peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        (root / ".worker-result.json").write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        (root / ".worker-error.json").write_text(json.dumps({"error": str(exc), "type": type(exc).__name__}), encoding="utf-8")


def _run_worker(apk: Path, output: Path, profile: str, timeout: int) -> dict:
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_worker, args=(str(apk), str(output), profile, timeout), daemon=True)
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.terminate()
        process.join(3)
        if process.is_alive():
            process.kill()
            process.join(3)
        raise ValueError(f"Analysis exceeded {timeout} seconds. Partial files are retained; no complete report was issued.")
    error = output / ".worker-error.json"
    if error.exists():
        detail = json.loads(error.read_text(encoding="utf-8"))
        error.unlink()
        raise ValueError(f"Package analysis failed ({detail['type']}): {detail['error']}")
    result_file = output / ".worker-result.json"
    if process.exitcode != 0 or not result_file.exists():
        raise ValueError(f"Analysis worker stopped with exit code {process.exitcode}; no complete report was issued.")
    if result_file.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError("Analysis exceeded the bounded report size.")
    result = json.loads(result_file.read_text(encoding="utf-8"))
    result_file.unlink()
    return result


def _bundle(output: Path) -> None:
    """Bundle generated artifacts only; the original APK is never re-exported."""
    with zipfile.ZipFile(output / "source-bundle.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        total = 0
        for directory in ("source", "native", "resources"):
            root = output / directory
            if not root.is_dir():
                continue
            for item in sorted(root.rglob("*")):
                if item.is_symlink() or not item.is_file():
                    continue
                total += item.stat().st_size
                if total > 256 * 1024**2:
                    raise ValueError("Source export exceeded 256 MiB.")
                archive.write(item, item.relative_to(output).as_posix())
        for name in ("analysis.json", "evidence-graph.json", "report.md", "rewrite-spec.md"):
            archive.write(output / name, name)


def analyze(apk_path: str | Path, output_dir: str | Path, *, profile: str = "standard",
            har_path: str | Path | None = None, timeout: int = 180,
            selected_tools: list[str] | None = None) -> dict:
    from .evidence import build_evidence
    from .report import write_reports
    apk = Path(apk_path).expanduser().resolve(strict=True)
    output = Path(output_dir).expanduser()
    if selected_tools:
        raise ValueError("External tool launchers were removed. Choose quick, standard or deep integrated analysis.")
    if not apk.is_file():
        raise ValueError("Choose an APK file.")
    if output.is_symlink():
        raise ValueError("Output directory must not be a symlink.")
    output = output.resolve()
    if output == apk or output in apk.parents:
        raise ValueError("Choose an output directory that does not contain the input APK.")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Choose a new or empty output directory; existing analysis is never overwritten.")
    if profile not in PROFILES:
        raise ValueError("Profile must be quick, standard or deep.")
    if not 1 <= timeout <= 3600:
        raise ValueError("Analysis timeout must be between 1 and 3600 seconds.")
    if har_path:
        har_path = Path(har_path).expanduser().resolve(strict=True)
        if not har_path.is_file():
            raise ValueError("Choose a HAR file.")
    output.mkdir(parents=True, exist_ok=True)
    lock = output / ".analysis-lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        raw = _run_worker(apk, output, profile, timeout)
        inspection, engine = raw["inspection"], raw["engines"]
        evidence = build_evidence(inspection, engine, output, har_path)
        safe = {key: val for key, val in inspection.items() if key != "strings"}
        safe["urls"] = [{"url": public_url(x.get("url", "")), "source": x.get("source", "")} for x in inspection.get("urls", [])]
        result = {
            "schema_version": 2, "generator": {"name": "APK-GOD", "version": __version__},
            "created_at": datetime.now(timezone.utc).isoformat(), "profile": profile,
            "input": {"filename": apk.name, "sha256": inspection.get("sha256"), "size_bytes": apk.stat().st_size},
            "inspection": safe, "engine_analysis": engine, "engine_runs": engine.get("engines", []),
            "tool_runs": [], "libraries": detect_tools(), "capabilities": capabilities(), "evidence": evidence,
            "performance": {"duration_seconds": raw["duration_seconds"], "peak_rss_kib": raw.get("peak_rss_kib"),
                            "comparison": "Measured for this run only; no superiority over upstream engines is claimed."},
            "limitations": [
                "Coverage is bounded and recorded per engine. This report does not certify complete application understanding.",
                "Reconstructed source is not guaranteed to match the original or form a buildable project.",
                "Static analysis did not launch the APK. Imported traffic is supplied evidence, not independently replayed behavior.",
                "Backend source and private business rules require separate backend evidence.",
                "This release does not reproduce every feature of the twenty reference projects; see the capability matrix.",
            ],
        }
        write_reports(result, output)
        (output / "analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        (output / "evidence-graph.json").write_text(json.dumps(evidence.get("graph", {}), indent=2, ensure_ascii=False), encoding="utf-8")
        _bundle(output)
        return result
    finally:
        lock.unlink(missing_ok=True)
