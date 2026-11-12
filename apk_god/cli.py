"""One interface for APK-GOD's integrated engines and evidence operations."""
from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from . import __version__


def make_parser():
    p = argparse.ArgumentParser(prog="apk-god", description="APK-GOD: integrated, evidence-led Android analysis.")
    p.add_argument("--version", action="version", version=f"APK-GOD {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("doctor", aliases=["tools"], help="Check embedded library availability and capabilities")
    d.add_argument("--json", action="store_true")
    for name, desc in [("analyze", "Analyze an APK locally"), ("batch", "Analyze all APKs in a directory")]:
        a = sub.add_parser(name, help=desc)
        a.add_argument("apk", type=Path, help="APK file" if name == "analyze" else "Directory containing APK files")
        a.add_argument("-o", "--output", type=Path)
        a.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
        a.add_argument("--har", type=Path, help="Import an existing HAR capture (analyze only)")
        a.add_argument("--timeout", type=int, default=180)
    s = sub.add_parser("serve", help="Start APK-GOD on 127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--workspace", type=Path, default=Path(".apk-god"))
    c = sub.add_parser("diff", help="Compare two analysis.json reports")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    c.add_argument("-o", "--output", type=Path)
    binary = sub.add_parser("binary", help="Recover native CFG and C-like source; optionally explore a symbolic goal")
    binary.add_argument("binary", type=Path)
    binary.add_argument("-o", "--output", type=Path, required=True)
    binary.add_argument("--functions", type=int, default=10)
    binary.add_argument("--steps", type=int, default=50)
    binary.add_argument("--find", type=lambda value: int(value, 0), help="Goal virtual address in the loaded image")
    binary.add_argument("--avoid", type=lambda value: int(value, 0), action="append", default=[])
    binary.add_argument("--timeout", type=int, default=180)
    ai = sub.add_parser("ai", help="Explain a redacted evidence summary with a configured AI endpoint")
    ai.add_argument("report", type=Path)
    ai.add_argument("--preview", action="store_true", help="Show the payload without contacting any provider")
    ai.add_argument("--output", type=Path, help="Write AI-only findings to a new JSON file")
    rt = sub.add_parser("runtime", help="Explicit test-process observation using the embedded runtime API")
    rsub = rt.add_subparsers(dest="runtime_command", required=True)
    rsub.add_parser("devices")
    rp = rsub.add_parser("processes")
    rp.add_argument("--device", required=True)
    ro = rsub.add_parser("observe")
    ro.add_argument("--device", required=True)
    ro.add_argument("--target", required=True, help="Running PID or exact process name")
    ro.add_argument("--seconds", type=float, default=5)
    ro.add_argument("--hook", action="append", default=[], help="Count calls to module:exported-symbol (repeatable)")
    ro.add_argument("-o", "--output", type=Path, required=True)
    return p


def _print_or_save(value, output=None):
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as handle:
            handle.write(text)
        print(output.resolve())
    else:
        print(text)


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        if args.command in {"doctor", "tools"}:
            from .tools import doctor
            found = doctor()
            if args.json:
                _print_or_save(found)
            else:
                print("APK-GOD embedded engines (no external tool launchers)")
                for item in found["libraries"]:
                    print(f"{item['id']:<14} {item['status']:<10} {item['version'] or '-':<14} {item['role']}")
                print("\n" + found["readiness_note"])
            return 0
        if args.command in {"analyze", "batch"}:
            from .analysis import analyze
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            output = args.output or Path("reports") / f"analysis-{stamp}"
            if args.command == "batch":
                if args.har:
                    raise ValueError("Use analyze to associate a HAR capture with one specific APK.")
                if not args.apk.is_dir():
                    raise ValueError("Batch input must be a directory.")
                files = sorted(args.apk.glob("*.apk"))
                if not files:
                    raise ValueError("No APK files found in the chosen directory.")
                if output.exists() and any(output.iterdir()):
                    raise ValueError("Choose a new or empty batch output directory.")
                summary = []
                for index, apk in enumerate(files, 1):
                    target = output / f"{index:04d}"
                    try:
                        result = analyze(apk, target, profile=args.profile, timeout=args.timeout)
                        summary.append({"file": apk.name, "status": "completed", "sha256": result["input"]["sha256"], "report": str(target / "report.html")})
                    except (ValueError, OSError) as exc:
                        summary.append({"file": apk.name, "status": "failed", "error": str(exc)})
                _print_or_save(summary, output / "batch-summary.json")
                return 0 if all(x["status"] == "completed" for x in summary) else 1
            result = analyze(args.apk, output, profile=args.profile, har_path=args.har, timeout=args.timeout)
            print(f"Report: {output.resolve() / 'report.html'}")
            print(f"Sources: {output.resolve() / 'source-bundle.zip'}")
            print(f"SHA256: {result['input']['sha256']}")
            print(f"Measured time: {result['performance']['duration_seconds']} seconds")
            print("Read the coverage section for errors, truncation and unsupported behavior.")
            return 0
        if args.command == "serve":
            from .server import serve
            serve(args.port, args.workspace)
            return 0
        if args.command == "diff":
            from .compare import compare_reports, load_report
            _print_or_save(compare_reports(load_report(args.before), load_report(args.after)), args.output)
            return 0
        if args.command == "binary":
            from .binary import analyze_binary_isolated
            result = analyze_binary_isolated(args.binary, args.output, timeout=args.timeout,
                max_functions=args.functions, max_steps=args.steps, find_address=args.find, avoid_addresses=args.avoid)
            print(args.output.resolve() / "native-analysis.json")
            print("Status: " + str(result.get("status")) + ". Read model assumptions and bounds in the report.")
            return 0
        if args.command == "ai":
            from .compare import load_report
            from .ai import enrich_report, payload_preview
            report = load_report(args.report)
            if args.preview:
                _print_or_save(payload_preview(report))
            else:
                if args.output and args.output.exists():
                    raise ValueError("AI output exists; choose a new output file before contacting the provider.")
                _print_or_save(enrich_report(report), args.output)
            return 0
        if args.command == "runtime":
            from . import runtime
            if args.runtime_command == "devices":
                _print_or_save(runtime.devices())
            elif args.runtime_command == "processes":
                _print_or_save(runtime.processes(args.device))
            else:
                target = int(args.target) if args.target.isdecimal() else args.target
                runtime.observe(args.device, target, seconds=args.seconds, hooks=args.hook, output=args.output)
                print(args.output.resolve())
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"APK-GOD: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 1
