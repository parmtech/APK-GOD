"""Bounded native reconstruction using our own isolated embedded-engine worker."""
from __future__ import annotations
import json
import multiprocessing
import os
from pathlib import Path


def _worker(source: str, output: str, options: dict, timeout: int):
    root = Path(output)
    try:
        if os.name == "posix":
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 2))
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
        from .symbolic import analyze_binary
        result = analyze_binary(source, root, **options)
        (root / "native-analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        (root / ".error.json").write_text(json.dumps({"error": str(exc)}), encoding="utf-8")


def analyze_binary_isolated(source: Path | str, output: Path | str, *, timeout: int = 180,
                            max_functions: int = 10, max_steps: int = 50,
                            find_address: int | None = None, avoid_addresses: list[int] | None = None) -> dict:
    source = Path(source).expanduser().resolve(strict=True)
    output = Path(output).expanduser()
    if output.is_symlink():
        raise ValueError("Output directory must not be a symlink.")
    output = output.resolve()
    if not source.is_file() or output == source or output in source.parents:
        raise ValueError("Choose a binary file and a separate output directory.")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Choose a new or empty output directory.")
    if not 1 <= timeout <= 600:
        raise ValueError("Native analysis timeout must be between 1 and 600 seconds.")
    if not 1 <= max_functions <= 50 or not 1 <= max_steps <= 500:
        raise ValueError("Use 1–50 functions and 1–500 symbolic steps.")
    options = {"max_functions": max_functions, "max_steps": max_steps,
               "find_address": find_address, "avoid_addresses": avoid_addresses}
    output.mkdir(parents=True, exist_ok=True)
    worker = multiprocessing.get_context("spawn").Process(target=_worker,
        args=(str(source), str(output), options, timeout), daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        worker.terminate()
        worker.join(3)
        if worker.is_alive():
            worker.kill()
            worker.join(3)
        raise ValueError("Native analysis reached its time limit. Partial files may remain; no complete result is claimed.")
    error = output / ".error.json"
    if error.exists():
        raise ValueError(json.loads(error.read_text(encoding="utf-8"))["error"])
    result = output / "native-analysis.json"
    if worker.exitcode != 0 or not result.exists():
        raise ValueError(f"Native analysis worker stopped (exit code {worker.exitcode}).")
    if result.stat().st_size > 64 * 1024**2:
        raise ValueError("Native analysis result exceeded the 64 MiB limit.")
    return json.loads(result.read_text(encoding="utf-8"))
