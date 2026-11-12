"""A loopback-only dashboard; APKs and reports stay in a local job directory."""
from __future__ import annotations
import hmac
import json
import secrets
import threading
import uuid
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

MAX_UPLOAD = 128 * 1024 * 1024


def make_server(port: int, workspace: Path):
    if not 0 <= port <= 65535:
        raise ValueError("Invalid port.")
    root = workspace.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    jobs, lock = {}, threading.Lock()
    slots = threading.BoundedSemaphore(2)
    token = secrets.token_urlsafe(32)
    for folder in sorted(root.iterdir())[-2000:]:
        if folder.is_symlink() or not re.fullmatch(r"[0-9a-f]{32}", folder.name) or not folder.is_dir():
            continue
        saved = folder / "job.json"
        try:
            if saved.is_symlink() or saved.stat().st_size > 32768:
                continue
            job = json.loads(saved.read_text(encoding="utf-8"))
            if job.get("id") != folder.name:
                continue
            if job.get("status") == "running":
                job.update(status="interrupted", message="The previous session ended before the analysis completed.")
            jobs[folder.name] = job
        except (OSError, ValueError, AttributeError):
            continue

    def persist(job):
        temporary = root / job["id"] / "job.tmp"
        temporary.write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
        temporary.replace(root / job["id"] / "job.json")

    class Handler(BaseHTTPRequestHandler):
        server_version = "APK-GOD/0.2"

        def log_message(self, fmt, *args):
            # Avoid retaining query strings or request data in ordinary server logs.
            pass

        def trusted(self):
            port_now = self.server.server_address[1]
            allowed = {f"127.0.0.1:{port_now}", f"localhost:{port_now}"}
            if self.headers.get("Host", "") not in allowed:
                self.send_json(403, {"error": "Only local dashboard requests are accepted."})
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in {"http://" + h for h in allowed}:
                self.send_json(403, {"error": "Cross-origin requests are not accepted."})
                return False
            return True

        def send_bytes(self, code, data, content_type):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(data)

        def send_json(self, code, data):
            self.send_bytes(code, json.dumps(data).encode(), "application/json; charset=utf-8")

        def do_GET(self):
            if not self.trusted():
                return
            path = urlsplit(self.path).path
            if path == "/":
                page = Path(__file__).parent / "static" / "index.html"
                return self.send_bytes(200, page.read_bytes(), "text/html; charset=utf-8")
            if path == "/api/session":
                return self.send_json(200, {"token": token})
            if path == "/api/tools":
                from .tools import detect_tools
                return self.send_json(200, {"tools": detect_tools()})
            if path == "/api/capabilities":
                from .tools import doctor
                return self.send_json(200, doctor())
            if path == "/api/jobs":
                with lock:
                    saved_jobs = sorted(jobs.values(), key=lambda x: x.get("created_at", ""), reverse=True)
                return self.send_json(200, {"jobs": saved_jobs[:200]})
            if path == "/api/about":
                from . import __version__
                return self.send_json(200, {"name": "APK-GOD", "version": __version__, "mode": "local",
                                           "external_tool_launchers": False,
                                           "notice": "APK-GOD includes original application code and uses separately licensed embedded libraries. See THIRD_PARTY_NOTICES.md."})
            parts = path.strip("/").split("/")
            if len(parts) >= 3 and parts[:2] == ["api", "jobs"]:
                with lock:
                    job = dict(jobs.get(parts[2], {}))
                if not job:
                    return self.send_json(404, {"error": "Unknown analysis."})
                if len(parts) == 3:
                    return self.send_json(200, job)
                allowed = {
                    "report.html": "text/html; charset=utf-8",
                    "analysis.json": "application/json; charset=utf-8",
                    "report.md": "text/markdown; charset=utf-8",
                    "rewrite-spec.md": "text/markdown; charset=utf-8",
                    "evidence-graph.json": "application/json; charset=utf-8",
                    "source-bundle.zip": "application/zip",
                }
                if len(parts) == 4 and parts[3] in allowed and job["status"] == "completed":
                    data = (root / parts[2] / "output" / parts[3]).read_bytes()
                    return self.send_bytes(200, data, allowed[parts[3]])
                if len(parts) >= 5 and parts[3] in {"source", "native", "resources"} and job["status"] == "completed":
                    from urllib.parse import unquote
                    output = (root / parts[2] / "output").resolve()
                    target = output.joinpath(*[unquote(part) for part in parts[3:]])
                    if target.is_symlink():
                        return self.send_json(403, {"error": "Invalid source path."})
                    resolved = target.resolve()
                    if not resolved.is_relative_to(output / parts[3]) or not resolved.is_file():
                        return self.send_json(404, {"error": "Source file not found."})
                    if resolved.stat().st_size > 8 * 1024**2:
                        return self.send_json(413, {"error": "Download the source bundle to inspect this file."})
                    return self.send_bytes(200, resolved.read_bytes(), "text/plain; charset=utf-8")
            self.send_json(404, {"error": "Not found."})

        def do_POST(self):
            if not self.trusted():
                return
            supplied = self.headers.get("X-APK-GOD-Token", "")
            if not hmac.compare_digest(supplied, token):
                return self.send_json(403, {"error": "Reload the local dashboard before uploading."})
            parsed = urlsplit(self.path)
            if parsed.path != "/api/analyze":
                return self.send_json(404, {"error": "Not found."})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.send_json(400, {"error": "Invalid content length."})
            if not 0 < length <= MAX_UPLOAD:
                return self.send_json(413, {"error": "Choose an APK up to 128 MiB."})
            query = parse_qs(parsed.query)
            if "tools" in query:
                return self.send_json(400, {"error": "External tool launchers have been removed. Choose an analysis profile."})
            profile = query.get("profile", ["standard"])[0]
            if profile not in {"quick", "standard", "deep"}:
                return self.send_json(400, {"error": "Choose quick, standard or deep analysis."})
            filename = self.headers.get("X-APK-GOD-Filename", "input.apk")[:256]
            from urllib.parse import unquote
            filename = Path(unquote(filename)).name
            if not slots.acquire(blocking=False):
                return self.send_json(429, {"error": "Two analyses are already running. Try after one finishes."})
            job_id = uuid.uuid4().hex
            job_dir = root / job_id
            try:
                job_dir.mkdir()
                apk = job_dir / "input.apk"
                self.connection.settimeout(30)
                remaining = length
                with apk.open("xb") as handle:
                    while remaining:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError("Upload ended before the declared size.")
                        handle.write(chunk)
                        remaining -= len(chunk)
            except (OSError, ValueError) as exc:
                slots.release()
                return self.send_json(400, {"error": str(exc)})
            job_base = {"id": job_id, "filename": filename, "profile": profile,
                        "created_at": datetime.now(timezone.utc).isoformat()}
            with lock:
                jobs[job_id] = {**job_base, "status": "running", "message": "Analyzing package, bytecode and native evidence with embedded engines."}
                persist(jobs[job_id])

            def work():
                try:
                    from .analysis import analyze
                    result = analyze(apk, job_dir / "output", profile=profile, timeout=300 if profile == "deep" else 180)
                    update = {
                        **job_base, "status": "completed",
                        "message": "Analysis report generated. Coverage and reconstruction limits are included.",
                        "report": f"/api/jobs/{job_id}/report.html",
                        "sha256": result["input"]["sha256"],
                        "findings": len(result["evidence"].get("findings", [])),
                        "package": result["inspection"].get("package", {}).get("package_name"),
                        "duration_seconds": result["performance"].get("duration_seconds"),
                        "classes": len(result["engine_analysis"].get("classes", [])),
                        "methods": len(result["engine_analysis"].get("methods", [])),
                    }
                except Exception as exc:
                    update = {**job_base, "status": "failed", "message": str(exc)}
                finally:
                    slots.release()
                with lock:
                    jobs[job_id] = update
                    persist(update)
            threading.Thread(target=work, daemon=True).start()
            self.send_json(202, {"id": job_id, "status": "running"})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(port=8765, workspace=Path(".apk-god")):
    server = make_server(port, workspace)
    print(f"APK GOD dashboard: http://127.0.0.1:{server.server_address[1]}", flush=True)
    print("Local files only. Stop with Ctrl+C.", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
