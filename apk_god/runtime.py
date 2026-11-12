"""Explicit runtime observation through the embedded Frida API, never its CLI."""
from __future__ import annotations
import json
import re
import threading
import time
import multiprocessing
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _frida():
    try:
        import frida
        return frida
    except ImportError as exc:
        raise ValueError("Runtime library is missing. Install APK-GOD with the runtime extra.") from exc


def _devices() -> list[dict]:
    return [{"id": x.id, "name": x.name, "type": x.type}
            for x in _frida().get_device_manager().enumerate_devices()]


def _device(device_id: str):
    if not device_id:
        raise ValueError("Select a device ID explicitly.")
    return _frida().get_device(device_id, timeout=5)


def _processes(device_id: str) -> list[dict]:
    return [{"pid": x.pid, "name": x.name} for x in _device(device_id).enumerate_processes(scope="minimal")]


def _script(hooks: list[str]) -> str:
    selected = []
    for hook in hooks:
        if not re.fullmatch(r"[^\s:/\\]{1,128}:[A-Za-z0-9_.$@?+\-]{1,128}", hook):
            raise ValueError("A trace hook must be module-name:exported-symbol.")
        module, symbol = hook.split(":", 1)
        selected.append({"module": module, "symbol": symbol})
    if len(selected) > 32:
        raise ValueError("At most 32 trace hooks are allowed per observation.")
    return """
const hooks = __HOOKS__;
const counts = Object.create(null);
send({type:'process',pid:Process.id,arch:Process.arch,platform:Process.platform,
      modules:Process.enumerateModules().slice(0,2048).map(m=>({name:m.name,base:m.base.toString(),size:m.size}))});
for (const h of hooks) {
  const key = h.module + ':' + h.symbol;
  try {
    const mod = Process.getModuleByName(h.module);
    const address = mod.getExportByName(h.symbol);
    counts[key] = 0;
    Interceptor.attach(address, {onEnter() {counts[key]++;}});
    send({type:'hook',symbol:key,status:'attached',address:address.toString()});
  } catch(e) {send({type:'hook',symbol:key,status:'unavailable',error:String(e)});}
}
rpc.exports = {snapshot() {return {counts:counts};}};
""".replace("__HOOKS__", json.dumps(selected))


def _observe(device_id: str, target: str | int, *, seconds: float = 5,
            hooks: list[str] | None = None, output: Path | str | None = None) -> dict:
    if not 0.1 <= seconds <= 300:
        raise ValueError("Runtime observation duration must be between 0.1 and 300 seconds.")
    if isinstance(target, int) and target <= 0 or isinstance(target, str) and not target.strip():
        raise ValueError("Select a running process ID or exact name.")
    code = _script(hooks or [])
    destination = Path(output) if output else None
    if destination and destination.exists():
        raise ValueError("Runtime report already exists; choose a new output file.")
    device = _device(device_id)
    events, guard, detached = [], threading.Lock(), threading.Event()
    session, script = None, None
    result = {"schema_version": 1, "basis": "runtime-observed", "device_id": device_id,
              "target": target, "created_at": datetime.now(timezone.utc).isoformat(),
              "duration_seconds": seconds, "events": events, "counts": {},
              "limitations": ["Only the selected process and exported symbols were observed.",
                              "Instrumentation may affect timing. No method arguments, credentials or memory dumps were collected."]}
    def on_message(message, data):
        payload = message.get("payload", {}) if message.get("type") == "send" else {"type": "script-error", "description": str(message.get("description", "Unknown script error"))[:1000]}
        if not isinstance(payload, dict):
            return
        with guard:
            if len(events) < 4096:
                events.append(payload)
    try:
        session = device.attach(target)
        session.on("detached", lambda *args: detached.set())
        script = session.create_script(code, name="apk-god-observer")
        script.on("message", on_message)
        script.load()
        started = time.monotonic()
        detached.wait(seconds)
        result["observed_seconds"] = round(time.monotonic() - started, 3)
        if not detached.is_set():
            result["counts"] = dict(script.exports_sync.snapshot().get("counts", {}))
            result["status"] = "completed"
        else:
            result["status"] = "detached"
            result["limitations"].append("The session detached before the full duration.")
    except Exception as exc:
        raise ValueError(f"Runtime observation failed: {exc}") from exc
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
    return result


def _runtime_worker(operation: str, arguments: dict, destination: str):
    try:
        value = {"devices": _devices, "processes": _processes, "observe": _observe}[operation](**arguments)
        payload = {"result": value}
    except Exception as exc:
        payload = {"error": str(exc)}
    Path(destination).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _isolated(operation: str, arguments: dict, timeout: float):
    """A native runtime backend can crash; isolate it from the UI and CLI."""
    with tempfile.TemporaryDirectory(prefix="apk-god-runtime-") as folder:
        destination = Path(folder) / "result.json"
        process = multiprocessing.get_context("spawn").Process(
            target=_runtime_worker, args=(operation, arguments, str(destination)), daemon=True)
        process.start()
        process.join(timeout)
        if process.is_alive():
            process.terminate()
            process.join(3)
            if process.is_alive():
                process.kill()
                process.join(3)
            raise ValueError("The runtime backend did not finish within its time limit.")
        if process.exitcode != 0 or not destination.exists():
            raise ValueError(f"The embedded runtime backend could not initialize or stopped (exit code {process.exitcode}). Check device support and instrumentation permissions; no successful observation is claimed.")
        if destination.stat().st_size > 16 * 1024**2:
            raise ValueError("Runtime result exceeded the size limit.")
        payload = json.loads(destination.read_text(encoding="utf-8"))
        if "error" in payload:
            raise ValueError(payload["error"])
        return payload["result"]


def devices() -> list[dict]:
    return _isolated("devices", {}, 15)


def processes(device_id: str) -> list[dict]:
    return _isolated("processes", {"device_id": device_id}, 15)


def observe(device_id: str, target: str | int, *, seconds: float = 5,
            hooks: list[str] | None = None, output: Path | str | None = None) -> dict:
    if not 0.1 <= seconds <= 300:
        raise ValueError("Runtime observation duration must be between 0.1 and 300 seconds.")
    _script(hooks or [])
    destination = Path(output) if output else None
    if destination and destination.exists():
        raise ValueError("Runtime report already exists; choose a new output file.")
    value = _isolated("observe", {"device_id": device_id, "target": target,
                                 "seconds": seconds, "hooks": hooks or []}, seconds + 20)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
    return value
