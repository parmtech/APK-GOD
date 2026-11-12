"""Bounded native reconstruction and symbolic exploration via embedded angr.

Targets are parsed and modeled, never launched by the host OS. Generated C-like
code and symbolic witnesses are reconstructions under an explicit model. They
are not original source or proof of behavior on an Android device.

Run this module in APK GOD's bounded worker when processing untrusted files.
Function, byte, state and step limits complement (not replace) a process timeout.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import logging
import time
from pathlib import Path

MAX_BINARY_BYTES = 64 * 1024**2
MAX_CFG_BYTES = 512 * 1024
MAX_FUNCTION_REGION_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 8 * 1024**2
MAX_GRAPH_NODES = 20_000
MAX_GRAPH_EDGES = 40_000


def _check_integer(name: str, value: int, minimum: int, maximum: int):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}.")


def _rank_function(name: str):
    if name == "main":
        return 0
    if name == "JNI_OnLoad" or name.startswith("Java_"):
        return 1
    if name.startswith("_") or name in {"frame_dummy", "register_tm_clones", "deregister_tm_clones"}:
        return 3
    return 2


def _executable_regions(project) -> list[tuple[int, int]]:
    obj = project.loader.main_object
    ranges = []
    for section in obj.sections:
        if section.is_executable and section.memsize:
            ranges.append((int(section.min_addr), int(section.max_addr) + 1))
    if not ranges:
        for segment in obj.segments:
            if segment.is_executable and segment.memsize:
                ranges.append((int(segment.min_addr), int(segment.max_addr) + 1))
    return ranges


def _in_regions(address: int, regions):
    return any(start <= address < end for start, end in regions)


def _candidates(project, regions, maximum):
    candidates = []
    seen = set()
    for symbol in project.loader.main_object.symbols:
        address = int(symbol.rebased_addr)
        if symbol.is_function and not symbol.is_import and address not in seen and _in_regions(address, regions):
            candidates.append({"name": str(symbol.name)[:1024], "address": address,
                               "size": max(0, int(symbol.size)), "basis": "symbol"})
            seen.add(address)
    candidates.sort(key=lambda x: (_rank_function(x["name"]), x["address"]))
    total = len(candidates)
    selected = candidates[:maximum]
    if not selected and _in_regions(project.entry, regions):
        selected.append({"name": "entry", "address": int(project.entry), "size": 0, "basis": "entrypoint"})
    if not selected and regions:
        selected.append({"name": "executable_region_start", "address": regions[0][0], "size": 0,
                         "basis": "region-start-hypothesis"})
    return selected, total


def _bounded_regions(candidates, executable, *, thumb_alignment=False):
    selected = []
    remaining = MAX_CFG_BYTES
    for item in candidates:
        start = item["address"] & ~1 if thumb_alignment else item["address"]
        containing = next(((low, high) for low, high in executable if low <= start < high), None)
        if containing is None or remaining <= 0:
            continue
        size = min(item["size"] or MAX_FUNCTION_REGION_BYTES, MAX_FUNCTION_REGION_BYTES,
                   containing[1] - start, remaining)
        if size > 0:
            selected.append((start, start + size))
            remaining -= size
    # Collapse overlap to avoid duplicated work in CFGFast.
    merged = []
    for start, end in sorted(selected):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _explore(project, path, find_address, avoid_addresses, max_steps, max_states, stdin_bytes):
    import angr
    import claripy

    result = {"status": "not-requested", "find_address": find_address,
              "avoid_addresses": sorted(avoid_addresses), "steps": 0, "max_steps": max_steps,
              "max_states": max_states, "instructions_per_step_limit": 128,
              "stdin_bytes": stdin_bytes, "pruned_states": 0, "found": False,
              "start_address": int(project.entry), "visited_addresses": [],
              "model": "angr symbolic entry state with built-in import/syscall models",
              "assumptions": [
                  "Shared libraries are not loaded; built-in SimProcedures or unconstrained import returns stand in for them.",
                  "The modeled process receives a fixed-length symbolic stdin and one argv element.",
                  "Uninitialized registers and memory are symbolic, not values observed on a device.",
                  "Host filesystem passthrough is disabled; no target machine code is executed by the host OS.",
              ]}
    if find_address is None:
        return result
    symbolic_input = claripy.BVS("apkgod_stdin", stdin_bytes * 8)
    stream = angr.SimFileStream(name="stdin", content=symbolic_input, has_end=True)
    state = project.factory.entry_state(
        args=[path.name], env={}, stdin=stream, concrete_fs=False,
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                     angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
    )
    manager = project.factory.simgr(state, save_unconstrained=True)
    visited = set()
    stops = {find_address, *avoid_addresses}

    def classify():
        manager.move(from_stash="active", to_stash="avoided", filter_func=lambda s: s.addr in avoid_addresses)
        manager.move(from_stash="active", to_stash="found", filter_func=lambda s: s.addr == find_address)
        for active in manager.active:
            if len(visited) < 4096:
                visited.add(int(active.addr))

    classify()
    for step in range(max_steps):
        if manager.stashes.get("found") or not manager.active:
            break
        if len(manager.active) > max_states:
            result["pruned_states"] += len(manager.active) - max_states
            del manager.active[max_states:]
        manager.step(num_inst=128, extra_stop_points=stops)
        result["steps"] = step + 1
        classify()
        # Only counts are needed for terminal paths; bounded retention avoids
        # accumulating every closed state and its solver history.
        for stash in ("deadended", "avoided", "unconstrained"):
            items = manager.stashes.get(stash, [])
            if len(items) > max_states:
                result["pruned_states"] += len(items) - max_states
                del items[max_states:]
    found = manager.stashes.get("found", [])
    result.update(found=bool(found), visited_addresses=sorted(visited), active_states=len(manager.active),
                  deadended_states=len(manager.stashes.get("deadended", [])),
                  avoided_states=len(manager.stashes.get("avoided", [])),
                  unconstrained_states=len(manager.stashes.get("unconstrained", [])),
                  errored_states=len(manager.errored), step_limit_reached=bool(manager.active and result["steps"] >= max_steps))
    if found:
        witness = found[0]
        result["status"] = "model-path-found"
        result["witness"] = {"stdin_hex": witness.solver.eval(symbolic_input, cast_to=bytes).hex(),
                             "path_addresses": [int(x) for x in list(witness.history.bbl_addrs)[-2047:]] + [find_address],
                             "interpretation": "One satisfying input in this symbolic model; not an observed device execution."}
    else:
        result["status"] = "not-found-within-bounds"
        result["interpretation"] = "No witness was found under these steps, states and environment assumptions; this is not proof of unreachability."
    return result


def analyze_binary(path: str | Path, output: str | Path, max_functions: int = 10,
                   max_steps: int = 50, find_address: int | None = None,
                   avoid_addresses: list[int] | None = None, *, max_states: int = 32,
                   stdin_bytes: int = 32, source_byte_limit: int = MAX_SOURCE_BYTES) -> dict:
    """Recover bounded native CFG/C-like code and optionally search for a goal.

Addresses are rebased virtual addresses in angr's loaded main image, as recorded
by ``image_base`` and the function table. A ``None`` goal leaves exploration off.
    """
    _check_integer("max_functions", max_functions, 1, 100)
    _check_integer("max_steps", max_steps, 1, 1000)
    _check_integer("max_states", max_states, 1, 128)
    _check_integer("stdin_bytes", stdin_bytes, 1, 4096)
    _check_integer("source_byte_limit", source_byte_limit, 0, MAX_SOURCE_BYTES)
    if find_address is not None:
        _check_integer("find_address", find_address, 0, (1 << 64) - 1)
    avoid = set(avoid_addresses or [])
    if len(avoid) > 100:
        raise ValueError("At most 100 avoid addresses are supported.")
    for address in avoid:
        _check_integer("avoid address", address, 0, (1 << 64) - 1)
    if find_address in avoid:
        raise ValueError("A find address cannot also be an avoid address.")
    binary_path = Path(path).expanduser().resolve(strict=True)
    if not binary_path.is_file() or not 0 < binary_path.stat().st_size <= MAX_BINARY_BYTES:
        raise ValueError("Choose a nonempty native binary up to 64 MiB.")
    raw = binary_path.read_bytes()
    if raw[:4] != b"\x7fELF":
        raise ValueError("Native reconstruction currently accepts ELF binaries only.")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    result = {"id": "symbolic", "status": "completed", "source": binary_path.name,
              "sha256": hashlib.sha256(raw).hexdigest(), "functions": [], "source_index": [],
              "cfg": {"nodes": [], "edges": []}, "warnings": [],
              "coverage": {"function_limit": max_functions, "cfg_byte_limit": MAX_CFG_BYTES,
                           "function_region_byte_limit": MAX_FUNCTION_REGION_BYTES, "source_byte_limit": source_byte_limit,
                           "truncated": False, "limit_reasons": []},
              "limitations": [
                  "Native C-like output is an inferred reconstruction, not original or guaranteed buildable source.",
                  "CFG recovery covers selected executable ranges; unresolved jumps and unselected functions remain unknown.",
                  "A symbolic witness establishes a path in the specified model, not runtime behavior on Android.",
              ]}
    try:
        import angr
    except ImportError:
        result.update(status="unavailable", message="Install the optional embedded angr dependency for native reconstruction.")
        return result
    except Exception as exc:
        result.update(status="failed", message=f"Embedded angr could not initialize ({type(exc).__name__}).")
        return result
    result["version"] = importlib.metadata.version("angr")
    for logger_name in ("angr", "cle", "pyvex"):
        logging.getLogger(logger_name).setLevel(logging.ERROR)

    def limited(reason):
        result["status"] = "partial"
        result["coverage"]["truncated"] = True
        if reason not in result["coverage"]["limit_reasons"]:
            result["coverage"]["limit_reasons"].append(reason)

    try:
        project = angr.Project(str(binary_path), auto_load_libs=False)
        executable = _executable_regions(project)
        result.update(image_base=int(project.loader.main_object.mapped_base), entrypoint=int(project.entry),
                      architecture=str(project.arch.name), address_kind="rebased-virtual-address")
        if find_address is not None and not _in_regions(find_address, executable):
            raise ValueError("Find address must be in an executable range of the loaded main image.")
        if any(not _in_regions(address, executable) for address in avoid):
            raise ValueError("Avoid addresses must be in executable ranges of the loaded main image.")
        candidates, total = _candidates(project, executable, max_functions)
        regions = _bounded_regions(candidates, executable, thumb_alignment=project.arch.name.startswith("ARM"))
        result["coverage"].update(symbol_function_candidates=total, selected_function_starts=len(candidates),
                                  executable_bytes=sum(end - start for start, end in executable),
                                  cfg_region_bytes=sum(end - start for start, end in regions),
                                  cfg_regions=[{"start": start, "end": end} for start, end in regions])
        if total > len(candidates):
            limited("Function selection limited to the requested count.")
        if result["coverage"]["cfg_region_bytes"] < result["coverage"]["executable_bytes"]:
            limited("CFG covers selected bounded function regions rather than every executable byte.")
        if not regions:
            result.update(status="partial", message="No analyzable executable region found.")
            return result
        cfg = project.analyses.CFGFast(
            regions=regions, function_starts=[x["address"] for x in candidates],
            symbols=False, function_prologues=False, start_at_entry=False,
            force_complete_scan=False, force_smart_scan=False, eh_frame=False,
            normalize=True, data_references=True, resolve_indirect_jumps=False,
        )
        for index, node in enumerate(cfg.graph.nodes):
            if index >= MAX_GRAPH_NODES:
                limited("Native CFG node export limit reached.")
                break
            result["cfg"]["nodes"].append({"address": int(node.addr), "size": int(node.size or 0),
                                              "function_address": int(node.function_address) if node.function_address is not None else None})
        visible_addresses = {node["address"] for node in result["cfg"]["nodes"]}
        for index, (left, right, edge) in enumerate(cfg.graph.edges(data=True)):
            if index >= MAX_GRAPH_EDGES:
                limited("Native CFG edge export limit reached.")
                break
            if int(left.addr) in visible_addresses and int(right.addr) in visible_addresses:
                result["cfg"]["edges"].append({"from": int(left.addr), "to": int(right.addr),
                                                  "kind": str(edge.get("jumpkind", "unknown"))})
        recovered = [function for function in cfg.kb.functions.values()
                     if not function.is_simprocedure and not function.is_plt
                     and _in_regions(int(function.addr), regions)]
        recovered.sort(key=lambda f: (_rank_function(str(f.name)), int(f.addr)))
        result["coverage"]["functions_recovered"] = len(recovered)
        if len(recovered) > max_functions:
            limited("Native reconstruction function limit reached.")
        source_bytes = 0
        for function in recovered[:max_functions]:
            record = {"name": str(function.name)[:1024], "address": int(function.addr),
                      "size": int(function.size), "blocks": len(function.block_addrs_set),
                      "unresolved_calls": bool(function.has_unresolved_calls),
                      "unresolved_jumps": bool(function.has_unresolved_jumps),
                      "status": "not-reconstructed"}
            result["functions"].append(record)
            try:
                decompiler = project.analyses.Decompiler(function, cfg=cfg.model)
                if decompiler.codegen is None or not decompiler.codegen.text:
                    record["reason"] = "Embedded decompiler produced no C-like representation."
                    result["status"] = "partial"
                    continue
                text = ("/* APK GOD: reconstructed by embedded angr; not original source. */\n"
                        "/* Address is relative to the recorded loaded image, not a device observation. */\n"
                        + decompiler.codegen.text)
                size = len(text.encode("utf-8", "replace"))
                if source_bytes + size > source_byte_limit:
                    limited("Native C-like source export limit reached.")
                    break
                relative = f"source/native_c/{result['sha256'][:16]}_{int(function.addr):x}.c"
                destination = output / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(text, encoding="utf-8", errors="replace")
                result["source_index"].append({"path": relative, "language": "c", "kind": "reconstructed",
                                                "source": binary_path.name, "function_address": int(function.addr),
                                                "lines": text.count("\n") + bool(text and not text.endswith("\n")),
                                                "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()})
                record.update(status="reconstructed", source_path=relative)
                source_bytes += size
            except Exception as exc:
                record.update(status="failed", reason=type(exc).__name__)
                result["status"] = "partial"
        result["coverage"].update(functions_reconstructed=sum(x["status"] == "reconstructed" for x in result["functions"]),
                                  source_bytes_written=source_bytes, cfg_nodes=len(result["cfg"]["nodes"]),
                                  cfg_edges=len(result["cfg"]["edges"]))
        result["exploration"] = _explore(project, binary_path, find_address, avoid, max_steps, max_states, stdin_bytes)
        if result["exploration"].get("pruned_states") or result["exploration"].get("step_limit_reached"):
            limited("Symbolic exploration reached a step or retained-state limit.")
        if result["exploration"].get("errored_states") or result["exploration"].get("unconstrained_states"):
            result["status"] = "partial"
            result["warnings"].append("Some symbolic paths errored or had unconstrained destinations; coverage is incomplete.")
    except ValueError:
        raise
    except Exception as exc:
        result.update(status="failed", message=f"Embedded native reconstruction failed ({type(exc).__name__}).")
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    return result
