"""Native-library inspection through embedded LIEF and Capstone APIs.

ELF metadata and linear disassembly are evidence, not native decompilation.
The module does not load the analyzed shared object into the running process.
"""
from __future__ import annotations

import hashlib
import struct
import tempfile
from pathlib import Path

MACHINES = {3: "x86", 40: "ARM", 62: "x86_64", 183: "AArch64", 243: "RISC-V"}


def reconstruct_native(raw: bytes, source: str, output: Path, *, max_functions: int = 10,
                       source_byte_limit: int = 8 * 1024**2) -> dict:
    """Reconstruct selected functions in-process, retaining original APK provenance.

The loader needs a file. Store it in a fresh private temporary directory with
a generated name and remove it afterwards. Never execute the extracted object.
The caller supplies a hard-bounded worker and the remaining shared export cap.
    """
    from .symbolic import MAX_SOURCE_BYTES, analyze_binary
    digest = hashlib.sha256(raw).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=".native-work-", dir=output) as temporary:
            binary = Path(temporary) / (digest[:24] + ".so")
            binary.write_bytes(raw)
            binary.chmod(0o400)
            result = analyze_binary(binary, output, max_functions=max_functions,
                                    find_address=None, source_byte_limit=min(source_byte_limit, MAX_SOURCE_BYTES))
        result["source"] = source
        for item in result.get("source_index", []):
            item["source"] = source
        for item in result.get("functions", []):
            item["source"] = source
        return result
    except Exception as exc:
        return {"id": "symbolic", "source": source, "sha256": digest, "status": "failed",
                "functions": [], "source_index": [], "coverage": {},
                "warnings": [f"Native reconstruction failed ({type(exc).__name__})."]}


def elf_header(raw: bytes) -> dict:
    if len(raw) < 52 or raw[:4] != b"\x7fELF":
        raise ValueError("Not a complete ELF header.")
    bits = {1: 32, 2: 64}.get(raw[4])
    endian = {1: "<", 2: ">"}.get(raw[5])
    if bits is None or endian is None:
        raise ValueError("Unsupported ELF class or byte order.")
    if bits == 64 and len(raw) < 64:
        raise ValueError("Truncated ELF64 header.")
    machine = struct.unpack_from(endian + "H", raw, 18)[0]
    entry = struct.unpack_from(endian + ("Q" if bits == 64 else "I"), raw, 24)[0]
    shoff = struct.unpack_from(endian + ("Q" if bits == 64 else "I"), raw, 40 if bits == 64 else 32)[0]
    shentsize, shnum = struct.unpack_from(endian + "HH", raw, 58 if bits == 64 else 46)
    phoff = struct.unpack_from(endian + ("Q" if bits == 64 else "I"), raw, 32 if bits == 64 else 28)[0]
    phentsize, phnum = struct.unpack_from(endian + "HH", raw, 54 if bits == 64 else 42)
    for offset, size, count in ((shoff, shentsize, shnum), (phoff, phentsize, phnum)):
        if count and (size == 0 or offset + size * count > len(raw)):
            raise ValueError("ELF table extends beyond the input file.")
    return {"format": "ELF", "bits": bits, "endianness": "little" if endian == "<" else "big",
            "machine_id": machine, "architecture": MACHINES.get(machine, f"machine-{machine}"),
            "entrypoint": entry, "section_count": shnum, "segment_count": phnum}


def _disassembler(header: dict, *, thumb: bool = False):
    import capstone as cs
    endian = cs.CS_MODE_LITTLE_ENDIAN if header["endianness"] == "little" else cs.CS_MODE_BIG_ENDIAN
    machine = header["machine_id"]
    if machine == 183:
        return cs.Cs(cs.CS_ARCH_ARM64, endian)
    if machine == 40:
        return cs.Cs(cs.CS_ARCH_ARM, (cs.CS_MODE_THUMB if thumb else cs.CS_MODE_ARM) | endian)
    if machine == 62:
        return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    if machine == 3:
        return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    return None


def analyze_native(raw: bytes, source: str, output: Path, *, max_instructions: int = 20_000,
                   max_symbols: int = 20_000) -> dict:
    result = {"source": source, "sha256": hashlib.sha256(raw).hexdigest(), "status": "failed",
              "symbols": [], "imports": [], "exports": [], "sections": [], "needed_libraries": [],
              "source_index": [], "warnings": [], "instruction_count": 0}
    try:
        result.update(elf_header(raw))
    except ValueError as exc:
        result["warnings"].append(str(exc))
        return result
    try:
        import lief
    except ImportError:
        result.update(status="partial", engine="builtin-elf-header")
        result["warnings"].append("Embedded LIEF is not installed; symbols and sections were not analyzed.")
        return result
    try:
        binary = lief.ELF.parse(raw)
        if binary is None:
            raise ValueError("Embedded ELF parser did not return a binary.")
        result.update(engine="lief", status="completed")
        result["needed_libraries"] = [str(x)[:4096] for x in binary.libraries][:4096]
        for index, symbol in enumerate(binary.symbols):
            if index >= max_symbols:
                result["warnings"].append(f"Symbol list limited to {max_symbols:,} entries.")
                result["status"] = "partial"
                break
            name = str(symbol.name)[:4096]
            if not name:
                continue
            record = {"name": name, "address": int(symbol.value), "size": int(symbol.size),
                      "type": str(symbol.type), "binding": str(symbol.binding),
                      "imported": bool(symbol.imported), "exported": bool(symbol.exported)}
            result["symbols"].append(record)
            if record["imported"]:
                result["imports"].append(name)
            if record["exported"]:
                result["exports"].append(name)
        result["imports"] = sorted(set(result["imports"]))
        result["exports"] = sorted(set(result["exports"]))
        executable = []
        for index, section in enumerate(binary.sections):
            if index >= 4096:
                result["warnings"].append("Section list limited to 4,096 entries.")
                result["status"] = "partial"
                break
            record = {"name": str(section.name)[:1024], "address": int(section.virtual_address),
                      "offset": int(section.offset), "size": int(section.size), "flags": int(section.flags)}
            result["sections"].append(record)
            if record["flags"] & 4 and record["offset"] + record["size"] <= len(raw):
                executable.append(record)
        if max_instructions <= 0:
            result["status"] = "partial"
            result["warnings"].append("Native instruction export disabled by the selected analysis profile.")
            return result
        try:
            disassembler = _disassembler(result)
        except ImportError:
            result["status"] = "partial"
            result["warnings"].append("Embedded Capstone is not installed; native instructions were not decoded.")
            return result
        if disassembler is None:
            result["status"] = "partial"
            result["warnings"].append("This ELF architecture is not supported by the instruction exporter.")
            return result
        ranges = []
        if result["machine_id"] == 40:
            # ARM code can switch between ARM, Thumb, and literal pools. A
            # single unconditional sweep would invent instructions in data.
            for symbol in result["symbols"]:
                if not symbol["type"].endswith("FUNC") or not symbol["size"]:
                    continue
                address = symbol["address"] & ~1
                for section in executable:
                    delta = address - section["address"]
                    if 0 <= delta and delta + symbol["size"] <= section["size"]:
                        ranges.append((symbol["name"], address, section["offset"] + delta,
                                       symbol["size"], bool(symbol["address"] & 1)))
                        break
            if not ranges:
                result["status"] = "partial"
                result["warnings"].append("ARM/Thumb instruction mode is unknown without bounded function symbols; disassembly skipped.")
                return result
        else:
            ranges = [(x["name"], x["address"], x["offset"], x["size"], False) for x in executable]
        lines = [f"; APK GOD — embedded Capstone disassembly of {source}",
                 "; Linear decoding does not establish reachable functions or runtime behavior."]
        total_candidates = sum(x[3] for x in ranges)
        covered_bytes = 0
        for name, address, offset, size, thumb in ranges:
            remaining = max_instructions - result["instruction_count"]
            if remaining <= 0:
                break
            engine = _disassembler(result, thumb=thumb)
            lines.append(f"\n; Range {name!r}; file offset 0x{offset:x}; virtual address 0x{address:x}")
            # No supported instruction is longer than 16 bytes. Bound copies
            # before crossing into the extension module.
            code = raw[offset:offset + min(size, remaining * 16)]
            for pc, width, mnemonic, operands in engine.disasm_lite(code, address, count=remaining):
                lines.append(f"0x{pc:016x}  {mnemonic:<12} {operands}")
                result["instruction_count"] += 1
                covered_bytes += width
        result["disassembly_coverage"] = {"candidate_bytes": total_candidates, "decoded_instruction_bytes": covered_bytes,
                                           "instruction_limit": max_instructions,
                                           "limit_reached": result["instruction_count"] >= max_instructions}
        if result["instruction_count"] >= max_instructions:
            result["status"] = "partial"
            result["warnings"].append("Native instruction export reached the selected profile limit.")
        if result["instruction_count"]:
            folder = output / "native"
            folder.mkdir(parents=True, exist_ok=True)
            filename = result["sha256"][:20] + ".asm"
            path = folder / filename
            text = "\n".join(lines) + "\n"
            path.write_text(text, encoding="utf-8")
            result["source_index"].append({"path": path.relative_to(output).as_posix(), "language": "assembly",
                                            "lines": len(lines), "source": source, "kind": "disassembly"})
    except Exception as exc:
        result["status"] = "failed"
        result["warnings"].append(f"Native analysis failed ({type(exc).__name__}); no complete native analysis is claimed.")
    return result
