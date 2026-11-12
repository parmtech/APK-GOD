"""Real format fixtures for embedded APK engines; no Android device required.

Fixtures below are generated from documented Android DEX/AXML structures. They
are first-party test data, not redistributed third-party applications.
"""
import hashlib
import importlib.util
import io
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from apk_god.engines import PROFILES, _validate_dex, analyze_engines
from apk_god.inspect_apk import decode_xml, inspect_apk
from apk_god.native import analyze_native, elf_header


def _uleb(value):
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def synthetic_dex():
    """One class with a constructor, answer()=42 and ping()->answer()."""
    strings = ["<init>", "I", "Ljava/lang/Object;", "Lorg/example/Sample;", "V", "answer", "ping"]
    index = {text: i for i, text in enumerate(strings)}
    string_off = 112
    type_off = string_off + len(strings) * 4
    proto_off = type_off + 4 * 4
    method_off = proto_off + 2 * 12
    class_off = method_off + 4 * 8
    data_off = class_off + 32
    data = bytearray()
    code_offsets = []
    bodies = [(1, 1, 1, [0x1070, 0, 0, 0x000e]),
              (1, 0, 0, [0x0013, 42, 0x000f]),
              (1, 0, 0, [0x0071, 2, 0, 0x000a, 0x000f])]
    for registers, inputs, outputs, code in bodies:
        while (data_off + len(data)) % 4:
            data.append(0)
        code_offsets.append(data_off + len(data))
        data.extend(struct.pack("<HHHHII", registers, inputs, outputs, 0, 0, len(code)))
        data.extend(struct.pack("<" + "H" * len(code), *code))
    string_data_off = data_off + len(data)
    string_offsets = []
    for text in strings:
        string_offsets.append(data_off + len(data))
        data.extend(_uleb(len(text)) + text.encode() + b"\x00")
    class_data_off = data_off + len(data)
    data.extend(b"\x00\x00\x03\x00")
    for flags, offset in zip([0x10001, 9, 9], code_offsets):
        data.extend(_uleb(1) + _uleb(flags) + _uleb(offset))
    while (data_off + len(data)) % 4:
        data.append(0)
    map_off = data_off + len(data)
    map_items = [(0x0000, 1, 0), (0x0001, len(strings), string_off), (0x0002, 4, type_off),
                 (0x0003, 2, proto_off), (0x0005, 4, method_off), (0x0006, 1, class_off),
                 (0x2001, 3, code_offsets[0]), (0x2002, len(strings), string_data_off),
                 (0x2000, 1, class_data_off), (0x1000, 1, map_off)]
    data.extend(struct.pack("<I", len(map_items)))
    for kind, count, offset in map_items:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    header = bytearray(112)
    header[:8] = b"dex\n035\x00"
    struct.pack_into("<III", header, 32, data_off + len(data), 112, 0x12345678)
    struct.pack_into("<I", header, 52, map_off)
    for offset, count, table in [(56, len(strings), string_off), (64, 4, type_off),
                                 (72, 2, proto_off), (80, 0, 0), (88, 4, method_off),
                                 (96, 1, class_off), (104, len(data), data_off)]:
        struct.pack_into("<II", header, offset, count, table)
    result = header + b"".join(struct.pack("<I", x) for x in string_offsets)
    result += b"".join(struct.pack("<I", index[x]) for x in ["I", "Ljava/lang/Object;", "Lorg/example/Sample;", "V"])
    result += struct.pack("<III", index["I"], 0, 0) + struct.pack("<III", index["V"], 3, 0)
    for class_index, proto, name in [(1, 1, "<init>"), (2, 1, "<init>"), (2, 0, "answer"), (2, 0, "ping")]:
        result += struct.pack("<HHI", class_index, proto, index[name])
    result += struct.pack("<IIIIIIII", 2, 1, 1, 0, 0xffffffff, 0, class_data_off, 0)
    result += data
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into("<I", result, 8, zlib.adler32(result[12:]) & 0xffffffff)
    return bytes(result)


def synthetic_axml():
    strings = ["manifest", "package", "org.example.native", "application"]
    string_data = bytearray()
    offsets = []
    for text in strings:
        offsets.append(len(string_data))
        encoded = text.encode()
        string_data.extend(bytes([len(text), len(encoded)]) + encoded + b"\x00")
    while len(string_data) % 4:
        string_data.append(0)
    pool_size = 28 + len(strings) * 4 + len(string_data)
    pool = struct.pack("<HHIIIIII", 1, 28, pool_size, len(strings), 0, 0x100, 28 + len(strings) * 4, 0)
    pool += b"".join(struct.pack("<I", x) for x in offsets) + string_data

    def start(name, attributes=()):
        size = 36 + len(attributes) * 20
        chunk = struct.pack("<HHIII", 0x102, 16, size, 1, 0xffffffff)
        chunk += struct.pack("<IIHHHHHH", 0xffffffff, name, 20, 20, len(attributes), 0, 0, 0)
        for attr_name, value in attributes:
            chunk += struct.pack("<IIIHBBI", 0xffffffff, attr_name, value, 8, 0, 3, value)
        return chunk

    def end(name):
        return struct.pack("<HHIIIII", 0x103, 16, 24, 1, 0xffffffff, 0xffffffff, name)

    chunks = pool + start(0, [(1, 2)]) + start(3) + end(3) + end(0)
    return struct.pack("<HHI", 3, 8, 8 + len(chunks)) + chunks


def synthetic_apk(path, *, dex=True, binary_manifest=False):
    manifest = (synthetic_axml() if binary_manifest else
                b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example" '
                b'android:versionName="1.0"><uses-permission android:name="android.permission.INTERNET"/>'
                b'<application android:debuggable="true"><activity android:name=".Sample" android:exported="false"/>'
                b'</application></manifest>')
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        if dex:
            archive.writestr("classes.dex", synthetic_dex())
        archive.writestr("assets/config.json", '{"url":"https://example.invalid/api"}')


class ArchiveTests(unittest.TestCase):
    def test_manifest_and_archive_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.apk"
            synthetic_apk(path)
            result = inspect_apk(path)
            self.assertEqual(result["package"]["package_name"], "org.example")
            self.assertEqual(result["components"][0]["name"], "org.example.Sample")
            self.assertFalse(result["components"][0]["exported"])
            self.assertEqual(result["dex"][0]["version"], "035")
            self.assertEqual(result["signatures"]["verification"], "not-performed")
            self.assertIn("android.permission.INTERNET", result["permissions"])

    def test_unsafe_ambiguous_and_symlink_members_rejected(self):
        for name in ["../outside", "/absolute", "C:/outside", "..\\outside"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "bad.apk"
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("AndroidManifest.xml", "<manifest/>")
                    archive.writestr(name, "payload")
                with self.assertRaises(ValueError):
                    inspect_apk(path)
        for member in ["duplicate", "symlink"]:
            with self.subTest(member=member), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "bad.apk"
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("AndroidManifest.xml", "<manifest/>")
                    if member == "duplicate":
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", UserWarning)
                            archive.writestr("AndroidManifest.xml", "<manifest/>")
                    else:
                        info = zipfile.ZipInfo("link")
                        info.create_system = 3
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        archive.writestr(info, "../outside")
                with self.assertRaises(ValueError):
                    inspect_apk(path)

    def test_compression_bomb_rejected_before_member_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bomb.apk"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("AndroidManifest.xml", "<manifest/>")
                archive.writestr("assets/bomb.txt", b"0" * (10 * 1024**2))
            with self.assertRaisesRegex(ValueError, "compression ratio"):
                inspect_apk(path)

    def test_xml_entities_are_not_expanded(self):
        root, text, warning = decode_xml(b'<!DOCTYPE x [<!ENTITY a "payload">]><manifest package="&a;"/>')
        self.assertIsNone(root)
        self.assertIsNone(text)
        self.assertIn("failed", warning)

    def test_bad_dex_table_bounds_rejected(self):
        data = bytearray(synthetic_dex())
        struct.pack_into("<I", data, 56, 0xffffffff)
        with self.assertRaisesRegex(ValueError, "table bounds"):
            _validate_dex(data)


@unittest.skipUnless(importlib.util.find_spec("androguard"), "Embedded Androguard is optional")
class EmbeddedDexTests(unittest.TestCase):
    def test_binary_axml_decodes_in_process(self):
        root, text, warning = decode_xml(synthetic_axml())
        self.assertIsNone(warning)
        self.assertEqual(root.get("package"), "org.example.native")
        self.assertIn("application", text)

    def test_dex_calls_cfg_disassembly_and_decompilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "fixture.apk"
            synthetic_apk(apk)
            result = analyze_engines(apk, root / "output", "quick")
            self.assertEqual(result["status"], "completed", result["warnings"])
            self.assertEqual(len(result["classes"]), 1)
            self.assertEqual(len(result["methods"]), 3)
            self.assertEqual(result["classes"][0]["name"], "Lorg/example/Sample;")
            self.assertTrue(any(x["caller"].endswith("->ping()I") and x["callee"].endswith("->answer()I")
                                for x in result["calls"]))
            self.assertTrue(any(x["method"].endswith("->answer()I") and x["blocks"] for x in result["cfg"]))
            java = [x for x in result["source_index"] if x["language"] == "java"]
            self.assertEqual(len(java), 1)
            reconstructed = (root / "output" / java[0]["path"]).read_text()
            self.assertIn("42", reconstructed)
            self.assertTrue(result["dex"][0]["header_sha1_matches"])
            self.assertTrue(result["dex"][0]["header_adler32_matches"])

    def test_profile_caps_are_recorded_as_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "fixture.apk"
            synthetic_apk(apk)
            limited = dict(PROFILES["quick"], methods=1, decompile_classes=0)
            with patch.dict(PROFILES, {"quick": limited}):
                result = analyze_engines(apk, root / "output", "quick")
            self.assertEqual(result["status"], "partial")
            self.assertTrue(result["coverage"]["truncated"])
            self.assertEqual(len(result["methods"]), 1)
            self.assertTrue(result["coverage"]["limit_reasons"])


class NativeTests(unittest.TestCase):
    def test_non_elf_not_mistaken_for_native_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = analyze_native(b"not an elf", "lib/test.so", Path(tmp))
            self.assertEqual(result["status"], "failed")
        with self.assertRaises(ValueError):
            elf_header(b"\x7fELF")

    @unittest.skipUnless(importlib.util.find_spec("lief") and importlib.util.find_spec("capstone")
                         and Path("/usr/bin/true").is_file(), "Linux ELF fixture/libraries unavailable")
    def test_elf_metadata_and_bounded_capstone_disassembly(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            result = analyze_native(Path("/usr/bin/true").read_bytes(), "lib/x86_64/fixture.so", output,
                                    max_instructions=10)
            self.assertEqual(result["format"], "ELF")
            self.assertTrue(result["sections"])
            self.assertEqual(result["instruction_count"], 10)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(result["disassembly_coverage"]["limit_reached"])
            self.assertTrue((output / result["source_index"][0]["path"]).is_file())


if __name__ == "__main__":
    unittest.main()
