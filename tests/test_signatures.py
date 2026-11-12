"""Original signed fixtures with independently constructed v2 digest records."""
import hashlib
import importlib.util
import io
import struct
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apk_god.signatures import inspect_signatures


def unsigned_apk(large=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="org.apkgod.signature.fixture"/>')
        archive.writestr("assets/payload", (b"fixture-content" * 80000) if large else b"fixture-content")
    return stream.getvalue()


def lp(data):
    return struct.pack("<I", len(data)) + data


def expected_digest(unsigned, name):
    """Digest the unsigned ZIP's sections; its original CD offset is the block start."""
    end = unsigned.rindex(b"PK\x05\x06")
    directory = struct.unpack_from("<I", unsigned, end + 16)[0]
    sections = (unsigned[:directory], unsigned[directory:end], unsigned[end:])
    pieces = []
    for section in sections:
        for start in range(0, len(section), 1048576):
            piece = section[start:start + 1048576]
            pieces.append(hashlib.new(name, b"\xa5" + struct.pack("<I", len(piece)) + piece).digest())
    return hashlib.new(name, b"\x5a" + struct.pack("<I", len(pieces)) + b"".join(pieces)).digest()


def wrap_signers(unsigned, signers, scheme_id=0x7109871A):
    value = lp(b"".join(lp(signer) for signer in signers))
    pair = struct.pack("<QI", len(value) + 4, scheme_id) + value
    size = len(pair) + 24
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    end = unsigned.rindex(b"PK\x05\x06")
    directory = struct.unpack_from("<I", unsigned, end + 16)[0]
    trailer = bytearray(unsigned[end:])
    struct.pack_into("<I", trailer, 16, directory + len(block))
    return unsigned[:directory] + block + unsigned[directory:end] + trailer


class LayoutTests(unittest.TestCase):
    def test_absent_v2_does_not_claim_unsigned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.apk"
            path.write_bytes(unsigned_apk())
            result = inspect_signatures(path)
            self.assertEqual(result["verification"], "v2-not-present")
            self.assertEqual(result["signer_trust"], "not-assessed")
            self.assertNotIn("unsigned", result["reason"])
            path.write_bytes(wrap_signers(unsigned_apk(), [b"opaque-v3-data"], scheme_id=0xF05368C0))
            result = inspect_signatures(path)
            self.assertEqual(result["verification"], "v2-not-present")
            self.assertIn("0xf05368c0", result["signing_block_ids"])

    def test_trailing_data_and_directory_gap_are_rejected(self):
        unsigned = unsigned_apk()
        end = unsigned.rindex(b"PK\x05\x06")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.apk"
            for content in [unsigned + b"trailing data", unsigned[:end] + b"gap" + unsigned[end:], b"not a zip"]:
                path.write_bytes(content)
                self.assertEqual(inspect_signatures(path)["verification"], "v2-invalid")


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Embedded cryptography is unavailable")
class CryptographicSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
        from cryptography.x509.oid import NameOID
        cls.keys = {"rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
                    "ec": ec.generate_private_key(ec.SECP256R1()),
                    "dsa": dsa.generate_private_key(key_size=2048)}
        cls.certs = {}
        identity = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "APK GOD temporary test signer")])
        now = datetime.now(timezone.utc)
        for kind, key in cls.keys.items():
            cert = (x509.CertificateBuilder().subject_name(identity).issuer_name(identity)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                    .sign(key, hashes.SHA256()))
            cls.certs[kind] = cert.public_bytes(serialization.Encoding.DER)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "fixture.apk"

    def tearDown(self):
        self.temp.cleanup()

    def signer(self, unsigned, kind, algorithms, *, digest_ids=None, corrupt_algorithm=None, certificate=None, bad_digest=False):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        key = self.keys[kind]
        digests = []
        for identifier in digest_ids if digest_ids is not None else algorithms:
            name = "sha512" if identifier in {0x0102, 0x0104, 0x0202} else "sha256"
            digest = expected_digest(unsigned, name)
            if bad_digest:
                digest = bytes([digest[0] ^ 1]) + digest[1:]
            digests.append(lp(struct.pack("<I", identifier) + lp(digest)))
        cert = certificate if certificate is not None else self.certs[kind]
        signed_data = lp(b"".join(digests)) + lp(lp(cert)) + lp(b"")
        signatures = []
        for identifier in algorithms:
            algorithm = hashes.SHA512() if identifier in {0x0102, 0x0104, 0x0202} else hashes.SHA256()
            if kind == "rsa":
                pad = padding.PSS(mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size) if identifier in {0x0101, 0x0102} else padding.PKCS1v15()
                signature = key.sign(signed_data, pad, algorithm)
            elif kind == "ec":
                signature = key.sign(signed_data, ec.ECDSA(algorithm))
            else:
                signature = key.sign(signed_data, algorithm)
            if identifier == corrupt_algorithm:
                signature = bytes([signature[0] ^ 1]) + signature[1:]
            signatures.append(lp(struct.pack("<I", identifier) + lp(signature)))
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return lp(signed_data) + lp(b"".join(signatures)) + lp(public)

    def verify(self, content):
        self.path.write_bytes(content)
        return inspect_signatures(self.path)

    def test_all_supported_standard_signature_algorithms(self):
        unsigned = unsigned_apk()
        for kind, identifier in [("rsa", 0x0101), ("rsa", 0x0102), ("rsa", 0x0103), ("rsa", 0x0104), ("ec", 0x0201), ("ec", 0x0202), ("dsa", 0x0301)]:
            with self.subTest(kind=kind, algorithm=hex(identifier)):
                result = self.verify(wrap_signers(unsigned, [self.signer(unsigned, kind, [identifier])]))
                self.assertEqual(result["verification"], "v2-valid", result)
                self.assertTrue(result["protected_content_verified"])
                self.assertTrue(result["signers"][0]["certificate_public_key_matches"])
                self.assertEqual(result["signers"][0]["algorithm_id"], f"0x{identifier:04x}")
                self.assertEqual(result["signer_trust"], "not-assessed")

    def test_chunk_boundary_and_multiple_signers(self):
        unsigned = unsigned_apk(large=True)
        result = self.verify(wrap_signers(unsigned, [self.signer(unsigned, "rsa", [0x0101]), self.signer(unsigned, "ec", [0x0202])]))
        self.assertEqual(result["verification"], "v2-valid", result)
        self.assertEqual(len(result["signers"]), 2)
        self.assertEqual(result["signers"][0]["content_digest"], expected_digest(unsigned, "sha256").hex())

    def test_payload_tamper_invalidates_authentic_content_digest(self):
        unsigned = unsigned_apk()
        signed = wrap_signers(unsigned, [self.signer(unsigned, "rsa", [0x0101])])
        result = self.verify(signed.replace(b"fixture-content", b"tamper!-content"))
        self.assertEqual(result["verification"], "v2-invalid")
        self.assertFalse(result["protected_content_verified"])
        self.assertIn("content digest", result["reason"])

    def test_authentic_signature_with_wrong_digest_is_invalid(self):
        unsigned = unsigned_apk()
        result = self.verify(wrap_signers(unsigned, [self.signer(unsigned, "rsa", [0x0101], bad_digest=True)]))
        self.assertEqual(result["verification"], "v2-invalid")
        self.assertIn("content digest", result["reason"])

    def test_algorithm_order_protection_and_no_weaker_signature_fallback(self):
        unsigned = unsigned_apk()
        wrong_order = self.signer(unsigned, "rsa", [0x0101, 0x0102], digest_ids=[0x0102, 0x0101])
        result = self.verify(wrap_signers(unsigned, [wrong_order]))
        self.assertEqual(result["verification"], "v2-invalid")
        self.assertIn("ordered algorithm", result["reason"])
        bad_strongest = self.signer(unsigned, "rsa", [0x0101, 0x0102], corrupt_algorithm=0x0102)
        result = self.verify(wrap_signers(unsigned, [bad_strongest]))
        self.assertEqual(result["verification"], "v2-invalid")
        self.assertIn("signature", result["reason"])

    def test_certificate_key_mismatch_and_one_invalid_signer_fail(self):
        unsigned = unsigned_apk()
        mismatched = self.signer(unsigned, "rsa", [0x0101], certificate=self.certs["ec"])
        result = self.verify(wrap_signers(unsigned, [mismatched]))
        self.assertEqual(result["verification"], "v2-invalid")
        self.assertIn("certificate", result["reason"])
        result = self.verify(wrap_signers(unsigned, [self.signer(unsigned, "rsa", [0x0101]), self.signer(unsigned, "ec", [0x0201], corrupt_algorithm=0x0201)]))
        self.assertEqual(result["verification"], "v2-invalid")
        self.assertEqual(result["signers"], [])

    def test_unknown_algorithm_empty_signer_and_malformed_block(self):
        unsigned = unsigned_apk()
        result = self.verify(wrap_signers(unsigned, [self.signer(unsigned, "rsa", [0x9001])]))
        self.assertEqual(result["verification"], "unsupported")
        self.assertEqual(self.verify(wrap_signers(unsigned, []))["verification"], "v2-invalid")
        signed = bytearray(wrap_signers(unsigned, [self.signer(unsigned, "ec", [0x0201])]))
        start = struct.unpack_from("<I", unsigned, unsigned.rindex(b"PK\x05\x06") + 16)[0]
        struct.pack_into("<Q", signed, start, struct.unpack_from("<Q", signed, start)[0] + 1)
        result = self.verify(signed)
        self.assertEqual(result["verification"], "v2-invalid")
        self.assertIn("size fields", result["reason"])


if __name__ == "__main__":
    unittest.main()
