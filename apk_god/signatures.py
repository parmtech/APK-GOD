"""Original, bounded APK Signature Scheme v2 integrity verification.

Format reference: https://source.android.com/docs/security/features/apksigning/v2
This implements cryptographic content integrity, not certificate trust, v1/v3
verification, APK installability or every Android platform policy check. It uses
the embedded cryptography primitives and never calls apksigner or another CLI.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from pathlib import Path

MAX_APK_BYTES = 512 * 1024**2
MAX_SIGNING_BLOCK = 16 * 1024**2
CHUNK_BYTES = 1024**2
V2_ID = 0x7109871A
MAGIC = b"APK Sig Block 42"
ALGORITHMS = {
    0x0101: ("RSA-PSS", "sha256", 20),
    0x0102: ("RSA-PSS", "sha512", 40),
    0x0103: ("RSA-PKCS1-v1_5", "sha256", 10),
    0x0104: ("RSA-PKCS1-v1_5", "sha512", 30),
    0x0201: ("ECDSA", "sha256", 20),
    0x0202: ("ECDSA", "sha512", 40),
    0x0301: ("DSA", "sha256", 10),
}


class _Invalid(ValueError):
    pass


class _Unsupported(ValueError):
    pass


class _Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.position = 0

    def remaining(self):
        return len(self.data) - self.position

    def take(self, count):
        if count < 0 or count > self.remaining():
            raise _Invalid("A signing field exceeds its enclosing length.")
        start = self.position
        self.position += count
        return self.data[start:self.position]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def field(self):
        return self.take(self.u32())

    def done(self):
        if self.remaining():
            raise _Invalid("Unexpected bytes remain in a signing structure.")


def _fields(data, limit, label):
    reader = _Reader(data)
    result = []
    while reader.remaining():
        if len(result) >= limit:
            raise _Unsupported(label + " exceeds the supported count limit.")
        result.append(reader.field())
    return result


def _read_at(handle, offset: int, count: int):
    if offset < 0 or count < 0:
        raise _Invalid("Negative ZIP or signing block boundary.")
    handle.seek(offset)
    value = handle.read(count)
    if len(value) != count:
        raise _Invalid("APK was truncated or changed during verification.")
    return value


def _locate(handle, size):
    tail_start = max(0, size - 22 - 65535)
    tail = _read_at(handle, tail_start, size - tail_start)
    end = len(tail)
    found = None
    while end:
        position = tail.rfind(b"PK\x05\x06", 0, end)
        if position < 0:
            break
        if position + 22 <= len(tail):
            comment_len = struct.unpack_from("<H", tail, position + 20)[0]
            if position + 22 + comment_len == len(tail):
                found = position
                break
        end = position
    if found is None:
        raise _Invalid("A final ZIP End of Central Directory record was not found; trailing bytes are not accepted.")
    eocd = tail[found:]
    eocd_offset = tail_start + found
    _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, _ = struct.unpack_from("<4s4H2IH", eocd)
    if disk or cd_disk or disk_entries != entries:
        raise _Unsupported("Multi-disk ZIP archives are not supported.")
    if entries == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        raise _Unsupported("ZIP64 APK layouts are not supported by this verifier.")
    if eocd_offset >= 20 and _read_at(handle, eocd_offset - 20, 4) == b"PK\x06\x07":
        raise _Unsupported("ZIP64 APK layouts are not supported by this verifier.")
    if cd_offset + cd_size != eocd_offset:
        raise _Invalid("The ZIP Central Directory is not immediately followed by its end record.")
    if cd_offset > size or (entries and (cd_size < 46 or _read_at(handle, cd_offset, 4) != b"PK\x01\x02")):
        raise _Invalid("The ZIP Central Directory boundary is invalid.")
    layout = {"file_size": size, "central_directory_offset": cd_offset,
              "central_directory_size": cd_size, "eocd_offset": eocd_offset,
              "eocd": eocd, "block_offset": None, "block_ids": [], "v2": None}
    if cd_offset < 24:
        return layout
    footer = _read_at(handle, cd_offset - 24, 24)
    if footer[8:] != MAGIC:
        return layout
    block_size = struct.unpack_from("<Q", footer)[0]
    if block_size < 24 or block_size + 8 > cd_offset:
        raise _Invalid("The APK signing block size is inconsistent with its location.")
    if block_size + 8 > MAX_SIGNING_BLOCK:
        raise _Unsupported("The APK signing block exceeds the 16 MiB verification limit.")
    start = cd_offset - block_size - 8
    block = _read_at(handle, start, block_size + 8)
    if struct.unpack_from("<Q", block)[0] != block_size:
        raise _Invalid("The APK signing block's two size fields disagree.")
    pairs, offset, count = memoryview(block)[8:-24], 0, 0
    while offset < len(pairs):
        count += 1
        if count > 2048:
            raise _Unsupported("The APK signing block contains too many ID-value pairs.")
        if len(pairs) - offset < 8:
            raise _Invalid("A signing ID-value pair has no complete length.")
        length = struct.unpack_from("<Q", pairs, offset)[0]
        offset += 8
        if length < 4 or length > len(pairs) - offset:
            raise _Invalid("A signing ID-value pair has an invalid length.")
        block_id = struct.unpack_from("<I", pairs, offset)[0]
        layout["block_ids"].append(f"0x{block_id:08x}")
        if block_id == V2_ID and layout["v2"] is None:
            # The platform format specifies the first v2 block.
            layout["v2"] = bytes(pairs[offset + 4:offset + length])
        offset += length
    layout["block_offset"] = start
    return layout


def _content_digest(handle, layout, algorithm):
    """Stream the three protected sections; chunk boundaries reset per section."""
    eocd = bytearray(layout["eocd"])
    struct.pack_into("<I", eocd, 16, layout["block_offset"])
    sections = ((0, layout["block_offset"]),
                (layout["central_directory_offset"], layout["central_directory_size"]))
    count = sum((length + CHUNK_BYTES - 1) // CHUNK_BYTES for _, length in sections)
    count += (len(eocd) + CHUNK_BYTES - 1) // CHUNK_BYTES
    digest = hashlib.new(algorithm)
    digest.update(b"\x5a" + struct.pack("<I", count))
    for offset, length in sections:
        handle.seek(offset)
        remaining = length
        while remaining:
            block = handle.read(min(CHUNK_BYTES, remaining))
            if not block:
                raise _Invalid("APK changed while protected content was being read.")
            remaining -= len(block)
            digest.update(hashlib.new(algorithm, b"\xa5" + struct.pack("<I", len(block)) + block).digest())
    for offset in range(0, len(eocd), CHUNK_BYTES):
        block = eocd[offset:offset + CHUNK_BYTES]
        digest.update(hashlib.new(algorithm, b"\xa5" + struct.pack("<I", len(block)) + block).digest())
    return digest.digest()


def _algorithm_records(data, field_name):
    records, order = {}, []
    for item in _fields(data, 32, field_name):
        parser = _Reader(item)
        identifier = parser.u32()
        value = bytes(parser.field())
        parser.done()
        if identifier in records:
            raise _Invalid("Duplicate algorithm IDs make signing records ambiguous.")
        if len(value) > 64 * 1024:
            raise _Unsupported("A signature or digest field exceeds its supported size.")
        records[identifier] = value
        order.append(identifier)
    return records, order


def _verify_crypto(public_key, signature, signed_data, identifier):
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
    name, digest_name, _ = ALGORITHMS[identifier]
    hash_type = hashes.SHA256() if digest_name == "sha256" else hashes.SHA512()
    try:
        key = serialization.load_der_public_key(public_key)
        if key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != public_key:
            raise _Invalid("The signer's public key is not an exact DER SubjectPublicKeyInfo value.")
        if name.startswith("RSA") and isinstance(key, rsa.RSAPublicKey):
            if key.key_size not in {1024, 2048, 4096, 8192, 16384}:
                raise _Unsupported("The RSA key size is outside the supported APK signing set.")
            pad = padding.PSS(mgf=padding.MGF1(hash_type), salt_length=hash_type.digest_size) if name == "RSA-PSS" else padding.PKCS1v15()
            key.verify(signature, signed_data, pad, hash_type)
        elif name == "ECDSA" and isinstance(key, ec.EllipticCurvePublicKey):
            if not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
                raise _Unsupported("The EC curve is outside the supported APK signing set.")
            key.verify(signature, signed_data, ec.ECDSA(hash_type))
        elif name == "DSA" and isinstance(key, dsa.DSAPublicKey):
            if key.key_size not in {1024, 2048, 3072}:
                raise _Unsupported("The DSA key size is outside the supported APK signing set.")
            key.verify(signature, signed_data, hash_type)
        else:
            raise _Invalid("The selected signature algorithm does not match the public key type.")
    except InvalidSignature:
        raise _Invalid("A signer's signature over its signed-data block is invalid.") from None
    except UnsupportedAlgorithm:
        raise _Unsupported("The cryptographic backend does not support this signing key or algorithm.") from None
    except (ValueError, TypeError) as exc:
        if isinstance(exc, (_Invalid, _Unsupported)):
            raise
        raise _Invalid("A signer's public key or signature encoding is invalid.") from None
    return key


def _verify_signer(data, digest_for):
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    parser = _Reader(data)
    signed_data = bytes(parser.field())
    signatures, signature_ids = _algorithm_records(parser.field(), "Signature list")
    public_key = bytes(parser.field())
    parser.done()
    if len(public_key) > 64 * 1024:
        raise _Unsupported("Signer public key exceeds its supported size.")
    known = [identifier for identifier in signature_ids if identifier in ALGORITHMS]
    if not known:
        raise _Unsupported("A signer has no supported v2 signature algorithm.")
    # Within one signer's key type, prefer SHA-512, then RSA-PSS for ties.
    strongest = max(known, key=lambda x: (ALGORITHMS[x][2], -signature_ids.index(x)))
    _verify_crypto(public_key, signatures[strongest], signed_data, strongest)
    # Parse authenticated signed data only after signature verification succeeds.
    authenticated = _Reader(signed_data)
    digests, digest_ids = _algorithm_records(authenticated.field(), "Digest list")
    certificates = _fields(authenticated.field(), 16, "Certificate chain")
    attributes = _fields(authenticated.field(), 128, "Additional attribute list")
    authenticated.done()
    if digest_ids != signature_ids:
        raise _Invalid("The ordered algorithm lists in signatures and signed digests differ.")
    if not certificates:
        raise _Invalid("A signer has no certificate.")
    certificate_objects = []
    try:
        for raw in certificates:
            if len(raw) > 1024**2:
                raise _Unsupported("A signer certificate exceeds its supported size.")
            cert = x509.load_der_x509_certificate(bytes(raw))
            if cert.public_bytes(serialization.Encoding.DER) != bytes(raw):
                raise _Invalid("A certificate is not an exact DER value.")
            certificate_objects.append(cert)
    except ValueError as exc:
        if isinstance(exc, (_Invalid, _Unsupported)):
            raise
        raise _Invalid("A signer certificate is not a valid DER X.509 certificate.") from None
    try:
        cert_key = certificate_objects[0].public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except UnsupportedAlgorithm:
        raise _Unsupported("The cryptographic backend cannot decode the signer's certificate public key.") from None
    if not hmac.compare_digest(cert_key, public_key):
        raise _Invalid("The first certificate's public key does not match the verified signer public key.")
    digest_name = ALGORITHMS[strongest][1]
    expected = digest_for(digest_name)
    if not hmac.compare_digest(digests[strongest], expected):
        raise _Invalid("The authenticated APK content digest does not match the protected file contents.")
    attribute_ids = []
    for raw in attributes:
        record = _Reader(raw)
        attribute_ids.append(f"0x{record.u32():08x}")
        # Other attribute data is not interpreted as a platform-policy verdict.
    return {"algorithm_id": f"0x{strongest:04x}", "algorithm": ALGORITHMS[strongest][0],
            "digest_algorithm": digest_name, "content_digest": expected.hex(),
            "signature_verified": True, "content_digest_matches": True,
            "certificate_public_key_matches": True,
            "certificate_sha256": hashlib.sha256(bytes(certificates[0])).hexdigest(),
            "certificate_chain_length": len(certificates), "additional_attribute_ids": attribute_ids,
            "algorithm_ids": [f"0x{x:04x}" for x in signature_ids]}


def inspect_signatures(path: str | Path) -> dict:
    """Return a bounded v2 result. Never interpret v2 absence as an unsigned APK."""
    result = {"scheme": "APK Signature Scheme v2", "verification": "v2-not-present", "signers": [],
              "protected_content_verified": False,
              "signer_trust": "not-assessed", "signing_block_ids": [],
              "limitations": [
                  "This result verifies supported v2 signatures and protected content only; it is not an Android installability verdict.",
                  "Certificate trust, certificate-chain trust, expiry policy, signing lineage, v1 signatures and v3/v3.1 signatures were not verified.",
                  "Platform-specific additional-attribute and anti-downgrade policy checks are outside this verifier's scope.",
                  "An absent v2 block does not mean the APK is unsigned; other signing schemes may be present.",
              ]}
    try:
        source = Path(path)
        if not source.is_file():
            raise _Invalid("Signature input must be a file.")
        with source.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if before.st_size > MAX_APK_BYTES:
                raise _Unsupported("APK exceeds the 512 MiB verification limit.")
            layout = _locate(handle, before.st_size)
            result["signing_block_ids"] = layout["block_ids"]
            if layout["v2"] is None:
                result["reason"] = "No APK Signature Scheme v2 block was found; other schemes were not verified."
                return result
            try:
                import cryptography  # noqa: F401 — optional embedded primitive provider
            except ImportError:
                raise _Unsupported("Install the embedded cryptography dependency to verify v2 signatures.") from None
            outer = _Reader(layout["v2"])
            signers = _fields(outer.field(), 16, "Signer list")
            outer.done()
            if not signers:
                raise _Invalid("The v2 block contains no signers.")
            content_digests = {}

            def digest_for(name):
                if name not in content_digests:
                    content_digests[name] = _content_digest(handle, layout, name)
                return content_digests[name]

            verified = [_verify_signer(signer, digest_for) for signer in signers]
            after = os.fstat(handle.fileno())
            path_after = source.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino) or (after.st_ino, after.st_dev) != (path_after.st_ino, path_after.st_dev):
                raise _Invalid("APK changed during signature verification.")
            result.update(verification="v2-valid", signers=verified,
                          reason="Every v2 signer passed supported signature, content digest and certificate-key matching checks.",
                          protected_content_verified=True)
    except _Unsupported as exc:
        result.update(verification="unsupported", reason=str(exc), protected_content_verified=False)
    except _Invalid as exc:
        result.update(verification="v2-invalid", reason=str(exc), protected_content_verified=False)
    except (OSError, struct.error, OverflowError):
        result.update(verification="v2-invalid", reason="The APK could not be read as a bounded signing structure.", protected_content_verified=False)
    return result
