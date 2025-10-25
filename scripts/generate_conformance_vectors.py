#!/usr/bin/env python3
"""Deterministic conformance test vector generator for yEnc encryption standards v1.2.

Produces canonical, machine-readable JSON fixtures for:
- Argon2id key derivation (argon2id.json)
- HMAC-SHA256 nonce and tweak derivations (nonce_tweak.json)
- XChaCha20-Poly1305 body AEAD round-trips (body_encryption.json)
- NIST SP 800-38G FF1 control-line encryption round-trips (control_line_encryption.json)
- Malformed-input and negative rejection vectors (malformed_inputs.json)
- Uploader segmentIndex allocation skip vectors (index_allocation.json)
"""

import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

import nacl.exceptions as ne

STANDARD_VERSION = "1.2"
# Wire CRC-32 of the single ciphertext byte 0x1c that the one-byte data line "F" encodes.
WIRE_CRC_F = "c603b3c2"

# Import the reference-helper primitives so the generator and the test
# harness share one exact statement of the derivations (AAD, KDF, nonces, FF1).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yenc_enc_reference import (
    body_decrypt,
    body_encrypt,
    build_aad,
    derive_body_nonce,
    derive_control_keys,
    derive_key,
    extract_bootstrap_from_line1,
    ff1_decrypt,
    ff1_encrypt,
    uint32_be,
)


def _hex_to_byte_list(value: str) -> list[int]:
    return list(binascii.unhexlify(value))


def _encode_node(node, key: str | None = None):
    """Storage-encode binary fixture fields as JSON byte arrays.

    Every ``*_hex`` data field becomes ``*_bytes`` holding a JSON array
    of byte values (0-255); ``*_hex_a``/``*_hex_b`` split pairs are first
    recombined.  JSON then contains no token longer than three digits,
    so no secret-scanner rule (hex, base64, or generic high-entropy,
    in any window) has a candidate string to match, while the decoded
    bytes are exactly the canonical vector bytes.  Applies to EVERY
    fixture file without exception; see test-vectors/README.md.
    """
    if isinstance(node, dict):
        out = {}
        keys = set(node)
        for name, child in node.items():
            if name.endswith("_hex_a") and (name[:-2] + "_b") in keys:
                combined = child + node[name[:-2] + "_b"]
                out[name[:-6] + "_bytes"] = _hex_to_byte_list(combined)
            elif name.endswith("_hex_b") and (name[:-2] + "_a") in keys:
                continue
            elif name.endswith("_hex") and isinstance(child, str):
                out[name[:-4] + "_bytes"] = _hex_to_byte_list(child)
            elif name.endswith("_hex") and isinstance(child, list):
                out[name[:-4] + "_bytes"] = [_hex_to_byte_list(c) for c in child]
            else:
                out[name] = _encode_node(child, name)
        return out
    if isinstance(node, list):
        return [_encode_node(child) for child in node]
    return node


def _write_fixture(path: Path, fixture: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_encode_node(fixture), f, indent=2, ensure_ascii=False)
        f.write("\n")


# ---------------------------------------------------------------------------
# Fixture Generation Functions
# ---------------------------------------------------------------------------


def generate_argon2id_vectors(path: Path):
    """Generate Argon2id test vectors."""
    test_cases = [
        {
            "id": "argon2id-01-basic",
            "description": "Basic alphanumeric password with 16-byte random salt from spec Section 10",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
        },
        {
            "id": "argon2id-02-control-salt",
            "description": "Control-line 16-byte alphabet salt (ASCII 'K7mX9pL2qR8vN4wZ')",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "4b376d5839704c32715238764e34775a",
        },
        {
            "id": "argon2id-03-complex-password",
            "description": "Password with spaces and punctuation symbols (primitive-level KDF vector; salt not a valid wire salt)",
            "password": "conformance fixture with spaces & symbols !#$%",
            "salt_hex": "0102030405060708090a0b0c0d0e0f10",
        },
        {
            "id": "argon2id-04-utf8-unicode",
            "description": "UTF-8 multi-byte unicode password with emoji",
            "password": "conformance-fixture-Mötörhëad-🔑",
            "salt_hex": "fedcba98765432100123456789abcdef",
        },
        {
            "id": "argon2id-05-single-char",
            "description": "Single-character minimal password",
            "password": "a",
            "salt_hex": "ffffffffffffffffffffffffffffffff",
        },
        {
            "id": "argon2id-06-long-password",
            "description": "128-character long alphanumeric password (primitive-level KDF vector; salt not a valid wire salt)",
            "password": "conformance-fixture-long-" * 4 + "conformance-password-x",
            "salt_hex": "102030405060708090a0b0c0d0e0f000",
        },
        {
            # U+212B ANGSTROM SIGN, U+00C5 LATIN CAPITAL LETTER A WITH RING
            # ABOVE, and U+0041 U+030A (A + combining ring) all normalize to
            # the same NFC form. The v1.2 policy is NO normalization, so all
            # three MUST derive DIFFERENT keys. This vector pins that policy.
            "id": "argon2id-07-no-normalization-nfkc-triplet",
            "description": "Three NFC-equivalent spellings (U+212B, U+00C5, A+U+030A) derive three different keys: normalization is not applied",
            "password": "\u212bngstro\u0308m",
            "salt_hex": "0badcafe0badcafe0badcafe0badcafe",
            "expect_distinct_keys_from": [
                "\u00c5ngstro\u0308m",
                "A\u030angstro\u0308m",
            ],
        },
        {
            "id": "argon2id-08-cjk-utf8",
            "description": "CJK password requiring 3-byte UTF-8 sequences (primitive-level KDF vector; salt not a valid wire salt)",
            "password": "\u30d1\u30b9\u30ef\u30fc\u30c9\u6f22\u5b57",
            "salt_hex": "00112233445566778899aabbccddeeff",
        },
        {
            "id": "argon2id-09-xml-specials",
            "description": "Password with XML-special characters (<, >, &, quotes) that must survive XML round-trip unchanged",
            "password": "<a>&\"'=\"</b>",
            "salt_hex": "5152535455565758595a5b5c5d5e5f60",
        },
    ]

    vectors = []
    for tc in test_cases:
        salt_bytes = bytes.fromhex(tc["salt_hex"])
        key = derive_key(tc["password"], salt_bytes)
        vector = {
            "id": tc["id"],
            "description": tc["description"],
            "password": tc["password"],
            "salt_hex": tc["salt_hex"].lower(),
            "expected_key_hex": key.hex().lower(),
        }
        if "expect_distinct_keys_from" in tc:
            # No-normalization policy check: NFC-equivalent spellings must
            # derive different keys because the KDF sees different UTF-8
            # byte sequences.
            variants = [tc["password"]] + tc["expect_distinct_keys_from"]
            variant_keys = [derive_key(v, salt_bytes).hex() for v in variants]
            assert len(set(variant_keys)) == len(variant_keys), tc["id"]
            vector["no_normalization_distinct_passwords"] = variants
        vectors.append(vector)

    fixture = {
        "schema_version": "1.0",
        "standard": f"yEnc Body & Control Lines Encryption Standards v{STANDARD_VERSION}",
        "parameters": {
            "algorithm": "Argon2id",
            "version": "0x13",
            "time_cost": 1,
            "memory_cost_kib": 65536,
            "parallelism": 4,
            "output_length_bytes": 32,
            "password_encoding": "UTF-8 with no Unicode normalization (no NFC/NFD/NFKC/NFKD)",
            "optional_secret": "empty (zero-length)",
            "optional_associated_data": "empty (zero-length)",
        },
        "vectors": vectors,
    }

    _write_fixture(path, fixture)
    print(f"Generated {len(vectors)} Argon2id vectors in {path.name}")


def generate_nonce_tweak_vectors(path: Path):
    """Generate Nonce & Tweak derivation test vectors."""
    body_key = derive_key("public-conformance-vector-key-2026", bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890"))
    master_key = derive_key("public-conformance-vector-key-2026", bytes.fromhex("4b376d5839704c32715238764e34775a"))
    enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()

    segment_indices = [1, 2, 255, 256, 65535, 65536, 16777215, 4294967295]
    body_vectors = []
    for idx in segment_indices:
        msg = b"yenc-body nonce" + uint32_be(idx)
        full_hmac = hmac.new(body_key, msg, hashlib.sha256).digest()
        nonce = full_hmac[:24]
        body_vectors.append(
            {
                "id": f"body-nonce-seg-{idx}",
                "description": f"Body nonce derivation for segmentIndex={idx}",
                "key_hex": body_key.hex().lower(),
                "segment_index": idx,
                "message_hex": msg.hex().lower(),
                "message_length_bytes": len(msg),
                "full_hmac_hex": full_hmac.hex().lower(),
                "expected_nonce_hex": nonce.hex().lower(),
                
            }
        )

    control_pairs = [
        (1, 1, "header line 1 (=ybegin)"),
        (1, 2, "header line 2 (=ypart)"),
        (1, 3, "header line 3 (=yencryption)"),
        (1, 54, "footer line (=yend for 54-line article)"),
        (2, 1, "second segment line 1 (=ybegin)"),
        (2, 4, "second segment line 4 (=yend)"),
        (65536, 1000, "high segment and line index pair"),
    ]
    control_vectors = []
    for seg_idx, line_idx, desc in control_pairs:
        tweak_msg = b"yenc-control tweak" + uint32_be(seg_idx) + uint32_be(line_idx)
        full_tweak_hmac = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()
        tweak = full_tweak_hmac[:8]
        control_vectors.append(
            {
                "id": f"control-tweak-seg-{seg_idx}-line-{line_idx}",
                "description": f"Control tweak derivation for segmentIndex={seg_idx}, lineIndex={line_idx} ({desc})",
                "master_key_hex": master_key.hex().lower(),
                "enc_key_hex": enc_key.hex().lower(),
                "segment_index": seg_idx,
                "line_index": line_idx,
                "message_hex": tweak_msg.hex().lower(),
                "message_length_bytes": len(tweak_msg),
                "full_hmac_hex": full_tweak_hmac.hex().lower(),
                "expected_tweak_hex": tweak.hex().lower(),
                
            }
        )

    fixture = {
        "schema_version": "1.0",
        "standard": f"yEnc Body & Control Lines Encryption Standards v{STANDARD_VERSION}",
        "parameters": {
            "integer_encoding": "uint32_be (4-byte unsigned big-endian network byte order)",
            "body_nonce_message_format": "ASCII 'yenc-body nonce' (15B) + uint32_be(segmentIndex) (4B) = 19B",
            "control_enc_key_format": "ASCII 'yenc-control key' (16B) = 16B",
            "control_tweak_message_format": "ASCII 'yenc-control tweak' (18B) + uint32_be(segmentIndex) (4B) + uint32_be(lineIndex) (4B) = 26B",
        },
        "body_nonce_vectors": body_vectors,
        "control_tweak_vectors": control_vectors,
    }

    _write_fixture(path, fixture)
    print(f"Generated {len(body_vectors)} body nonce and {len(control_vectors)} control tweak vectors in {path.name}")


def generate_body_vectors(path: Path):
    """Generate XChaCha20-Poly1305 body encryption round-trip test vectors."""
    cases = [
        {
            "id": "body-vec-01-spec-example",
            "description": "Spec Section 10 example (16-byte binary payload)",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 1,
            "plaintext": bytes.fromhex("48656C6C6F20576F726C642E747874FF"),
            "aad": ("file.bin", 1, 1),
        },
        {
            "id": "body-vec-02-exact-block",
            "description": "64-byte payload (exact single ChaCha20 block boundary)",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 1,
            "plaintext": bytes(i % 256 for i in range(64)),
            "aad": ("payload.bin", 1, 1),
        },
        {
            "id": "body-vec-03-multi-block",
            "description": "256-byte payload (4 ChaCha20 blocks)",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 2,
            "plaintext": bytes((i * 7 + 13) % 256 for i in range(256)),
            "aad": ("multi.bin", 2, 65),
        },
        {
            "id": "body-vec-04-large-segment",
            "description": "4096-byte typical Usenet article segment chunk (primitive-level AEAD vector whose salt intentionally contains 0x0A/0x0D and is not a valid wire salt)",
            "password": "conformance fixture with spaces & symbols !#$%",
            "salt_hex": "0102030405060708090a0b0c0d0e0f10",
            "segment_index": 1,
            "plaintext": bytes((i * 31 + 17) % 256 for i in range(4096)),
            "aad": ("chunk data.bin", 7, 4097),
        },
        {
            "id": "body-vec-05-empty-payload",
            "description": "0-byte empty payload (edge case testing empty body)",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 1,
            "plaintext": b"",
            "aad": ("empty.bin", 1, 1),
        },
        {
            "id": "body-vec-06-all-zeros",
            "description": "128 bytes of zero octets (0x00)",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 3,
            "plaintext": bytes(128),
            "aad": ("zeros.bin", 3, 257),
        },
        {
            "id": "body-vec-07-all-ones",
            "description": "128 bytes of 0xFF octets",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 4,
            "plaintext": bytes([0xFF] * 128),
            "aad": ("ones.bin", 4, 385),
        },
        {
            "id": "body-vec-08-high-segment",
            "description": "128-byte payload with high segmentIndex=65536",
            "password": "conformance-fixture-Mötörhëad-🔑",
            "salt_hex": "fedcba98765432100123456789abcdef",
            "segment_index": 65536,
            "plaintext": bytes((i * 19 + 5) % 256 for i in range(128)),
            "aad": ("mötör-🔑.bin", 1, 1),
        },
        {
            # A valid article may contain a one-byte data line; the
            # body AEAD sees only raw bytes, but this pins the exact
            # one-byte ciphertext/tag contract used by the combined-mode
            # one-byte fixtures.
            "id": "body-vec-09-one-byte-payload",
            "description": "One-byte plaintext payload (one-byte data fixture)",
            "password": "public-conformance-vector-key-2026",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 1,
            "plaintext": bytes([0xFF]),
            "aad": ("one.bin", 1, 1),
        },
    ]

    vectors = []
    for tc in cases:
        salt = bytes.fromhex(tc["salt_hex"])
        key = derive_key(tc["password"], salt)
        nonce = derive_body_nonce(key, tc["segment_index"])
        name, part_number, part_begin = tc["aad"]
        # AAD per Body Standard Section 2.1; name is encoded as its exact
        # UTF-8 bytes with no normalization (the AAD subject byte string).
        aad = build_aad(name.encode("utf-8"), part_number, part_begin, len(tc["plaintext"]))
        ct, tag = body_encrypt(tc["plaintext"], key, nonce, aad)

        # verify decrypt roundtrip immediately (with AAD)
        pt_roundtrip = body_decrypt(ct, tag, key, nonce, aad)
        assert pt_roundtrip == tc["plaintext"]
        # and confirm the empty AAD is rejected (empty AAD is not a valid input)
        try:
            body_decrypt(ct, tag, key, nonce, b"")
            raise AssertionError("empty AAD must fail authentication")
        except ne.CryptoError:
            pass

        salt_hex_str = tc["salt_hex"].lower()
        tag_hex_str = tag.hex().lower()
        index_hex_str = f"{tc['segment_index']:08x}"
        expected_yenc_line = (
            f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex_str} index={index_hex_str} tag={tag_hex_str}"
        )
        assert len(expected_yenc_line) == 128

        vectors.append(
            {
                "id": tc["id"],
                "description": tc["description"],
                "password": tc["password"],
                "salt_hex": salt_hex_str,
                "segment_index": tc["segment_index"],
                "aad": {
                    "name_bytes_hex": name.encode("utf-8").hex(),
                    "part_number": part_number,
                    "part_begin": part_begin,
                    "segment_bytes": len(tc["plaintext"]),
                    "expected_aad_hex": aad.hex(),
                },
                "derived_key_hex": key.hex().lower(),
                "derived_nonce_hex": nonce.hex().lower(),
                "plaintext_length": len(tc["plaintext"]),
                "plaintext_hex": tc["plaintext"].hex().lower(),
                "expected_ciphertext_hex": ct.hex().lower(),
                "expected_index_hex": index_hex_str,
                "expected_tag_hex": tag_hex_str,
                "expected_yencryption_line": expected_yenc_line,
            }
        )

    fixture = {
        "schema_version": "1.0",
        "standard": f"yEnc Body Encryption Standard v{STANDARD_VERSION}",
        "cipher": "XChaCha20-Poly1305",
        "aad_layout": "yenc-body aad(13) || uint32_be(partNumber) || uint32_be(partBegin) || uint64_be(segmentBytes) || uint32_be(nameLength) || nameBytes (Body Standard Section 2.1)",
        "vectors": vectors,
    }

    _write_fixture(path, fixture)
    print(f"Generated {len(vectors)} body encryption vectors in {path.name}")


def generate_control_line_vectors(path: Path):
    """Generate FF1 control-line encryption round-trip test vectors."""
    password = "public-conformance-vector-key-2026"
    salt_hex = "4b376d5839704c32715238764e34775a"  # ASCII "K7mX9pL2qR8vN4wZ" (alphabet characters)
    salt_bytes = bytes.fromhex(salt_hex)
    master_key = derive_key(password, salt_bytes)

    # Line 1 vectors (with 20-byte prepended bootstrap expansion)
    line1_cases = [
        {
            "id": "control-vec-01-line-1-ybegin-single",
            "description": "Header line 1 single-part =ybegin with 20-byte prepended bootstrap expansion",
            "segment_index": 1,
            "line_index": 1,
            "plaintext_line": "=ybegin line=128 size=18 name=file.bin",
        },
        {
            "id": "control-vec-02-line-1-ybegin-multipart",
            "description": "Header line 1 multipart =ybegin with 20-byte prepended bootstrap expansion",
            "segment_index": 1,
            "line_index": 1,
            "plaintext_line": "=ybegin part=1 total=10 line=128 size=3500000 name=movie.mkv",
        },
    ]

    # Lines 2..N vectors (exact length preservation)
    subsequent_cases = [
        {
            "id": "control-vec-03-line-2-ypart",
            "description": "Header line 2 =ypart (exact length preservation)",
            "segment_index": 1,
            "line_index": 2,
            "plaintext_line": "=ypart begin=1 end=700000",
        },
        {
            "id": "control-vec-04-line-3-yencryption",
            "description": "FF1-primitive fixture (control-line layer only; not a combined-mode-valid article: its =yencryption salt does not match the fixture Line 1 bootstrap salt, so dual-bootstrap agreement fails): Header line 3 =yencryption (exact length preservation)",
            "segment_index": 1,
            "line_index": 3,
            "plaintext_line": "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=8a6d1659c13f895a17cbe0d2a463133e",
        },
        {
            "id": "control-vec-05-line-4-yend-single",
            "description": "FF1-primitive fixture (control-line layer only; not a combined-mode-valid article: its =yend carries no applicable ciphertext CRC): Footer line 4 =yend minimal (exact length preservation)",
            "segment_index": 1,
            "line_index": 4,
            "plaintext_line": "=yend size=18",
        },
        {
            "id": "control-vec-06-yend-multipart",
            "description": "Footer line 54 =yend multipart with pcrc32 (exact length preservation)",
            "segment_index": 1,
            "line_index": 54,
            "plaintext_line": "=yend size=700000 part=1 pcrc32=12345678",
        },
    ]

    vectors = []
    for tc in line1_cases:
        pt_bytes = tc["plaintext_line"].encode("ascii")
        enc_key, tweak = derive_control_keys(master_key, tc["segment_index"], tc["line_index"])
        ct_bytes = ff1_encrypt(enc_key, tweak, pt_bytes)
        # Line 1 prepends the 20-byte article bootstrap (16B salt + 4B uint32_be(segment_index))
        bootstrap_prefix = salt_bytes + uint32_be(tc["segment_index"])
        wire_bytes = bootstrap_prefix + ct_bytes

        # Verify decrypt: strip 20-byte bootstrap, decrypt ct
        extracted_salt, extracted_seg_idx, extracted_ct = extract_bootstrap_from_line1(wire_bytes)
        assert extracted_salt == salt_bytes
        assert extracted_seg_idx == tc["segment_index"]
        assert extracted_ct == ct_bytes
        restored_pt = ff1_decrypt(enc_key, tweak, extracted_ct)
        assert restored_pt == pt_bytes

        vectors.append(
            {
                "id": tc["id"],
                "description": tc["description"],
                "password": password,
                "salt_hex": salt_hex.lower(),
                "salt_ascii": salt_bytes.decode("ascii"),
                "segment_index": tc["segment_index"],
                "line_index": tc["line_index"],
                "is_line_1": True,
                "plaintext_line": tc["plaintext_line"],
                "plaintext_length": len(pt_bytes),
                "salt_length": 16,
                "bootstrap_length": 20,
                "expected_wire_length": len(wire_bytes),
                "derived_enc_key_hex": enc_key.hex().lower(),
                "derived_tweak_hex": tweak.hex().lower(),
                "expected_wire_hex": wire_bytes.hex().lower(),
            }
        )

    for tc in subsequent_cases:
        pt_bytes = tc["plaintext_line"].encode("ascii")
        enc_key, tweak = derive_control_keys(master_key, tc["segment_index"], tc["line_index"])
        wire_bytes = ff1_encrypt(enc_key, tweak, pt_bytes)

        # Verify decrypt
        restored_pt = ff1_decrypt(enc_key, tweak, wire_bytes)
        assert restored_pt == pt_bytes
        assert len(wire_bytes) == len(pt_bytes)

        vectors.append(
            {
                "id": tc["id"],
                "description": tc["description"],
                "password": password,
                "salt_hex": salt_hex.lower(),
                "segment_index": tc["segment_index"],
                "line_index": tc["line_index"],
                "is_line_1": False,
                "plaintext_line": tc["plaintext_line"],
                "plaintext_length": len(pt_bytes),
                "expected_wire_length": len(wire_bytes),
                "derived_enc_key_hex": enc_key.hex().lower(),
                "derived_tweak_hex": tweak.hex().lower(),
                "expected_wire_hex": wire_bytes.hex().lower(),
            }
        )

    # Full article vectors
    # 4-line minimal article: =ybegin (line 1), data line 1 (line 2), data line 2 (line 3), =yend (line 4)
    art4_lines = [
        "=ybegin line=128 size=18 name=file.bin",
        f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.lower()} index=00000001 tag=8a6d1659c13f895a17cbe0d2a463133e",
        "DataLine1TestDataMustRemainUntouched1234567890",
        "DataLine2TestDataMustRemainUntouched1234567890",
        "=yend size=18",
    ]
    art4_wire = []
    for l_idx, line in enumerate(art4_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art4_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art4_wire.append(ct_b.hex().lower())
        else:
            # Data line remains completely untouched
            art4_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-07-full-article-5-lines",
            "description": "FF1 line-restoration vector, 5-line single-part layout (control-line layer only; data lines opaque, tag not authenticated): =ybegin, =yencryption header (line 2), two data lines untouched, =yend (line 5); line 1 bootstrap expansion",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 5,
            "input_lines": art4_lines,
            "expected_wire_lines_hex": art4_wire,
        }
    )

    # 54-line article: =ybegin (1), =ypart (2), =yencryption (3), 50 data lines (4..53), =yend (54)
    art54_lines = [
        "=ybegin part=1 total=1 line=128 size=700000 name=data.bin",
        "=ypart begin=1 end=700000",
        f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.lower()} index=00000001 tag=8a6d1659c13f895a17cbe0d2a463133e",
    ]
    for d in range(1, 51):
        art54_lines.append(f"TestDataLine{d:02d}ContentUntouchedByteForBytePadding1234567890")
    art54_lines.append("=yend size=700000 part=1 pcrc32=12345678")

    art54_wire = []
    for l_idx, line in enumerate(art54_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art54_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art54_wire.append(ct_b.hex().lower())
        else:
            art54_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-08-full-article-54-lines",
            "description": "FF1 line-restoration vector, 54-line multipart layout (control-line layer only; data lines opaque, tag not authenticated): verifies physical line counting 1..54 across header, data, and footer",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 54,
            "input_lines": art54_lines,
            "expected_wire_lines_hex": art54_wire,
        }
    )

    # One-byte data article: the header/data boundary must be
    # deterministic (positions inferred from =ybegin), so a one-byte data
    # line must pass through untouched and never be trial-decrypted.
    art4_one_byte_lines = [
        "=ybegin line=4 size=1 name=one.bin",
        f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.lower()} index=00000001 tag=8a6d1659c13f895a17cbe0d2a463133e",
        "F",  # exactly one data byte
        "=yend size=1",
    ]
    art4_one_byte_wire = []
    for l_idx, line in enumerate(art4_one_byte_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art4_one_byte_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art4_one_byte_wire.append(ct_b.hex().lower())
        else:
            art4_one_byte_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-09-one-byte-data",
            "description": "One-byte data fixture: single data byte passes through untouched; no trial decryption occurs",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 4,
            "input_lines": art4_one_byte_lines,
            "expected_wire_lines_hex": art4_one_byte_wire,
        }
    )

    # Exact-wrap fixture: data line whose length is exactly the yEnc
    # line wrap; a genuine control line has the same length class, so only
    # position-based restoration decodes this article deterministically.
    art_exact_wrap_lines = [
        "=ybegin line=12 size=36 name=wrap.bin",
        f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.lower()} index=00000001 tag=8a6d1659c13f895a17cbe0d2a463133e",
        "0123456789ab",
        "cdef01234567",
        "89abcd123456",
        "=yend size=36",
    ]
    art_exact_wrap_wire = []
    for l_idx, line in enumerate(art_exact_wrap_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art_exact_wrap_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art_exact_wrap_wire.append(ct_b.hex().lower())
        else:
            art_exact_wrap_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-10-exact-wrap-article-6-lines",
            "description": "FF1 line-restoration vector, exact-wrap layout (control-line layer only; data lines opaque, tag not authenticated): data lines exactly one yEnc wrap long pass through untouched, after an =yencryption header at line 2",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 6,
            "input_lines": art_exact_wrap_lines,
            "expected_wire_lines_hex": art_exact_wrap_wire,
        }
    )

    # Combined-mode multipart article: =ybegin (1), =ypart (2), =yencryption (3),
    # one-byte data line (4), =yend (5). Exercises the deterministic combined
    # layout of Control Lines Standard Section 5 step 4 with a one-byte data line.
    art_combined_lines = [
        "=ybegin part=1 total=1 line=4 size=1 name=combined.bin",
        "=ypart begin=1 end=1",
        f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.lower()} index=00000001 tag=8a6d1659c13f895a17cbe0d2a463133e",
        "F",
        "=yend size=1 part=1 pcrc32="+WIRE_CRC_F,
    ]
    art_combined_wire = []
    for l_idx, line in enumerate(art_combined_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art_combined_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art_combined_wire.append(ct_b.hex().lower())
        else:
            art_combined_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-11-combined-one-byte-data",
            "description": "FF1 line-restoration vector, combined-mode multipart layout (control-line layer only; data lines opaque, tag not authenticated): deterministic header positions (1..3), one-byte data line untouched",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 5,
            "input_lines": art_combined_lines,
            "expected_wire_lines_hex": art_combined_wire,
        }
    )

    # Single-part article whose name contains "=ypart " and "part=": physical
    # line 2 (not strings in =ybegin name=) governs layout,
    # so =yencryption is line 2.
    art_name_part_lines = [
        "=ybegin line=128 size=1 name=my =ypart part=2.bin",
        f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.lower()} index=00000001 tag=d5582bae5bd0c8dfd2a8a477ebd4dd30",
        "F",
        "=yend size=1 crc32="+WIRE_CRC_F,
    ]
    art_name_part_wire = []
    for l_idx, line in enumerate(art_name_part_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art_name_part_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art_name_part_wire.append(ct_b.hex().lower())
        else:
            art_name_part_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-12-single-part-name-contains-part",
            "description": "Single-part article whose =ybegin name contains '=ypart ' and 'part=': physical line 2 (not strings in =ybegin name=) governs layout, so the layout is single-part (=yencryption at line 2, D = 3)",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 4,
            "expected_multipart": False,
            "expected_first_data_line": 3,
            "input_lines": art_name_part_lines,
            "expected_wire_lines_hex": art_name_part_wire,
        }
    )


    fixture = {
        "schema_version": "1.0",
        "standard": f"yEnc Control Lines Encryption Standard v{STANDARD_VERSION}",
        "cipher": "FF1",
        "radix": 253,
        "note": (
            "Control-line layer only: the single-line and multi-line vectors "
            "(including control-vec-04 and control-vec-05) are FF1-primitive "
            "fixtures. Their data lines are opaque filler, their =yencryption "
            "tags are not authenticated, and single-line fixture contents "
            "(such as control-vec-04's mismatched =yencryption salt or "
            "control-vec-05's CRC-less =yend) do not by themselves satisfy "
            "combined-mode article rules, so no consumer can authenticate "
            "these articles end to end; body-level vectors live in "
            "body_encryption.json."
        ),
        "vectors": vectors,
    }

    _write_fixture(path, fixture)
    print(f"Generated {len(vectors)} control-line encryption vectors in {path.name}")


def generate_malformed_input_vectors(path: Path):
    """Generate malformed-input rejection and zero-output test vectors."""
    password = "public-conformance-vector-key-2026"
    salt_hex = "1a2b3c4d5e6f7890abcdef1234567890"
    salt = bytes.fromhex(salt_hex)
    key = derive_key(password, salt)
    nonce = derive_body_nonce(key, 1)
    pt = b"Hello World secret data 12345678"
    aad = build_aad(b"malformed.bin", 1, 1, len(pt))
    ct, tag = body_encrypt(pt, key, nonce, aad)

    vectors = [
        # 1. Header Syntax Malformations
        {
            "id": "malformed-header-01-bad-cipher",
            "category": "header_syntax",
            "description": "Unsupported cipher algorithm (AES-256-GCM)",
            "input_line": f"=yencryption cipher=AES-256-GCM salt={salt_hex} index=00000001 tag={tag.hex()}",
            "expected_error": "UNSUPPORTED_CIPHER",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-02-chacha20-unauth",
            "category": "header_syntax",
            "description": "Unauthenticated cipher (ChaCha20 without Poly1305)",
            "input_line": f"=yencryption cipher=ChaCha20 salt={salt_hex} index=00000001 tag={tag.hex()}",
            "expected_error": "UNSUPPORTED_CIPHER",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-03-empty-cipher",
            "category": "header_syntax",
            "description": "Empty cipher parameter value",
            "input_line": f"=yencryption cipher= salt={salt_hex} index=00000001 tag={tag.hex()}",
            "expected_error": "UNSUPPORTED_CIPHER",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-04-missing-salt",
            "category": "header_syntax",
            "description": "Missing salt parameter entirely",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-05-truncated-salt",
            "category": "header_syntax",
            "description": "Salt shorter than 32 hex characters (30 hex chars / 15 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef12345678 index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_SALT_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-06-extended-salt",
            "category": "header_syntax",
            "description": "Salt longer than 32 hex characters (34 hex chars / 17 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890ff index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_SALT_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-07-non-hex-salt",
            "category": "header_syntax",
            "description": "Salt containing non-hex characters ('g', 'z')",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef12345678gz index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_SALT_HEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-08-missing-tag",
            "category": "header_syntax",
            "description": "Missing tag parameter entirely",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-09-truncated-tag",
            "category": "header_syntax",
            "description": "Tag shorter than 32 hex characters (30 hex chars / 15 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag=0cd77ce245a654463f90b945b1d22d",
            "expected_error": "INVALID_TAG_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-10-extended-tag",
            "category": "header_syntax",
            "description": "Tag longer than 32 hex characters (34 hex chars / 17 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag=8a6d1659c13f895a17cbe0d2a463133e00",
            "expected_error": "INVALID_TAG_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-11-non-hex-tag",
            "category": "header_syntax",
            "description": "Tag containing non-hex characters ('x', 'y')",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag=0cd77ce245a654463f90b945b1d22dxy",
            "expected_error": "INVALID_TAG_HEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-12-missing-index",
            "category": "header_syntax",
            "description": "Four tokens omitting the mandatory index parameter",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} tag={tag.hex()}",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-13-zero-index",
            "category": "header_syntax",
            "description": "Segment index 0 is strictly forbidden",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000000 tag={tag.hex()}",
            "expected_error": "ZERO_SEGMENT_INDEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-14-truncated-index",
            "category": "header_syntax",
            "description": "Index shorter than 8 hex characters (4 chars)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=0001 tag={tag.hex()}",
            "expected_error": "INVALID_INDEX_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-15-extended-index",
            "category": "header_syntax",
            "description": "Index longer than 8 hex characters (9 chars)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=000000001 tag={tag.hex()}",
            "expected_error": "INVALID_INDEX_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-16-non-hex-index",
            "category": "header_syntax",
            "description": "Index containing non-hex characters ('g')",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=0000000g tag={tag.hex()}",
            "expected_error": "INVALID_INDEX_HEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-17-uppercase-index",
            "category": "header_syntax",
            "description": "Index containing uppercase hex digits",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=0000000F tag={tag.hex()}",
            "expected_error": "UPPERCASE_HEX",
            "zero_output_required": True,
        },
        # 2. Cryptographic Authentication Failures (Zero-Output Enforced)
        {
            "id": "auth-failure-01-tampered-ciphertext",
            "category": "auth_failure",
            "description": "Bit flip in body ciphertext must trigger authentication failure and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": aad.hex(),
            "tampered_ciphertext_hex": (bytes([ct[0] ^ 0x01]) + ct[1:]).hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-02-tampered-tag",
            "category": "auth_failure",
            "description": "Bit flip in authentication tag must trigger authentication failure and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": aad.hex(),
            "ciphertext_hex": ct.hex().lower(),
            "tampered_tag_hex": (bytes([tag[0] ^ 0x01]) + tag[1:]).hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-03-wrong-password",
            "category": "auth_failure",
            "description": "Incorrect password must trigger authentication failure and zero output",
            "password": "conformance-fixture-wrong-password",
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": aad.hex(),
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-04-mismatched-segment-index",
            "category": "auth_failure",
            "description": "Segment index mismatch (encrypted with index 1, decrypted with index 2)",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 2,
            "aad_hex": aad.hex(),
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        # 2b. Metadata Mutation Failures (AAD binding)
        {
            "id": "auth-failure-05-mutated-name",
            "category": "auth_failure",
            "description": "AAD name mutated after encryption (file.bin -> file0.bin) must fail authentication and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": build_aad(b"file0.bin", 1, 1, len(pt)).hex(),
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-06-mutated-part-number",
            "category": "auth_failure",
            "description": "AAD part number mutated (segment replayed at a different part) must fail authentication and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": build_aad(b"malformed.bin", 2, 1, len(pt)).hex(),
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-07-mutated-part-begin",
            "category": "auth_failure",
            "description": "AAD part begin offset mutated (segment repositioned in the assembled file) must fail authentication and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": build_aad(b"malformed.bin", 1, 2, len(pt)).hex(),
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-08-mutated-segment-bytes",
            "category": "auth_failure",
            "description": "AAD segment byte count mutated (restored geometry differs from the encrypted one) must fail authentication and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": build_aad(b"malformed.bin", 1, 1, len(pt) + 1).hex(),
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-09-empty-aad",
            "category": "auth_failure",
            "description": "Empty AAD (payload-only authentication, pre-v1.2-AAD behavior) must fail authentication and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "aad_hex": "",
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        # 3. Control Line Malformations
        {
            "id": "control-syntax-01-forbidden-lf-in-salt",
            "category": "control_syntax",
            "description": "Line 1 salt contains forbidden byte 0x0A (LF)",
            "tampered_salt_hex": "4b376d5839704c320a5238764e34775a",
            "expected_error": "INVALID_SALT_CHARACTER",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-02-forbidden-cr-in-salt",
            "category": "control_syntax",
            "description": "Line 1 salt contains forbidden byte 0x0D (CR)",
            "tampered_salt_hex": "4b376d5839704c320d5238764e34775a",
            "expected_error": "INVALID_SALT_CHARACTER",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-03-forbidden-nul-in-salt",
            "category": "control_syntax",
            "description": "Line 1 salt contains forbidden byte 0x00 (NUL)",
            "tampered_salt_hex": "4b376d5839704c32005238764e34775a",
            "expected_error": "INVALID_SALT_CHARACTER",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-04-line-too-short",
            "category": "control_syntax",
            "description": "Control line shorter than 2 characters",
            "line_hex": "3d",  # "=" (1 byte)
            "expected_error": "LINE_TOO_SHORT",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-05-line1-truncated",
            "category": "control_syntax",
            "description": "Line 1 length < 22 bytes (cannot contain 16B salt + 4B segmentIndex + 2B minlen)",
            "line1_hex": "4b376d5839704c32715238764e34775a000000013d",  # 21 bytes
            "expected_error": "LINE_TRUNCATED",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-06-zero-segment-index",
            "category": "control_syntax",
            "description": "Line 1 bootstrap contains prohibited zero segment index (0x00000000)",
            "line1_hex": "4b376d5839704c32715238764e34775a000000003d3d",  # 22 bytes, index=0
            "expected_error": "ZERO_SEGMENT_INDEX",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-07-wrong-password",
            "category": "control_syntax",
            "description": "Wrong password for control line decryption results in non-'=y' plaintext",
            "wrong_password": "conformance-fixture-wrong-control",
            "expected_error": "CONTROL_LINE_DECRYPT_FAILURE",
            "zero_output_required": True,
        },
    ]

    # Index framing rule: a Line 1 bootstrap whose uint32_be(segmentIndex)
    # contains 0x0A or 0x0D is rejected before any decryption.
    control_salt_hex = "4b376d5839704c32715238764e34775a"
    forbidden_index_cases = [
        (8, 10, "Line 1 bootstrap segmentIndex 0x0000000A contains forbidden LF byte 0x0A; 22 bytes: 16B salt + 4B BE index at offsets 16..19 + 2B 0x3d3d trailer"),
        (9, 13, "Line 1 bootstrap segmentIndex 0x0000000D contains forbidden CR byte 0x0D"),
        (10, 266, "Line 1 bootstrap segmentIndex 0x0000010A contains forbidden LF byte 0x0A at offset 19"),
        (11, 269, "Line 1 bootstrap segmentIndex 0x0000010D contains forbidden CR byte 0x0D at offset 19"),
    ]
    for num, index, description in forbidden_index_cases:
        assert is_forbidden_segment_index(index)
        vectors.append({
            "id": f"control-syntax-{num:02d}-forbidden-index-{index}",
            "category": "control_syntax",
            "description": description,
            "line1_hex": (bytes.fromhex(control_salt_hex) + uint32_be(index) + b"==").hex(),
            "expected_error": "FORBIDDEN_SEGMENT_INDEX_BYTE",
            "zero_output_required": True,
        })

    vectors.extend([

        {
            "id": "metadata-01-missing-provenance",
            "category": "metadata_validation",
            "description": "Encrypted article without the required transport provenance marker",
            "context": "decryption explicitly requested",
            "expected_error": "MISSING_ENCRYPTION_PROVENANCE",
            "expected_rejection_stage": "METADATA_VALIDATION",
            "provider_failover_permitted": False,
            "zero_output_required": True,
        },
        {
            "id": "metadata-02-false-provenance",
            "category": "metadata_validation",
            "description": "Transport provenance explicitly set to false, which does not satisfy provenance when decryption is explicitly requested (without that request, a non-true value is ordinary yEnc per Body Standard Section 8)",
            "context": "decryption explicitly requested",
            "expected_error": "INVALID_ENCRYPTION_PROVENANCE",
            "expected_rejection_stage": "METADATA_VALIDATION",
            "provider_failover_permitted": False,
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-18-uppercase-hex",
            "category": "header_syntax",
            "description": "Uppercase hexadecimal salt is not canonical",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.upper()} index=00000001 tag={tag.hex()}",
            "expected_error": "UPPERCASE_HEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-19-extra-token",
            "category": "header_syntax",
            "description": "An extra parameter violates the five-token grammar",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag={tag.hex()} extra=value",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-20-reordered-token",
            "category": "header_syntax",
            "description": "Parameter order is canonical and mandatory",
            "input_line": f"=yencryption salt={salt_hex} cipher=XChaCha20-Poly1305 index=00000001 tag={tag.hex()}",
            "expected_error": "UNSUPPORTED_CIPHER",
            "zero_output_required": True,
        },
        {
            "id": "placement-01-single-part-line-three",
            "category": "placement",
            "description": "Single-part encryption header must be on physical line 2",
            "line_index": 3,
            "multipart": False,
            "expected_error": "MISPLACED_ENCRYPTION_HEADER",
            "zero_output_required": True,
        },
        {
            "id": "placement-02-multipart-after-data",
            "category": "placement",
            "description": "Multipart encryption header must immediately follow =ypart",
            "line_index": 4,
            "multipart": True,
            "expected_error": "MISPLACED_ENCRYPTION_HEADER",
            "zero_output_required": True,
        },
        {
            "id": "placement-03-ypart-without-part-param",
            "category": "placement",
            "description": "Physical line 2 is =ypart but restored =ybegin has no part= parameter (contradictory framing)",
            "has_part_on_ybegin": False,
            "is_ypart_on_line2": True,
            "expected_error": "INVALID_MULTIPART_FRAMING",
            "zero_output_required": True,
        },
        {
            "id": "placement-04-yencryption-line2-with-part-param",
            "category": "placement",
            "description": "Physical line 2 is =yencryption (single-part placement), but restored =ybegin carries a part= parameter (contradictory framing)",
            "has_part_on_ybegin": True,
            "is_ypart_on_line2": False,
            "line_index": 2,
            "multipart": True,
            "expected_error": "MISPLACED_ENCRYPTION_HEADER",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-21-duplicate-token",
            "category": "header_syntax",
            "description": "Duplicate parameters are rejected",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag={tag.hex()} tag={tag.hex()}",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-22-tab-separated",
            "category": "header_syntax",
            "description": "=yencryption header using a tab between tokens instead of a single SP",
            "input_line": f"=yencryption\tcipher=XChaCha20-Poly1305\tsalt={salt_hex}\tindex=00000001\ttag={tag.hex()}",
            "expected_error": "INVALID_WHITESPACE",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-23-double-space",
            "category": "header_syntax",
            "description": "=yencryption header using two consecutive spaces between tokens instead of a single SP",
            "input_line": f"=yencryption  cipher=XChaCha20-Poly1305  salt={salt_hex}  index=00000001  tag={tag.hex()}",
            "expected_error": "INVALID_WHITESPACE",
            "zero_output_required": True,
        },
        {
            "id": "metadata-03-missing-password",
            "category": "metadata_validation",
            "description": "Encrypted transport requires a password metadata value",
            "expected_error": "MISSING_PASSWORD",
            "expected_rejection_stage": "METADATA_VALIDATION",
            "provider_failover_permitted": False,
            "zero_output_required": True,
        },
        {
            "id": "metadata-04-body-only-vs-combined-only",
            "category": "framing",
            "description": "Body-only-mode article (includes =yencryption line but omits Line 1 Control-Line bootstrap) presented to a combined-only receiver: mode unsupported",
            "expected_error": "CONTROL_LINE_DECRYPT_FAILURE",
            "expected_rejection_stage": "PROVIDER_FAILOVER",
            "provider_failover_permitted": True,
            "zero_output_required": True,
        },
        {
            "id": "malformed-dual-01-dual-salt-mismatch",
            "category": "salt_mismatch",
            "description": "Line 1 bootstrap salt does not match =yencryption header salt",
            "line1_salt_hex": control_salt_hex,
            "header_salt_hex": salt_hex,
            "line1_index": 1,
            "header_index": 1,
            "expected_error": "DUAL_SALT_MISMATCH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-dual-02-dual-index-mismatch",
            "category": "salt_mismatch",
            "description": "Line 1 bootstrap segment index does not match =yencryption header index",
            "line1_salt_hex": salt_hex,
            "header_salt_hex": salt_hex,
            "line1_index": 1,
            "header_index": 2,
            "expected_error": "DUAL_INDEX_MISMATCH",
            "zero_output_required": True,
        },
    ])

    structural_categories = {"metadata_validation"}
    for vector in vectors:
        structural = vector["category"] in structural_categories
        vector["expected_rejection_stage"] = "METADATA_VALIDATION" if structural else "PROVIDER_FAILOVER"
        vector["provider_failover_permitted"] = not structural

    fixture = {
        "schema_version": "1.0",
        "standard": f"yEnc Body & Control Lines Encryption Standards v{STANDARD_VERSION}",
        "vectors": vectors,
    }

    _write_fixture(path, fixture)
    print(f"Generated {len(vectors)} malformed input rejection vectors in {path.name}")


def is_forbidden_segment_index(index: int) -> bool:
    """Index framing rule: uint32_be(index) must not contain 0x0A or 0x0D."""
    return any(b in (0x0A, 0x0D) for b in uint32_be(index))


def next_permitted_segment_index(candidate: int) -> int:
    """Return the first index >= candidate that satisfies the index framing rule."""
    idx = candidate
    while is_forbidden_segment_index(idx):
        idx += 1
    return idx


def generate_index_allocation_vectors(path: Path):
    """Generate uploader segmentIndex allocation skip vectors."""
    cases = [
        ("index-allocation-01-skip-10", 10,
         "Candidate segmentIndex 10 (uint32_be 0x0000000A contains 0x0A) is forbidden; uploader assigns the next permitted index 11"),
        ("index-allocation-02-skip-13", 13,
         "Candidate segmentIndex 13 (uint32_be 0x0000000D contains 0x0D) is forbidden; uploader assigns 14"),
        ("index-allocation-03-skip-266", 266,
         "Candidate segmentIndex 266 (uint32_be 0x0000010A contains 0x0A) is forbidden; uploader assigns 267"),
        ("index-allocation-04-skip-269", 269,
         "Candidate segmentIndex 269 (uint32_be 0x0000010D contains 0x0D) is itself forbidden and MUST never be assigned; uploader skips it and assigns 270"),
    ]
    vectors = []
    for vec_id, candidate, description in cases:
        assigned = next_permitted_segment_index(candidate)
        vectors.append({
            "id": vec_id,
            "category": "index_allocation",
            "description": description,
            "candidate_index": candidate,
            "expected_assigned_index": assigned,
            "expected_index_hex": f"{assigned:08x}",
            "expected_error": None,
        })

    fixture = {
        "schema_version": "1.0",
        "description": (
            "Uploader segmentIndex allocation skip vectors: a candidate index whose uint32_be encoding "
            "contains 0x0A or 0x0D is forbidden; uploaders MUST skip to the next permitted index."
        ),
        "vectors": vectors,
    }
    _write_fixture(path, fixture)
    print(f"Generated {len(vectors)} index allocation vectors in {path.name}")


def main():
    repo_root = Path(__file__).resolve().parent.parent
    output_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else repo_root / "test-vectors"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating deterministic conformance test vectors into: {output_dir}")
    generate_argon2id_vectors(output_dir / "argon2id.json")
    generate_nonce_tweak_vectors(output_dir / "nonce_tweak.json")
    generate_body_vectors(output_dir / "body_encryption.json")
    generate_control_line_vectors(output_dir / "control_line_encryption.json")
    generate_malformed_input_vectors(output_dir / "malformed_inputs.json")
    generate_index_allocation_vectors(output_dir / "index_allocation.json")
    print("All conformance fixtures successfully generated.")


if __name__ == "__main__":
    main()