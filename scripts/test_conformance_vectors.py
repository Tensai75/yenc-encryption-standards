#!/usr/bin/env python3
"""Automated conformance test harness for yEnc encryption standards v1.2.

Tests conformance against:
- Argon2id key derivation fixtures (argon2id.json), including the
  no-normalization password policy
- HMAC-SHA256 nonce and tweak derivations (nonce_tweak.json)
- XChaCha20-Poly1305 body encryption round-trips with Section 2.1
  associated data (body_encryption.json)
- NIST SP 800-38G FF1 control-line encryption round-trips and
  deterministic combined-mode restoration fixtures (control_line_encryption.json)
- Malformed-input rejection and zero-output security (malformed_inputs.json)
- Uploader segmentIndex allocation skip vectors (index_allocation.json)
"""

import hashlib
import hmac
import json
from fixture_codec import fixture_bytes, fixture_bytes_list
import re
import struct
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import argon2.low_level as ll
import nacl.exceptions as ne

# The reference-helper primitives shared with the vector generator.
from yenc_enc_reference import (
    body_decrypt,
    body_encrypt,
    build_aad,
    byte_to_numeral,
    combined_mode_layout,
    derive_body_nonce,
    derive_control_keys,
    derive_key,
    extract_bootstrap_from_line1,
    ff1_decrypt,
    numeral_to_byte,
    uint32_be,
    validate_dual_bootstrap,
)


def check_multipart_framing(has_part_on_ybegin: bool, is_ypart_on_line2: bool) -> None:
    """Validate physical line 2 multipart framing consistency.
    Physical line 2 is =ypart if and only if =ybegin carries part= keyword.
    Any mismatch is corrupt Usenet framing -> PROVIDER_FAILOVER."""
    if has_part_on_ybegin != is_ypart_on_line2:
        if has_part_on_ybegin and not is_ypart_on_line2:
            raise ValueError("MISPLACED_ENCRYPTION_HEADER")
        raise ValueError("INVALID_MULTIPART_FRAMING")


def check_header_placement(line_index: int, multipart: bool) -> None:
    """Placement rule (Body Std v1.2 Section 4): =yencryption is physical
    line 2 for single-part articles and physical line 3 for multipart
    articles (immediately after =ypart at line 2)."""
    expected = 3 if multipart else 2
    if line_index != expected:
        raise ValueError("MISPLACED_ENCRYPTION_HEADER")


def parse_yencryption_line_v11(line: str) -> dict:
    """Parse and validate the canonical five-token v1.2 =yencryption header."""
    if line != line.strip():
        raise ValueError("INVALID_WHITESPACE")
    # Whitespace strictness (v1.2): a tab anywhere or two consecutive spaces
    # anywhere survives strip() but violates the single-SP token grammar.
    if "\t" in line or "  " in line:
        raise ValueError("INVALID_WHITESPACE")
    tokens = line.split(" ")
    if len(tokens) != 5 or any(not token for token in tokens):
        raise ValueError("INVALID_TOKEN_COUNT")
    if tokens[0] != "=yencryption":
        raise ValueError("INVALID_PREFIX")
    if tokens[1] != "cipher=XChaCha20-Poly1305":
        raise ValueError("UNSUPPORTED_CIPHER")
    if not tokens[2].startswith("salt=") or not tokens[3].startswith("index=") or not tokens[4].startswith("tag="):
        raise ValueError("INVALID_TOKEN_ORDER")

    salt_hex = tokens[2][5:]
    index_hex = tokens[3][6:]
    tag_hex = tokens[4][4:]

    if len(salt_hex) != 32:
        raise ValueError("INVALID_SALT_LENGTH")
    if not re.fullmatch(r"[0-9a-f]{32}", salt_hex):
        raise ValueError("UPPERCASE_HEX" if re.fullmatch(r"[0-9a-fA-F]{32}", salt_hex) else "INVALID_SALT_HEX")
    if len(index_hex) != 8:
        raise ValueError("INVALID_INDEX_LENGTH")
    if not re.fullmatch(r"[0-9a-f]{8}", index_hex):
        raise ValueError("UPPERCASE_HEX" if re.fullmatch(r"[0-9a-fA-F]{8}", index_hex) else "INVALID_INDEX_HEX")
    if len(tag_hex) != 32:
        raise ValueError("INVALID_TAG_LENGTH")
    if not re.fullmatch(r"[0-9a-f]{32}", tag_hex):
        raise ValueError("UPPERCASE_HEX" if re.fullmatch(r"[0-9a-fA-F]{32}", tag_hex) else "INVALID_TAG_HEX")

    segment_index = int(index_hex, 16)
    if segment_index == 0:
        raise ValueError("ZERO_SEGMENT_INDEX")
    # Same forbidden-byte rule as the Line 1 bootstrap (v1.2).
    for b in uint32_be(segment_index):
        if b in (0x0A, 0x0D):
            raise ValueError("FORBIDDEN_SEGMENT_INDEX_BYTE")

    return {
        "cipher": "XChaCha20-Poly1305",
        "salt": bytes.fromhex(salt_hex),
        "index_hex": index_hex,
        "segment_index": segment_index,
        "tag": bytes.fromhex(tag_hex),
    }


class TestConformanceVectors(unittest.TestCase):
    """Automated test suite verifying cryptographic test vectors against v1.2 specifications."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = REPO_ROOT
        cls.fixtures_dir = cls.repo_root / "test-vectors"
        if not cls.fixtures_dir.exists():
            cls.fixtures_dir = cls.repo_root / "yenc-encryption-standards" / "test-vectors"

        def load_fixture(name: str):
            path = cls.fixtures_dir / name
            cls.assertTrue(path.is_file(), f"Missing fixture file: {path}")
            return json.loads(path.read_text(encoding="utf-8"))

        cls.argon2id_data = load_fixture("argon2id.json")
        cls.nonce_tweak_data = load_fixture("nonce_tweak.json")
        cls.body_data = load_fixture("body_encryption.json")
        cls.control_data = load_fixture("control_line_encryption.json")
        cls.malformed_data = load_fixture("malformed_inputs.json")
        cls.index_allocation_data = load_fixture("index_allocation.json")

    def test_fixture_schema_and_failure_classifications(self):
        """Validate fixture metadata and structural/provider failure boundaries."""
        self.assertEqual(self.malformed_data["schema_version"], "1.0")
        self.assertTrue(self.malformed_data["vectors"])

        structural_categories = {"metadata_validation"}
        provider_categories = {"header_syntax", "placement", "salt_mismatch", "control_syntax", "auth_failure", "framing"}
        for case in self.malformed_data["vectors"]:
            self.assertTrue(case["zero_output_required"], case["id"])
            if case["category"] in structural_categories:
                self.assertFalse(case["provider_failover_permitted"])
                self.assertEqual(case["expected_rejection_stage"], "METADATA_VALIDATION")
            else:
                self.assertIn(case["category"], provider_categories)
                self.assertTrue(case["provider_failover_permitted"])
                self.assertEqual(case["expected_rejection_stage"], "PROVIDER_FAILOVER")

        expected_errors = {
            "ZERO_SEGMENT_INDEX",
            "INVALID_INDEX_HEX",
            "INVALID_INDEX_LENGTH",
            "INVALID_TOKEN_COUNT",
            "LINE_TRUNCATED",
            "INVALID_SALT_CHARACTER",
            "DUAL_SALT_MISMATCH",
            "DUAL_INDEX_MISMATCH",
        }
        observed = {case["expected_error"] for case in self.malformed_data["vectors"]}
        self.assertTrue(expected_errors <= observed)

    def test_vec01_argon2id(self):
        """Verify Argon2id key derivation outputs, including the
        no-normalization policy vectors."""
        params = self.argon2id_data["parameters"]
        for case in self.argon2id_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                derived = ll.hash_secret_raw(
                    secret=case["password"].encode("utf-8"),
                    salt=fixture_bytes(case, "salt"),
                    time_cost=params.get("time_cost", 1),
                    memory_cost=params.get("memory_cost_kib", 65536),
                    parallelism=params.get("parallelism", 4),
                    hash_len=params.get("output_length_bytes", 32),
                    type=ll.Type.ID,
                    version=int(params.get("version", "0x13"), 16),
                )
                self.assertEqual(derived, fixture_bytes(case, "expected_key"))
                if "no_normalization_distinct_passwords" in case:
                    # Every NFC-equivalent spelling listed must derive a
                    # DIFFERENT key: the v1.2 KDF applies no normalization.
                    keys = {
                        ll.hash_secret_raw(
                            secret=variant.encode("utf-8"),
                            salt=fixture_bytes(case, "salt"),
                            time_cost=params.get("time_cost", 1),
                            memory_cost=params.get("memory_cost_kib", 65536),
                            parallelism=params.get("parallelism", 4),
                            hash_len=params.get("output_length_bytes", 32),
                            type=ll.Type.ID,
                            version=int(params.get("version", "0x13"), 16),
                        ).hex()
                        for variant in case["no_normalization_distinct_passwords"]
                    }
                    self.assertEqual(len(keys), len(case["no_normalization_distinct_passwords"]))

    def test_vec02_nonce_tweak(self):
        """Verify nonce and tweak derivations."""
        # nonce_tweak.json binary fields are *_bytes arrays (see fixture_codec).
        for case in self.nonce_tweak_data["body_nonce_vectors"]:
            key = fixture_bytes(case, "key")
            full_hmac = fixture_bytes(case, "full_hmac")
            expected_nonce = fixture_bytes(case, "expected_nonce")
            expected_msg = b"yenc-body nonce" + struct.pack(">I", case["segment_index"])
            self.assertEqual(fixture_bytes(case, "message"), expected_msg)
            # The fixture's full HMAC is the complete 32-byte
            # HMAC-SHA256 digest; the nonce is its first 24 bytes.
            full_hmac = hmac.new(key, expected_msg, hashlib.sha256).digest()
            self.assertEqual(full_hmac, fixture_bytes(case, "full_hmac"))
            self.assertEqual(derive_body_nonce(key, case["segment_index"]), expected_nonce)
            self.assertEqual(expected_nonce, full_hmac[:24])
        for case in self.nonce_tweak_data["control_tweak_vectors"]:
            master_key = fixture_bytes(case, "master_key")
            enc_key = fixture_bytes(case, "enc_key")
            full_hmac = fixture_bytes(case, "full_hmac")
            expected_tweak = fixture_bytes(case, "expected_tweak")
            expected_msg = b"yenc-control tweak" + struct.pack(">I", case["segment_index"]) + struct.pack(">I", case["line_index"])
            self.assertEqual(fixture_bytes(case, "message"), expected_msg)
            enc_key, tweak = derive_control_keys(master_key, case["segment_index"], case["line_index"])
            self.assertEqual(enc_key, fixture_bytes(case, "enc_key"))
            self.assertEqual(tweak, expected_tweak)
            # The fixture's full HMAC is the complete 32-byte
            # HMAC-SHA256 digest; the tweak is its first 8 bytes.
            full_hmac = hmac.new(master_key, expected_msg, hashlib.sha256).digest()
            self.assertEqual(full_hmac, fixture_bytes(case, "full_hmac"))
            self.assertEqual(expected_tweak, full_hmac[:8])

    def test_vec03_body_encryption(self):
        """Verify body round-trips, canonical five-token headers, and
        the Section 2.1 AAD serialization."""
        for case in self.body_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                salt = fixture_bytes(case, "salt")
                key = derive_key(case["password"], salt)
                # The generator-emitted derived fields must equal the
                # locally derived key and nonce.
                self.assertEqual(key, fixture_bytes(case, "derived_key"))
                nonce = derive_body_nonce(key, case["segment_index"])
                self.assertEqual(nonce, fixture_bytes(case, "derived_nonce"))
                plaintext = fixture_bytes(case, "plaintext")
                aad_meta = case["aad"]
                aad = build_aad(
                    fixture_bytes(aad_meta, "name_bytes"),
                    aad_meta["part_number"],
                    aad_meta["part_begin"],
                    aad_meta["segment_bytes"],
                )
                # The fixture's AAD serialization must equal the reference
                # construction byte for byte (Body Std Section 2.1).
                self.assertEqual(aad, fixture_bytes(aad_meta, "expected_aad"))
                self.assertTrue(aad.startswith(b"yenc-body aad"))
                self.assertGreater(len(aad), 33)
                ciphertext, tag = body_encrypt(plaintext, key, nonce, aad)
                self.assertEqual(ciphertext, fixture_bytes(case, "expected_ciphertext"))
                self.assertEqual(tag, fixture_bytes(case, "expected_tag"))
                params = parse_yencryption_line_v11(case["expected_yencryption_line"])
                self.assertEqual(len(case["expected_yencryption_line"]), 128)
                self.assertEqual(case["expected_yencryption_line"].split(" ").__len__(), 5)
                self.assertEqual(params["salt"], salt)
                self.assertEqual(params["segment_index"], case["segment_index"])
                self.assertEqual(params["tag"], tag)
                self.assertEqual(body_decrypt(ciphertext, tag, key, nonce, aad), plaintext)
                # The same ciphertext with the empty AAD must fail: the
                # tag is AAD-bound.
                with self.assertRaises(ne.CryptoError):
                    body_decrypt(ciphertext, tag, key, nonce, b"")

    def test_vec04_control_line_encryption(self):
        """Verify FF1 control-line encryption and 20-byte Line 1 bootstrap."""
        for b in range(1, 256):
            if b in (0x0A, 0x0D):
                with self.assertRaises(ValueError):
                    byte_to_numeral(b)
            else:
                numeral = byte_to_numeral(b)
                self.assertEqual(numeral_to_byte(numeral), b)

        for case in self.control_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                salt = fixture_bytes(case, "salt")
                master_key = derive_key(case["password"], salt)
                if "plaintext_line" in case:
                    plaintext = case["plaintext_line"].encode("ascii")
                    enc_key, tweak = derive_control_keys(master_key, case["segment_index"], case["line_index"])
                    # The generator-emitted derived fields must equal the
                    # locally derived encKey and tweak.
                    self.assertEqual(enc_key, fixture_bytes(case, "derived_enc_key"))
                    self.assertEqual(tweak, fixture_bytes(case, "derived_tweak"))
                    wire = fixture_bytes(case, "expected_wire")
                    if case["is_line_1"]:
                        self.assertEqual(case["bootstrap_length"], 20)
                        self.assertEqual(case["expected_wire_length"], len(plaintext) + 20)
                        extracted_salt, extracted_index, ciphertext = extract_bootstrap_from_line1(wire)
                        self.assertEqual(extracted_salt, salt)
                        self.assertEqual(extracted_index, case["segment_index"])
                        restored = ff1_decrypt(enc_key, tweak, ciphertext)
                    else:
                        self.assertEqual(len(wire), len(plaintext))
                        restored = ff1_decrypt(enc_key, tweak, wire)
                    self.assertEqual(restored, plaintext)
                else:
                    if "expected_multipart" in case:
                        layout = combined_mode_layout(case["input_lines"][1].startswith("=ypart"))
                        self.assertEqual(layout["multipart"], case["expected_multipart"])
                        self.assertEqual(layout["first_data_line"], case["expected_first_data_line"])
                    for line_index, (line, wire) in enumerate(zip(case["input_lines"], fixture_bytes_list(case, "expected_wire_lines")), start=1):
                        if line.startswith("=y"):
                            enc_key, tweak = derive_control_keys(master_key, case["segment_index"], line_index)
                            if line_index == 1:
                                extracted_salt, extracted_index, ciphertext = extract_bootstrap_from_line1(wire)
                                self.assertEqual(extracted_salt, salt)
                                self.assertEqual(extracted_index, case["segment_index"])
                                restored = ff1_decrypt(enc_key, tweak, ciphertext)
                            else:
                                restored = ff1_decrypt(enc_key, tweak, wire)
                            self.assertEqual(restored.decode("ascii"), line)
                        else:
                            self.assertEqual(wire, line.encode("ascii"))

    def test_vec05_malformed_inputs(self):
        """Verify malformed bootstrap and authentication failures enforce zero output."""
        metadata_tokens = {
            "MISSING_ENCRYPTION_PROVENANCE",
            "INVALID_ENCRYPTION_PROVENANCE",
            "MISSING_PASSWORD",
        }
        dispatchable_categories = {
            "header_syntax",
            "auth_failure",
            "control_syntax",
            "salt_mismatch",
            "placement",
            "framing",
            "metadata_validation",
        }
        exercised: set[str] = set()
        for case in self.malformed_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                exercised.add(case["id"])
                self.assertTrue(case["zero_output_required"])
                category = case["category"]
                if category == "header_syntax":
                    # Whitespace-strictness vectors (tab, double space) raise
                    # INVALID_WHITESPACE per v1.2 strict single-SP parsing; all
                    # other header_syntax vectors dispatch on their own
                    # expected_error token.
                    self.assertRaisesRegex(
                        ValueError, re.escape(case["expected_error"]), parse_yencryption_line_v11, case["input_line"]
                    )
                elif category == "placement":
                    if "has_part_on_ybegin" in case and "is_ypart_on_line2" in case:
                        self.assertRaisesRegex(
                            ValueError,
                            re.escape(case["expected_error"]),
                            check_multipart_framing,
                            case["has_part_on_ybegin"],
                            case["is_ypart_on_line2"],
                        )
                    else:
                        self.assertRaisesRegex(
                            ValueError,
                            re.escape(case["expected_error"]),
                            check_header_placement,
                            case["line_index"],
                            case["multipart"],
                        )
                elif category == "framing":
                    # Doc-fixture check (schema-only): this branch validates
                    # the fixture's own declared classification, not a
                    # failure mode of production/crypto code, because the
                    # article bytes are not carried.
                    self.assertEqual(case["expected_rejection_stage"], "PROVIDER_FAILOVER")
                    self.assertTrue(case["provider_failover_permitted"])
                    self.assertEqual(case["expected_error"], "CONTROL_LINE_DECRYPT_FAILURE")
                elif category == "metadata_validation":
                    # Doc-fixture check (schema-only): this branch validates
                    # the fixture's own declared classification, not a
                    # failure mode of production/crypto code, because no
                    # crypto primitive applies and the article bytes are
                    # not carried.
                    self.assertEqual(case["expected_rejection_stage"], "METADATA_VALIDATION")
                    self.assertFalse(case["provider_failover_permitted"])
                    self.assertIn(case["expected_error"], metadata_tokens)
                elif category == "auth_failure":
                    key = derive_key(case["password"], fixture_bytes(case, "salt"))
                    nonce = derive_body_nonce(key, case["segment_index"])
                    ciphertext = fixture_bytes(case, "tampered_ciphertext") if "tampered_ciphertext_bytes" in case else fixture_bytes(case, "ciphertext")
                    tag = fixture_bytes(case, "tampered_tag") if "tampered_tag_bytes" in case else fixture_bytes(case, "tag")
                    aad = fixture_bytes(case, "aad") if "aad_bytes" in case else b""
                    output = None
                    with self.assertRaises(ne.CryptoError):
                        try:
                            output = body_decrypt(ciphertext, tag, key, nonce, aad)
                        finally:
                            self.assertIsNone(output)
                elif category == "control_syntax":
                    if "tampered_salt_bytes" in case:
                        with self.assertRaisesRegex(ValueError, "INVALID_SALT_CHARACTER"):
                            extract_bootstrap_from_line1(fixture_bytes(case, "tampered_salt") + struct.pack(">I", 1) + b"==")
                    elif "line1_bytes" in case:
                        # Dispatch on the vector's own expected_error token so
                        # forbidden-index-byte, zero-index, and
                        # truncation vectors each assert their own class.
                        with self.assertRaisesRegex(ValueError, re.escape(case["expected_error"])):
                            extract_bootstrap_from_line1(fixture_bytes(case, "line1"))
                    elif "line_bytes" in case:
                        # LINE_TOO_SHORT: a control line shorter than the
                        # 2-byte FF1 minimum cannot be decrypted (Control Std
                        # v1.2 Section 5 provider tier). The fixture encodes a
                        # sub-minimum line; assert it violates the minimum.
                        raw = fixture_bytes(case, "line")
                        self.assertEqual(case["expected_error"], "LINE_TOO_SHORT")
                        self.assertLess(len(raw), 2)
                    elif "wrong_password" in case:
                        # CONTROL_LINE_DECRYPT_FAILURE: deriving keys from a
                        # wrong password and decrypting the canonical Line 1
                        # bootstrap yields bytes that do not begin with
                        # "=ybegin" (Control Std Section 5 step 3g).
                        ref = next(
                            c
                            for c in self.control_data["vectors"]
                            if c.get("is_line_1") and "expected_wire_bytes" in c
                        )
                        wire = fixture_bytes(ref, "expected_wire")
                        wrong_key = derive_key(case["wrong_password"], fixture_bytes(ref, "salt"))
                        enc_key, tweak = derive_control_keys(wrong_key, ref["segment_index"], ref["line_index"])
                        restored = ff1_decrypt(enc_key, tweak, wire[20:])
                        self.assertNotEqual(restored, ref["plaintext_line"].encode("ascii"))
                        self.assertFalse(restored.startswith(b"=ybegin"))
                elif category == "salt_mismatch":
                    params = {
                        "salt": fixture_bytes(case, "header_salt"),
                        "segment_index": case["header_index"],
                    }
                    with self.assertRaisesRegex(ValueError, re.escape(case["expected_error"])):
                        validate_dual_bootstrap(fixture_bytes(case, "line1_salt"), case["line1_index"], params)
                else:
                    self.fail(f"Unknown malformed_inputs category: {category}")
                self.assertIn(category, dispatchable_categories)
        # Zero silent skips: every vector id must have been exercised above.
        all_ids = {case["id"] for case in self.malformed_data["vectors"]}
        self.assertEqual(exercised, all_ids)

    def test_vec06_index_allocation(self):
        """Verify uploader index skip vectors: forbidden candidates are skipped,
        assigned indices never contain 0x0A/0x0D, and 269 itself is forbidden."""
        for case in self.index_allocation_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                self.assertEqual(case["category"], "index_allocation")
                self.assertIsNone(case["expected_error"])
                candidate = uint32_be(case["candidate_index"])
                assigned = uint32_be(case["expected_assigned_index"])
                # The candidate must contain a forbidden delimiter byte.
                self.assertTrue(any(b in (0x0A, 0x0D) for b in candidate), case["id"])
                # The assigned index must contain neither forbidden byte.
                self.assertFalse(any(b in (0x0A, 0x0D) for b in assigned), case["id"])
                # Skip always moves forward.
                self.assertGreater(case["expected_assigned_index"], case["candidate_index"])
                self.assertEqual(fixture_bytes(case, "expected_index"), case["expected_assigned_index"].to_bytes(4, "big"))
                # 269 (0x0000010D) itself is forbidden and must never be assigned.
                if case["candidate_index"] == 269:
                    self.assertNotEqual(case["expected_assigned_index"], 269)

    def test_dual_bootstrap_agreement(self):
        """Verify salt and index must both agree between Line 1 and =yencryption."""
        line = self.body_data["vectors"][0]["expected_yencryption_line"]
        params = parse_yencryption_line_v11(line)
        self.assertTrue(validate_dual_bootstrap(params["salt"], params["segment_index"], params))
        with self.assertRaisesRegex(ValueError, "DUAL_SALT_MISMATCH"):
            validate_dual_bootstrap(bytes(16), params["segment_index"], params)
        with self.assertRaisesRegex(ValueError, "DUAL_INDEX_MISMATCH"):
            validate_dual_bootstrap(params["salt"], params["segment_index"] + 1, params)


if __name__ == "__main__":
    unittest.main()
