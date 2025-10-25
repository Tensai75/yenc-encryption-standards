#!/usr/bin/env python3
"""Behavioural specification checks for yEnc encryption standards v1.2.

This suite checks what can fail independently of editorial rewording,
plus a deliberate, admitted set of exact-substring checks (see
test_constants_agree_between_standards: it asserts exact substrings such
as "Version: 1.2", KDF parameter spellings, and the literal wire form, so
editorial rewording of those strings will fail here by design):

- The three specification files exist and are non-empty.
- Constants agree between the two .txt standards (KDF parameters,
  versions, wire grammar), including the admitted exact-substring checks
  described above.
- Section cross-references between the documents resolve to real sections.
- Every hexadecimal value printed in the Section 10 examples of both
  standards is recomputed from the reference helper.
"""

import re
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from yenc_enc_reference import (
    body_encrypt,
    build_aad,
    derive_body_nonce,
    derive_control_keys,
    derive_key,
    ff1_encrypt,
    uint32_be,
)


class TestStandardsV1(unittest.TestCase):
    """Behavioural suite recomputing the worked examples and cross-document constants."""

    @classmethod
    def setUpClass(cls):
        cls.standards_dir = Path(__file__).resolve().parent.parent
        cls.body_spec_path = cls.standards_dir / "yEnc Body Encryption Standard.txt"
        cls.control_spec_path = cls.standards_dir / "yEnc Control Lines Encryption Standard.txt"
        cls.readme_path = cls.standards_dir / "README.md"
        cls.body_spec = cls.body_spec_path.read_text(encoding="utf-8")
        cls.control_spec = cls.control_spec_path.read_text(encoding="utf-8")
        cls.readme = cls.readme_path.read_text(encoding="utf-8")

    def test_spec_environment(self):
        """All three specification files exist and contain non-empty UTF-8 text."""
        self.assertTrue(self.body_spec_path.is_file(), f"Missing {self.body_spec_path}")
        self.assertTrue(self.control_spec_path.is_file(), f"Missing {self.control_spec_path}")
        self.assertTrue(self.readme_path.is_file(), f"Missing {self.readme_path}")
        self.assertGreater(len(self.body_spec), 0, "Body specification file is empty")
        self.assertGreater(len(self.control_spec), 0, "Control lines specification file is empty")
        self.assertGreater(len(self.readme), 0, "README file is empty")

    def test_constants_agree_between_standards(self):
        """KDF parameters, versions, and the wire grammar agree in both .txt files.

        Admitted exact-substring checks: this test intentionally asserts
        exact substrings (version, KDF parameter spellings, wire form), so
        rewording those strings fails here by design rather than silently.
        """
        for spec in (self.body_spec, self.control_spec):
            self.assertIn("Version: 1.2", spec)
            self.assertIn("Argon2id", spec)
            self.assertIn("time=1", spec)
            self.assertRegex(spec, r"memory=(?:65536\s*KiB|64\s*MB)")
            self.assertRegex(spec, r"parallelism=4|threads=4")
            self.assertRegex(spec, r"32-byte output|256-bit output")
            self.assertIn("0x13", spec)
            self.assertIn("Dual-Bootstrap Agreement", spec)
            self.assertIn("253-byte Alphabet", spec)
            for byte in ("0x00", "0x0A", "0x0D"):
                self.assertIn(byte, spec)
            self.assertIn("METADATA_VALIDATION", spec)
            self.assertIn("PROVIDER_FAILOVER", spec)
            self.assertIn("zero output", spec.lower())
            self.assertIn("1..=4294967295", spec)
        wire_form = "=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>"
        for text in (self.body_spec, self.control_spec):
            self.assertIn(wire_form, text)

    def test_cross_references_resolve(self):
        """Cross-document section pointers point at sections that exist."""
        body_sections = set(re.findall(r"^(\d+)\. [A-Z]", self.body_spec, re.MULTILINE))
        control_sections = set(re.findall(r"^(\d+)\. [A-Z]", self.control_spec, re.MULTILINE))
        self.assertIn("8", body_sections)
        self.assertIn("2.1", self.body_spec)
        for match in re.findall(r"Body Standard Section (\d+(?:\.\d+)?)", self.control_spec):
            self.assertIn(match, body_sections | {"2.1"}, f"Control standard cites missing Body section {match}")
        for match in re.findall(r"Control Lines Standard Section (\d+(?:\.\d+)?)", self.body_spec):
            self.assertIn(match, control_sections, f"Body standard cites missing Control section {match}")

    def test_section_10_examples_match_reference(self):
        """Recompute every hex value printed in the Body and Control Section 10 examples (via the reference helper)."""
        plaintext = bytes.fromhex("48656C6C6F20576F726C642E747874FF")
        salt = bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890")
        key = derive_key("public-conformance-vector-key-2026", salt)
        nonce = derive_body_nonce(key, 1)
        body_10 = self.body_spec.split("\n10. Example", 1)[1]

        aad = build_aad(b"file.bin", 1, 1, 16)
        self.assertIn(aad.hex(), re.sub(r"\s+", "", body_10))
        ciphertext, tag = body_encrypt(plaintext, key, nonce, aad)
        self.assertIn(f"tag={tag.hex()}", body_10)
        self.assertIn(f"=yend size=16 crc32={zlib.crc32(ciphertext):08x}", body_10)

        aad_part = build_aad(b"file.bin", 1, 1, 8)
        ciphertext_part, tag_part = body_encrypt(plaintext[:8], key, nonce, aad_part)
        self.assertIn(f"tag={tag_part.hex()}", body_10)
        self.assertIn(ciphertext_part.hex(), body_10)
        self.assertIn(f"=yend size=8 part=1 pcrc32={zlib.crc32(ciphertext_part):08x}", body_10)

        control_10 = self.control_spec.split("\n10. Example", 1)[1]
        self.assertIn(key.hex(), control_10)
        enc_key, _ = derive_control_keys(key, 1, 1)
        self.assertIn(enc_key.hex(), control_10)
        lines = {
            1: "=ybegin line=128 size=16 name=file.bin",
            2: f"=yencryption cipher=XChaCha20-Poly1305 salt={salt.hex()} index=00000001 tag={tag.hex()}",
            4: f"=yend size=16 crc32={zlib.crc32(ciphertext):08x}",
        }
        for line_index, plain_line in lines.items():
            self.assertIn(plain_line, control_10)
            line_key, tweak = derive_control_keys(key, 1, line_index)
            wire = ff1_encrypt(line_key, tweak, plain_line.encode("ascii"))
            self.assertIn(tweak.hex(), control_10)
            self.assertIn(wire.hex(), control_10)
            if line_index == 1:
                self.assertIn((salt + uint32_be(1) + wire).hex(), control_10)


if __name__ == "__main__":
    unittest.main()
