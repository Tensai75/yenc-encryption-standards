# yEnc Encryption Standards

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Experimental Wire Contract (v1.2)](https://img.shields.io/badge/Status-v1.2%20Experimental-blue.svg)]()

This repository contains specifications for two encryption standards for yEnc-encoded binary blocks used in Usenet transfers. Version 1.2 defines the two standards for use together; an upload is either encrypted with both or not encrypted at all.

## Standards Overview

### 1. yEnc Control Lines Encryption Standard

This standard obfuscates and protects metadata. It targets the yEnc header and footer lines (lines beginning with "=y") and uses FF1 Format-Preserving Encryption.

Encrypted control lines keep the exact length (lines 2..N) and character compatibility. The first control line (lineIndex=1) expands by 20 bytes because of the prepended article bootstrap (16-byte raw salt from the 253-byte Alphabet and 4-byte big-endian uint32 segmentIndex); the expansion is measured on line content, excluding any trailing line terminator, and bootstrap extraction happens after NNTP dot-unstuffing. Only metadata is encrypted; binary data lines remain completely untouched. File names, sizes, part information, and yEnc structure are hidden. Line counting uses 1-based physical line numbers after NNTP dot-unstuffing. Line terminators are preserved on restoration: the restoration layer preserves byte-for-byte the terminators it receives (bare LF is never canonicalized to CRLF by restoration itself), and a transport layer MAY have normalized bare LF to CRLF earlier (Body Standard Section 9); line contents, physical line count, bootstrap bytes, CRC, AAD, and authenticated plaintext remain unchanged either way. Restoration APIs that receive raw terminators preserve them exactly. Decoding is deterministic and position-based: header positions are inferred from the restored structure and data lines are never decrypted.

### 2. yEnc Body Encryption Standard

This standard protects content with authentication. It targets binary file data before yEnc encoding and uses XChaCha20-Poly1305 Authenticated Encryption.

It encrypts the actual file data and detects tampering through cryptographic authentication; failed authentication results in complete decryption failure with zero partial data output. Each encryption binds exact associated data (AAD): the segment's part number, part begin offset, segment byte count, and the `=ybegin` name value, serialized as `"yenc-body aad" || uint32_be(partNumber) || uint32_be(partBegin) || uint64_be(segmentBytes) || uint32_be(nameLength) || name` (Body Standard Section 2.1). This authenticates the raw restored name, part, range, and segment length: modifying any of those fields, or the ciphertext, fails authentication. The AEAD authenticates each article against its own restored control lines only; an intact article carries its own valid AAD and has no cryptographic freshness binding to a Message-ID, an NZB slot, or any external record, so replaying an intact article is not detected by cryptography. Receiver queue and coverage checks (missing-article bookkeeping, declared-range assembly, repair tooling) remain responsible for segment coverage and ordering; swapping two intact segments does not fail authentication. NNTP headers, subjects, Message-IDs, and XML order remain outside the AEAD and are explicitly unauthenticated. The canonical format is a strict five-token control line `=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>` in lowercase hex (128 characters). Placement is physical line 2 for single-part articles (immediately after `=ybegin`) and physical line 3 for multipart articles (immediately after `=ypart`). An article is multipart if and only if physical line 2 after `=ybegin` is `=ypart`; otherwise it is single-part. The wire CRC covers ciphertext and is verified before AEAD decryption; after authentication succeeds, decoders MUST either clear the CRC metadata (crc32 = None) or recompute it over authenticated plaintext so downstream consumers verify plaintext CRC.

## Usage Scenarios

Version 1.2 defines combined mode only (control line encryption and body encryption together); other framing modes are reserved for future standards. For protection of both content and metadata, apply both standards together. With both standards in use, the 16-byte raw salt and 4-byte big-endian segmentIndex from Line 1 MUST equal the 16-byte salt and 8-hex index carried in `=yencryption` byte-for-byte and value-for-value; because one salt is shared, the combined-mode salt MUST lie in the intersection of both domains (the 253-byte Alphabet, with bytes 0x00, 0x0A, and 0x0D excluded). v1.2 producers emit combined mode only; receivers MUST support combined mode and reject other modes under PROVIDER_FAILOVER. An upload that needs neither protection is ordinary yEnc and uses neither standard.

## Body Encryption vs. Preprocessing

Body encryption is an alternative to preprocessing encryption such as password-protected archives, not an addition to it. Encrypting each segment while the article is built has these practical advantages:

- **No intermediate files**: no encrypted copy of the release is written to disk first, so no extra storage is needed and nothing has to be cleaned up afterwards.
- **Streaming**: encryption happens in the same pass as yEnc encoding, with memory bounded to one article regardless of file size.
- **Authenticated**: Poly1305 detects any modification, so tampered or corrupted articles are rejected instead of producing damaged output.
- **One password**: both standards use the same password, with domain-separated key derivation, so the NZB carries a single password.

## Password Management and Canonical NZB Metadata

### Transport Provenance vs Archive Passwords

To distinguish encrypted yEnc transport from unencrypted uploads carrying archive passwords (such as password-protected RAR or 7z files), compliant NZB documents carry explicit metadata flags:

1. Encrypted Transport: When yEnc encryption is present, the NZB `<head>` MUST contain `<meta type="yenc_encrypted">true</meta>`. `<meta type="password">` is the interoperable way to deliver the transport password. Clients MAY also take the password from their own sources (user input, API, configuration) and let it override the NZB value; how a client obtains, stores, or displays the password is up to the client.
2. Archive Password Decoupling: If an NZB contains `<meta type="password">` without `<meta type="yenc_encrypted">true</meta>`, the password applies solely to downstream extraction tools. The download client MUST process segments as standard unencrypted yEnc blocks without attempting transport decryption.

### NZB 1.1 Example (Encrypted Release)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">correct horse battery staple</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="poster@example.com"
       date="1727280000"
       subject="4Qd7sJm2pL yEnc (1/2)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="750000" number="1">article-1@example.com</segment>
      <segment bytes="750000" number="2">article-2@example.com</segment>
    </segments>
  </file>
  <file poster="poster@example.com"
       date="1727280001"
       subject="n8Vx3KaP yEnc (1/1)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="500000" number="1">article-3@example.com</segment>
    </segments>
  </file>
</nzb>
```

### NZB 1.1 Example (Unencrypted Release with Archive Password)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">archive_extraction_password</meta>
  </head>
  <file poster="poster@example.com"
       date="1727280000"
       subject="archive.part01.rar yEnc (1/2)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="750000" number="1">article-rar-1@example.com</segment>
      <segment bytes="750000" number="2">article-rar-2@example.com</segment>
    </segments>
  </file>
</nzb>
```

### Segment Identity Rules

- `segmentIndex` is an explicit unsigned 32-bit integer in range `1..=4294967295` encoded in article bootstrap bytes, not in the NZB; see the two standards for the framing rule and the exact encoding.

## Processing and Failure Rules

The two .txt standards are the normative source for all rules; the lists below are only a summary with pointers.

- NZB gating: `<meta type="yenc_encrypted">true</meta>` (trimmed, ASCII case-insensitive) enables transport decryption; any other value means ordinary yEnc, and a password without it stays an archive password (Body Standard Section 8).
- `=ybegin` keywords: yEnc keywords on the restored `=ybegin` line are the space-separated tokens before `name=`; the `name=` value is the remainder of the line after `name=`, so text inside the name (such as `part=`) is never a keyword and is part of the AAD subject (Body Standard Section 2.1, Control Lines Standard Section 3).
- Optional `yenc_version` and `yenc_cipher` metadata: an absent entry is allowed; a present but empty or non-matching value (`1.2` exactly; `XChaCha20-Poly1305` case-insensitive, both after trimming whitespace) is a `METADATA_VALIDATION` failure (Body Standard Section 8).
- Header placement: an article is multipart if and only if physical line 2 after `=ybegin` is `=ypart`; receivers decrypt physical line 2 first and never read `part=` from `=ybegin` to decide placement (Body Standard Sections 3-5).
- For a file that fits in one segment, the uploader chooses single-part framing or a one-part multipart block; both are conformant (Body Standard Section 4).
- Key derivation: Argon2id with the exact fixed inputs of Body Standard Section 4; passwords are used unaltered and must be XML-representable when carried by NZB metadata.
- Error tiers: `METADATA_VALIDATION` (NZB metadata or local configuration, before fetch, aborts the job) and `PROVIDER_FAILOVER` (fetched article bytes, retry another provider); both tiers release zero plaintext and zero ciphertext (Body Standard Section 5).
- The wire CRC covers ciphertext and is verified before AEAD authentication; afterwards decoders clear or recompute it over plaintext (Body Standard Section 5).
- Transport: producers dot-stuff per RFC 3977 Section 3.1.1; consumers dot-unstuff before line splitting; CRLF is canonical and bare LF is accepted; restoration preserves the terminators it receives and transport MAY have normalized bare LF to CRLF earlier, while line contents, physical line count, bootstrap, CRC, AAD, and authenticated plaintext remain unchanged (Body Standard Section 9); memory stays bounded to one article.

## Wire Specifications and Invariants

### Control Lines Encryption Specification

File: [`yEnc Control Lines Encryption Standard.txt`](./yEnc%20Control%20Lines%20Encryption%20Standard.txt)  
Algorithm: FF1 Format-Preserving Encryption

```
Target: yEnc control lines (lines beginning with "=y")
Alphabet: 253 bytes (0x01-0xFF excluding CR/LF: 0x0D and 0x0A)
Cipher: FF1 with AES-256
Key Derivation: Argon2id(password UTF-8 no-normalization, salt, time=1, memory=65536 KiB, parallelism=4, 32-byte output, version 0x13)
Tweak: HMAC-SHA256(masterKey, "yenc-control tweak" || uint32_be(segmentIndex) || uint32_be(lineIndex))[0:8]
Length: Line 1 expands by 20 bytes; lines 2..N preserve exact byte length
Restoration: deterministic, position-based; data lines are never decrypted
```

### Body Encryption Specification

File: [`yEnc Body Encryption Standard.txt`](./yEnc%20Body%20Encryption%20Standard.txt)  
Algorithm: XChaCha20-Poly1305 Authenticated Encryption

```
Target: Binary file data (before yEnc encoding)
Cipher: XChaCha20 (256-bit key, 192-bit nonce)
Authentication: Poly1305 (128-bit tag)
Key Derivation: Argon2id(password UTF-8 no-normalization, salt, time=1, memory=65536 KiB, parallelism=4, 32-byte output, version 0x13)
Nonce: HMAC-SHA256(key, "yenc-body nonce" || uint32_be(segmentIndex))[0:24]
AAD: "yenc-body aad" || uint32_be(partNumber) || uint32_be(partBegin) || uint64_be(segmentBytes) || uint32_be(nameLength) || name (Body Standard Section 2.1)
Format: =yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>
Placement: Single-part line 2 (after =ybegin); multipart line 3 (after =ypart)
CRC Handling: Wire CRC in =yend covers ciphertext; verified then cleared (crc32 = None) or recomputed over authenticated plaintext
```

A client MUST NOT release or write unauthenticated plaintext or ciphertext to any downstream target (assembly, downstream caches, files, or observable sinks). Internal restored metadata, intermediate ciphertext, and article-sized working buffers MAY pass between internal helpers inside the validation pipeline, but unauthenticated payload MUST NOT reach downstream stages before validation completes. Working memory MUST remain O(article_size) and MUST NOT grow with a multipart file or release (Body Standard Sections 5 and 9).

## Status

Both specifications are experimental v1.2 wire contracts; v1.2 is pre-release and not published. Version 1.2 defines combined mode only (control line encryption and body encryption together); other framing modes are reserved for future standards. The two .txt files in this repository are the only normative source.

## Tooling and Conformance Suite

### Scripts (`scripts/`)

The repository provides automated validation and reference implementations under `scripts/`:

- `yenc_enc_reference.py`: Reference helper for cryptographic derivations (Argon2id KDF, HMAC-SHA256 nonces and tweaks, NIST SP 800-38G FF1 with Radix 253 Alphabet, and XChaCha20-Poly1305 AEAD); the two .txt standards remain the only normative source.
- `generate_conformance_vectors.py`: Deterministic test vector generator producing JSON fixtures with cryptographic inputs, wire lines, and expected outcomes.
- `test_conformance_vectors.py`: Automated test harness exercising all generated test vector fixtures and validating failure-mode enforcement.
- `test_standards_v1.py`: Behavioural specification checks recomputing the Section 10 examples and cross-document constants, including admitted exact-substring checks on version, KDF parameter spellings, and the wire form.

Run tests using pytest or direct invocation:
```bash
pip install -r scripts/requirements.txt
pytest scripts/
```

### Test Vectors (`test-vectors/`)

Test vectors (helper artifacts for implementers; the two .txt standards are the only normative source) are maintained under `test-vectors/`:

- `argon2id.json`: Key derivation test vectors including exact byte handling with no Unicode normalization.
- `nonce_tweak.json`: HMAC-SHA256 body nonce (19-byte message, first 24 bytes of output) and control tweak (26-byte message, first 8 bytes of output) derivation vectors.
- `body_encryption.json`: XChaCha20-Poly1305 AEAD round-trips with Section 2.1 Associated Data.
- `control_line_encryption.json`: NIST SP 800-38G FF1 control-line encryption round-trips and deterministic multi-line article layout fixtures.
- `malformed_inputs.json`: Malformed headers, bad salts, corrupted tags, framing mismatches, and zero-output assertions.
- `index_allocation.json`: Uploader segmentIndex sequence progression skipping indices containing forbidden delimiter bytes (0x0A, 0x0D).

To regenerate vectors deterministically:
```bash
python3 scripts/generate_conformance_vectors.py test-vectors
```

## Contributing

For questions, implementation discussion, or conceptual feedback, use [Discussions](../../discussions). To report an error or propose an improvement, [open an issue](../../issues/new) with the motivation and rationale. Specification changes go through [pull requests](../../pulls) that describe the motivation and impact, keep both standards consistent, note backward compatibility implications, and state which standard(s) are affected.

## Related Work

- [NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp-800-38g/final): FF1 and FF3 Format-Preserving Encryption specification
- [RFC 8439](https://tools.ietf.org/html/rfc8439): ChaCha20 and Poly1305 for AEAD (XChaCha20-Poly1305 extension)
- [yEnc specification](http://www.yenc.org/yenc-draft.1.3.txt): Original yEnc encoding format
- [Argon2](https://tools.ietf.org/html/rfc9106): Password-based key derivation function (RFC 9106)

## License

This specification is released under the MIT License. See [LICENSE](LICENSE) for details.

---

**Maintainer**: [@Tensai75](https://github.com/Tensai75)  
**Repository**: [github.com/Tensai75/yenc-encryption-standards](https://github.com/Tensai75/yenc-encryption-standards)
