# yEnc Encryption Standards

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Experimental](https://img.shields.io/badge/Status-Experimental-red.svg)]()

This repository contains specifications for **two complementary encryption standards** designed specifically for yEnc-encoded binary blocks used in Usenet transfers. Both standards can be used individually or combined depending on security and obfuscation requirements.

## Standards Overview

### 1. yEnc Control Lines Encryption Standard

**Purpose**: Obfuscation and metadata protection  
**Target**: yEnc header and footer lines (lines beginning with "=y")  
**Method**: FF1 Format-Preserving Encryption

- **Format-preserving**: Encrypted control lines maintain exact length and character compatibility
- **Selective encryption**: Only metadata is encrypted, binary data remains untouched
- **Total obfuscation**: Hides file names, sizes, part information, and yEnc structure
- **Optional**: Can be omitted when obfuscation is not required

### 2. yEnc Body Encryption Standard

**Purpose**: Content protection with authentication  
**Target**: Binary file data before yEnc encoding  
**Method**: XChaCha20-Poly1305 Authenticated Encryption

- **Content security**: Encrypts actual file data with strong authentication
- **Integrity protection**: Detects tampering through cryptographic authentication
- **Transparent**: Standard yEnc parsers process encrypted blocks normally
- **Optional**: Can be omitted if cryptographic protection of file content is not required

## Usage Scenarios

### Scenario 1: Content Protection Only

- **Use**: Body Encryption Standard only
- **When**: Need strong file protection but metadata can remain visible
- **Benefits**: Strong authenticated encryption, standard yEnc compatibility

### Scenario 2: Obfuscation

- **Use**: Control Lines Encryption Standard only
- **When**: Need to hide upload metadata but file content protection handled separately or not required
- **Benefits**: Complete metadata obfuscation, format-preserving compatibility

### Scenario 3: Maximum Security

- **Use**: Both standards combined
- **When**: Need complete protection of both content and metadata
- **Benefits**: Authenticated file encryption + total metadata obfuscation

### Scenario 4: Standard Upload

- **Use**: Neither standard
- **When**: No special security requirements
- **Benefits**: Standard yEnc processing, maximum compatibility

## Password Management

**NZB File Storage**: When encryption is used, the password CAN be stored in the NZB file using the standard password meta tag:

```xml
<meta type="password">your_encryption_password</meta>
```

**Download Client Behavior**: Download clients MUST use the password from the NZB meta tag (if available) for automatic decryption of encrypted yEnc blocks.

**Combined Encryption**: When using both encryption standards together (Scenario 3), the **same password MUST be used** for both control lines and body encryption. This approach is:

- **Cryptographically secure**: Different domain separation strings ensure independent key derivation
- **User-friendly**: Single password management instead of tracking multiple passwords
- **Implementation-friendly**: Simplified NZB handling and software configuration

**External Preprocessing**: If external encryption was used in preprocessing (e.g., password-protected RAR files), the **same password MUST be used** for yEnc block encryption to avoid multiple passwords in the NZB file and maintain single-password simplicity for end users.

This unified password approach provides maximum security with optimal usability and implementation simplicity.

## Body Encryption vs. Preprocessing Methods

The **Body Encryption Standard** is designed to replace traditional preprocessing encryption methods such as password-protected RAR archives. On-the-fly body encryption offers significant advantages over preprocessing approaches:

### Efficiency Benefits

**Storage Requirements**:

- **No temporary files**: Encryption happens during upload, eliminating need for encrypted intermediate files
- **50% storage reduction**: Avoids storing both original and encrypted versions simultaneously
- **Streaming processing**: Files can be encrypted and uploaded directly from source without disk buffering

**Performance Advantages**:

- **Streamlined processing**: Single-pass encryption without intermediate archive creation
- **Efficient algorithm**: ChaCha20 is optimized for software implementation and runs efficiently on modern CPUs
- **Reduced I/O operations**: Eliminates read/write cycles for temporary encrypted files
- **Memory efficiency**: Streaming encryption uses constant memory regardless of file size

**Operational Benefits**:

- **Simplified workflow**: Single-step encryption+upload instead of encrypt-then-upload process
- **Reduced complexity**: No need to manage temporary encrypted archives or cleanup processes
- **Better error handling**: Immediate feedback on encryption/upload failures without orphaned temp files
- **Atomic operations**: Upload and encryption success/failure are coupled together

### Traditional Preprocessing Limitations

**RAR/ZIP Password Protection**:

- Requires full file compression before upload
- Creates temporary encrypted archives consuming additional disk space
- Slower compression algorithms with higher CPU overhead
- Two-stage process prone to interruption and cleanup issues
- Limited to compression tool's encryption capabilities

**On-the-fly Body Encryption**:

- Direct encryption during yEnc encoding process
- No intermediate file creation or storage overhead
- Modern authenticated encryption with stronger security guarantees
- Integrated error handling and recovery mechanisms
- Cryptographically superior to legacy archive encryption methods

## Specifications

### Control Lines Encryption Standard

**File**: [`yEnc Control Lines Encryption Standard.txt`](./yEnc%20Control%20Lines%20Encryption%20Standard.txt)

**Algorithm**: FF1 Format-Preserving Encryption

```
Target: yEnc control lines (lines beginning with "=y")
Alphabet: 253 bytes (0x01-0xFF excluding CR/LF)
Cipher: FF1 with AES-256
Key Derivation: Argon2id(password, salt)
Tweak: HMAC-SHA256(master, "yenc-control tweak" || segmentIndex || lineIndex)
Salt: SHA-256("yenc-control salt" || password)[0:16] (deterministic)
```

### Body Encryption Standard

**File**: [`yEnc Body Encryption Standard.txt`](./yEnc%20Body%20Encryption%20Standard.txt)

**Algorithm**: XChaCha20-Poly1305 Authenticated Encryption

```
Target: Binary file data (before yEnc encoding)
Cipher: XChaCha20 (256-bit key, 192-bit nonce)
Authentication: Poly1305 (128-bit tag)
Key Derivation: Argon2id(password, salt, 256-bit output)
Nonce: HMAC-SHA256(key, "yenc-body nonce" || segmentIndex)[0:24]
Salt: SHA-256("yenc-body salt" || password)[0:16] (deterministic)
```

## Security Properties

### Control Lines Encryption

- **Confidentiality**: AES-256 equivalent security for metadata
- **Format-preserving**: No information leakage through format changes
- **Deterministic**: Consistent output for identical inputs
- **Obfuscation**: Complete hiding of yEnc structure and metadata
- **Note**: Provides confidentiality only, not integrity verification

### Body Encryption

- **Confidentiality**: XChaCha20 encryption of file content
- **Authenticity**: Poly1305 authentication prevents tampering
- **Integrity**: Cryptographic verification of data integrity
- **Non-malleability**: Authentication tag prevents modification attacks
- **Note**: Provides both confidentiality and integrity protection

### Combined Usage

- **Total protection**: Both content and metadata encrypted
- **Defense in depth**: Multiple encryption layers with different algorithms
- **Flexible deployment**: Can be applied independently or together

## Implementation Considerations

### Control Lines Encryption

- Requires FF1-compatible library supporting custom alphabets
- First line of article body must be inspected prior to yEnc parsing in order to detect and decrypt encrypted control lines
- No backward compatibility: existing download tools and yEnc parsers will not recognize encrypted control lines

### Body Encryption

- Requires XChaCha20-Poly1305 implementation (widely available)
- Authentication tag stored in `=yencryption` control line
- Standard yEnc tools can process encrypted blocks normally
- Failed authentication must abort decryption completely

### Both Standards

- Segment indexing must be globally unique across entire upload session
- NZB files must include file numbering for proper segmentIndex calculation
- Password can be stored in NZB meta tags for automatic decryption

## Status

Both specifications are currently in **experimental** status. The standards are being developed collaboratively and may undergo changes based on community feedback and security review.

## Contributing

We welcome contributions to improve and refine the yEnc encryption standards:

### Discussions

For general questions, implementation discussions, or conceptual feedback, please use the [**Discussions**](../../discussions) section.

### Issues and Change Requests

- **Bug reports**: Found an error in the specification? Please [open an issue](../../issues/new).
- **Enhancement proposals**: Suggestions for improvements should be submitted as [issues](../../issues/new) with detailed rationale.
- **Specification changes**: Proposed modifications to the standard should be submitted as [pull requests](../../pulls) with clear justification and impact analysis.

### Pull Requests

When submitting PRs for specification changes:

1. Clearly describe the motivation and impact
2. Update relevant sections consistently across both standards
3. Consider backward compatibility implications
4. Include example scenarios if applicable
5. Specify which standard(s) are affected by the changes

## Related Work

- [NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp/800-38g/final): FF1 and FF3 Format-Preserving Encryption specification
- [RFC 8439](https://tools.ietf.org/html/rfc8439): ChaCha20 and Poly1305 for AEAD (XChaCha20-Poly1305 extension)
- [yEnc specification](http://www.yenc.org/yenc-draft.1.3.txt): Original yEnc encoding format
- [Argon2](https://tools.ietf.org/html/rfc9106): Password-based key derivation function

## License

This specification is released under the MIT License. See [LICENSE](LICENSE) for details.

---

**Maintainer**: [@Tensai75](https://github.com/Tensai75)  
**Repository**: [github.com/Tensai75/yenc-encryption-standards](https://github.com/Tensai75/yenc-encryption-standards)
