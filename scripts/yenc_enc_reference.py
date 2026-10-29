#!/usr/bin/env python3
"""Reference implementation helpers for the yEnc encryption standards v1.2.

This module is a reference helper for the derivations that implementations
must reproduce (the two .txt standards remain the only normative source):

- Argon2id key derivation with the exact v1.2 KDF inputs (UTF-8 password
  encoding with no normalization, v=0x13, t=1, m=65536 KiB, p=4, 32-byte
  output, empty optional secret/AD).
- Body nonce derivation (Body Standard Section 4).
- Associated Data (AAD) serialization exactly per Body Standard Section 2.1.
- Body encryption/decryption with that AAD (Section 4 / Section 5).
- Control-line FF1 key and tweak derivation (Control Lines Standard
  Section 4) and the deterministic combined-mode restoration rule
  (Control Lines Standard Section 5, step 4).
- NIST SP 800-38G FF1 encryption and decryption over the 253-character Alphabet.
- Dual-bootstrap validation and Line 1 bootstrap extraction.

Nothing in this module is an optimization target; clarity and exact
agreement with the normative text are the only goals.
"""

import hashlib
import hmac
import math
import struct

import argon2.low_level as ll
import nacl.bindings as nb
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Exact v1.2 KDF parameters (Body Standard Section 4 / Control Lines
# Standard Section 4).
ARGON2ID_VERSION = 0x13  # decimal 19
ARGON2ID_TIME_COST = 1
ARGON2ID_MEMORY_COST_KIB = 65536  # 64 MiB
ARGON2ID_PARALLELISM = 4
ARGON2ID_HASH_LEN = 32

AAD_PREFIX = b"yenc-body aad"  # exactly 13 bytes (Body Standard Section 2.1)

# The 253-character Alphabet (Control Lines Standard Section 2):
# all 256 octets excluding 0x00 (NUL), 0x0A (LF), and 0x0D (CR).
ALPHABET = bytes([b for b in range(256) if b not in (0x00, 0x0A, 0x0D)])
BYTE_TO_NUMERAL = {b: i for i, b in enumerate(ALPHABET)}
NUMERAL_TO_BYTE = {i: b for i, b in enumerate(ALPHABET)}


def uint32_be(val: int) -> bytes:
    """Serialize 32-bit unsigned integer in big-endian network byte order."""
    if not (0 <= val <= 0xFFFFFFFF):
        raise ValueError(f"Value {val} out of range for uint32_be")
    return struct.pack(">I", val)


def uint64_be(val: int) -> bytes:
    """Serialize 64-bit unsigned integer in big-endian network byte order."""
    if not (0 <= val <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError(f"Value {val} out of range for uint64_be")
    return struct.pack(">Q", val)


def kdf_password_bytes(password: str) -> bytes:
    """Encode the password to UTF-8 with NO normalization (v1.2 Section 4).

    The normative rule is byte-level identity of the UTF-8 encoding of the
    exact code-point sequence supplied; this function deliberately performs
    no NFC/NFD/NFKC/NFKD folding.
    """
    return password.encode("utf-8")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive the 32-byte Argon2id key with the exact v1.2 parameters."""
    return ll.hash_secret_raw(
        secret=kdf_password_bytes(password),
        salt=salt,
        time_cost=ARGON2ID_TIME_COST,
        memory_cost=ARGON2ID_MEMORY_COST_KIB,
        parallelism=ARGON2ID_PARALLELISM,
        hash_len=ARGON2ID_HASH_LEN,
        type=ll.Type.ID,
        version=ARGON2ID_VERSION,
    )


def derive_body_nonce(body_key: bytes, segment_index: int) -> bytes:
    """Derive the 24-byte body nonce: HMAC-SHA256(key, prefix || uint32_be)[0:24]."""
    message = b"yenc-body nonce" + uint32_be(segment_index)
    return hmac.new(body_key, message, hashlib.sha256).digest()[:24]


def build_aad(
    name_bytes: bytes,
    part_number: int,
    part_begin: int,
    segment_bytes: int,
) -> bytes:
    """Serialize the Associated Data exactly per Body Standard Section 2.1.

    Fixed layout:
      "yenc-body aad" || uint32_be(partNumber) || uint32_be(partBegin) ||
      uint64_be(segmentBytes) || uint32_be(nameLength) || nameBytes
    """
    if not name_bytes:
        raise ValueError("AAD subject must be non-empty; empty AAD is invalid")
    return (
        AAD_PREFIX
        + uint32_be(part_number)
        + uint32_be(part_begin)
        + uint64_be(segment_bytes)
        + uint32_be(len(name_bytes))
        + name_bytes
    )


def body_encrypt(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt payload with XChaCha20-Poly1305 and the Section 2.1 AAD."""
    out = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return out[:-16], out[-16:]


def body_decrypt(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Authenticate and decrypt with the Section 2.1 AAD; raises on failure.

    The caller must treat a raised error as PROVIDER_FAILOVER and must
    release zero bytes (Body Standard Section 5 zero-output rule); this
    function never returns partial plaintext.
    """
    return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext + tag, aad, nonce, key
    )


def derive_control_keys(master_key: bytes, segment_index: int, line_index: int):
    """Derive the 32-byte FF1 encKey and 8-byte tweak (Control Std Section 4)."""
    enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()
    tweak_msg = b"yenc-control tweak" + uint32_be(segment_index) + uint32_be(line_index)
    tweak = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()[:8]
    return enc_key, tweak


def byte_to_numeral(b: int) -> int:
    """Map byte octet to numeral 0..252 per yEnc Control Lines Standard v1.2."""
    if 0x01 <= b <= 0x09:
        return b - 1
    elif b == 0x0B:
        return 9
    elif b == 0x0C:
        return 10
    elif 0x0E <= b <= 0xFF:
        return b - 3
    raise ValueError(f"Byte 0x{b:02x} is outside the 253-byte Alphabet (0x00, 0x0A, 0x0D forbidden)")


def numeral_to_byte(i: int) -> int:
    """Map numeral 0..252 back to byte octet per yEnc Control Lines Standard v1.2."""
    if 0 <= i <= 8:
        return i + 1
    elif i == 9:
        return 0x0B
    elif i == 10:
        return 0x0C
    elif 11 <= i <= 252:
        return i + 3
    raise ValueError(f"Numeral {i} is out of range [0, 252]")


def num_radix(numerals: list[int], radix: int) -> int:
    res = 0
    for n in numerals:
        res = res * radix + n
    return res


def str_radix(val: int, radix: int, m: int) -> list[int]:
    res = [0] * m
    for i in range(m):
        res[m - 1 - i] = val % radix
        val //= radix
    return res


def cbc_mac(aes_enc, data: bytes) -> bytes:
    block = bytes(16)
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        xored = bytes(a ^ b for a, b in zip(block, chunk))
        block = aes_enc(xored)
    return block


def ff1_encrypt_numerals(key: bytes, tweak: bytes, numerals: list[int], radix: int = 253) -> list[int]:
    """NIST SP 800-38G FF1 Encryption over arbitrary numeral strings."""
    backend = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    aes_enc = backend.update
    n = len(numerals)
    t = len(tweak)
    u = n // 2
    v = n - u
    b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    d = 4 * math.ceil(b / 4) + 4

    p = bytearray(16)
    p[0], p[1], p[2] = 1, 2, 1
    p[3:6] = radix.to_bytes(3, "big")
    p[6] = 10
    p[7] = u % 256
    p[8:12] = n.to_bytes(4, "big")
    p[12:16] = t.to_bytes(4, "big")

    pad_len = ((-t - b - 1) % 16 + 16) % 16
    q_prefix = tweak + bytes(pad_len)

    A = list(numerals[:u])
    B = list(numerals[u:])

    for i in range(10):
        q = q_prefix + bytes([i]) + num_radix(B, radix).to_bytes(b, "big")
        R = cbc_mac(aes_enc, bytes(p) + q)
        S = bytearray(R)
        j = 1
        while len(S) < d:
            j_bytes = j.to_bytes(16, "big")
            blk = bytes(a ^ b for a, b in zip(R, j_bytes))
            S.extend(aes_enc(blk))
            j += 1
        y = int.from_bytes(S[:d], "big")
        m = u if i % 2 == 0 else v
        c = (num_radix(A, radix) + y) % (radix**m)
        C = str_radix(c, radix, m)
        A = B
        B = C

    return A + B


def ff1_decrypt_numerals(key: bytes, tweak: bytes, numerals: list[int], radix: int = 253) -> list[int]:
    """NIST SP 800-38G FF1 Decryption over arbitrary numeral strings."""
    backend = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    aes_enc = backend.update
    n = len(numerals)
    t = len(tweak)
    u = n // 2
    v = n - u
    b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    d = 4 * math.ceil(b / 4) + 4

    p = bytearray(16)
    p[0], p[1], p[2] = 1, 2, 1
    p[3:6] = radix.to_bytes(3, "big")
    p[6] = 10
    p[7] = u % 256
    p[8:12] = n.to_bytes(4, "big")
    p[12:16] = t.to_bytes(4, "big")

    pad_len = ((-t - b - 1) % 16 + 16) % 16
    q_prefix = tweak + bytes(pad_len)

    A = list(numerals[:u])
    B = list(numerals[u:])

    for round_idx in range(10):
        i = 9 - round_idx
        q = q_prefix + bytes([i]) + num_radix(A, radix).to_bytes(b, "big")
        R = cbc_mac(aes_enc, bytes(p) + q)
        S = bytearray(R)
        j = 1
        while len(S) < d:
            j_bytes = j.to_bytes(16, "big")
            blk = bytes(a ^ b for a, b in zip(R, j_bytes))
            S.extend(aes_enc(blk))
            j += 1
        y = int.from_bytes(S[:d], "big")
        m = u if i % 2 == 0 else v
        c = (num_radix(B, radix) - y) % (radix**m)
        C = str_radix(c, radix, m)
        B = A
        A = C

    return A + B


def ff1_encrypt(key: bytes, tweak: bytes, plaintext_bytes: bytes, radix: int = 253) -> bytes:
    """Encrypt control line byte string using FF1 over Radix 253 Alphabet."""
    numerals = [byte_to_numeral(b) for b in plaintext_bytes]
    ct_numerals = ff1_encrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in ct_numerals)


def ff1_decrypt(key: bytes, tweak: bytes, ciphertext_bytes: bytes, radix: int = 253) -> bytes:
    """Decrypt control line byte string using FF1 over Radix 253 Alphabet."""
    numerals = [byte_to_numeral(b) for b in ciphertext_bytes]
    pt_numerals = ff1_decrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in pt_numerals)


def extract_bootstrap_from_line1(line1_bytes: bytes) -> tuple[bytes, int, bytes]:
    """Extract salt (16B), uint32_be segmentIndex (4B), and ciphertext (>=2B) from Line 1."""
    if len(line1_bytes) < 22:
        raise ValueError("LINE_TRUNCATED")
    salt = line1_bytes[:16]
    for b in salt:
        if b in (0x00, 0x0A, 0x0D):
            raise ValueError("INVALID_SALT_CHARACTER")
    seg_idx = struct.unpack(">I", line1_bytes[16:20])[0]
    if seg_idx == 0:
        raise ValueError("ZERO_SEGMENT_INDEX")
    # Index framing rule (Control Std v1.2 Section 2/4/5/8): a uint32_be(segmentIndex)
    # containing 0x0A or 0x0D injects an NNTP line delimiter into the Line 1
    # prefix and splits the bootstrap short. Decoders MUST reject under
    # PROVIDER_FAILOVER.
    for b in line1_bytes[16:20]:
        if b in (0x0A, 0x0D):
            raise ValueError("FORBIDDEN_SEGMENT_INDEX_BYTE")
    ciphertext = line1_bytes[20:]
    return salt, seg_idx, ciphertext


def validate_dual_bootstrap(line1_salt: bytes, line1_index: int, yenc_params: dict) -> bool:
    """Verify byte-for-byte salt equality and value-for-value index equality."""
    if line1_salt != yenc_params["salt"]:
        raise ValueError("DUAL_SALT_MISMATCH")
    if line1_index != yenc_params["segment_index"]:
        raise ValueError("DUAL_INDEX_MISMATCH")
    return True


def combined_mode_layout(is_multipart: bool) -> dict:
    """Return the deterministic combined-mode layout (Control Std Section 5 step 4).

    is_multipart is true when physical line 2 restored to =ypart.
    """
    if is_multipart:
        return {"multipart": True, "header_line_indices": [1, 2, 3], "first_data_line": 4}
    return {"multipart": False, "header_line_indices": [1, 2], "first_data_line": 3}
