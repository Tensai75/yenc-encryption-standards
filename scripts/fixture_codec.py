"""Shared fixture-storage codec for the conformance vectors.

Every binary data field in test-vectors/*.json is stored as a JSON
array of byte values under a ``*_bytes`` name (see
test-vectors/README.md).  ``fixture_bytes`` accepts either that array
form or a legacy hex string, and always returns the canonical bytes.
"""
import binascii


def fixture_bytes(case: dict, name: str) -> bytes:
    """Return canonical bytes for fixture field ``name`` (no suffix)."""
    arr = case.get(name + "_bytes")
    if arr is not None:
        if isinstance(arr, list) and arr and isinstance(arr[0], list):
            raise TypeError(f"{name}_bytes holds a list of values, use fixture_bytes_list")
        return bytes(arr)
    hex_value = case.get(name + "_hex")
    if hex_value is None:
        hex_value = (case.get(name + "_hex_a") or "") + (case.get(name + "_hex_b") or "")
    return binascii.unhexlify(hex_value)


def fixture_bytes_list(case: dict, name: str) -> list[bytes]:
    arr = case.get(name + "_bytes")
    if arr is not None:
        return [bytes(item) for item in arr]
    return [binascii.unhexlify(item) for item in case.get(name + "_hex", [])]
