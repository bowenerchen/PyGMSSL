"""Internal utility functions for byte manipulation and common operations."""

import os
import struct


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(b, "big")


def int_to_bytes(n: int, length: int) -> bytes:
    """Convert integer to big-endian bytes of given length."""
    return n.to_bytes(length, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def rotl32(x: int, n: int) -> int:
    """32-bit left rotation."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def rotr32(x: int, n: int) -> int:
    """32-bit right rotation."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def pack_u32_be(values: list[int]) -> bytes:
    """Pack a list of uint32 values as big-endian bytes."""
    return struct.pack(f">{len(values)}I", *values)


def unpack_u32_be(data: bytes) -> list[int]:
    """Unpack big-endian bytes into a list of uint32 values."""
    n = len(data) // 4
    return list(struct.unpack(f">{n}I", data[:n * 4]))


def rand_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return os.urandom(n)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings to prevent timing attacks."""
    import hmac
    return hmac.compare_digest(a, b)
