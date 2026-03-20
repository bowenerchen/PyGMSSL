"""GF(2^128) finite field arithmetic for GHASH."""

MASK128 = (1 << 128) - 1

# Reduction polynomial: x^128 + x^7 + x^2 + x + 1
# R = 0xE1 << 120 = 0xE1000000000000000000000000000000
R = 0xE1 << 120


def bytes_to_gf128(b: bytes) -> int:
    """Convert 16 bytes to GF(2^128) element (MSB first, big-endian).

    GCM interprets the leftmost bit as the coefficient of x^127.
    """
    if len(b) != 16:
        raise ValueError("bytes_to_gf128 requires exactly 16 bytes")
    return int.from_bytes(b, "big") & MASK128


def gf128_to_bytes(x: int) -> bytes:
    """Convert GF(2^128) element back to 16 bytes."""
    return (x & MASK128).to_bytes(16, "big")


def gf128_mul(X: int, Y: int) -> int:
    """Multiply two GF(2^128) elements.

    Uses the irreducible polynomial: x^128 + x^7 + x^2 + x + 1
    R = 0xE1000000000000000000000000000000 (as 128-bit)
    """
    Z = 0
    V = X & MASK128
    Y = Y & MASK128
    for i in range(128):
        if Y & (1 << (127 - i)):
            Z ^= V
        if V & 1:
            V = (V >> 1) ^ R
        else:
            V = V >> 1
    return Z & MASK128
