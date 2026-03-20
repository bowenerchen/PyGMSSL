"""Convert SM2 ciphertext/signature formats between eet wire layouts and pygmssl canonical C1||C3||C2."""

from __future__ import annotations

from gmssl.hazmat.primitives.serialization import decode_sm2_signature_der
from gmssl._backends._sm2_ciphertext import (
    encode_sm2_ciphertext,
    normalize_sm2_ciphertext,
)


def raw_c1c3c2_from_c1c2c3(ct: bytes) -> bytes:
    """C1(64)||C2||C3(32) -> C1'(65)||C3||C2."""
    return normalize_sm2_ciphertext(ct, "C1C2C3")


def raw_c1c3c2_from_c1c3c2_eet_raw(ct: bytes) -> bytes:
    """C1(64)||C3(32)||C2 -> C1'(65)||C3||C2."""
    return normalize_sm2_ciphertext(ct, "C1C3C2")


def raw_c1c3c2_from_asn1_der(der: bytes, order: str) -> bytes:
    """order 'c1c3c2' | 'c1c2c3' -> canonical."""
    fmt = "C1C3C2_ASN1" if order == "c1c3c2" else "C1C2C3_ASN1"
    return normalize_sm2_ciphertext(der, fmt)


def pygmssl_raw_to_eet_c1c3c2(raw: bytes) -> bytes:
    """Canonical -> eet raw C1C3C2 (64-byte C1)."""
    return encode_sm2_ciphertext(raw, "C1C3C2")


def pygmssl_raw_to_eet_c1c2c3(raw: bytes) -> bytes:
    return encode_sm2_ciphertext(raw, "C1C2C3")
