"""SM2 ciphertext wire formats aligned with eet (-m C1C3C2, C1C2C3, *_ASN1).

Canonical internal layout: C1 (65 bytes, 04||x||y) || C3 (32) || C2 (variable).
"""

from __future__ import annotations

from gmssl._backends._asn1 import (
    decode_tlv,
    decode_integer,
    encode_integer,
    encode_octet_string,
    encode_sequence,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
)

# eet sm2 encrypt/decrypt -m values
SM2_CIPHERTEXT_FORMAT_C1C3C2 = "C1C3C2"
SM2_CIPHERTEXT_FORMAT_C1C2C3 = "C1C2C3"
SM2_CIPHERTEXT_FORMAT_C1C3C2_ASN1 = "C1C3C2_ASN1"
SM2_CIPHERTEXT_FORMAT_C1C2C3_ASN1 = "C1C2C3_ASN1"

SM2_EET_CIPHERTEXT_FORMATS = frozenset(
    {
        SM2_CIPHERTEXT_FORMAT_C1C3C2,
        SM2_CIPHERTEXT_FORMAT_C1C2C3,
        SM2_CIPHERTEXT_FORMAT_C1C3C2_ASN1,
        SM2_CIPHERTEXT_FORMAT_C1C2C3_ASN1,
    }
)


def validate_sm2_ciphertext_format(ciphertext_format: str | None) -> None:
    if ciphertext_format is None:
        return
    if ciphertext_format not in SM2_EET_CIPHERTEXT_FORMATS:
        raise ValueError(
            "ciphertext_format must be None (default C1||C3||C2 with 65-byte C1) or one of: "
            + ", ".join(sorted(SM2_EET_CIPHERTEXT_FORMATS))
        )


def _int_bytes_to_u256(b: bytes) -> bytes:
    n = int.from_bytes(b, "big", signed=True if b and (b[0] & 0x80) else False)
    if n < 0:
        raise ValueError("Negative coordinate in SM2 point")
    out = n.to_bytes(32, "big")
    if len(out) > 32:
        raise ValueError("Coordinate too large for SM2")
    return out.rjust(32, b"\x00")[-32:]


def c1_to_uncompressed_65(c1: bytes) -> bytes:
    """eet raw modes use C1 = x||y (64 bytes); canonical uses 04||x||y."""
    if len(c1) == 65 and c1[0] == 0x04:
        return c1
    if len(c1) == 64:
        return b"\x04" + c1
    raise ValueError(f"Unsupported C1 length {len(c1)}")


def _parse_asn1_two_int_two_oct(seq: bytes, order: str) -> tuple[bytes, bytes, bytes]:
    """order 'c1c3c2' -> c1_65, c3, c2; 'c1c2c3' -> c1_65, c3, c2."""
    p = 0
    parts: list[tuple[int, bytes]] = []
    while p < len(seq):
        tag, val, p = decode_tlv(seq, p)
        parts.append((tag, val))
    if len(parts) != 4:
        raise ValueError(f"Expected 4 ASN.1 fields, got {len(parts)}")
    if parts[0][0] != TAG_INTEGER or parts[1][0] != TAG_INTEGER:
        raise ValueError("First fields must be INTEGER (C1 coordinates)")
    if parts[2][0] != TAG_OCTET_STRING or parts[3][0] != TAG_OCTET_STRING:
        raise ValueError("Last fields must be OCTET STRING")
    xb = _int_bytes_to_u256(parts[0][1])
    yb = _int_bytes_to_u256(parts[1][1])
    c1 = b"\x04" + xb + yb
    o1, o2 = parts[2][1], parts[3][1]
    if order == "c1c3c2":
        c3, c2 = o1, o2
    elif order == "c1c2c3":
        c2, c3 = o1, o2
    else:
        raise ValueError(order)
    return c1, c3, c2


def normalize_sm2_ciphertext(ciphertext: bytes, ciphertext_format: str | None) -> bytes:
    """Wire layout -> canonical C1(65)||C3(32)||C2."""
    if ciphertext_format is None:
        return ciphertext
    validate_sm2_ciphertext_format(ciphertext_format)
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C3C2:
        if len(ciphertext) < 64 + 32 + 1:
            raise ValueError("C1C3C2 ciphertext too short")
        c1_64, c3, c2 = ciphertext[:64], ciphertext[64:96], ciphertext[96:]
        return c1_to_uncompressed_65(c1_64) + c3 + c2
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C2C3:
        if len(ciphertext) < 64 + 32 + 1:
            raise ValueError("C1C2C3 ciphertext too short")
        c1_64, rest = ciphertext[:64], ciphertext[64:]
        if len(rest) < 33:
            raise ValueError("C1C2C3 missing C3")
        c2_len = len(rest) - 32
        c2, c3 = rest[:c2_len], rest[c2_len:]
        return c1_to_uncompressed_65(c1_64) + c3 + c2
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C3C2_ASN1:
        tag, seq, _ = decode_tlv(ciphertext, 0)
        if tag != TAG_SEQUENCE:
            raise ValueError("Expected outer SEQUENCE")
        c1, c3, c2 = _parse_asn1_two_int_two_oct(seq, "c1c3c2")
        return c1 + c3 + c2
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C2C3_ASN1:
        tag, seq, _ = decode_tlv(ciphertext, 0)
        if tag != TAG_SEQUENCE:
            raise ValueError("Expected outer SEQUENCE")
        c1, c3, c2 = _parse_asn1_two_int_two_oct(seq, "c1c2c3")
        return c1 + c3 + c2
    raise ValueError(ciphertext_format)


def encode_sm2_ciphertext(canonical: bytes, ciphertext_format: str | None) -> bytes:
    """Canonical C1(65)||C3(32)||C2 -> wire layout."""
    if ciphertext_format is None:
        return canonical
    validate_sm2_ciphertext_format(ciphertext_format)
    if len(canonical) < 98:
        raise ValueError("canonical ciphertext too short")
    c1, c3, c2 = canonical[:65], canonical[65:97], canonical[97:]
    if len(c1) != 65 or c1[0] != 0x04:
        raise ValueError("Expected uncompressed C1 in canonical form")
    x = int.from_bytes(c1[1:33], "big")
    y = int.from_bytes(c1[33:65], "big")
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C3C2:
        return c1[1:] + c3 + c2
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C2C3:
        return c1[1:] + c2 + c3
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C3C2_ASN1:
        body = [
            encode_integer(x),
            encode_integer(y),
            encode_octet_string(c3),
            encode_octet_string(c2),
        ]
        return encode_sequence(body)
    if ciphertext_format == SM2_CIPHERTEXT_FORMAT_C1C2C3_ASN1:
        body = [
            encode_integer(x),
            encode_integer(y),
            encode_octet_string(c2),
            encode_octet_string(c3),
        ]
        return encode_sequence(body)
    raise ValueError(ciphertext_format)
