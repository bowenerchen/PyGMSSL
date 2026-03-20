"""SM2 signature wire formats aligned with eet (``-m RS``, ``-m RS_ASN1``)."""

from __future__ import annotations

from gmssl.hazmat.primitives.serialization import (
    decode_sm2_signature_der,
    encode_sm2_signature_der,
)

SM2_SIGNATURE_FORMAT_RS = "RS"
SM2_SIGNATURE_FORMAT_RS_ASN1 = "RS_ASN1"

SM2_EET_SIGNATURE_FORMATS = frozenset(
    {SM2_SIGNATURE_FORMAT_RS, SM2_SIGNATURE_FORMAT_RS_ASN1}
)


def validate_sm2_signature_format(signature_format: str | None) -> None:
    if signature_format is None:
        return
    if signature_format not in SM2_EET_SIGNATURE_FORMATS:
        raise ValueError(
            "signature_format must be None (default RS), 'RS', or 'RS_ASN1', got "
            + repr(signature_format)
        )


def normalize_sm2_signature_to_rs(signature: bytes, signature_format: str | None) -> bytes:
    """Wire layout -> 64-byte r||s."""
    if signature_format is None or signature_format == SM2_SIGNATURE_FORMAT_RS:
        if len(signature) != 64:
            raise ValueError(f"RS signature must be 64 bytes, got {len(signature)}")
        return signature
    if signature_format == SM2_SIGNATURE_FORMAT_RS_ASN1:
        return decode_sm2_signature_der(signature)
    raise ValueError(signature_format)


def encode_sm2_signature_wire(rs64: bytes, signature_format: str | None) -> bytes:
    """64-byte r||s -> wire layout."""
    if len(rs64) != 64:
        raise ValueError(f"internal signature must be 64 bytes, got {len(rs64)}")
    if signature_format is None or signature_format == SM2_SIGNATURE_FORMAT_RS:
        return rs64
    if signature_format == SM2_SIGNATURE_FORMAT_RS_ASN1:
        return encode_sm2_signature_der(rs64)
    raise ValueError(signature_format)
