"""eet/GmSSL-compatible SM2 SubjectPublicKeyInfo (tests only; not part of pygmssl)."""

from __future__ import annotations

from gmssl.hazmat.primitives.serialization import (
    encode_sequence,
    encode_oid,
    encode_bit_string,
    _pem_encode,
)

# As in eet-generated PEM (see tests-api/shell/fixtures/test_sm2_sm2_public.pem)
EC_PUBLIC_KEY_OID = (1, 2, 840, 10045, 2, 1)
SM2_NAMED_CURVE_OID = (1, 2, 156, 10197, 1, 301)


def encode_sm2_spki_for_eet(pub_uncompressed_65: bytes) -> bytes:
    if len(pub_uncompressed_65) != 65 or pub_uncompressed_65[0] != 0x04:
        raise ValueError("Expected 65-byte uncompressed SM2 public point (04||x||y)")
    alg = encode_sequence(
        [
            encode_oid(EC_PUBLIC_KEY_OID),
            encode_oid(SM2_NAMED_CURVE_OID),
        ]
    )
    return encode_sequence([alg, encode_bit_string(pub_uncompressed_65)])


def write_sm2_public_pem_for_eet(pub_uncompressed_65: bytes) -> bytes:
    return _pem_encode(encode_sm2_spki_for_eet(pub_uncompressed_65), "PUBLIC KEY")
