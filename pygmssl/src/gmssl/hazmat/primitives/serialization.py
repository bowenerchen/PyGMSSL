"""
Key serialization – PEM and DER encoding/decoding.

Usage::

    from gmssl.hazmat.primitives import serialization

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
"""

import base64
from enum import Enum
from gmssl._backends._asn1 import (
    encode_sequence, encode_integer, encode_octet_string,
    encode_oid, encode_null, encode_context, encode_bit_string,
    decode_tlv, decode_integer, TAG_SEQUENCE,
)
from gmssl._backends._pkcs8_pbes2_sm4 import (
    decrypt_pkcs8_private_key_der,
    encrypt_pkcs8_private_key_der,
)


class Encoding(Enum):
    PEM = "PEM"
    DER = "DER"


class PrivateFormat(Enum):
    PKCS8 = "PKCS8"
    Raw = "Raw"


class PublicFormat(Enum):
    SubjectPublicKeyInfo = "SubjectPublicKeyInfo"
    UncompressedPoint = "UncompressedPoint"
    Raw = "Raw"


class NoEncryption:
    pass


class BestAvailableEncryption:
    def __init__(self, password: bytes):
        self.password = password


# SM2 OID: 1.2.156.10197.1.301
SM2_OID = (1, 2, 156, 10197, 1, 301)
SM2_CURVE_OID = (1, 2, 156, 10197, 1, 301)
# id-ecPublicKey — used with SM2 named curve OID in GmSSL / eet PKCS#8 (see RFC 5480)
EC_PUBLIC_KEY_OID = (1, 2, 840, 10045, 2, 1)


def _pem_encode(der_data: bytes, label: str) -> bytes:
    b64 = base64.b64encode(der_data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    pem = f"-----BEGIN {label}-----\n"
    pem += '\n'.join(lines) + '\n'
    pem += f"-----END {label}-----\n"
    return pem.encode('ascii')


def _pem_decode(pem_data: bytes) -> tuple[bytes, str]:
    """Decode PEM to DER bytes and label."""
    text = pem_data.decode('ascii')
    lines = text.strip().split('\n')
    begin_line = lines[0]
    end_line = lines[-1]
    label = begin_line.replace('-----BEGIN ', '').replace('-----', '').strip()
    b64_data = ''.join(lines[1:-1])
    return (base64.b64decode(b64_data), label)


def encode_sm2_private_key_pkcs8_encrypted(
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    password: bytes,
    *,
    iterations: int = 65536,
    salt: bytes | None = None,
    iv: bytes | None = None,
) -> bytes:
    """Encode SM2 private key as PKCS#8 EncryptedPrivateKeyInfo DER (eet-compatible).

    Uses PBES2 with PBKDF2-HMAC-SM3 and SM4-CBC (PKCS#7 padding). Default
    *iterations* is 65536 to match ``eet sm2 generate`` / GmSSL.

    The decrypted inner structure uses ``id-ecPublicKey`` + SM2 curve OID so that
    ``eet sm2 sign`` / GmSSL can load the PEM (see :func:`encode_sm2_private_key_pkcs8_gmssl`).
    """
    plain = encode_sm2_private_key_pkcs8_gmssl(private_key_bytes, public_key_bytes)
    return encrypt_pkcs8_private_key_der(
        plain, password, iterations=iterations, salt=salt, iv=iv
    )


def encode_sm2_private_key_pkcs8_gmssl(private_key_bytes: bytes, public_key_bytes: bytes) -> bytes:
    """PKCS#8 PrivateKeyInfo DER matching GmSSL / eet ``sm2 generate`` (inner algorithm).

    ``AlgorithmIdentifier`` is ``id-ecPublicKey`` with SM2 named curve parameters;
    the private key field is a SEC1 ``ECPrivateKey`` (same as :func:`encode_sm2_private_key_pkcs8`).
    """
    alg_id = encode_sequence(
        [encode_oid(EC_PUBLIC_KEY_OID), encode_oid(SM2_CURVE_OID)]
    )
    # Match GmSSL/eet SEC1 ECPrivateKey: optional [0] namedCurve inside the key SEQUENCE.
    ec_privkey = encode_sequence([
        encode_integer(1),
        encode_octet_string(private_key_bytes),
        encode_context(0, encode_oid(SM2_CURVE_OID)),
        encode_context(1, encode_bit_string(public_key_bytes)),
    ])
    return encode_sequence([
        encode_integer(0),
        alg_id,
        encode_octet_string(ec_privkey),
    ])


def encode_sm2_private_key_pkcs8(private_key_bytes: bytes, public_key_bytes: bytes) -> bytes:
    """Encode SM2 private key in PKCS#8 DER format."""
    # AlgorithmIdentifier
    alg_id = encode_sequence([encode_oid(SM2_OID), encode_oid(SM2_CURVE_OID)])
    # ECPrivateKey (RFC 5915)
    ec_privkey = encode_sequence([
        encode_integer(1),  # version
        encode_octet_string(private_key_bytes),
        encode_context(1, encode_bit_string(public_key_bytes)),
    ])
    # PKCS8 PrivateKeyInfo
    return encode_sequence([
        encode_integer(0),  # version
        alg_id,
        encode_octet_string(ec_privkey),
    ])


def encode_sm2_public_key_spki(public_key_bytes: bytes) -> bytes:
    """Encode SM2 public key in SubjectPublicKeyInfo DER format."""
    alg_id = encode_sequence([encode_oid(SM2_OID), encode_oid(SM2_CURVE_OID)])
    return encode_sequence([alg_id, encode_bit_string(public_key_bytes)])


def encode_sm2_signature_der(signature: bytes) -> bytes:
    """Encode raw SM2 signature (64 bytes: r||s) as ASN.1 DER SEQUENCE of two INTEGERs.

    Matches GmSSL sm2_signature_to_der / X.509 BIT STRING contents (typical length ~71).
    """
    if len(signature) != 64:
        raise ValueError(f"SM2 signature must be 64 bytes, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    return encode_sequence([encode_integer(r), encode_integer(s)])


def decode_sm2_signature_der(der: bytes) -> bytes:
    """Decode ASN.1 DER SEQUENCE of two INTEGERs (r, s) to 64 bytes r||s.

    Matches eet ``-m RS_ASN1`` / GmSSL DER signatures.
    """
    tag, seq, _ = decode_tlv(der, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError("Expected SEQUENCE for SM2 signature DER")
    p = 0
    r, p = decode_integer(seq, p)
    s, p = decode_integer(seq, p)
    rb = int(r).to_bytes(32, "big")
    sb = int(s).to_bytes(32, "big")
    if len(rb) > 32 or len(sb) > 32:
        rb = rb.rjust(32, b"\x00")[-32:]
        sb = sb.rjust(32, b"\x00")[-32:]
    return rb + sb


def load_pem_private_key(data: bytes, password: bytes | None = None):
    """Load a PEM-encoded private key.

    Supports plaintext ``PRIVATE KEY`` (PKCS#8) and ``ENCRYPTED PRIVATE KEY``
    (PBES2 / PBKDF2-HMAC-SM3 / SM4-CBC, compatible with eet). For encrypted
    PEM, *password* must be ``bytes``; for plaintext PEM, *password* must be
    ``None``.
    """
    der, label = _pem_decode(data)
    if label == "ENCRYPTED PRIVATE KEY" or (
        "ENCRYPTED" in label and "PRIVATE" in label
    ):
        if password is None:
            raise TypeError(
                "Encrypted private key requires password as bytes, not None"
            )
        plain = decrypt_pkcs8_private_key_der(der, password)
        return _load_sm2_private_key_pkcs8(plain)
    if password is not None:
        raise TypeError(
            "Password was given but private key is not encrypted; "
            "use password=None for plaintext PEM"
        )
    if 'SM2' in label or 'PRIVATE' in label:
        return _load_sm2_private_key_pkcs8(der)
    raise ValueError(f"Unknown PEM label: {label}")


def load_pem_public_key(data: bytes):
    """Load a PEM-encoded public key."""
    der, label = _pem_decode(data)
    if 'PUBLIC' in label:
        return _load_sm2_public_key_spki(der)
    raise ValueError(f"Unknown PEM label: {label}")


def _load_sm2_private_key_pkcs8(der: bytes):
    from gmssl.hazmat.primitives.asymmetric.sm2 import SM2PrivateKey
    from gmssl._backends._sm2_field import SM2_G, scalar_multiply

    tag, seq_data, _ = decode_tlv(der, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError(f"Expected SEQUENCE tag in PrivateKeyInfo, got 0x{tag:02x}")
    offset = 0
    tag, ver_data, offset = decode_tlv(seq_data, offset)  # version
    tag, alg_data, offset = decode_tlv(seq_data, offset)  # algorithmIdentifier
    tag, pk_data, offset = decode_tlv(seq_data, offset)  # privateKey (OCTET STRING)

    tag, ec_seq, _ = decode_tlv(pk_data, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError(f"Expected SEQUENCE tag in ECPrivateKey, got 0x{tag:02x}")
    ec_offset = 0
    tag, _, ec_offset = decode_tlv(ec_seq, ec_offset)  # version
    tag, d_bytes, ec_offset = decode_tlv(ec_seq, ec_offset)  # privateKey OCTET STRING value

    d = int.from_bytes(d_bytes, 'big')
    P = scalar_multiply(d, SM2_G)
    pub_x, pub_y = P.to_affine()
    return SM2PrivateKey(int(d), int(pub_x), int(pub_y))


def _load_sm2_public_key_spki(der: bytes):
    from gmssl.hazmat.primitives.asymmetric.sm2 import SM2PublicKey
    from gmssl._backends._sm2_field import is_on_curve

    tag, seq_data, _ = decode_tlv(der, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError(f"Expected SEQUENCE tag, got 0x{tag:02x}")
    offset = 0
    tag, _, offset = decode_tlv(seq_data, offset)  # algorithmIdentifier
    tag, pk_data, offset = decode_tlv(seq_data, offset)  # subjectPublicKey (BIT STRING)
    pub_bytes = pk_data[1:]
    if pub_bytes[0] != 0x04:
        raise ValueError("Only uncompressed points are supported")
    x = int.from_bytes(pub_bytes[1:33], 'big')
    y = int.from_bytes(pub_bytes[33:65], 'big')
    if not is_on_curve(x, y):
        raise ValueError("Loaded public key point is not on SM2 curve")
    return SM2PublicKey(x, y)
