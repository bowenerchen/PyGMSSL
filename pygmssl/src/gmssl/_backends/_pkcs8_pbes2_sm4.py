"""PKCS#8 EncryptedPrivateKeyInfo: PBES2 + PBKDF2-HMAC-SM3 + SM4-CBC (eet / GmSSL compatible)."""

from __future__ import annotations

import os

from gmssl.exceptions import InvalidParameter
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.hazmat.primitives.hashes import SM3
from gmssl.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gmssl._backends._asn1 import (
    TAG_SEQUENCE,
    TAG_OCTET_STRING,
    decode_tlv,
    decode_oid,
    encode_sequence,
    encode_oid,
    encode_octet_string,
    encode_integer,
)

# id-PBES2
PBES2_OID = (1, 2, 840, 113549, 1, 5, 13)
# id-PBKDF2
PBKDF2_OID = (1, 2, 840, 113549, 1, 5, 12)
# GM PRF for PBKDF2 (HMAC-SM3)
PBKDF2_PRF_HMAC_SM3_OID = (1, 2, 156, 10197, 1, 401, 2)
# SM4-CBC (GmSSL / eet)
SM4_CBC_OID = (1, 2, 156, 10197, 1, 104, 2)

SM4_KEY_BYTES = 16
SM4_BLOCK_BYTES = 16

_DEFAULT_PBKDF2_ITERATIONS = 65536


def _algorithm_identifier(oid: tuple[int, ...], parameters: bytes) -> bytes:
    return encode_sequence([encode_oid(oid), parameters])


def _encode_pbkdf2_hmac_sm3_params(
    salt: bytes, iterations: int, key_length: int
) -> bytes:
    prf_alg = encode_sequence([encode_oid(PBKDF2_PRF_HMAC_SM3_OID)])
    return encode_sequence(
        [
            encode_octet_string(salt),
            encode_integer(iterations),
            encode_integer(key_length),
            prf_alg,
        ]
    )


def _encode_pbes2_encryption_algorithm(
    salt: bytes, iterations: int, key_length: int, iv: bytes
) -> bytes:
    kdf = _algorithm_identifier(
        PBKDF2_OID, _encode_pbkdf2_hmac_sm3_params(salt, iterations, key_length)
    )
    enc = _algorithm_identifier(SM4_CBC_OID, encode_octet_string(iv))
    pbes2_params = encode_sequence([kdf, enc])
    return _algorithm_identifier(PBES2_OID, pbes2_params)


def encrypt_pkcs8_private_key_der(
    plaintext_pkcs8_der: bytes,
    password: bytes,
    *,
    iterations: int = _DEFAULT_PBKDF2_ITERATIONS,
    salt: bytes | None = None,
    iv: bytes | None = None,
) -> bytes:
    """Build EncryptedPrivateKeyInfo DER (PBES2 / PBKDF2-HMAC-SM3 / SM4-CBC)."""
    if iterations < 1:
        raise ValueError("iterations must be positive")
    if salt is not None and len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")
    if iv is not None and len(iv) != SM4_BLOCK_BYTES:
        raise ValueError("iv must be 16 bytes")
    s = salt if salt is not None else os.urandom(16)
    v = iv if iv is not None else os.urandom(SM4_BLOCK_BYTES)

    kdf = PBKDF2HMAC(
        algorithm=SM3(),
        length=SM4_KEY_BYTES,
        salt=s,
        iterations=iterations,
    )
    key = kdf.derive(password)

    # PKCS#7 padding is applied inside Cipher CBC encryptor.finalize() (do not pre-pad).
    cipher = Cipher(algorithms.SM4(key), modes.CBC(v))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_pkcs8_der) + encryptor.finalize()

    enc_alg = _encode_pbes2_encryption_algorithm(s, iterations, SM4_KEY_BYTES, v)
    return encode_sequence([enc_alg, encode_octet_string(ciphertext)])


def _int_from_der_integer_content(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=bool(value and (value[0] & 0x80)))


def _parse_pbkdf2_params(data: bytes) -> tuple[bytes, int, int, tuple[int, ...]]:
    """Return salt, iterations, key_length, prf_oid."""
    offset = 0
    tag, salt, offset = decode_tlv(data, offset)
    if tag != TAG_OCTET_STRING:
        raise ValueError("PBKDF2 salt must be OCTET STRING")
    tag, iter_bytes, offset = decode_tlv(data, offset)
    if tag != 0x02:
        raise ValueError("PBKDF2 iterationCount must be INTEGER")
    iterations = _int_from_der_integer_content(iter_bytes)
    key_length = SM4_KEY_BYTES
    prf_oid: tuple[int, ...] | None = None
    while offset < len(data):
        tag, chunk, offset = decode_tlv(data, offset)
        if tag == 0x02:
            key_length = _int_from_der_integer_content(chunk)
        elif tag == TAG_SEQUENCE:
            prf_oid, _ = decode_oid(chunk, 0)
        else:
            raise ValueError("Unexpected element in PBKDF2-params")
    if prf_oid is None:
        raise ValueError("PBKDF2 PRF must be present (HMAC-SM3 required)")
    return salt, iterations, key_length, prf_oid


def _parse_encryption_scheme(data: bytes) -> tuple[tuple[int, ...], bytes]:
    offset = 0
    enc_oid, offset = decode_oid(data, offset)
    tag, iv, offset = decode_tlv(data, offset)
    if tag != TAG_OCTET_STRING:
        raise ValueError("SM4-CBC parameters must be OCTET STRING (IV)")
    if offset != len(data):
        raise ValueError("Trailing data in encryptionScheme")
    return enc_oid, iv


def decrypt_pkcs8_private_key_der(encrypted_der: bytes, password: bytes) -> bytes:
    """Decrypt EncryptedPrivateKeyInfo DER to plaintext PKCS#8 PrivateKeyInfo DER."""
    tag, seq, _ = decode_tlv(encrypted_der, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError("Expected SEQUENCE for EncryptedPrivateKeyInfo")
    offset = 0
    tag, enc_alg, offset = decode_tlv(seq, offset)
    if tag != TAG_SEQUENCE:
        raise ValueError("Expected encryptionAlgorithm SEQUENCE")
    tag, enc_data, offset = decode_tlv(seq, offset)
    if tag != TAG_OCTET_STRING:
        raise ValueError("encryptedData must be OCTET STRING")
    if offset != len(seq):
        raise ValueError("Trailing data in EncryptedPrivateKeyInfo")

    alg_oid, off = decode_oid(enc_alg, 0)
    if alg_oid != PBES2_OID:
        raise ValueError(
            f"Unsupported PKCS#8 encryption (expected PBES2), got OID {alg_oid}"
        )
    tag, pbes2_params, off = decode_tlv(enc_alg, off)
    if tag != TAG_SEQUENCE or off != len(enc_alg):
        raise ValueError("Invalid PBES2 AlgorithmIdentifier")

    p = 0
    tag, kdf_alg, p = decode_tlv(pbes2_params, p)
    tag, enc_scheme, p = decode_tlv(pbes2_params, p)
    if p != len(pbes2_params):
        raise ValueError("Invalid PBES2-params")

    kdf_oid, q = decode_oid(kdf_alg, 0)
    if kdf_oid != PBKDF2_OID:
        raise ValueError(f"Unsupported key derivation (expected PBKDF2), got {kdf_oid}")
    tag, kdf_params, q = decode_tlv(kdf_alg, q)
    if tag != TAG_SEQUENCE or q != len(kdf_alg):
        raise ValueError("Invalid PBKDF2 AlgorithmIdentifier")

    salt, iterations, key_length, prf_oid = _parse_pbkdf2_params(kdf_params)
    if prf_oid != PBKDF2_PRF_HMAC_SM3_OID:
        raise ValueError(
            f"Unsupported PBKDF2 PRF (expected HMAC-SM3), got OID {prf_oid}"
        )
    if key_length != SM4_KEY_BYTES:
        raise ValueError(f"SM4 key length must be {SM4_KEY_BYTES}, got {key_length}")

    enc_oid, iv = _parse_encryption_scheme(enc_scheme)
    if enc_oid != SM4_CBC_OID:
        raise ValueError(
            f"Unsupported PKCS#8 cipher (expected SM4-CBC), got OID {enc_oid}"
        )
    if len(iv) != SM4_BLOCK_BYTES:
        raise ValueError("SM4-CBC IV must be 16 bytes")

    kdf = PBKDF2HMAC(
        algorithm=SM3(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password)

    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(enc_data) + decryptor.finalize()
    except (InvalidParameter, ValueError) as e:
        raise ValueError("Incorrect password or corrupted encrypted private key") from e
    return plaintext
