"""
SM2 asymmetric cryptography – high-level API.

Usage::

    from gmssl.hazmat.primitives.asymmetric import sm2

    private_key = sm2.generate_private_key()
    public_key = private_key.public_key()

    sig = private_key.sign(b"data")
    public_key.verify(sig, b"data")

    ct = public_key.encrypt(b"secret")
    pt = private_key.decrypt(ct)

Optional eet-compatible wire layout (``ciphertext_format``)::

    ct = public_key.encrypt(b"secret", ciphertext_format="C1C3C2")
    pt = private_key.decrypt(ct, ciphertext_format="C1C3C2")

Signature output/input (``signature_format``), aligned with eet ``sm2 sign|verify -m``::

    der = private_key.sign(b"data", signature_format="RS_ASN1")
    public_key.verify(der, b"data", signature_format="RS_ASN1")
"""

from __future__ import annotations
from gmssl.exceptions import InvalidSignature
from gmssl._backends._sm2_signature import (
    encode_sm2_signature_wire,
    normalize_sm2_signature_to_rs,
    validate_sm2_signature_format,
)
from gmssl._backends._sm2_algo import (
    sm2_sign, sm2_verify, sm2_encrypt, sm2_decrypt,
    sm2_generate_keypair, sm2_ecdh, compute_z,
    SM2_DEFAULT_ID, SM2_MAX_PLAINTEXT_SIZE,
)

DefaultID = SM2_DEFAULT_ID


def generate_private_key() -> SM2PrivateKey:
    d, pub_x, pub_y = sm2_generate_keypair()
    return SM2PrivateKey(d, pub_x, pub_y)


class SM2PublicKey:
    def __init__(self, x: int, y: int) -> None:
        self._x = x
        self._y = y

    @property
    def x(self) -> int:
        return self._x

    @property
    def y(self) -> int:
        return self._y

    def verify(
        self,
        signature: bytes,
        data: bytes,
        uid: bytes = DefaultID,
        signature_format: str | None = None,
    ) -> None:
        """Verify signature.

        ``signature_format`` defaults to ``None`` (64-byte ``r||s``, same as eet ``-m RS``).
        Use ``\"RS_ASN1\"`` for DER ``SEQUENCE { r, s }`` (eet default sign output).
        """
        validate_sm2_signature_format(signature_format)
        try:
            rs = normalize_sm2_signature_to_rs(signature, signature_format)
        except ValueError as e:
            raise InvalidSignature(str(e)) from e
        r = int.from_bytes(rs[:32], 'big')
        s = int.from_bytes(rs[32:], 'big')
        if not sm2_verify(self._x, self._y, data, r, s, uid):
            raise InvalidSignature("SM2 signature verification failed")

    def encrypt(self, plaintext: bytes, ciphertext_format: str | None = None) -> bytes:
        """Encrypt plaintext.

        ``ciphertext_format`` defaults to ``None``: C1(65-byte uncompressed) || C3 || C2.
        Use ``\"C1C3C2\"``, ``\"C1C2C3\"``, ``\"C1C3C2_ASN1\"``, or ``\"C1C2C3_ASN1\"``
        for layouts compatible with eet ``sm2 encrypt -m``.
        """
        return sm2_encrypt(self._x, self._y, plaintext, ciphertext_format=ciphertext_format)

    def public_bytes_uncompressed(self) -> bytes:
        return b'\x04' + self._x.to_bytes(32, 'big') + self._y.to_bytes(32, 'big')


class SM2PrivateKey:
    def __init__(self, d: int, pub_x: int, pub_y: int) -> None:
        self._d = d
        self._pub_x = pub_x
        self._pub_y = pub_y

    def public_key(self) -> SM2PublicKey:
        return SM2PublicKey(self._pub_x, self._pub_y)

    @property
    def private_key_int(self) -> int:
        return self._d

    def sign(
        self, data: bytes, uid: bytes = DefaultID, signature_format: str | None = None
    ) -> bytes:
        validate_sm2_signature_format(signature_format)
        r, s = sm2_sign(self._d, self._pub_x, self._pub_y, data, uid)
        rs = int(r).to_bytes(32, 'big') + int(s).to_bytes(32, 'big')
        return encode_sm2_signature_wire(rs, signature_format)

    def decrypt(self, ciphertext: bytes, ciphertext_format: str | None = None) -> bytes:
        return sm2_decrypt(self._d, ciphertext, ciphertext_format=ciphertext_format)

    def exchange(self, peer_public_key: SM2PublicKey) -> bytes:
        x, y = sm2_ecdh(self._d, peer_public_key.x, peer_public_key.y)
        return int(x).to_bytes(32, 'big') + int(y).to_bytes(32, 'big')

    def private_bytes(self) -> bytes:
        return self._d.to_bytes(32, 'big')
