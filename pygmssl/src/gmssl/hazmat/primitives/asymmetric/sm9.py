"""
SM9 identity-based cryptography – high-level API.

Usage::

    from gmssl.hazmat.primitives.asymmetric import sm9

    master = sm9.generate_sign_master_key()
    user_key = master.extract_key("alice@example.com")
    sig = user_key.sign(b"data")
    master.public_key().verify(sig, b"data", "alice@example.com")
"""

from __future__ import annotations

from gmssl.exceptions import InvalidSignature
from gmssl._backends._sm9_algo import (
    sm9_sign_master_key_generate, sm9_sign_user_key_extract,
    sm9_sign, sm9_verify,
    sm9_enc_master_key_generate, sm9_enc_user_key_extract,
    sm9_encrypt, sm9_decrypt,
)
from gmssl._backends._sm9_field import G1Point, G2Point


def gmssl_backend_available() -> bool:
    """Return True if libgmssl is loaded (required for SM9 sign/encrypt/KEM)."""
    from gmssl._backends._sm9_gmssl_native import gmssl_lib_available

    return gmssl_lib_available()


def generate_sign_master_key() -> SM9SignMasterKey:
    ks, Ppubs = sm9_sign_master_key_generate()
    return SM9SignMasterKey(ks, Ppubs)


def generate_enc_master_key() -> SM9EncMasterKey:
    ke, Ppube = sm9_enc_master_key_generate()
    return SM9EncMasterKey(ke, Ppube)


class SM9SignMasterPublicKey:
    def __init__(self, Ppubs: G2Point) -> None:
        self._Ppubs = Ppubs

    def verify(self, signature: bytes, data: bytes, user_id: str) -> None:
        if len(signature) != 96:
            raise InvalidSignature("Invalid signature length")
        h = int.from_bytes(signature[:32], 'big')
        sx = int.from_bytes(signature[32:64], 'big')
        sy = int.from_bytes(signature[64:96], 'big')
        S = G1Point(sx, sy)
        if not sm9_verify(self._Ppubs, user_id, data, h, S):
            raise InvalidSignature("SM9 signature verification failed")


class SM9SignMasterKey:
    def __init__(self, ks: int, Ppubs: G2Point) -> None:
        self._ks = ks
        self._Ppubs = Ppubs

    def public_key(self) -> SM9SignMasterPublicKey:
        return SM9SignMasterPublicKey(self._Ppubs)

    def extract_key(self, user_id: str) -> SM9SignKey:
        dA = sm9_sign_user_key_extract(self._ks, user_id)
        return SM9SignKey(dA, self._Ppubs)


class SM9SignKey:
    def __init__(self, dA: G1Point, Ppubs: G2Point) -> None:
        self._dA = dA
        self._Ppubs = Ppubs

    def sign(self, data: bytes) -> bytes:
        h, S = sm9_sign(self._dA, self._Ppubs, data)
        return (h.to_bytes(32, 'big') +
                int(S.x).to_bytes(32, 'big') +
                int(S.y).to_bytes(32, 'big'))


class SM9EncMasterPublicKey:
    def __init__(self, Ppube: G1Point) -> None:
        self._Ppube = Ppube

    def encrypt(self, plaintext: bytes, user_id: str) -> bytes:
        return sm9_encrypt(self._Ppube, user_id, plaintext)


class SM9EncMasterKey:
    def __init__(self, ke: int, Ppube: G1Point) -> None:
        self._ke = ke
        self._Ppube = Ppube

    def public_key(self) -> SM9EncMasterPublicKey:
        return SM9EncMasterPublicKey(self._Ppube)

    def extract_key(self, user_id: str) -> SM9EncKey:
        de = sm9_enc_user_key_extract(self._ke, user_id)
        return SM9EncKey(de)


class SM9EncKey:
    def __init__(self, de: G2Point) -> None:
        self._de = de

    def decrypt(self, ciphertext: bytes, user_id: str) -> bytes:
        return sm9_decrypt(self._de, user_id, ciphertext)
