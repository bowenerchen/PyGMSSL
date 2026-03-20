"""
HKDF – HMAC-based Key Derivation Function (RFC 5869).

Usage::

    from gmssl.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    from gmssl.hazmat.primitives import hashes

    hkdf = HKDF(algorithm=hashes.SM3(), length=32, salt=salt, info=info)
    key = hkdf.derive(input_key_material)
"""

from __future__ import annotations
import math
from gmssl.hazmat.primitives.hashes import HashAlgorithm
from gmssl.hazmat.primitives.hmac import HMAC
from gmssl.exceptions import InvalidKey
from gmssl._backends._utils import constant_time_compare


class HKDFExpand:
    """HKDF-Expand only (when you already have a PRK)."""

    def __init__(self, *, algorithm: HashAlgorithm, length: int, info: bytes) -> None:
        self._algorithm = algorithm
        self._length = length
        self._info = info
        self._used = False
        max_length = 255 * algorithm.digest_size
        if length > max_length:
            raise ValueError(f"Cannot derive more than {max_length} bytes")

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise RuntimeError("HKDFExpand instances can only be used once.")
        self._used = True
        return self._expand(key_material)

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        derived = self.derive(key_material)
        if not constant_time_compare(derived, expected_key):
            raise InvalidKey("Derived key does not match expected key.")

    def _expand(self, prk: bytes) -> bytes:
        hash_len = self._algorithm.digest_size
        n = math.ceil(self._length / hash_len)
        okm = b""
        t = b""
        for i in range(1, n + 1):
            h = HMAC(prk, self._algorithm)
            h.update(t + self._info + bytes([i]))
            t = h.finalize()
            okm += t
        return okm[:self._length]


class HKDF:
    """Full HKDF (Extract + Expand)."""

    def __init__(self, *, algorithm: HashAlgorithm, length: int,
                 salt: bytes | None, info: bytes) -> None:
        self._algorithm = algorithm
        self._length = length
        self._salt = salt if salt else b'\x00' * algorithm.digest_size
        self._info = info
        self._used = False

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise RuntimeError("HKDF instances can only be used once.")
        self._used = True
        prk = self._extract(key_material)
        return HKDFExpand(
            algorithm=self._algorithm, length=self._length, info=self._info
        ).derive(prk)

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        derived = self.derive(key_material)
        if not constant_time_compare(derived, expected_key):
            raise InvalidKey("Derived key does not match expected key.")

    def _extract(self, ikm: bytes) -> bytes:
        h = HMAC(self._salt, self._algorithm)
        h.update(ikm)
        return h.finalize()
