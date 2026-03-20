"""
PBKDF2-HMAC key derivation.

Usage::

    from gmssl.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from gmssl.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(b"password")
"""

from __future__ import annotations
import struct
from gmssl.hazmat.primitives.hashes import HashAlgorithm
from gmssl.hazmat.primitives.hmac import HMAC
from gmssl.exceptions import InvalidKey
from gmssl._backends._utils import constant_time_compare, xor_bytes


class PBKDF2HMAC:
    def __init__(self, *, algorithm: HashAlgorithm, length: int,
                 salt: bytes, iterations: int) -> None:
        self._algorithm = algorithm
        self._length = length
        self._salt = salt
        self._iterations = iterations
        self._used = False

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise RuntimeError("PBKDF2HMAC instances can only be used once.")
        self._used = True
        return self._pbkdf2(key_material)

    def verify(self, key_material: bytes, expected_key: bytes) -> None:
        derived = self.derive(key_material)
        if not constant_time_compare(derived, expected_key):
            raise InvalidKey("Derived key does not match expected key.")

    def _pbkdf2(self, password: bytes) -> bytes:
        hlen = self._algorithm.digest_size
        blocks_needed = (self._length + hlen - 1) // hlen
        dk = b""
        for i in range(1, blocks_needed + 1):
            dk += self._f(password, i)
        return dk[:self._length]

    def _f(self, password: bytes, block_index: int) -> bytes:
        h = HMAC(password, self._algorithm)
        h.update(self._salt + struct.pack('>I', block_index))
        u = h.finalize()
        result = u
        for _ in range(self._iterations - 1):
            h2 = HMAC(password, self._algorithm)
            h2.update(u)
            u = h2.finalize()
            result = xor_bytes(result, u)
        return result
