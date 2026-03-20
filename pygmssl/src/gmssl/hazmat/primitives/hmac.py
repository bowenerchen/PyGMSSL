"""
HMAC – Hash-based Message Authentication Code.

Usage::

    from gmssl.hazmat.primitives import hashes, hmac

    h = hmac.HMAC(key, hashes.SM3())
    h.update(b"message")
    signature = h.finalize()

    h2 = hmac.HMAC(key, hashes.SM3())
    h2.update(b"message")
    h2.verify(signature)  # raises InvalidSignature if mismatch
"""

from __future__ import annotations
from gmssl.exceptions import AlreadyFinalized, InvalidSignature
from gmssl.hazmat.primitives.hashes import Hash, HashAlgorithm
from gmssl._backends._utils import constant_time_compare, xor_bytes


class HMAC:
    """HMAC context following the ``update → finalize / verify`` pattern."""

    def __init__(self, key: bytes, algorithm: HashAlgorithm) -> None:
        self._algorithm = algorithm
        self._finalized = False
        block_size = algorithm.block_size

        if len(key) > block_size:
            h = Hash(algorithm)
            h.update(key)
            key = h.finalize()

        key = key.ljust(block_size, b'\x00')
        self._o_key = xor_bytes(key, bytes([0x5C] * block_size))
        i_key = xor_bytes(key, bytes([0x36] * block_size))

        self._inner = Hash(algorithm)
        self._inner.update(i_key)

    @property
    def algorithm(self) -> HashAlgorithm:
        return self._algorithm

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._inner.update(data)

    def copy(self) -> HMAC:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        other = HMAC.__new__(HMAC)
        other._algorithm = self._algorithm
        other._finalized = False
        other._o_key = self._o_key
        other._inner = self._inner.copy()
        return other

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._finalized = True
        inner_digest = self._inner.finalize()
        outer = Hash(self._algorithm)
        outer.update(self._o_key)
        outer.update(inner_digest)
        return outer.finalize()

    def verify(self, signature: bytes) -> None:
        computed = self.finalize()
        if not constant_time_compare(computed, signature):
            raise InvalidSignature("Signature did not match digest.")
