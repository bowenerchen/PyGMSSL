"""
PKCS#7 padding for block ciphers.

Usage::

    from gmssl.hazmat.primitives.padding import PKCS7

    padder = PKCS7(128).padder()       # 128-bit block
    padded = padder.update(data) + padder.finalize()

    unpadder = PKCS7(128).unpadder()
    original = unpadder.update(padded) + unpadder.finalize()
"""

from __future__ import annotations
from gmssl.exceptions import AlreadyFinalized, InvalidParameter


class _PKCS7Padder:
    def __init__(self, block_size_bytes: int) -> None:
        self._block_size = block_size_bytes
        self._buf = bytearray()
        self._finalized = False

    def update(self, data: bytes) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Padder was already finalized.")
        self._buf.extend(data)
        n = (len(self._buf) // self._block_size) * self._block_size
        result = bytes(self._buf[:n])
        del self._buf[:n]
        return result

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Padder was already finalized.")
        self._finalized = True
        pad_len = self._block_size - (len(self._buf) % self._block_size)
        self._buf.extend(bytes([pad_len] * pad_len))
        result = bytes(self._buf)
        self._buf.clear()
        return result


class _PKCS7Unpadder:
    def __init__(self, block_size_bytes: int) -> None:
        self._block_size = block_size_bytes
        self._buf = bytearray()
        self._finalized = False

    def update(self, data: bytes) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Unpadder was already finalized.")
        self._buf.extend(data)
        n = max((len(self._buf) // self._block_size) * self._block_size - self._block_size, 0)
        result = bytes(self._buf[:n])
        del self._buf[:n]
        return result

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Unpadder was already finalized.")
        self._finalized = True
        if len(self._buf) == 0 or len(self._buf) % self._block_size != 0:
            raise InvalidParameter("Invalid PKCS7 padding")
        pad_byte = self._buf[-1]
        valid = int(1 <= pad_byte <= self._block_size)
        for i in range(self._block_size):
            if i < pad_byte:
                valid &= int(self._buf[-(i + 1)] == pad_byte)
        if not valid:
            raise InvalidParameter("Invalid PKCS7 padding")
        result = bytes(self._buf[:-pad_byte])
        self._buf.clear()
        return result


class PKCS7:
    """PKCS#7 padding scheme.  *block_size* is in **bits** (e.g. 128 for SM4)."""

    def __init__(self, block_size: int) -> None:
        if block_size % 8 != 0 or block_size < 8 or block_size > 2048:
            raise ValueError("block_size must be a multiple of 8 between 8 and 2048")
        self._block_size_bytes = block_size // 8

    def padder(self) -> _PKCS7Padder:
        return _PKCS7Padder(self._block_size_bytes)

    def unpadder(self) -> _PKCS7Unpadder:
        return _PKCS7Unpadder(self._block_size_bytes)
