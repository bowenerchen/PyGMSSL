"""Symmetric cipher algorithm descriptors."""

from __future__ import annotations


class CipherAlgorithm:
    """Base for cipher algorithm descriptors."""
    name: str
    key_size: int      # in bytes
    block_size: int    # in bytes

    def __init__(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(f"{self.name} requires a {self.key_size}-byte key, got {len(key)}")
        self._key = key

    @property
    def key(self) -> bytes:
        return self._key


class SM4(CipherAlgorithm):
    name = "SM4"
    key_size = 16
    block_size = 16


class AES(CipherAlgorithm):
    name = "AES"
    block_size = 16

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16, 24, or 32 bytes, got {len(key)}")
        self.key_size = len(key)
        self._key = key
