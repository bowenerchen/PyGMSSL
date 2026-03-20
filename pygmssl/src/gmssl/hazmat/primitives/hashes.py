"""
Hash algorithm primitives – cryptography-style API.

Usage::

    from gmssl.hazmat.primitives import hashes

    digest = hashes.Hash(hashes.SM3())
    digest.update(b"hello")
    result = digest.finalize()
"""

from __future__ import annotations

import hashlib
from typing import Union

from gmssl.exceptions import AlreadyFinalized
from gmssl._backends._sm3 import SM3State

_Bytes = Union[bytes, bytearray, memoryview]


class HashAlgorithm:
    """Base class for hash algorithm descriptors."""
    name: str
    digest_size: int
    block_size: int


class SM3(HashAlgorithm):
    name = "sm3"
    digest_size = 32
    block_size = 64


class SHA256(HashAlgorithm):
    name = "sha256"
    digest_size = 32
    block_size = 64


class SHA384(HashAlgorithm):
    name = "sha384"
    digest_size = 48
    block_size = 128


class SHA512(HashAlgorithm):
    name = "sha512"
    digest_size = 64
    block_size = 128


class SHA224(HashAlgorithm):
    name = "sha224"
    digest_size = 28
    block_size = 64


class Hash:
    """
    Streaming hash context following the ``update → finalize`` pattern.

    Supports :meth:`copy` for forking intermediate states.
    """

    def __init__(self, algorithm: HashAlgorithm) -> None:
        self._algorithm = algorithm
        self._finalized = False

        if isinstance(algorithm, SM3):
            self._state: SM3State | None = SM3State()
            self._hashlib = None
        else:
            self._state = None
            self._hashlib = hashlib.new(algorithm.name)

    @property
    def algorithm(self) -> HashAlgorithm:
        return self._algorithm

    def update(self, data: _Bytes) -> None:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        if self._state is not None:
            self._state.update(data)
        else:
            assert self._hashlib is not None
            self._hashlib.update(data)

    def copy(self) -> Hash:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        h = Hash.__new__(Hash)
        h._algorithm = self._algorithm
        h._finalized = False
        if self._state is not None:
            h._state = self._state.copy()
            h._hashlib = None
        else:
            assert self._hashlib is not None
            h._state = None
            h._hashlib = self._hashlib.copy()
        return h

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._finalized = True
        if self._state is not None:
            return self._state.finalize()
        else:
            assert self._hashlib is not None
            return self._hashlib.digest()
