"""
SM3 cryptographic hash – pure Python implementation.

Reference: GM/T 0004-2012, GmSSL src/sm3.c
"""

import struct

_MASK32 = 0xFFFFFFFF

_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)

_T = (0x79CC4519,) * 16 + (0x7A879D8A,) * 48

def _rotl32(x: int, n: int) -> int:
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & _MASK32

_K = tuple(_rotl32(_T[j], j % 32) for j in range(64))

def _ff(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)

def _gg(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return ((y ^ z) & x) ^ z

def _p0(x: int) -> int:
    return x ^ _rotl32(x, 9) ^ _rotl32(x, 17)

def _p1(x: int) -> int:
    return x ^ _rotl32(x, 15) ^ _rotl32(x, 23)


def _compress(digest: list[int], block: bytes) -> None:
    W = list(struct.unpack('>16I', block))

    for j in range(16, 68):
        W.append(
            _p1(W[j-16] ^ W[j-9] ^ _rotl32(W[j-3], 15))
            ^ _rotl32(W[j-13], 7)
            ^ W[j-6]
        )

    A, B, C, D, E, F, G, H = digest

    for j in range(64):
        SS1 = _rotl32((_rotl32(A, 12) + E + _K[j]) & _MASK32, 7)
        SS2 = SS1 ^ _rotl32(A, 12)
        TT1 = (_ff(j, A, B, C) + D + SS2 + (W[j] ^ W[j+4])) & _MASK32
        TT2 = (_gg(j, E, F, G) + H + SS1 + W[j]) & _MASK32
        D = C
        C = _rotl32(B, 9)
        B = A
        A = TT1
        H = G
        G = _rotl32(F, 19)
        F = E
        E = _p0(TT2)

    digest[0] ^= A
    digest[1] ^= B
    digest[2] ^= C
    digest[3] ^= D
    digest[4] ^= E
    digest[5] ^= F
    digest[6] ^= G
    digest[7] ^= H


DIGEST_SIZE = 32
BLOCK_SIZE = 64


class SM3State:
    """Low-level SM3 hash state."""

    __slots__ = ('_digest', '_nblocks', '_buf', '_num')

    def __init__(self) -> None:
        self._digest: list[int] = list(_IV)
        self._nblocks: int = 0
        self._buf: bytearray = bytearray()
        self._num: int = 0

    def copy(self) -> 'SM3State':
        other = SM3State.__new__(SM3State)
        other._digest = self._digest[:]
        other._nblocks = self._nblocks
        other._buf = bytearray(self._buf)
        other._num = self._num
        return other

    def update(self, data: bytes | bytearray | memoryview) -> None:
        data = memoryview(data)
        offset = 0

        if self._buf:
            need = BLOCK_SIZE - len(self._buf)
            if len(data) < need:
                self._buf.extend(data)
                return
            self._buf.extend(data[:need])
            _compress(self._digest, bytes(self._buf))
            self._nblocks += 1
            self._buf.clear()
            offset = need

        while offset + BLOCK_SIZE <= len(data):
            _compress(self._digest, bytes(data[offset:offset + BLOCK_SIZE]))
            self._nblocks += 1
            offset += BLOCK_SIZE

        if offset < len(data):
            self._buf.extend(data[offset:])

    def finalize(self) -> bytes:
        num = len(self._buf)
        block = bytearray(self._buf)
        block.append(0x80)

        if num <= BLOCK_SIZE - 9:
            block.extend(b'\x00' * (BLOCK_SIZE - num - 9))
        else:
            block.extend(b'\x00' * (BLOCK_SIZE - num - 1))
            _compress(self._digest, bytes(block))
            block = bytearray(BLOCK_SIZE - 8)

        total_bits_hi = self._nblocks >> 23
        total_bits_lo = (self._nblocks << 9) + (num << 3)
        block.extend(struct.pack('>II', total_bits_hi & _MASK32, total_bits_lo & _MASK32))

        _compress(self._digest, bytes(block))
        return struct.pack('>8I', *self._digest)


def sm3_hash(data: bytes) -> bytes:
    """One-shot SM3 digest."""
    s = SM3State()
    s.update(data)
    return s.finalize()
