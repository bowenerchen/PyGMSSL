"""
ZUC stream cipher - pure Python implementation.
Supports both ZUC-128 and ZUC-256 based on GmSSL src/zuc.c.
"""

import struct
from typing import List


# ZUC-128 constants
KD = (
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC,
)

# S0 S-box from GmSSL zuc.c
S0 = (
    0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
    0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
    0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
    0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
    0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
    0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
    0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
    0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
    0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
    0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
    0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
    0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
    0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
    0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
    0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
    0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60,
)

# S1 S-box from GmSSL zuc.c
S1 = (
    0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
    0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
    0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
    0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
    0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
    0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
    0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
    0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
    0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
    0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
    0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
    0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
    0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2,
)

# ZUC-256 D constants
ZUC256_D = (
    (0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
     0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30),
    (0x22, 0x2F, 0x25, 0x2A, 0x6D, 0x40, 0x40, 0x40,
     0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30),
    (0x23, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
     0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30),
    (0x23, 0x2F, 0x25, 0x2A, 0x6D, 0x40, 0x40, 0x40,
     0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30),
)


def _add31(a: int, b: int) -> int:
    """31-bit modular addition: (a + b) mod (2^31 - 1)."""
    result = (a + b) & 0xFFFFFFFF
    return ((result & 0x7FFFFFFF) + (result >> 31)) & 0x7FFFFFFF


def _rot31(a: int, k: int) -> int:
    """31-bit rotate left by k bits."""
    a = a & 0x7FFFFFFF
    return (((a << k) | (a >> (31 - k))) & 0x7FFFFFFF)


def _rot32(a: int, k: int) -> int:
    """32-bit rotate left by k bits."""
    a = a & 0xFFFFFFFF
    return ((a << k) | (a >> (32 - k))) & 0xFFFFFFFF


def _l1(x: int) -> int:
    """L1 linear transform."""
    x = x & 0xFFFFFFFF
    return (x ^ _rot32(x, 2) ^ _rot32(x, 10) ^ _rot32(x, 18) ^ _rot32(x, 24)) & 0xFFFFFFFF


def _l2(x: int) -> int:
    """L2 linear transform."""
    x = x & 0xFFFFFFFF
    return (x ^ _rot32(x, 8) ^ _rot32(x, 14) ^ _rot32(x, 22) ^ _rot32(x, 30)) & 0xFFFFFFFF


def _makeu32(a: int, b: int, c: int, d: int) -> int:
    """Build 32-bit word from 4 bytes."""
    return (((a & 0xFF) << 24) | ((b & 0xFF) << 16) |
            ((c & 0xFF) << 8) | (d & 0xFF)) & 0xFFFFFFFF


def _f(x0: int, x1: int, x2: int, r1: int, r2: int) -> tuple[int, int, int]:
    """
    F function. Returns (output, new_r1, new_r2).
    output = (X0 ^ R1) + R2  (using old R1, R2)
    """
    x0 = x0 & 0xFFFFFFFF
    x1 = x1 & 0xFFFFFFFF
    x2 = x2 & 0xFFFFFFFF
    r1 = r1 & 0xFFFFFFFF
    r2 = r2 & 0xFFFFFFFF

    output = ((x0 ^ r1) + r2) & 0xFFFFFFFF

    w1 = (r1 + x1) & 0xFFFFFFFF
    w2 = (r2 ^ x2) & 0xFFFFFFFF

    u = _l1(((w1 << 16) | (w2 >> 16)) & 0xFFFFFFFF)
    v = _l2(((w2 << 16) | (w1 >> 16)) & 0xFFFFFFFF)

    new_r1 = _makeu32(
        S0[u >> 24],
        S1[(u >> 16) & 0xFF],
        S0[(u >> 8) & 0xFF],
        S1[u & 0xFF],
    )
    new_r2 = _makeu32(
        S0[v >> 24],
        S1[(v >> 16) & 0xFF],
        S0[(v >> 8) & 0xFF],
        S1[v & 0xFF],
    )
    return output, new_r1, new_r2


def _f_update_only(x1: int, x2: int, r1: int, r2: int) -> tuple[int, int]:
    """F_ update R1,R2 only, no output. Returns (new_r1, new_r2)."""
    _, new_r1, new_r2 = _f(0, x1, x2, r1, r2)
    return new_r1, new_r2


class ZUCState:
    """ZUC-128 state machine. key=16 bytes, iv=16 bytes."""

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(key) != 16:
            raise ValueError("ZUC-128 requires 16-byte key")
        if len(iv) != 16:
            raise ValueError("ZUC-128 requires 16-byte IV")

        # LFSR loading: LFSR[i] = (key[i] << 23) | (KD[i] << 8) | iv[i]
        self.lfsr = [0] * 16
        for i in range(16):
            self.lfsr[i] = (
                ((key[i] & 0xFF) << 23) |
                ((KD[i] & 0xFFFF) << 8) |
                (iv[i] & 0xFF)
            ) & 0x7FFFFFFF

        r1 = 0
        r2 = 0

        # 32 rounds of initialization
        for _ in range(32):
            x0 = ((self.lfsr[15] & 0x7FFF8000) << 1) | (self.lfsr[14] & 0xFFFF)
            x0 &= 0xFFFFFFFF
            x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15)
            x1 &= 0xFFFFFFFF
            x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15)
            x2 &= 0xFFFFFFFF

            w, r1, r2 = _f(x0, x1, x2, r1, r2)
            u = w >> 1

            # LFSRWithInitialisationMode(u)
            v = self.lfsr[0]
            v = _add31(v, _rot31(self.lfsr[0], 8))
            v = _add31(v, _rot31(self.lfsr[4], 20))
            v = _add31(v, _rot31(self.lfsr[10], 21))
            v = _add31(v, _rot31(self.lfsr[13], 17))
            v = _add31(v, _rot31(self.lfsr[15], 15))
            v = _add31(v, u)

            for j in range(15):
                self.lfsr[j] = self.lfsr[j + 1]
            self.lfsr[15] = v

        # BitReconstruction2 and F_ and LFSRWithWorkMode
        x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15)
        x1 &= 0xFFFFFFFF
        x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15)
        x2 &= 0xFFFFFFFF
        r1, r2 = _f_update_only(x1, x2, r1, r2)

        a = self.lfsr[0]
        a += (self.lfsr[0] << 8)
        a += (self.lfsr[4] << 20)
        a += (self.lfsr[10] << 21)
        a += (self.lfsr[13] << 17)
        a += (self.lfsr[15] << 15)
        a = (a & 0x7FFFFFFF) + (a >> 31)
        v = (a & 0x7FFFFFFF) + (a >> 31)
        if v == 0:
            v = 0x7FFFFFFF
        for j in range(15):
            self.lfsr[j] = self.lfsr[j + 1]
        self.lfsr[15] = v & 0x7FFFFFFF

        self.r1 = r1
        self.r2 = r2

    def _lfsr_work_mode(self) -> None:
        """LFSRWithWorkMode - advance LFSR in work mode."""
        a = self.lfsr[0]
        a += (self.lfsr[0] << 8)
        a += (self.lfsr[4] << 20)
        a += (self.lfsr[10] << 21)
        a += (self.lfsr[13] << 17)
        a += (self.lfsr[15] << 15)
        a = (a & 0x7FFFFFFF) + (a >> 31)
        v = (a & 0x7FFFFFFF) + (a >> 31)
        if v == 0:
            v = 0x7FFFFFFF
        for j in range(15):
            self.lfsr[j] = self.lfsr[j + 1]
        self.lfsr[15] = v & 0x7FFFFFFF

    def generate_keyword(self) -> int:
        """Generate one 32-bit keyword."""
        x0 = ((self.lfsr[15] & 0x7FFF8000) << 1) | (self.lfsr[14] & 0xFFFF)
        x0 &= 0xFFFFFFFF
        x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15)
        x1 &= 0xFFFFFFFF
        x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15)
        x2 &= 0xFFFFFFFF
        x3 = ((self.lfsr[2] & 0xFFFF) << 16) | (self.lfsr[0] >> 15)
        x3 &= 0xFFFFFFFF

        f_out, self.r1, self.r2 = _f(x0, x1, x2, self.r1, self.r2)
        z = (x3 ^ f_out) & 0xFFFFFFFF
        self._lfsr_work_mode()
        return z

    def generate_keystream(self, nwords: int) -> List[int]:
        """Generate n 32-bit keywords."""
        result = []
        for _ in range(nwords):
            result.append(self.generate_keyword())
        return result

    def encrypt(self, data: bytes) -> bytes:
        """XOR data with keystream. Encryption is symmetric (decrypt = encrypt)."""
        result = bytearray(len(data))
        for i in range(0, len(data), 4):
            if i + 4 <= len(data):
                z = self.generate_keyword()
                block = struct.pack(">I", z)
                for j in range(4):
                    result[i + j] = data[i + j] ^ block[j]
            else:
                z = self.generate_keyword()
                block = struct.pack(">I", z)
                remainder = len(data) - i
                for j in range(remainder):
                    result[i + j] = data[i + j] ^ block[j]
        return bytes(result)


def _zuc256_makeu31(a: int, b: int, c: int, d: int) -> int:
    """ZUC256_MAKEU31: 31-bit word from 4 bytes."""
    return (((a & 0xFF) << 23) | ((b & 0xFF) << 16) |
            ((c & 0xFF) << 8) | (d & 0xFF)) & 0x7FFFFFFF


class ZUC256State:
    """ZUC-256 state machine. key=32 bytes, iv=23 bytes."""

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(key) != 32:
            raise ValueError("ZUC-256 requires 32-byte key")
        if len(iv) != 23:
            raise ValueError("ZUC-256 requires 23-byte IV")

        k = list(key)
        iv_list = list(iv)

        # macbits=0 for stream cipher -> D = ZUC256_D[0]
        d = ZUC256_D[0]

        # IV 6-bit fields from bytes 17-22
        iv17 = (iv_list[17] >> 2) & 0x3F
        iv18 = (((iv_list[17] & 0x3) << 4) | (iv_list[18] >> 4)) & 0x3F
        iv19 = (((iv_list[18] & 0xF) << 2) | (iv_list[19] >> 6)) & 0x3F
        iv20 = (iv_list[19] & 0x3F)
        iv21 = (iv_list[20] >> 2) & 0x3F
        iv22 = (((iv_list[20] & 0x3) << 4) | (iv_list[21] >> 4)) & 0x3F
        iv23 = (((iv_list[21] & 0xF) << 2) | (iv_list[22] >> 6)) & 0x3F
        iv24 = (iv_list[22] & 0x3F)

        # LFSR loading for ZUC-256
        self.lfsr = [0] * 16
        self.lfsr[0] = _zuc256_makeu31(k[0], d[0], k[21], k[16])
        self.lfsr[1] = _zuc256_makeu31(k[1], d[1], k[22], k[17])
        self.lfsr[2] = _zuc256_makeu31(k[2], d[2], k[23], k[18])
        self.lfsr[3] = _zuc256_makeu31(k[3], d[3], k[24], k[19])
        self.lfsr[4] = _zuc256_makeu31(k[4], d[4], k[25], k[20])
        self.lfsr[5] = _zuc256_makeu31(iv_list[0], (d[5] | iv17) & 0xFF, k[5], k[26])
        self.lfsr[6] = _zuc256_makeu31(iv_list[1], (d[6] | iv18) & 0xFF, k[6], k[27])
        self.lfsr[7] = _zuc256_makeu31(iv_list[10], (d[7] | iv19) & 0xFF, k[7], iv_list[2])
        self.lfsr[8] = _zuc256_makeu31(k[8], (d[8] | iv20) & 0xFF, iv_list[3], iv_list[11])
        self.lfsr[9] = _zuc256_makeu31(k[9], (d[9] | iv21) & 0xFF, iv_list[12], iv_list[4])
        self.lfsr[10] = _zuc256_makeu31(iv_list[5], (d[10] | iv22) & 0xFF, k[10], k[28])
        self.lfsr[11] = _zuc256_makeu31(k[11], (d[11] | iv23) & 0xFF, iv_list[6], iv_list[13])
        self.lfsr[12] = _zuc256_makeu31(k[12], (d[12] | iv24) & 0xFF, iv_list[7], iv_list[14])
        self.lfsr[13] = _zuc256_makeu31(k[13], d[13], iv_list[15], iv_list[8])
        self.lfsr[14] = _zuc256_makeu31(k[14], (d[14] | (k[31] >> 4)) & 0xFF, iv_list[16], iv_list[9])
        self.lfsr[15] = _zuc256_makeu31(k[15], (d[15] | (k[31] & 0x0F)) & 0xFF, k[30], k[29])

        r1 = 0
        r2 = 0

        # 32 rounds of initialization (same as ZUC-128)
        for _ in range(32):
            x0 = ((self.lfsr[15] & 0x7FFF8000) << 1) | (self.lfsr[14] & 0xFFFF)
            x0 &= 0xFFFFFFFF
            x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15)
            x1 &= 0xFFFFFFFF
            x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15)
            x2 &= 0xFFFFFFFF

            w, r1, r2 = _f(x0, x1, x2, r1, r2)
            u = w >> 1

            v = self.lfsr[0]
            v = _add31(v, _rot31(self.lfsr[0], 8))
            v = _add31(v, _rot31(self.lfsr[4], 20))
            v = _add31(v, _rot31(self.lfsr[10], 21))
            v = _add31(v, _rot31(self.lfsr[13], 17))
            v = _add31(v, _rot31(self.lfsr[15], 15))
            v = _add31(v, u)

            for j in range(15):
                self.lfsr[j] = self.lfsr[j + 1]
            self.lfsr[15] = v

        x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15)
        x1 &= 0xFFFFFFFF
        x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15)
        x2 &= 0xFFFFFFFF
        r1, r2 = _f_update_only(x1, x2, r1, r2)

        a = self.lfsr[0]
        a += (self.lfsr[0] << 8)
        a += (self.lfsr[4] << 20)
        a += (self.lfsr[10] << 21)
        a += (self.lfsr[13] << 17)
        a += (self.lfsr[15] << 15)
        a = (a & 0x7FFFFFFF) + (a >> 31)
        v = (a & 0x7FFFFFFF) + (a >> 31)
        if v == 0:
            v = 0x7FFFFFFF
        for j in range(15):
            self.lfsr[j] = self.lfsr[j + 1]
        self.lfsr[15] = v & 0x7FFFFFFF

        self.r1 = r1
        self.r2 = r2

    def _lfsr_work_mode(self) -> None:
        """LFSRWithWorkMode."""
        a = self.lfsr[0]
        a += (self.lfsr[0] << 8)
        a += (self.lfsr[4] << 20)
        a += (self.lfsr[10] << 21)
        a += (self.lfsr[13] << 17)
        a += (self.lfsr[15] << 15)
        a = (a & 0x7FFFFFFF) + (a >> 31)
        v = (a & 0x7FFFFFFF) + (a >> 31)
        if v == 0:
            v = 0x7FFFFFFF
        for j in range(15):
            self.lfsr[j] = self.lfsr[j + 1]
        self.lfsr[15] = v & 0x7FFFFFFF

    def generate_keyword(self) -> int:
        """Generate one 32-bit keyword."""
        x0 = ((self.lfsr[15] & 0x7FFF8000) << 1) | (self.lfsr[14] & 0xFFFF)
        x0 &= 0xFFFFFFFF
        x1 = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15)
        x1 &= 0xFFFFFFFF
        x2 = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15)
        x2 &= 0xFFFFFFFF
        x3 = ((self.lfsr[2] & 0xFFFF) << 16) | (self.lfsr[0] >> 15)
        x3 &= 0xFFFFFFFF

        f_out, self.r1, self.r2 = _f(x0, x1, x2, self.r1, self.r2)
        z = (x3 ^ f_out) & 0xFFFFFFFF
        self._lfsr_work_mode()
        return z

    def generate_keystream(self, nwords: int) -> List[int]:
        """Generate n 32-bit keywords."""
        result = []
        for _ in range(nwords):
            result.append(self.generate_keyword())
        return result

    def encrypt(self, data: bytes) -> bytes:
        """XOR data with keystream."""
        result = bytearray(len(data))
        for i in range(0, len(data), 4):
            if i + 4 <= len(data):
                z = self.generate_keyword()
                block = struct.pack(">I", z)
                for j in range(4):
                    result[i + j] = data[i + j] ^ block[j]
            else:
                z = self.generate_keyword()
                block = struct.pack(">I", z)
                remainder = len(data) - i
                for j in range(remainder):
                    result[i + j] = data[i + j] ^ block[j]
        return bytes(result)


# Test vectors when run as main
if __name__ == "__main__":
    # ZUC-128 test vectors from GmSSL zuctest.c
    zuc128_tests = [
        (bytes(16), bytes(16), [0x27BEDE74, 0x018082DA]),
        (bytes([0xFF] * 16), bytes([0xFF] * 16), [0x0657CFA0, 0x7096398B]),
        (
            bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b"),
            bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766"),
            [0x14F1C272, 0x3279C419],
        ),
    ]
    print("ZUC-128 keystream tests:")
    for i, (key, iv, expected) in enumerate(zuc128_tests):
        state = ZUCState(key, iv)
        actual = state.generate_keystream(2)
        ok = actual == expected
        print(f"  Test {i + 1}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            print(f"    Expected: {[hex(x) for x in expected]}")
            print(f"    Got:      {[hex(x) for x in actual]}")

    # ZUC-256 test vectors from GmSSL zuctest.c
    zuc256_expected_0 = [
        0x58D03AD6, 0x2E032CE2, 0xDAFC683A, 0x39BDCB03, 0x52A2BC67,
        0xF1B7DE74, 0x163CE3A1, 0x01EF5558, 0x9639D75B, 0x95FA681B,
        0x7F090DF7, 0x56391CCC, 0x903B7612, 0x744D544C, 0x17BC3FAD,
        0x8B163B08, 0x21787C0B, 0x97775BB8, 0x4943C6BB, 0xE8AD8AFD,
    ]
    zuc256_expected_1 = [
        0x3356CBAE, 0xD1A1C18B, 0x6BAA4FFE, 0x343F777C, 0x9E15128F,
        0x251AB65B, 0x949F7B26, 0xEF7157F2, 0x96DD2FA9, 0xDF95E3EE,
        0x7A5BE02E, 0xC32BA585, 0x505AF316, 0xC2F9DED2, 0x7CDBD935,
        0xE441CE11, 0x15FD0A80, 0xBB7AEF67, 0x68989416, 0xB8FAC8C2,
    ]
    zuc256_tests = [
        (bytes(32), bytes(23), zuc256_expected_0),
        (bytes([0xFF] * 32), bytes([0xFF] * 23), zuc256_expected_1),
    ]
    print("\nZUC-256 keystream tests:")
    for i, (key, iv, expected) in enumerate(zuc256_tests):
        state = ZUC256State(key, iv)
        actual = state.generate_keystream(20)
        ok = actual == expected
        print(f"  Test {i + 1}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            for j in range(20):
                if actual[j] != expected[j]:
                    print(f"    First diff at word {j}: expected {hex(expected[j])}, got {hex(actual[j])}")
                    break

    print("\nAll tests completed.")
