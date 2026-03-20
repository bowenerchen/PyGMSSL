"""
SM3-KDF – Key Derivation Function based on SM3 (GM/T 0003-2012).

This is the KDF specified in the SM2 standard, using SM3 as the hash function.
KDF(Z, klen) = H(Z || ct_1) || H(Z || ct_2) || ...
where ct_i is a 32-bit big-endian counter starting from 1.
"""

from __future__ import annotations
import struct
from gmssl.hazmat.primitives.hashes import Hash, SM3


def sm3_kdf(z: bytes, klen: int) -> bytes:
    """
    SM3-based KDF as defined in GM/T 0003-2012.

    Args:
        z: shared info / seed material
        klen: desired output length in bytes

    Returns:
        Derived key of *klen* bytes.
    """
    ct = 1
    ha = b""
    while len(ha) < klen:
        h = Hash(SM3())
        h.update(z)
        h.update(struct.pack('>I', ct))
        ha += h.finalize()
        ct += 1
    return ha[:klen]
