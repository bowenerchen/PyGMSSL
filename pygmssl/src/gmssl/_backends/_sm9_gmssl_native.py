"""
Optional SM9 backend: call GmSSL libgmssl for pairing and Fp12 arithmetic.

SM9 Miller loop + final exponentiation in pure Python is error-prone; this
module matches GmSSL-3.x bit-for-bit when a shared library is available.

Search order for the library:
  1. Environment variable ``PYGMSSL_GMSSL_LIBRARY`` (full path)
  2. Sibling path ``<repo>/GmSSL-3.1.1/build/bin/libgmssl.{dylib,so}`` relative
     to this package (development layout)
  3. ``ctypes.util.find_library("gmssl")``
"""

from __future__ import annotations

import ctypes
from ctypes.util import find_library
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from gmssl._backends._sm9_field import G1Point, G2Point


class SM9BN(ctypes.Structure):
    _fields_ = [("v", ctypes.c_uint64 * 8)]


class SM9FP2(ctypes.Structure):
    _fields_ = [("c0", SM9BN), ("c1", SM9BN)]


class SM9FP4(ctypes.Structure):
    _fields_ = [("a0", SM9FP2), ("a1", SM9FP2)]


class SM9FP12(ctypes.Structure):
    _fields_ = [("c0", SM9FP4), ("c1", SM9FP4), ("c2", SM9FP4)]


class SM9Point(ctypes.Structure):
    _fields_ = [("X", SM9BN), ("Y", SM9BN), ("Z", SM9BN)]


class SM9TwistPoint(ctypes.Structure):
    _fields_ = [("X", SM9FP2), ("Y", SM9FP2), ("Z", SM9FP2)]


class SM3_CTX(ctypes.Structure):
    _fields_ = [
        ("digest", ctypes.c_uint32 * 8),
        ("nblocks", ctypes.c_uint64),
        ("block", ctypes.c_uint8 * 64),
        ("num", ctypes.c_size_t),
    ]


class SM9_ENC_MASTER_KEY(ctypes.Structure):
    _fields_ = [("Ppube", SM9Point), ("ke", SM9BN)]


class SM9_ENC_KEY(ctypes.Structure):
    _fields_ = [("Ppube", SM9Point), ("de", SM9TwistPoint)]


class SM9_SIGN_MASTER_KEY(ctypes.Structure):
    _fields_ = [("Ppubs", SM9TwistPoint), ("ks", SM9BN)]


class SM9_SIGN_KEY(ctypes.Structure):
    _fields_ = [("Ppubs", SM9TwistPoint), ("ds", SM9Point)]


class SM9_SIGNATURE(ctypes.Structure):
    _fields_ = [("h", SM9BN), ("S", SM9Point)]


class SM9_SIGN_CTX(ctypes.Structure):
    _fields_ = [("sm3_ctx", SM3_CTX)]


# sm9_do_encrypt uses sizeof(K) with K[SM9_MAX_PLAINTEXT_SIZE + SM3_HMAC_SIZE]
SM9_KEM_KLEN = 255 + 32


def _int_to_sm9_bn(x: int) -> SM9BN:
    """Pack a field element or 256-bit integer (big-endian) into GmSSL sm9_bn_t."""
    b = int(x).to_bytes(32, "big")
    limbs = (ctypes.c_uint64 * 8)()
    for i in range(8):
        off = (7 - i) * 4
        limbs[i] = int.from_bytes(b[off : off + 4], "big")
    return SM9BN(limbs)


def _int_to_fn_bn(x: int) -> SM9BN:
    """Scalar in [0, N) as sm9_bn_t."""
    from gmssl._backends._sm9_field import SM9_N

    v = int(x) % int(SM9_N)
    b = v.to_bytes(32, "big")
    limbs = (ctypes.c_uint64 * 8)()
    for i in range(8):
        off = (7 - i) * 4
        limbs[i] = int.from_bytes(b[off : off + 4], "big")
    return SM9BN(limbs)


def _lib_candidates() -> list[Path]:
    out: list[Path] = []
    env = os.environ.get("PYGMSSL_GMSSL_LIBRARY")
    if env:
        out.append(Path(env))
    here = Path(__file__).resolve()
    # .../GMSSL/pygmssl/src/gmssl/_backends/this.py -> parents[4] == GMSSL repo root
    repo_gmssl = here.parents[4] / "GmSSL-3.1.1" / "build" / "bin"
    if sys.platform == "darwin":
        out.append(repo_gmssl / "libgmssl.dylib")
    else:
        out.append(repo_gmssl / "libgmssl.so")
    return out


_lib: Optional[ctypes.CDLL] = None


def _load_lib() -> Optional[ctypes.CDLL]:
    global _lib
    if _lib is not None:
        return _lib
    for p in _lib_candidates():
        if p.is_file():
            try:
                _lib = ctypes.CDLL(str(p))
                break
            except OSError:
                continue
    if _lib is None:
        try:
            name = find_library("gmssl")
            if name:
                _lib = ctypes.CDLL(name)
        except OSError:
            _lib = None
    if _lib is None:
        return None

    L = _lib
    L.sm9_pairing.argtypes = [
        ctypes.POINTER(SM9FP12),
        ctypes.POINTER(SM9TwistPoint),
        ctypes.POINTER(SM9Point),
    ]
    L.sm9_pairing.restype = None

    L.sm9_fp12_pow.argtypes = [
        ctypes.POINTER(SM9FP12),
        ctypes.POINTER(SM9FP12),
        ctypes.POINTER(SM9BN),
    ]
    L.sm9_fp12_pow.restype = None

    L.sm9_fp12_mul.argtypes = [
        ctypes.POINTER(SM9FP12),
        ctypes.POINTER(SM9FP12),
        ctypes.POINTER(SM9FP12),
    ]
    L.sm9_fp12_mul.restype = None

    L.sm9_fp12_to_bytes.argtypes = [ctypes.POINTER(SM9FP12), ctypes.c_void_p]
    L.sm9_fp12_to_bytes.restype = None

    L.sm9_twist_point_mul_generator.argtypes = [
        ctypes.POINTER(SM9TwistPoint),
        ctypes.POINTER(SM9BN),
    ]
    L.sm9_twist_point_mul_generator.restype = None

    L.sm9_twist_point_mul.argtypes = [
        ctypes.POINTER(SM9TwistPoint),
        ctypes.POINTER(SM9BN),
        ctypes.POINTER(SM9TwistPoint),
    ]
    L.sm9_twist_point_mul.restype = None

    L.sm9_twist_point_add_full.argtypes = [
        ctypes.POINTER(SM9TwistPoint),
        ctypes.POINTER(SM9TwistPoint),
        ctypes.POINTER(SM9TwistPoint),
    ]
    L.sm9_twist_point_add_full.restype = None

    L.sm9_twist_point_to_uncompressed_octets.argtypes = [
        ctypes.POINTER(SM9TwistPoint),
        ctypes.c_void_p,
    ]
    L.sm9_twist_point_to_uncompressed_octets.restype = ctypes.c_int

    L.sm3_init.argtypes = [ctypes.POINTER(SM3_CTX)]
    L.sm3_init.restype = None

    L.sm3_update.argtypes = [
        ctypes.POINTER(SM3_CTX),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    L.sm3_update.restype = None

    L.sm9_point_set_infinity.argtypes = [ctypes.POINTER(SM9Point)]
    L.sm9_point_set_infinity.restype = None

    L.sm9_point_mul_generator.argtypes = [
        ctypes.POINTER(SM9Point),
        ctypes.POINTER(SM9BN),
    ]
    L.sm9_point_mul_generator.restype = None

    L.sm9_point_to_uncompressed_octets.argtypes = [
        ctypes.POINTER(SM9Point),
        ctypes.c_void_p,
    ]
    L.sm9_point_to_uncompressed_octets.restype = ctypes.c_int

    L.sm9_point_from_uncompressed_octets.argtypes = [
        ctypes.POINTER(SM9Point),
        ctypes.c_void_p,
    ]
    L.sm9_point_from_uncompressed_octets.restype = ctypes.c_int

    L.sm9_kem_encrypt.argtypes = [
        ctypes.POINTER(SM9_ENC_MASTER_KEY),
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(SM9Point),
    ]
    L.sm9_kem_encrypt.restype = ctypes.c_int

    L.sm9_kem_decrypt.argtypes = [
        ctypes.POINTER(SM9_ENC_KEY),
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(SM9Point),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
    ]
    L.sm9_kem_decrypt.restype = ctypes.c_int

    L.sm9_do_sign.argtypes = [
        ctypes.POINTER(SM9_SIGN_KEY),
        ctypes.POINTER(SM3_CTX),
        ctypes.POINTER(SM9_SIGNATURE),
    ]
    L.sm9_do_sign.restype = ctypes.c_int

    L.sm9_do_verify.argtypes = [
        ctypes.POINTER(SM9_SIGN_MASTER_KEY),
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(SM3_CTX),
        ctypes.POINTER(SM9_SIGNATURE),
    ]
    L.sm9_do_verify.restype = ctypes.c_int

    L.sm9_sign_init.argtypes = [ctypes.POINTER(SM9_SIGN_CTX)]
    L.sm9_sign_init.restype = ctypes.c_int

    L.sm9_sign_update.argtypes = [
        ctypes.POINTER(SM9_SIGN_CTX),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    L.sm9_sign_update.restype = ctypes.c_int

    L.sm9_verify_init.argtypes = [ctypes.POINTER(SM9_SIGN_CTX)]
    L.sm9_verify_init.restype = ctypes.c_int

    L.sm9_verify_update.argtypes = [
        ctypes.POINTER(SM9_SIGN_CTX),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    L.sm9_verify_update.restype = ctypes.c_int

    return _lib


def gmssl_lib_available() -> bool:
    return _load_lib() is not None


def _g1_to_c(P) -> SM9Point:
    if P.inf:
        return SM9Point(_int_to_sm9_bn(1), _int_to_sm9_bn(1), _int_to_sm9_bn(0))
    return SM9Point(
        _int_to_sm9_bn(P.x),
        _int_to_sm9_bn(P.y),
        _int_to_sm9_bn(1),
    )


def _g2_to_c(Q) -> SM9TwistPoint:
    """Map Python Fp2 (c0,c1) to GmSSL sm9_fp2_t[2] (a[0],a[1]).

    GmSSL sm9_fp2_to_bytes writes [a[1]|a[0]]; hazmat Fp2 stores c0=a[1], c1=a[0]
    for the SM9_G2 constants. ctypes fields c0,c1 are C a[0],a[1] respectively.
    """
    if Q.inf:
        one = SM9FP2(_int_to_sm9_bn(1), _int_to_sm9_bn(0))
        zzero = SM9FP2(_int_to_sm9_bn(0), _int_to_sm9_bn(0))
        return SM9TwistPoint(one, one, zzero)
    # C a[0] = Python c1, C a[1] = Python c0
    return SM9TwistPoint(
        SM9FP2(_int_to_sm9_bn(Q.x.c1), _int_to_sm9_bn(Q.x.c0)),
        SM9FP2(_int_to_sm9_bn(Q.y.c1), _int_to_sm9_bn(Q.y.c0)),
        SM9FP2(_int_to_sm9_bn(1), _int_to_sm9_bn(0)),
    )


class NativeFp12:
    """Fp12 element backed by GmSSL (pairing target group)."""

    __slots__ = ("_data",)

    def __init__(self, data: SM9FP12) -> None:
        self._data = SM9FP12()
        ctypes.memmove(
            ctypes.byref(self._data),
            ctypes.byref(data),
            ctypes.sizeof(SM9FP12),
        )

    def pow(self, exp: int) -> NativeFp12:
        lib = _load_lib()
        assert lib is not None
        out = SM9FP12()
        k = _int_to_fn_bn(int(exp))
        lib.sm9_fp12_pow(ctypes.byref(out), ctypes.byref(self._data), ctypes.byref(k))
        return NativeFp12(out)

    def __mul__(self, other: NativeFp12) -> NativeFp12:
        lib = _load_lib()
        assert lib is not None
        out = SM9FP12()
        lib.sm9_fp12_mul(
            ctypes.byref(out),
            ctypes.byref(self._data),
            ctypes.byref(other._data),
        )
        return NativeFp12(out)

    def to_bytes(self) -> bytes:
        lib = _load_lib()
        assert lib is not None
        buf = (ctypes.c_uint8 * 384)()
        lib.sm9_fp12_to_bytes(ctypes.byref(self._data), buf)
        return bytes(buf)


def native_pairing(P, Q) -> NativeFp12:
    """GmSSL sm9_pairing(r, Q, P) with P in G1, Q in G2."""
    lib = _load_lib()
    if lib is None:
        raise RuntimeError(
            "GmSSL shared library not found. Set PYGMSSL_GMSSL_LIBRARY to the path "
            "of libgmssl (e.g. GmSSL-3.1.1/build/bin/libgmssl.dylib) or install gmssl "
            "so find_library('gmssl') succeeds."
        )
    out = SM9FP12()
    cq = _g2_to_c(Q)
    cp = _g1_to_c(P)
    lib.sm9_pairing(ctypes.byref(out), ctypes.byref(cq), ctypes.byref(cp))
    return NativeFp12(out)


def _twist_c_to_g2(R: SM9TwistPoint):
    from gmssl._backends._sm9_field import Fp2, G2Point

    lib = _load_lib()
    assert lib is not None
    buf = (ctypes.c_uint8 * 129)()
    lib.sm9_twist_point_to_uncompressed_octets(ctypes.byref(R), buf)
    oct = bytes(buf)
    if oct[0] != 0x04:
        return G2Point.infinity()
    x0 = int.from_bytes(oct[1:33], "big")
    x1 = int.from_bytes(oct[33:65], "big")
    y0 = int.from_bytes(oct[65:97], "big")
    y1 = int.from_bytes(oct[97:129], "big")
    return G2Point(Fp2(x0, x1), Fp2(y0, y1))


def native_g2_mul_generator(k: int):
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL library required for SM9 G2")
    R = SM9TwistPoint()
    lib.sm9_twist_point_mul_generator(ctypes.byref(R), ctypes.byref(_int_to_fn_bn(k)))
    return _twist_c_to_g2(R)


def native_g1_mul_generator(k: int):
    """k * P1 on GmSSL's G1; matches GM/T test vectors (Python g1_mul may differ)."""
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL library required for SM9 G1")
    R = SM9Point()
    lib.sm9_point_mul_generator(ctypes.byref(R), ctypes.byref(_int_to_fn_bn(k)))
    return _g1_from_sm9_point(R)


def native_g2_mul(k: int, P):
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL library required for SM9 G2")
    R = SM9TwistPoint()
    Pc = _g2_to_c(P)
    lib.sm9_twist_point_mul(
        ctypes.byref(R), ctypes.byref(_int_to_fn_bn(k)), ctypes.byref(Pc)
    )
    return _twist_c_to_g2(R)


def native_g2_add(P, Q):
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL library required for SM9 G2")
    R = SM9TwistPoint()
    lib.sm9_twist_point_add_full(
        ctypes.byref(R), ctypes.byref(_g2_to_c(P)), ctypes.byref(_g2_to_c(Q))
    )
    return _twist_c_to_g2(R)


def _id_void_keepalive(uid: bytes):
    """Binary-safe user id pointer for GmSSL (const char * + length)."""
    if not uid:
        return ctypes.c_void_p(0), 0, None
    arr = (ctypes.c_ubyte * len(uid))(*uid)
    return ctypes.cast(arr, ctypes.c_void_p), len(uid), arr


def _sm9_bn_to_int(bn: SM9BN) -> int:
    b = bytearray(32)
    for i in range(8):
        off = (7 - i) * 4
        b[off : off + 4] = int(bn.v[i]).to_bytes(4, "big")
    return int.from_bytes(b, "big")


def _g1_from_sm9_point(P: SM9Point):
    from gmpy2 import mpz

    from gmssl._backends._sm9_field import G1Point

    lib = _load_lib()
    assert lib is not None
    buf = (ctypes.c_uint8 * 65)()
    if lib.sm9_point_to_uncompressed_octets(ctypes.byref(P), buf) != 1:
        raise RuntimeError("sm9_point_to_uncompressed_octets failed")
    oct = bytes(buf)
    if oct[0] != 0x04:
        return G1Point.infinity()
    x = mpz(int.from_bytes(oct[1:33], "big"))
    y = mpz(int.from_bytes(oct[33:65], "big"))
    return G1Point(x, y)


def native_sm9_kem_encrypt(Ppube, uid: bytes) -> tuple[bytes, bytes]:
    """GmSSL sm9_kem_encrypt: returns (K, C1) with len(K)==SM9_KEM_KLEN and len(C1)==65."""
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL shared library required for SM9 KEM")
    mpk = SM9_ENC_MASTER_KEY()
    mpk.Ppube = _g1_to_c(Ppube)
    mpk.ke = SM9BN((ctypes.c_uint64 * 8)())
    C = SM9Point()
    K = (ctypes.c_uint8 * SM9_KEM_KLEN)()
    idp, idl, _keep = _id_void_keepalive(uid)
    rv = lib.sm9_kem_encrypt(
        ctypes.byref(mpk),
        idp,
        idl,
        SM9_KEM_KLEN,
        ctypes.cast(K, ctypes.POINTER(ctypes.c_uint8)),
        ctypes.byref(C),
    )
    if rv != 1:
        raise RuntimeError("sm9_kem_encrypt failed")
    c1buf = (ctypes.c_uint8 * 65)()
    if lib.sm9_point_to_uncompressed_octets(ctypes.byref(C), c1buf) != 1:
        raise RuntimeError("C1 serialization failed")
    return bytes(K), bytes(c1buf)


def native_sm9_kem_decrypt(de, uid: bytes, c1_uncompressed: bytes, klen: int) -> bytes:
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL shared library required for SM9 KEM")
    if len(c1_uncompressed) != 65 or c1_uncompressed[0] != 0x04:
        raise ValueError("C1 must be 65-byte uncompressed G1 octets")
    key = SM9_ENC_KEY()
    lib.sm9_point_set_infinity(ctypes.byref(key.Ppube))
    key.de = _g2_to_c(de)
    C = SM9Point()
    c1_arr = (ctypes.c_ubyte * 65)(*c1_uncompressed)
    if (
        lib.sm9_point_from_uncompressed_octets(
            ctypes.byref(C), ctypes.cast(c1_arr, ctypes.c_void_p)
        )
        != 1
    ):
        raise ValueError("invalid C1 point octets")
    K = (ctypes.c_uint8 * klen)()
    idp, idl, _keep = _id_void_keepalive(uid)
    rv = lib.sm9_kem_decrypt(
        ctypes.byref(key),
        idp,
        idl,
        ctypes.byref(C),
        klen,
        ctypes.cast(K, ctypes.POINTER(ctypes.c_uint8)),
    )
    if rv != 1:
        raise ValueError("sm9_kem_decrypt failed")
    return bytes(K)


def native_sm9_do_sign(ds, Ppubs, message: bytes):
    """GmSSL sm9_do_sign with SM3 state from sm9_sign_init/update (H2 prefix + message)."""
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL shared library required for SM9 sign")
    sk = SM9_SIGN_KEY()
    sk.ds = _g1_to_c(ds)
    sk.Ppubs = _g2_to_c(Ppubs)
    sctx = SM9_SIGN_CTX()
    if lib.sm9_sign_init(ctypes.byref(sctx)) != 1:
        raise RuntimeError("sm9_sign_init failed")
    if message:
        mbuf = (ctypes.c_ubyte * len(message))(*message)
        if (
            lib.sm9_sign_update(
                ctypes.byref(sctx),
                ctypes.cast(mbuf, ctypes.c_void_p),
                len(message),
            )
            != 1
        ):
            raise RuntimeError("sm9_sign_update failed")
    sig = SM9_SIGNATURE()
    if lib.sm9_do_sign(ctypes.byref(sk), ctypes.byref(sctx.sm3_ctx), ctypes.byref(sig)) != 1:
        raise RuntimeError("sm9_do_sign failed")
    h = _sm9_bn_to_int(sig.h)
    S = _g1_from_sm9_point(sig.S)
    return h, S


def native_sm9_do_verify(Ppubs, uid: bytes, message: bytes, h: int, S) -> bool:
    lib = _load_lib()
    if lib is None:
        raise RuntimeError("GmSSL shared library required for SM9 verify")
    mpk = SM9_SIGN_MASTER_KEY()
    mpk.Ppubs = _g2_to_c(Ppubs)
    mpk.ks = SM9BN((ctypes.c_uint64 * 8)())
    sig = SM9_SIGNATURE()
    sig.h = _int_to_fn_bn(h)
    sig.S = _g1_to_c(S)
    vctx = SM9_SIGN_CTX()
    if lib.sm9_verify_init(ctypes.byref(vctx)) != 1:
        raise RuntimeError("sm9_verify_init failed")
    if message:
        mbuf = (ctypes.c_ubyte * len(message))(*message)
        if (
            lib.sm9_verify_update(
                ctypes.byref(vctx),
                ctypes.cast(mbuf, ctypes.c_void_p),
                len(message),
            )
            != 1
        ):
            raise RuntimeError("sm9_verify_update failed")
    idp, idl, _keep = _id_void_keepalive(uid)
    ret = lib.sm9_do_verify(
        ctypes.byref(mpk),
        idp,
        idl,
        ctypes.byref(vctx.sm3_ctx),
        ctypes.byref(sig),
    )
    return ret == 1
