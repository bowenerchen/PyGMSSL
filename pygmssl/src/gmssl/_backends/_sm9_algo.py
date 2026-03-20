"""
SM9 identity-based cryptography algorithm operations.

Reference: GM/T 0044-2016
"""

import os
import gmpy2
from gmpy2 import mpz

from gmssl._backends._sm9_field import (
    SM9_P, SM9_N, SM9_G1, SM9_G2,
    G1Point, G2Point, Fp2,
    g1_mul, g1_add, g1_neg,
    g2_mul, g2_add,
)
from gmssl._backends._sm9_gmssl_native import (
    SM9_KEM_KLEN,
    gmssl_lib_available,
    native_g1_mul_generator,
    native_g2_mul_generator,
    native_sm9_do_sign,
    native_sm9_do_verify,
    native_sm9_kem_decrypt,
    native_sm9_kem_encrypt,
)
from gmssl._backends._sm3 import SM3State

HID_SIGN = 0x01
HID_ENC = 0x03

_SM9_NEED_GMSSL = (
    "SM9 signing and encryption require GmSSL libgmssl (KEM and H2 follow GmSSL). "
    "Set PYGMSSL_GMSSL_LIBRARY or build GmSSL-3.1.1 so "
    "GmSSL-3.1.1/build/bin/libgmssl.{dylib,so} exists beside this repo."
)


def _sm9_secure_random_mod_n():
    """Generate a cryptographically secure random integer in [1, SM9_N-1].
    Uses rejection sampling to avoid modulo bias (same approach as SM2).
    """
    n_bits = SM9_N.bit_length()
    extra_bits = 64
    total_bits = n_bits + extra_bits
    total_bytes = (total_bits + 7) // 8
    upper_bound = (1 << total_bits) - ((1 << total_bits) % int(SM9_N))

    while True:
        k_bytes = os.urandom(total_bytes)
        k = int.from_bytes(k_bytes, 'big')
        if k < upper_bound:
            k = mpz(k % int(SM9_N))
            if 1 <= k < SM9_N:
                return k


def _sm9_hash(ct_byte, data, n):
    """SM9 hash function H_v: maps to [1, n-1].

    Matches GmSSL: Ha = SM3(ct_byte||data||0x00000001) || SM3(ct_byte||data||0x00000002)
    Then h = (int.from_bytes(Ha[:40]) mod (n-1)) + 1.
    """
    h1 = SM3State()
    h1.update(bytes([ct_byte]))
    h1.update(data)
    h1.update(b'\x00\x00\x00\x01')
    ha1 = h1.finalize()

    h2 = SM3State()
    h2.update(bytes([ct_byte]))
    h2.update(data)
    h2.update(b'\x00\x00\x00\x02')
    ha2 = h2.finalize()

    Ha = ha1 + ha2
    ha_int = mpz(int.from_bytes(Ha[:40], 'big'))
    return (ha_int % (n - 1)) + 1


def sm9_sign_master_key_generate():
    """Generate SM9 signing master key pair.
    Returns (ks: int, Ppubs: G2Point).
    """
    ks = _sm9_secure_random_mod_n()
    Ppubs = g2_mul(int(ks), SM9_G2)
    return (int(ks), Ppubs)


def sm9_sign_user_key_extract(ks, user_id):
    """Extract user signing private key.
    dA = (ks / (H1(IDA||hid, N) + ks)) * G1
    """
    uid_bytes = user_id if isinstance(user_id, bytes) else user_id.encode()
    h1 = _sm9_hash(0x01, uid_bytes + bytes([HID_SIGN]), SM9_N)
    t1 = (h1 + mpz(ks)) % SM9_N
    if t1 == 0:
        raise ValueError("Invalid: t1 is zero, regenerate master key")
    t2 = (mpz(ks) * gmpy2.invert(t1, SM9_N)) % SM9_N
    if gmssl_lib_available():
        dA = native_g1_mul_generator(int(t2))
    else:
        dA = g1_mul(int(t2), SM9_G1)
    return dA


def sm9_sign(user_key_dA, Ppubs, message):
    """SM9 digital signature.
    Returns (h: int, S: G1Point).
    """
    if not gmssl_lib_available():
        raise RuntimeError(_SM9_NEED_GMSSL)
    if not isinstance(message, bytes):
        message = message.encode()
    h, S = native_sm9_do_sign(user_key_dA, Ppubs, message)
    return (int(h), S)


def sm9_verify(Ppubs, user_id, message, h, S):
    """SM9 signature verification.
    Returns True if valid.
    """
    h = mpz(h)
    if not (1 <= h < SM9_N):
        return False
    if not gmssl_lib_available():
        raise RuntimeError(_SM9_NEED_GMSSL)
    uid_bytes = user_id if isinstance(user_id, bytes) else user_id.encode()
    if not isinstance(message, bytes):
        message = message.encode()
    return native_sm9_do_verify(Ppubs, uid_bytes, message, int(h), S)


def sm9_enc_master_key_generate():
    """Generate SM9 encryption master key pair.
    Returns (ke: int, Ppube: G1Point).
    """
    ke = _sm9_secure_random_mod_n()
    if gmssl_lib_available():
        Ppube = native_g1_mul_generator(int(ke))
    else:
        Ppube = g1_mul(int(ke), SM9_G1)
    return (int(ke), Ppube)


def sm9_enc_user_key_extract(ke, user_id):
    """Extract user encryption private key.
    de = (ke / (H1(IDB||hid, N) + ke)) * G2
    """
    uid_bytes = user_id if isinstance(user_id, bytes) else user_id.encode()
    h1 = _sm9_hash(0x01, uid_bytes + bytes([HID_ENC]), SM9_N)
    t1 = (h1 + mpz(ke)) % SM9_N
    if t1 == 0:
        raise ValueError("Invalid: t1 is zero")
    t2 = (mpz(ke) * gmpy2.invert(t1, SM9_N)) % SM9_N
    if gmssl_lib_available():
        de = native_g2_mul_generator(int(t2))
    else:
        de = g2_mul(int(t2), SM9_G2)
    return de


def sm9_encrypt(Ppube, user_id, plaintext):
    """SM9 identity-based encryption.
    Returns ciphertext bytes: C1(65B) || C3(32B) || C2(len(M)B)
    """
    if not gmssl_lib_available():
        raise RuntimeError(_SM9_NEED_GMSSL)
    if not plaintext:
        raise ValueError("Plaintext must not be empty")
    uid_bytes = user_id if isinstance(user_id, bytes) else user_id.encode()
    inlen = len(plaintext)
    if inlen > 255:
        raise ValueError("Plaintext exceeds SM9 single-message limit (255 bytes)")

    K_full, C1_bytes = native_sm9_kem_encrypt(Ppube, uid_bytes)
    if len(K_full) != SM9_KEM_KLEN:
        raise RuntimeError("unexpected KEM key length from libgmssl")
    K1 = K_full[:inlen]
    K2 = K_full[inlen : inlen + 32]
    C2 = bytes(a ^ b for a, b in zip(plaintext, K1))

    from gmssl.hazmat.primitives.hmac import HMAC as _HMAC
    from gmssl.hazmat.primitives.hashes import SM3 as _SM3

    mac = _HMAC(K2, _SM3())
    mac.update(C2)
    C3 = mac.finalize()

    return C1_bytes + C3 + C2


def sm9_decrypt(user_key_de, user_id, ciphertext):
    """SM9 identity-based decryption."""
    if not gmssl_lib_available():
        raise RuntimeError(_SM9_NEED_GMSSL)
    uid_bytes = user_id if isinstance(user_id, bytes) else user_id.encode()

    C1_bytes = ciphertext[:65]
    C3 = ciphertext[65:97]
    C2 = ciphertext[97:]

    if len(ciphertext) < 97 or C1_bytes[0] != 0x04:
        raise ValueError("Invalid SM9 ciphertext format")
    x1 = mpz(int.from_bytes(C1_bytes[1:33], "big"))
    y1 = mpz(int.from_bytes(C1_bytes[33:65], "big"))
    if not G1Point.is_on_curve(x1, y1):
        raise ValueError("C1 point is not on SM9 G1 curve")

    K_full = native_sm9_kem_decrypt(user_key_de, uid_bytes, C1_bytes, SM9_KEM_KLEN)
    c2len = len(C2)
    K1 = K_full[:c2len]
    K2 = K_full[c2len : c2len + 32]

    if K1 == b"\x00" * len(K1):
        raise ValueError("KDF produced all-zero K1")

    M = bytes(a ^ b for a, b in zip(C2, K1))

    from gmssl.hazmat.primitives.hmac import HMAC as _HMAC
    from gmssl.hazmat.primitives.hashes import SM3 as _SM3

    mac = _HMAC(K2, _SM3())
    mac.update(C2)
    u = mac.finalize()

    if u != C3:
        raise ValueError("SM9 decryption: hash verification failed")

    return M
