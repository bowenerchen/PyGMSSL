"""SM2 algorithm operations: sign, verify, encrypt, decrypt, ECDH, compute_z."""

import os
import struct
import gmpy2
from gmpy2 import mpz

from gmssl._backends._sm2_field import (
    SM2_P, SM2_A, SM2_B, SM2_N, SM2_GX, SM2_GY, SM2_G,
    JacobianPoint, scalar_multiply, point_add, point_to_bytes, bytes_to_point,
    is_on_curve,
)
from gmssl._backends._sm3 import SM3State

SM2_DEFAULT_ID = b"1234567812345678"

# GM/T 0003 / GmSSL: single-block SM2 encryption plaintext length upper bound
SM2_MAX_PLAINTEXT_SIZE = 255


def _secure_random_mod_n():
    """Generate a cryptographically secure random integer in [1, n-1].
    Uses rejection sampling to avoid modulo bias.
    
    According to cryptographic best practices (RFC 6979), we generate
    random bits with extra margin and use rejection sampling to ensure
    uniform distribution over the range [1, n-1].
    """
    # Calculate the bit length of SM2_N
    n_bits = SM2_N.bit_length()  # Should be 256
    # Generate random with extra bits to minimize bias (n_bits + 64)
    extra_bits = 64
    total_bits = n_bits + extra_bits
    total_bytes = (total_bits + 7) // 8  # 40 bytes for 320 bits
    
    # Calculate the rejection bound: 2^total_bits - (2^total_bits mod n)
    # This ensures uniform distribution
    upper_bound = (1 << total_bits) - ((1 << total_bits) % SM2_N)
    
    while True:
        k_bytes = os.urandom(total_bytes)
        k = int.from_bytes(k_bytes, 'big')
        # Reject if k >= upper_bound to avoid bias
        if k < upper_bound:
            k = mpz(k % SM2_N)
            if 1 <= k < SM2_N:
                return k


def compute_z(pub_x, pub_y, uid=SM2_DEFAULT_ID):
    """Compute Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA).
    ENTL = len(uid) in bits as 2-byte big-endian.
    """
    entl = len(uid) * 8
    h = SM3State()
    h.update(struct.pack('>H', entl))
    h.update(uid)
    h.update(int(SM2_A).to_bytes(32, 'big'))
    h.update(int(SM2_B).to_bytes(32, 'big'))
    h.update(int(SM2_GX).to_bytes(32, 'big'))
    h.update(int(SM2_GY).to_bytes(32, 'big'))
    h.update(int(pub_x).to_bytes(32, 'big'))
    h.update(int(pub_y).to_bytes(32, 'big'))
    return h.finalize()


def sm2_sign(private_key_int, pub_x, pub_y, message, uid=SM2_DEFAULT_ID):
    """SM2 digital signature.
    Returns (r, s) as (mpz, mpz).
    """
    z = compute_z(pub_x, pub_y, uid)
    h = SM3State()
    h.update(z)
    h.update(message)
    e = mpz(int.from_bytes(h.finalize(), 'big'))
    d = mpz(private_key_int)

    while True:
        k = _secure_random_mod_n()
        kG = scalar_multiply(k, SM2_G)
        x1, y1 = kG.to_affine()
        r = (e + x1) % SM2_N
        if r == 0 or r + k == SM2_N:
            continue
        d_inv = gmpy2.invert(mpz(1) + d, SM2_N)
        s = (d_inv * (k - r * d)) % SM2_N
        if s == 0:
            continue
        return (r, s)


def sm2_verify(pub_x, pub_y, message, r, s, uid=SM2_DEFAULT_ID):
    """SM2 signature verification.
    Returns True if valid.
    """
    if not is_on_curve(pub_x, pub_y):
        return False
    r = mpz(r)
    s = mpz(s)
    if not (1 <= r < SM2_N and 1 <= s < SM2_N):
        return False

    z = compute_z(pub_x, pub_y, uid)
    h = SM3State()
    h.update(z)
    h.update(message)
    e = mpz(int.from_bytes(h.finalize(), 'big'))

    t = (r + s) % SM2_N
    if t == 0:
        return False

    P = JacobianPoint.from_affine(pub_x, pub_y)
    sG = scalar_multiply(s, SM2_G)
    tP = scalar_multiply(t, P)
    R = point_add(sG, tP)

    if R.is_infinity():
        return False

    x1, y1 = R.to_affine()
    R_ = (e + x1) % SM2_N
    return R_ == r


def sm2_encrypt(pub_x, pub_y, plaintext):
    """SM2 public key encryption.
    Returns ciphertext: C1 || C3 || C2
    C1 = point kG (uncompressed 65 bytes), C3 = SM3 hash (32 bytes), C2 = encrypted data
    """
    if not plaintext:
        raise ValueError("Plaintext must not be empty")
    if len(plaintext) > SM2_MAX_PLAINTEXT_SIZE:
        raise ValueError(
            f"SM2 plaintext must be at most {SM2_MAX_PLAINTEXT_SIZE} bytes, got {len(plaintext)}"
        )
    if not is_on_curve(pub_x, pub_y):
        raise ValueError("Public key point is not on SM2 curve")
    from gmssl.hazmat.primitives.kdf.sm3kdf import sm3_kdf
    m = plaintext
    P = JacobianPoint.from_affine(mpz(pub_x), mpz(pub_y))

    while True:
        k = _secure_random_mod_n()

        C1_point = scalar_multiply(k, SM2_G)
        x1, y1 = C1_point.to_affine()

        kP = scalar_multiply(k, P)
        x2, y2 = kP.to_affine()

        x2_bytes = int(x2).to_bytes(32, 'big')
        y2_bytes = int(y2).to_bytes(32, 'big')

        t = sm3_kdf(x2_bytes + y2_bytes, len(m))
        if t == b'\x00' * len(m):
            continue

        C2 = bytes(a ^ b for a, b in zip(m, t))

        h = SM3State()
        h.update(x2_bytes)
        h.update(m)
        h.update(y2_bytes)
        C3 = h.finalize()

        C1 = point_to_bytes(x1, y1)
        return C1 + C3 + C2


def sm2_decrypt(private_key_int, ciphertext):
    """SM2 private key decryption.
    Input: C1(65 bytes) || C3(32 bytes) || C2(variable)
    """
    if len(ciphertext) < 98:
        raise ValueError("Ciphertext too short (minimum 98 bytes: 65 C1 + 32 C3 + 1 C2)")
    from gmssl.hazmat.primitives.kdf.sm3kdf import sm3_kdf

    C1_bytes = ciphertext[:65]
    C3 = ciphertext[65:97]
    C2 = ciphertext[97:]

    x1, y1 = bytes_to_point(C1_bytes)
    C1_point = JacobianPoint.from_affine(x1, y1)

    d = mpz(private_key_int)
    dC1 = scalar_multiply(d, C1_point)
    x2, y2 = dC1.to_affine()

    x2_bytes = int(x2).to_bytes(32, 'big')
    y2_bytes = int(y2).to_bytes(32, 'big')

    t = sm3_kdf(x2_bytes + y2_bytes, len(C2))
    if t == b'\x00' * len(C2):
        raise ValueError("KDF produced all-zero output")

    M = bytes(a ^ b for a, b in zip(C2, t))

    h = SM3State()
    h.update(x2_bytes)
    h.update(M)
    h.update(y2_bytes)
    u = h.finalize()

    if u != C3:
        raise ValueError("SM2 decryption: hash verification failed")

    return M


def sm2_generate_keypair():
    """Generate SM2 key pair.
    Returns (private_key_int, pub_x, pub_y).
    """
    d = _secure_random_mod_n()
    P = scalar_multiply(d, SM2_G)
    pub_x, pub_y = P.to_affine()
    return (int(d), int(pub_x), int(pub_y))


def sm2_ecdh(private_key_int, peer_pub_x, peer_pub_y):
    """SM2 ECDH key agreement (basic, without full SM2 key exchange protocol).
    Returns shared point (x, y).
    """
    if not is_on_curve(peer_pub_x, peer_pub_y):
        raise ValueError("Peer public key point is not on SM2 curve")
    d = mpz(private_key_int)
    P = JacobianPoint.from_affine(mpz(peer_pub_x), mpz(peer_pub_y))
    S = scalar_multiply(d, P)
    return S.to_affine()
