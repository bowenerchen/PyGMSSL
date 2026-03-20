"""Tests for SM2 elliptic curve cryptography."""

import os
import pytest
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl._backends._sm2_algo import SM2_MAX_PLAINTEXT_SIZE
from gmssl.exceptions import InvalidSignature


class TestSM2Constants:
    def test_max_plaintext_matches_gmt(self):
        assert SM2_MAX_PLAINTEXT_SIZE == 255


class TestSM2ComputeZ:
    """Known Z = SM3(ENTL||ID||curve||G||public) for a fixed point (regression)."""

    def test_compute_z_generator_with_default_id(self):
        from gmpy2 import mpz

        from gmssl._backends._sm2_algo import SM2_DEFAULT_ID, compute_z
        from gmssl._backends._sm2_field import SM2_G, SM2_GX, SM2_GY, scalar_multiply

        p = scalar_multiply(mpz(1), SM2_G)
        x, y = p.to_affine()
        assert int(x) == int(SM2_GX) and int(y) == int(SM2_GY)
        z = compute_z(x, y, SM2_DEFAULT_ID)
        assert (
            z.hex()
            == "5b32bfe35482899b195d72c09d33ccdb465b2ded883240ff91f120a68bc91de8"
        )


class TestSM2KeyGen:
    def test_generate_key(self):
        key = sm2.generate_private_key()
        pub = key.public_key()
        assert pub.x > 0
        assert pub.y > 0

    def test_public_bytes(self):
        key = sm2.generate_private_key()
        pub_bytes = key.public_key().public_bytes_uncompressed()
        assert len(pub_bytes) == 65
        assert pub_bytes[0] == 0x04


class TestSM2SignVerify:
    def test_sign_verify(self):
        key = sm2.generate_private_key()
        data = b"test message for SM2 signing"
        sig = key.sign(data)
        assert len(sig) == 64
        key.public_key().verify(sig, data)

    def test_verify_wrong_data(self):
        key = sm2.generate_private_key()
        sig = key.sign(b"correct data")
        with pytest.raises(InvalidSignature):
            key.public_key().verify(sig, b"wrong data")

    def test_verify_wrong_key(self):
        key1 = sm2.generate_private_key()
        key2 = sm2.generate_private_key()
        sig = key1.sign(b"data")
        with pytest.raises(InvalidSignature):
            key2.public_key().verify(sig, b"data")

    def test_sign_with_custom_id(self):
        key = sm2.generate_private_key()
        uid = b"alice@example.com"
        sig = key.sign(b"hello", uid=uid)
        key.public_key().verify(sig, b"hello", uid=uid)


class TestSM2EncryptDecrypt:
    def test_encrypt_plaintext_exceeds_gmt_limit(self):
        key = sm2.generate_private_key()
        too_long = b"x" * 256
        with pytest.raises(ValueError, match="at most 255"):
            key.public_key().encrypt(too_long)

    def test_encrypt_decrypt(self):
        key = sm2.generate_private_key()
        plaintext = b"SM2 encryption test"
        ct = key.public_key().encrypt(plaintext)
        pt = key.decrypt(ct)
        assert pt == plaintext

    def test_encrypt_various_lengths(self):
        key = sm2.generate_private_key()
        for length in [1, 16, 32, 100, 255]:
            data = os.urandom(length)
            ct = key.public_key().encrypt(data)
            pt = key.decrypt(ct)
            assert pt == data


class TestSM2ECDH:
    def test_ecdh(self):
        key1 = sm2.generate_private_key()
        key2 = sm2.generate_private_key()
        shared1 = key1.exchange(key2.public_key())
        shared2 = key2.exchange(key1.public_key())
        assert shared1 == shared2
