"""Tests for KDF implementations."""

import os
from gmssl.hazmat.primitives import hashes
from gmssl.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gmssl.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from gmssl.hazmat.primitives.kdf.sm3kdf import sm3_kdf


class TestPBKDF2:
    def test_derive_basic(self):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=1000)
        key = kdf.derive(b"password")
        assert len(key) == 32

    def test_deterministic(self):
        salt = b'\x00' * 16
        kdf1 = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=100)
        key1 = kdf1.derive(b"password")
        kdf2 = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=100)
        key2 = kdf2.derive(b"password")
        assert key1 == key2

    def test_different_passwords(self):
        salt = b'\x00' * 16
        kdf1 = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=100)
        key1 = kdf1.derive(b"password1")
        kdf2 = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=100)
        key2 = kdf2.derive(b"password2")
        assert key1 != key2

    def test_verify(self):
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=100)
        key = kdf.derive(b"password")
        kdf2 = PBKDF2HMAC(algorithm=hashes.SM3(), length=32, salt=salt, iterations=100)
        kdf2.verify(b"password", key)


class TestHKDF:
    def test_derive_basic(self):
        hkdf = HKDF(algorithm=hashes.SM3(), length=32, salt=None, info=b"test")
        key = hkdf.derive(b"input key material")
        assert len(key) == 32

    def test_deterministic(self):
        salt = b'\x00' * 32
        hkdf1 = HKDF(algorithm=hashes.SM3(), length=32, salt=salt, info=b"info")
        key1 = hkdf1.derive(b"ikm")
        hkdf2 = HKDF(algorithm=hashes.SM3(), length=32, salt=salt, info=b"info")
        key2 = hkdf2.derive(b"ikm")
        assert key1 == key2

    def test_different_info(self):
        salt = b'\x00' * 32
        hkdf1 = HKDF(algorithm=hashes.SM3(), length=32, salt=salt, info=b"info1")
        key1 = hkdf1.derive(b"ikm")
        hkdf2 = HKDF(algorithm=hashes.SM3(), length=32, salt=salt, info=b"info2")
        key2 = hkdf2.derive(b"ikm")
        assert key1 != key2

    def test_expand_only(self):
        expand = HKDFExpand(algorithm=hashes.SM3(), length=64, info=b"expand-test")
        key = expand.derive(b'\x00' * 32)
        assert len(key) == 64


class TestSM3KDF:
    def test_basic(self):
        key = sm3_kdf(b"shared_info", 32)
        assert len(key) == 32

    def test_deterministic(self):
        k1 = sm3_kdf(b"z_value", 48)
        k2 = sm3_kdf(b"z_value", 48)
        assert k1 == k2
        assert len(k1) == 48

    def test_various_lengths(self):
        for length in [16, 32, 48, 64, 100]:
            key = sm3_kdf(b"test", length)
            assert len(key) == length
