"""Tests for SM9 identity-based cryptography."""

import pytest

from gmssl._backends._sm9_gmssl_native import gmssl_lib_available

pytestmark = pytest.mark.skipif(
    not gmssl_lib_available(),
    reason=(
        "SM9 uses GmSSL libgmssl via ctypes. Build GmSSL-3.1.1 (see repo sibling path) "
        "or set PYGMSSL_GMSSL_LIBRARY to libgmssl.{dylib,so}."
    ),
)

from gmssl.hazmat.primitives.asymmetric import sm9
from gmssl.exceptions import InvalidSignature


class TestSM9Sign:
    def test_sign_verify(self):
        master = sm9.generate_sign_master_key()
        user_key = master.extract_key("alice@example.com")
        sig = user_key.sign(b"test message")
        assert len(sig) == 96
        master.public_key().verify(sig, b"test message", "alice@example.com")

    def test_verify_wrong_message(self):
        master = sm9.generate_sign_master_key()
        user_key = master.extract_key("alice@example.com")
        sig = user_key.sign(b"correct")
        with pytest.raises(InvalidSignature):
            master.public_key().verify(sig, b"wrong", "alice@example.com")

    def test_verify_wrong_id(self):
        master = sm9.generate_sign_master_key()
        user_key = master.extract_key("alice@example.com")
        sig = user_key.sign(b"data")
        with pytest.raises(InvalidSignature):
            master.public_key().verify(sig, b"data", "bob@example.com")


class TestSM9Encrypt:
    def test_encrypt_decrypt(self):
        master = sm9.generate_enc_master_key()
        user_key = master.extract_key("bob@example.com")
        ct = master.public_key().encrypt(b"secret message", "bob@example.com")
        pt = user_key.decrypt(ct, "bob@example.com")
        assert pt == b"secret message"

    def test_encrypt_various_lengths(self):
        master = sm9.generate_enc_master_key()
        user_key = master.extract_key("user@test.com")
        import os
        for length in [1, 16, 32, 64]:
            data = os.urandom(length)
            ct = master.public_key().encrypt(data, "user@test.com")
            pt = user_key.decrypt(ct, "user@test.com")
            assert pt == data
