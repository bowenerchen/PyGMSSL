"""Tests for SM4 block cipher – vectors from GM/T 0002-2012 and GmSSL test suite."""

import os
import pytest
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.hazmat.primitives.ciphers.modes import GCM
from gmssl.hazmat.primitives import padding


# --- GM/T 0002-2012 standard test vectors ---

USER_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
PLAINTEXT = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
CIPHERTEXT = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")

EXPECTED_RK = [
    0xf12186f9, 0x41662b61, 0x5a6ab19a, 0x7ba92077,
    0x367360f4, 0x776a0c61, 0xb6bb89b3, 0x24763151,
    0xa520307c, 0xb7584dbd, 0xc30753ed, 0x7ee55b57,
    0x6988608c, 0x30d895b7, 0x44ba14af, 0x104495a1,
    0xd120b428, 0x73b55fa3, 0xcc874966, 0x92244439,
    0xe89e641f, 0x98ca015a, 0xc7159060, 0x99e1fd2e,
    0xb79bd80c, 0x1d2115b0, 0x0e228aeb, 0xf1780c81,
    0x428d3654, 0x62293496, 0x01cf72e5, 0x9124a012,
]


class TestSM4Core:
    def test_key_schedule(self):
        from gmssl._backends._sm4 import sm4_key_schedule
        rk = sm4_key_schedule(USER_KEY)
        assert rk == EXPECTED_RK

    def test_encrypt_block(self):
        cipher = Cipher(algorithms.SM4(USER_KEY), modes.ECB())
        enc = cipher.encryptor()
        ct = enc.update(PLAINTEXT) + enc.finalize()
        assert ct == CIPHERTEXT

    def test_decrypt_block(self):
        cipher = Cipher(algorithms.SM4(USER_KEY), modes.ECB())
        dec = cipher.decryptor()
        pt = dec.update(CIPHERTEXT) + dec.finalize()
        assert pt == PLAINTEXT


class TestSM4CBC:
    def test_cbc_roundtrip(self):
        key = b'\x00' * 16
        iv = b'\x00' * 16
        data = b'\x00' * 32
        cipher_enc = Cipher(algorithms.SM4(key), modes.CBC(iv))
        enc = cipher_enc.encryptor()
        ct = enc.update(data) + enc.finalize()

        cipher_dec = Cipher(algorithms.SM4(key), modes.CBC(iv))
        dec = cipher_dec.decryptor()
        pt = dec.update(ct) + dec.finalize()
        assert pt == data

    @pytest.mark.parametrize("data_len", [0, 7, 16, 33, 64])
    def test_cbc_padding_various_lengths(self, data_len):
        key = b'\x00' * 16
        iv = b'\x00' * 16
        data = os.urandom(data_len)

        cipher_enc = Cipher(algorithms.SM4(key), modes.CBC(iv))
        enc = cipher_enc.encryptor()
        ct = enc.update(data) + enc.finalize()

        cipher_dec = Cipher(algorithms.SM4(key), modes.CBC(iv))
        dec = cipher_dec.decryptor()
        pt = dec.update(ct) + dec.finalize()
        assert pt == data


class TestSM4CTR:
    def test_ctr_roundtrip(self):
        key = b'\x00' * 16
        nonce = b'\x00' * 16
        data = b'\x00' * 30

        cipher_enc = Cipher(algorithms.SM4(key), modes.CTR(nonce))
        enc = cipher_enc.encryptor()
        ct = enc.update(data) + enc.finalize()

        cipher_dec = Cipher(algorithms.SM4(key), modes.CTR(nonce))
        dec = cipher_dec.decryptor()
        pt = dec.update(ct) + dec.finalize()
        assert pt == data

    def test_ctr_known_vector(self):
        """Test vector from GmSSL sm4test.c test_sm4_ctr_with_carray."""
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        ctr = bytes.fromhex("0000000000000000000000000000FFFF")
        plaintext = bytes.fromhex(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
            "CCCCCCCCCCCCCCCCDDDDDDDDDDDD"
        )
        expected_ct = bytes.fromhex(
            "7EA678F9F0CBE2000917C63D4E77B4C8"
            "6E4E8532B0046E4AC1E97DA8B831"
        )

        cipher = Cipher(algorithms.SM4(key), modes.CTR(ctr))
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        assert ct == expected_ct


class TestSM4GCM:
    """SM4-GCM test vectors from RFC 8998 Appendix A.1."""

    def test_gcm_rfc8998_encrypt(self):
        """RFC 8998 A.1 SM4-GCM test vector - encryption."""
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        iv = bytes.fromhex("00001234567800000000ABCD")
        aad = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
        plaintext = bytes.fromhex(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
            "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
            "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
            "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
        )
        expected_ct = bytes.fromhex(
            "17F399F08C67D5EE19D0DC9969C4BB7D"
            "5FD46FD3756489069157B282BB200735"
            "D82710CA5C22F0CCFA7CBF93D496AC15"
            "A56834CBCF98C397B4024A2691233B8D"
        )
        expected_tag = bytes.fromhex("83DE3541E4C2B58177E065A9BF7B62EC")

        cipher_enc = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher_enc.encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(plaintext) + enc.finalize()
        tag = enc.tag

        assert ct == expected_ct
        assert tag == expected_tag

    def test_gcm_rfc8998_decrypt(self):
        """RFC 8998 A.1 - decrypt and verify tag."""
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        iv = bytes.fromhex("00001234567800000000ABCD")
        aad = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
        ciphertext = bytes.fromhex(
            "17F399F08C67D5EE19D0DC9969C4BB7D"
            "5FD46FD3756489069157B282BB200735"
            "D82710CA5C22F0CCFA7CBF93D496AC15"
            "A56834CBCF98C397B4024A2691233B8D"
        )
        tag = bytes.fromhex("83DE3541E4C2B58177E065A9BF7B62EC")
        expected_pt = bytes.fromhex(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
            "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
            "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
            "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
        )
        cipher_dec = Cipher(algorithms.SM4(key), modes.GCM(iv, tag=tag))
        dec = cipher_dec.decryptor()
        dec.authenticate_additional_data(aad)
        pt = dec.update(ciphertext) + dec.finalize()
        assert pt == expected_pt

    def test_gcm_gbt36624_c5_empty_plaintext(self):
        """GB/T 36624-2018 C.5 test 1: empty plaintext."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("000000000000000000000000")
        expected_tag = bytes.fromhex("232F0CFE308B49EA6FC88229B5DC858D")
        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher.encryptor()
        ct = enc.update(b"") + enc.finalize()
        assert ct == b""
        assert enc.tag == expected_tag

    def test_gcm_decrypt_accepts_truncated_tag_when_min_tag_length_set(self):
        """Decryption compares only the first len(tag) bytes of the MAC (documented semantics)."""
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        iv = bytes.fromhex("000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        full_tag = enc.tag
        short_tag = full_tag[:8]
        dec = Cipher(
            algorithms.SM4(key), modes.GCM(iv, tag=short_tag, min_tag_length=8)
        ).decryptor()
        assert dec.update(ct) + dec.finalize() == plaintext

    def test_gcm_roundtrip(self):
        """GCM encrypt/decrypt roundtrip with random keys."""
        key = os.urandom(16)
        iv = os.urandom(12)
        aad = b"optional authenticated data"
        plaintext = b"secret message"
        cipher_enc = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher_enc.encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(plaintext) + enc.finalize()
        tag = enc.tag
        cipher_dec = Cipher(algorithms.SM4(key), modes.GCM(iv, tag=tag))
        dec = cipher_dec.decryptor()
        dec.authenticate_additional_data(aad)
        pt = dec.update(ct) + dec.finalize()
        assert pt == plaintext

    def test_gcm_roundtrip_with_aad(self):
        """GCM encrypt/decrypt roundtrip with AAD."""
        key = os.urandom(16)
        iv = os.urandom(12)
        aad = b"additional authenticated data"
        plaintext = b"secret message"
        cipher_enc = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher_enc.encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(plaintext) + enc.finalize()
        tag = enc.tag
        cipher_dec = Cipher(algorithms.SM4(key), modes.GCM(iv, tag=tag))
        dec = cipher_dec.decryptor()
        dec.authenticate_additional_data(aad)
        pt = dec.update(ct) + dec.finalize()
        assert pt == plaintext


class TestPKCS7Padding:
    @pytest.mark.parametrize("data_len", [0, 1, 15, 16, 17, 31, 32])
    def test_pad_unpad_roundtrip(self, data_len):
        data = os.urandom(data_len)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        assert len(padded) % 16 == 0
        assert len(padded) > 0

        unpadder = padding.PKCS7(128).unpadder()
        result = unpadder.update(padded) + unpadder.finalize()
        assert result == data
