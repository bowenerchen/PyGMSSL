"""Tests for SM4-GCM AEAD – vectors from RFC 8998 and GB/T 36624-2018."""

from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.exceptions import InvalidTag
import pytest


class TestSM4GCM:
    def test_rfc8998_vector(self):
        """RFC 8998 A.1 SM4-GCM test vector."""
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

        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher.encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(plaintext) + enc.finalize()
        assert ct == expected_ct
        assert enc.tag == expected_tag

        cipher2 = Cipher(algorithms.SM4(key), modes.GCM(iv, expected_tag))
        dec = cipher2.decryptor()
        dec.authenticate_additional_data(aad)
        pt = dec.update(ct) + dec.finalize()
        assert pt == plaintext

    def test_gbt36624_empty(self):
        """GB/T 36624-2018 C.5 test 1: empty plaintext."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("000000000000000000000000")
        expected_tag = bytes.fromhex("232F0CFE308B49EA6FC88229B5DC858D")

        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher.encryptor()
        ct = enc.update(b"") + enc.finalize()
        assert ct == b""
        assert enc.tag == expected_tag

    def test_gbt36624_one_block(self):
        """GB/T 36624-2018 C.5 test 2: one block of zeros."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected_ct = bytes.fromhex("7DE2AA7F1110188218063BE1BFEB6D89")
        expected_tag = bytes.fromhex("B851B5F39493752BE508F1BB4482C557")

        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        assert ct == expected_ct
        assert enc.tag == expected_tag

    def test_gcm_tag_mismatch_raises(self):
        key = b'\x00' * 16
        iv = b'\x00' * 12
        bad_tag = b'\xff' * 16

        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher.encryptor()
        ct = enc.update(b"hello world12345") + enc.finalize()
        real_tag = enc.tag

        cipher2 = Cipher(algorithms.SM4(key), modes.GCM(iv, bad_tag))
        dec = cipher2.decryptor()
        dec.update(ct)
        with pytest.raises(InvalidTag):
            dec.finalize()

    def test_gcm_roundtrip(self):
        import os
        key = os.urandom(16)
        iv = os.urandom(12)
        aad = os.urandom(20)
        plaintext = os.urandom(100)

        cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
        enc = cipher.encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(plaintext) + enc.finalize()
        tag = enc.tag

        cipher2 = Cipher(algorithms.SM4(key), modes.GCM(iv, tag))
        dec = cipher2.decryptor()
        dec.authenticate_additional_data(aad)
        pt = dec.update(ct) + dec.finalize()
        assert pt == plaintext
