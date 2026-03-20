"""Tests for ZUC stream cipher – vectors from GmSSL zuctest.c."""

import struct
from gmssl._backends._zuc import ZUCState, ZUC256State


class TestZUC128:
    VECTORS = [
        (b'\x00' * 16, b'\x00' * 16, [0x27bede74, 0x018082da]),
        (b'\xff' * 16, b'\xff' * 16, [0x0657cfa0, 0x7096398b]),
        (
            bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b"),
            bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766"),
            [0x14f1c272, 0x3279c419],
        ),
    ]

    def test_keystream_vectors(self):
        for key, iv, expected in self.VECTORS:
            state = ZUCState(key, iv)
            words = state.generate_keystream(2)
            assert words == expected, f"Failed for key={key.hex()}"

    def test_encrypt_decrypt_roundtrip(self):
        key = b'\x00' * 16
        iv = b'\x00' * 16
        plaintext = b"Hello ZUC stream cipher test!"
        s1 = ZUCState(key, iv)
        ct = s1.encrypt(plaintext)
        s2 = ZUCState(key, iv)
        pt = s2.encrypt(ct)
        assert pt == plaintext


class TestZUC256:
    def test_keystream_all_zeros(self):
        key = b'\x00' * 32
        iv = b'\x00' * 23
        expected_first4 = [0x58d03ad6, 0x2e032ce2, 0xdafc683a, 0x39bdcb03]
        state = ZUC256State(key, iv)
        words = state.generate_keystream(4)
        assert words == expected_first4

    def test_keystream_all_ones(self):
        key = b'\xff' * 32
        iv = b'\xff' * 23
        expected_first4 = [0x3356cbae, 0xd1a1c18b, 0x6baa4ffe, 0x343f777c]
        state = ZUC256State(key, iv)
        words = state.generate_keystream(4)
        assert words == expected_first4

    def test_encrypt_decrypt_roundtrip(self):
        key = b'\x00' * 32
        iv = b'\x00' * 23
        plaintext = b"ZUC-256 stream cipher test data!"
        s1 = ZUC256State(key, iv)
        ct = s1.encrypt(plaintext)
        s2 = ZUC256State(key, iv)
        pt = s2.encrypt(ct)
        assert pt == plaintext
