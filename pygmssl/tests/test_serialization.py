"""Tests for ASN.1/DER/PEM serialization."""

from pathlib import Path

import pytest

from gmssl._backends._asn1 import (
    encode_integer, decode_integer, encode_sequence,
    encode_oid, decode_oid, encode_octet_string,
    encode_tlv, decode_tlv, TAG_INTEGER,
)
from gmssl.hazmat.primitives import serialization
from gmssl.hazmat.primitives.asymmetric import sm2


class TestSM2SignatureDER:
    def test_encode_sm2_signature_der_roundtrip_integers(self):
        sig64 = bytes.fromhex(
            "00" * 31
            + "01"
            + "00" * 31
            + "02"
        )
        der = serialization.encode_sm2_signature_der(sig64)
        assert der[0] == 0x30
        tag, inner, _ = decode_tlv(der, 0)
        assert tag == 0x30
        r, off = decode_integer(inner, 0)
        s, _ = decode_integer(inner, off)
        assert r == 1 and s == 2

    def test_decode_sm2_signature_der_roundtrip(self):
        sig64 = bytes.fromhex("00" * 31 + "01" + "00" * 31 + "02")
        der = serialization.encode_sm2_signature_der(sig64)
        assert serialization.decode_sm2_signature_der(der) == sig64


class TestASN1:
    def test_encode_decode_integer(self):
        for val in [0, 1, 127, 128, 255, 256, 65535, -1, -128]:
            encoded = encode_integer(val)
            decoded, _ = decode_integer(encoded)
            assert decoded == val

    def test_encode_decode_oid(self):
        oid = (1, 2, 156, 10197, 1, 301)
        encoded = encode_oid(oid)
        decoded, _ = decode_oid(encoded)
        assert decoded == oid

    def test_encode_sequence(self):
        seq = encode_sequence([encode_integer(1), encode_integer(2)])
        assert seq[0] == 0x30


class TestPEM:
    def test_sm2_key_pem_roundtrip(self):
        key = sm2.generate_private_key()
        pub = key.public_key()

        priv_der = serialization.encode_sm2_private_key_pkcs8(
            key.private_bytes(),
            pub.public_bytes_uncompressed()
        )
        pem = serialization._pem_encode(priv_der, "PRIVATE KEY")
        der_back, label = serialization._pem_decode(pem)
        assert der_back == priv_der
        assert label == "PRIVATE KEY"

    def test_sm2_public_key_spki(self):
        key = sm2.generate_private_key()
        pub = key.public_key()
        spki = serialization.encode_sm2_public_key_spki(pub.public_bytes_uncompressed())
        assert spki[0] == 0x30

    def test_load_pem_private_key_roundtrip(self):
        key = sm2.generate_private_key()
        priv_der = serialization.encode_sm2_private_key_pkcs8(
            key.private_bytes(),
            key.public_key().public_bytes_uncompressed(),
        )
        pem = serialization._pem_encode(priv_der, "PRIVATE KEY")
        loaded = serialization.load_pem_private_key(pem)
        assert loaded.private_key_int == key.private_key_int

    def test_load_pem_public_key_roundtrip(self):
        key = sm2.generate_private_key()
        pub = key.public_key()
        spki = serialization.encode_sm2_public_key_spki(pub.public_bytes_uncompressed())
        pem = serialization._pem_encode(spki, "PUBLIC KEY")
        loaded = serialization.load_pem_public_key(pem)
        assert loaded.x == pub.x and loaded.y == pub.y

    def test_sm2_encrypted_pkcs8_pem_roundtrip(self):
        key = sm2.generate_private_key()
        pub = key.public_key()
        pwd = b"unit-test-passphrase"
        enc_der = serialization.encode_sm2_private_key_pkcs8_encrypted(
            key.private_bytes(),
            pub.public_bytes_uncompressed(),
            pwd,
            iterations=400,
        )
        pem = serialization._pem_encode(enc_der, "ENCRYPTED PRIVATE KEY")
        loaded = serialization.load_pem_private_key(pem, pwd)
        assert loaded.private_key_int == key.private_key_int

    def test_load_encrypted_pem_requires_password(self):
        key = sm2.generate_private_key()
        enc_der = serialization.encode_sm2_private_key_pkcs8_encrypted(
            key.private_bytes(),
            key.public_key().public_bytes_uncompressed(),
            b"x",
            iterations=200,
        )
        pem = serialization._pem_encode(enc_der, "ENCRYPTED PRIVATE KEY")
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(pem, None)

    def test_load_plain_pem_rejects_password(self):
        key = sm2.generate_private_key()
        priv_der = serialization.encode_sm2_private_key_pkcs8(
            key.private_bytes(),
            key.public_key().public_bytes_uncompressed(),
        )
        pem = serialization._pem_encode(priv_der, "PRIVATE KEY")
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(pem, b"any")

    def test_wrong_password_encrypted_pem(self):
        key = sm2.generate_private_key()
        enc_der = serialization.encode_sm2_private_key_pkcs8_encrypted(
            key.private_bytes(),
            key.public_key().public_bytes_uncompressed(),
            b"right",
            iterations=300,
        )
        pem = serialization._pem_encode(enc_der, "ENCRYPTED PRIVATE KEY")
        with pytest.raises(ValueError, match="password|corrupted"):
            serialization.load_pem_private_key(pem, b"wrong")

    @pytest.mark.slow
    def test_eet_fixture_encrypted_private_key_matches_public_pem(self):
        """tests-api fixture: eet sm2 generate (PBKDF2 65536 + SM4-CBC)."""
        fix_priv = (
            Path(__file__).resolve().parents[2]
            / "tests-api"
            / "shell"
            / "fixtures"
            / "test_sm2_sm2_private.pem"
        )
        fix_pub = fix_priv.parent / "test_sm2_sm2_public.pem"
        if not fix_priv.is_file():
            pytest.skip("tests-api SM2 fixture not present")
        pem_priv = fix_priv.read_bytes()
        pem_pub = fix_pub.read_bytes()
        key = serialization.load_pem_private_key(pem_priv, b"ApiTestPwd01")
        pub = key.public_key()
        pub2 = serialization.load_pem_public_key(pem_pub)
        assert pub.x == pub2.x and pub.y == pub2.y
