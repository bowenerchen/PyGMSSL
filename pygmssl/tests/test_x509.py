"""Tests for X.509 certificate and CSR."""

from gmssl._backends._asn1 import decode_tlv, TAG_BIT_STRING, TAG_SEQUENCE
from gmssl.x509 import (
    Certificate, CertificateBuilder,
    CertificateSigningRequest, CertificateSigningRequestBuilder,
    Name, NameAttribute,
)
from gmssl.x509.name import OID_CN, OID_O, OID_C
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization


class TestX509Certificate:
    def test_create_self_signed(self):
        key = sm2.generate_private_key()
        subject = Name([
            NameAttribute(OID_C, "CN"),
            NameAttribute(OID_O, "Test Org"),
            NameAttribute(OID_CN, "test.example.com"),
        ])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(1234567890)
            .not_valid_before("250101000000Z")
            .not_valid_after("350101000000Z")
            .sign(key)
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        assert der[0] == 0x30

        pem = cert.public_bytes(serialization.Encoding.PEM)
        assert b"BEGIN CERTIFICATE" in pem

    def test_certificate_signature_value_is_sm2_der(self):
        """BIT STRING contents must be ASN.1 SEQUENCE (r,s), per GmSSL x509_cer.c."""
        key = sm2.generate_private_key()
        subject = Name([NameAttribute(OID_CN, "test")])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .sign(key)
        )
        der = cert.public_bytes(serialization.Encoding.DER)
        tag, outer, _ = decode_tlv(der, 0)
        assert tag == TAG_SEQUENCE
        p = 0
        _, _, p = decode_tlv(outer, p)  # tbsCertificate
        _, _, p = decode_tlv(outer, p)  # signatureAlgorithm
        tag, bitstr_val, _ = decode_tlv(outer, p)  # signatureValue
        assert tag == TAG_BIT_STRING
        unused, sig_der = bitstr_val[0], bitstr_val[1:]
        assert unused == 0
        st, inner, _ = decode_tlv(sig_der, 0)
        assert st == TAG_SEQUENCE
        # Two INTEGERs (r, s)
        _, r_val, p = decode_tlv(inner, 0)
        _, s_val, _ = decode_tlv(inner, p)
        assert len(r_val) >= 1 and len(s_val) >= 1

    def test_cert_pem_roundtrip(self):
        key = sm2.generate_private_key()
        subject = Name([NameAttribute(OID_CN, "test")])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .sign(key)
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        cert2 = Certificate.from_pem(pem)
        assert cert2.public_bytes(serialization.Encoding.DER) == cert.public_bytes(serialization.Encoding.DER)


class TestCSR:
    def test_create_csr(self):
        key = sm2.generate_private_key()
        subject = Name([
            NameAttribute(OID_CN, "test.example.com"),
            NameAttribute(OID_O, "Test Org"),
        ])
        csr = (
            CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(key)
        )
        der = csr.public_bytes(serialization.Encoding.DER)
        assert der[0] == 0x30

        pem = csr.public_bytes(serialization.Encoding.PEM)
        assert b"BEGIN CERTIFICATE REQUEST" in pem


class TestName:
    def test_name_repr(self):
        name = Name([
            NameAttribute(OID_C, "CN"),
            NameAttribute(OID_CN, "test"),
        ])
        r = repr(name)
        assert "CN" in r
        assert "test" in r
