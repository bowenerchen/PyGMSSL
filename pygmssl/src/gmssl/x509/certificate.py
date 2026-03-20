"""X.509 Certificate creation, parsing, and verification."""

from __future__ import annotations
import os
import time
from gmssl._backends._asn1 import (
    encode_sequence, encode_integer, encode_bit_string,
    encode_oid, encode_context,
    encode_utc_time,
)
from gmssl.x509.name import Name
from gmssl.hazmat.primitives import serialization


SM2_SIGN_OID = (1, 2, 156, 10197, 1, 501)


class CertificateBuilder:
    """Builder pattern for X.509 certificate creation."""

    def __init__(self):
        self._subject = None
        self._issuer = None
        self._public_key = None
        self._serial_number = None
        self._not_valid_before = None
        self._not_valid_after = None

    def subject_name(self, name: Name) -> CertificateBuilder:
        self._subject = name
        return self

    def issuer_name(self, name: Name) -> CertificateBuilder:
        self._issuer = name
        return self

    def public_key(self, key) -> CertificateBuilder:
        self._public_key = key
        return self

    def serial_number(self, number: int) -> CertificateBuilder:
        self._serial_number = number
        return self

    def not_valid_before(self, time_str: str) -> CertificateBuilder:
        self._not_valid_before = time_str
        return self

    def not_valid_after(self, time_str: str) -> CertificateBuilder:
        self._not_valid_after = time_str
        return self

    def sign(self, private_key, algorithm=None) -> Certificate:
        """Sign the certificate with the given private key."""
        tbs = self._build_tbs()
        sig = private_key.sign(tbs)
        sig_der = serialization.encode_sm2_signature_der(sig)

        sig_alg = encode_sequence([encode_oid(SM2_SIGN_OID)])
        cert_der = encode_sequence([
            tbs,
            sig_alg,
            encode_bit_string(sig_der),
        ])
        return Certificate(cert_der)

    def _build_tbs(self) -> bytes:
        version = encode_context(0, encode_integer(2))  # v3
        serial = encode_integer(
            self._serial_number or int.from_bytes(os.urandom(16), 'big')
        )
        sig_alg = encode_sequence([encode_oid(SM2_SIGN_OID)])
        issuer = self._issuer.to_der() if self._issuer else self._subject.to_der()

        validity = encode_sequence([
            encode_utc_time(self._not_valid_before or "250101000000Z"),
            encode_utc_time(self._not_valid_after or "350101000000Z"),
        ])
        subject = self._subject.to_der()

        pub_key_bytes = self._public_key.public_bytes_uncompressed()
        spki = serialization.encode_sm2_public_key_spki(pub_key_bytes)

        return encode_sequence([version, serial, sig_alg, issuer, validity, subject, spki])


class Certificate:
    """Represents a parsed X.509 certificate."""

    def __init__(self, der_data: bytes):
        self._der = der_data

    def public_bytes(self, encoding) -> bytes:
        if encoding == serialization.Encoding.DER:
            return self._der
        elif encoding == serialization.Encoding.PEM:
            return serialization._pem_encode(self._der, "CERTIFICATE")
        raise ValueError(f"Unsupported encoding: {encoding}")

    @classmethod
    def from_pem(cls, pem_data: bytes) -> Certificate:
        der, label = serialization._pem_decode(pem_data)
        return cls(der)

    @classmethod
    def from_der(cls, der_data: bytes) -> Certificate:
        return cls(der_data)
