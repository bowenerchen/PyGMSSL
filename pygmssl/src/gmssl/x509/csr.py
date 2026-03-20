"""X.509 Certificate Signing Request (CSR)."""

from __future__ import annotations
import os
from gmssl._backends._asn1 import (
    encode_sequence, encode_integer, encode_bit_string,
    encode_oid, encode_context,
)
from gmssl.x509.name import Name
from gmssl.hazmat.primitives import serialization

SM2_SIGN_OID = (1, 2, 156, 10197, 1, 501)


class CertificateSigningRequestBuilder:
    """Builder for CSR."""

    def __init__(self):
        self._subject = None

    def subject_name(self, name: Name) -> CertificateSigningRequestBuilder:
        self._subject = name
        return self

    def sign(self, private_key, algorithm=None) -> CertificateSigningRequest:
        pub_key = private_key.public_key()
        pub_bytes = pub_key.public_bytes_uncompressed()
        spki = serialization.encode_sm2_public_key_spki(pub_bytes)

        csr_info = encode_sequence([
            encode_integer(0),  # version
            self._subject.to_der(),
            spki,
            encode_context(0, b''),  # attributes (empty)
        ])

        sig = private_key.sign(csr_info)
        sig_der = serialization.encode_sm2_signature_der(sig)
        sig_alg = encode_sequence([encode_oid(SM2_SIGN_OID)])

        csr_der = encode_sequence([csr_info, sig_alg, encode_bit_string(sig_der)])
        return CertificateSigningRequest(csr_der)


class CertificateSigningRequest:
    def __init__(self, der_data: bytes):
        self._der = der_data

    def public_bytes(self, encoding) -> bytes:
        if encoding == serialization.Encoding.DER:
            return self._der
        elif encoding == serialization.Encoding.PEM:
            return serialization._pem_encode(self._der, "CERTIFICATE REQUEST")
        raise ValueError(f"Unsupported encoding: {encoding}")
