"""X.509 Distinguished Name."""

from __future__ import annotations
from gmssl._backends._asn1 import (
    encode_sequence, encode_set, encode_oid,
    encode_utf8_string, encode_printable_string,
)


OID_CN = (2, 5, 4, 3)
OID_O = (2, 5, 4, 10)
OID_OU = (2, 5, 4, 11)
OID_C = (2, 5, 4, 6)
OID_ST = (2, 5, 4, 8)
OID_L = (2, 5, 4, 7)
OID_EMAIL = (1, 2, 840, 113549, 1, 9, 1)

_OID_MAP = {
    'CN': OID_CN, 'O': OID_O, 'OU': OID_OU,
    'C': OID_C, 'ST': OID_ST, 'L': OID_L,
    'EMAIL': OID_EMAIL,
}


class NameAttribute:
    def __init__(self, oid: tuple[int, ...], value: str):
        self.oid = oid
        self.value = value

    def to_der(self) -> bytes:
        if self.oid == OID_C:
            val = encode_printable_string(self.value)
        else:
            val = encode_utf8_string(self.value)
        return encode_set([encode_sequence([encode_oid(self.oid), val])])


class Name:
    def __init__(self, attributes: list[NameAttribute]):
        self._attrs = attributes

    def to_der(self) -> bytes:
        return encode_sequence([a.to_der() for a in self._attrs])

    def __repr__(self):
        parts = []
        rev_map = {v: k for k, v in _OID_MAP.items()}
        for a in self._attrs:
            name = rev_map.get(a.oid, str(a.oid))
            parts.append(f"{name}={a.value}")
        return "Name(" + ", ".join(parts) + ")"
