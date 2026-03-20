"""ASN.1 DER encoding and decoding primitives."""

import struct

# Tag values
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

# Context-specific tags
TAG_CONTEXT_0 = 0xA0
TAG_CONTEXT_1 = 0xA1
TAG_CONTEXT_2 = 0xA2
TAG_CONTEXT_3 = 0xA3


def encode_length(length: int) -> bytes:
    """Encode ASN.1 DER length."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode ASN.1 DER length. Returns (length, new_offset)."""
    if data[offset] < 0x80:
        return (data[offset], offset + 1)
    num_bytes = data[offset] & 0x7F
    offset += 1
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + i]
    return (length, offset + num_bytes)


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a TLV (Tag-Length-Value) triplet."""
    return bytes([tag]) + encode_length(len(value)) + value


def decode_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Decode a TLV. Returns (tag, value, new_offset)."""
    tag = data[offset]
    offset += 1
    length, offset = decode_length(data, offset)
    value = data[offset:offset + length]
    return (tag, value, offset + length)


def encode_integer(value: int) -> bytes:
    """Encode an integer as ASN.1 DER INTEGER."""
    if value == 0:
        return encode_tlv(TAG_INTEGER, b'\x00')
    if value > 0:
        b = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
    else:
        byte_len = (value.bit_length() + 8) // 8
        b = value.to_bytes(byte_len, 'big', signed=True)
    return encode_tlv(TAG_INTEGER, b)


def decode_integer(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode ASN.1 DER INTEGER. Returns (value, new_offset)."""
    tag, value, new_offset = decode_tlv(data, offset)
    assert tag == TAG_INTEGER
    return (int.from_bytes(value, 'big', signed=True if value[0] & 0x80 else False), new_offset)


def encode_octet_string(value: bytes) -> bytes:
    return encode_tlv(TAG_OCTET_STRING, value)


def encode_bit_string(value: bytes, unused_bits: int = 0) -> bytes:
    return encode_tlv(TAG_BIT_STRING, bytes([unused_bits]) + value)


def encode_oid(oid: tuple[int, ...]) -> bytes:
    """Encode OID as DER."""
    encoded = bytes([40 * oid[0] + oid[1]])
    for component in oid[2:]:
        if component < 0x80:
            encoded += bytes([component])
        else:
            parts = []
            while component > 0:
                parts.append(component & 0x7F)
                component >>= 7
            parts.reverse()
            for i in range(len(parts) - 1):
                encoded += bytes([parts[i] | 0x80])
            encoded += bytes([parts[-1]])
    return encode_tlv(TAG_OID, encoded)


def decode_oid(data: bytes, offset: int = 0) -> tuple[tuple[int, ...], int]:
    """Decode OID from DER."""
    tag, value, new_offset = decode_tlv(data, offset)
    assert tag == TAG_OID
    oid = [value[0] // 40, value[0] % 40]
    i = 1
    while i < len(value):
        component = 0
        while value[i] & 0x80:
            component = (component << 7) | (value[i] & 0x7F)
            i += 1
        component = (component << 7) | value[i]
        oid.append(component)
        i += 1
    return (tuple(oid), new_offset)


def encode_sequence(items: list[bytes]) -> bytes:
    return encode_tlv(TAG_SEQUENCE, b''.join(items))


def encode_set(items: list[bytes]) -> bytes:
    return encode_tlv(TAG_SET, b''.join(items))


def encode_utf8_string(value: str) -> bytes:
    return encode_tlv(TAG_UTF8_STRING, value.encode('utf-8'))


def encode_printable_string(value: str) -> bytes:
    return encode_tlv(TAG_PRINTABLE_STRING, value.encode('ascii'))


def encode_utc_time(value: str) -> bytes:
    """value should be like '230101000000Z'."""
    return encode_tlv(TAG_UTC_TIME, value.encode('ascii'))


def encode_null() -> bytes:
    return encode_tlv(TAG_NULL, b'')


def encode_context(tag_num: int, value: bytes, constructed: bool = True) -> bytes:
    """Encode context-specific tag."""
    tag = 0xA0 | tag_num if constructed else 0x80 | tag_num
    return bytes([tag]) + encode_length(len(value)) + value
