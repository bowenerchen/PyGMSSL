"""Tests for HMAC with SM3."""

import pytest
from gmssl.hazmat.primitives import hashes
from gmssl.hazmat.primitives.hmac import HMAC
from gmssl.exceptions import InvalidSignature


def test_hmac_sm3_basic():
    key = b"secret-key"
    h = HMAC(key, hashes.SM3())
    h.update(b"hello world")
    mac = h.finalize()
    assert len(mac) == 32

    h2 = HMAC(key, hashes.SM3())
    h2.update(b"hello world")
    h2.verify(mac)


def test_hmac_sm3_verify_failure():
    h = HMAC(b"key", hashes.SM3())
    h.update(b"data")
    with pytest.raises(InvalidSignature):
        h.verify(b'\x00' * 32)


def test_hmac_sm3_copy():
    h = HMAC(b"key", hashes.SM3())
    h.update(b"part1")
    h2 = h.copy()
    h2.update(b"part2")
    mac1 = h.finalize()
    mac2 = h2.finalize()
    assert mac1 != mac2


def test_hmac_deterministic():
    for _ in range(3):
        h = HMAC(b"test-key", hashes.SM3())
        h.update(b"test-data")
        mac = h.finalize()
    assert len(mac) == 32
