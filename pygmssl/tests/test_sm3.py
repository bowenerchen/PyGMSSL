"""Tests for SM3 hash algorithm – vectors from GM/T 0004-2012 and GmSSL test suite."""

import pytest
from gmssl.hazmat.primitives import hashes
from gmssl.exceptions import AlreadyFinalized


# --- GM/T 0004-2012 standard test vectors ---

def test_sm3_abc():
    """Standard vector: SM3("abc")."""
    h = hashes.Hash(hashes.SM3())
    h.update(b"abc")
    assert h.finalize().hex() == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def test_sm3_64byte_repeated():
    """Standard vector: SM3("abcd" * 16)."""
    h = hashes.Hash(hashes.SM3())
    h.update(b"abcd" * 16)
    assert h.finalize().hex() == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"


# --- Incremental update ---

def test_sm3_incremental():
    """update() called multiple times should produce the same result."""
    h1 = hashes.Hash(hashes.SM3())
    h1.update(b"abc")

    h2 = hashes.Hash(hashes.SM3())
    h2.update(b"a")
    h2.update(b"bc")

    assert h1.finalize() == h2.finalize()


# --- Empty input ---

def test_sm3_empty():
    h = hashes.Hash(hashes.SM3())
    digest = h.finalize()
    assert len(digest) == 32
    assert digest.hex() == "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"


# --- Copy ---

def test_sm3_copy():
    h = hashes.Hash(hashes.SM3())
    h.update(b"abc")
    h2 = h.copy()
    h2.update(b"def")
    d1 = h.finalize()
    d2 = h2.finalize()
    assert d1 != d2
    assert len(d1) == 32
    assert len(d2) == 32


# --- Already finalized ---

def test_sm3_double_finalize_raises():
    h = hashes.Hash(hashes.SM3())
    h.update(b"test")
    h.finalize()
    with pytest.raises(AlreadyFinalized):
        h.finalize()


def test_sm3_update_after_finalize_raises():
    h = hashes.Hash(hashes.SM3())
    h.finalize()
    with pytest.raises(AlreadyFinalized):
        h.update(b"data")


# --- Large data ---

def test_sm3_large_data():
    """Hash 1 MB of zeros."""
    h = hashes.Hash(hashes.SM3())
    h.update(b'\x00' * (1024 * 1024))
    digest = h.finalize()
    assert len(digest) == 32


# --- Algorithm properties ---

def test_sm3_algorithm_properties():
    alg = hashes.SM3()
    assert alg.name == "sm3"
    assert alg.digest_size == 32
    assert alg.block_size == 64


# --- GmSSL test vectors (hex-encoded inputs) ---

class TestGmSSLVectors:
    """Test vectors from GmSSL sm3test.c (selected subset)."""

    VECTORS = [
        (
            "616263",
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        ),
        (
            "6162636461626364616263646162636461626364616263646162636461626364"
            "6162636461626364616263646162636461626364616263646162636461626364",
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        ),
    ]

    @pytest.mark.parametrize("msg_hex,digest_hex", VECTORS)
    def test_vector(self, msg_hex: str, digest_hex: str):
        h = hashes.Hash(hashes.SM3())
        h.update(bytes.fromhex(msg_hex))
        assert h.finalize().hex() == digest_hex.lower()
