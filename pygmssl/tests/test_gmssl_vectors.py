"""
Known-answer tests aligned with GmSSL-3.1.1 test programs (sm3test.c, sm4test.c).

Vectors are copied from GmSSL test sources for regression against that implementation.
"""

import pytest
from gmssl.hazmat.primitives import hashes
from gmssl._backends._sm4 import (
    sm4_key_schedule,
    sm4_encrypt_block,
)


class TestSM3GmSSLVectors:
    """Digest cases 1–2 from GmSSL-3.1.1/tests/sm3test.c (dgsthex[0], dgsthex[1])."""

    @pytest.mark.parametrize(
        "msg_hex,expected_hex",
        [
            (
                "616263",
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            ),
            (
                "6162636461626364616263646162636461626364616263646162636461626364"
                "6162636461626364616263646162636461626364616263646162636461626364",
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
            ),
        ],
    )
    def test_sm3_digest_matches_gmssl(self, msg_hex, expected_hex):
        data = bytes.fromhex(msg_hex)
        expected = bytes.fromhex(expected_hex)
        h = hashes.Hash(hashes.SM3())
        h.update(data)
        assert h.finalize() == expected


class TestSM4GmSSLVectors:
    """Block encrypt from GmSSL-3.1.1/tests/sm4test.c test_sm4()."""

    def test_sm4_key_schedule_and_block_encrypt(self):
        user_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        plaintext = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        expected_ct = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")
        rk = sm4_key_schedule(user_key)
        ct = sm4_encrypt_block(rk, plaintext)
        assert ct == expected_ct
