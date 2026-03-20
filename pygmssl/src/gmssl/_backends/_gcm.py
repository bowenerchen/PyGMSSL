"""GCM authenticated encryption mode."""

import struct
from gmssl._backends._gf128 import gf128_mul, bytes_to_gf128, gf128_to_bytes
from gmssl._backends._utils import xor_bytes

BLOCK_SIZE = 16


def _inc32(counter: bytearray) -> None:
    """Increment last 4 bytes of counter (32-bit big-endian) in place."""
    c = int.from_bytes(counter[12:16], "big")
    c = (c + 1) & 0xFFFFFFFF
    counter[12:16] = c.to_bytes(4, "big")


class GCMState:
    """State for GCM authenticated encryption/decryption."""

    def __init__(self, rk: list[int], iv: bytes, encrypt_block_fn):
        self._rk = rk
        self._encrypt_block = encrypt_block_fn

        zero_block = bytes(BLOCK_SIZE)
        H_bytes = encrypt_block_fn(rk, zero_block)
        self._H = bytes_to_gf128(H_bytes)

        if len(iv) == 12:
            self._j0 = bytearray(iv) + b"\x00\x00\x00\x01"
        else:
            self._j0 = self._ghash_iv(iv)

        self._counter = bytearray(self._j0)
        _inc32(self._counter)

        self._ghash_x = 0
        self._aad_done = False
        self._aad_len = 0
        self._c_len = 0

        self._aad_buf = bytearray()
        self._ct_ghash_buf = bytearray()
        self._ks_buf = bytearray()

    def _ghash_iv(self, iv: bytes) -> bytes:
        x = 0
        for i in range(0, len(iv), BLOCK_SIZE):
            block = iv[i : i + BLOCK_SIZE]
            if len(block) < BLOCK_SIZE:
                block = block + bytes(BLOCK_SIZE - len(block))
            ai = bytes_to_gf128(block)
            x = gf128_mul(x ^ ai, self._H)
        len_block = struct.pack(">QQ", 0, len(iv) * 8)
        x = gf128_mul(x ^ bytes_to_gf128(len_block), self._H)
        return gf128_to_bytes(x)

    def _ghash_block_update(self, block: bytes) -> None:
        ai = bytes_to_gf128(block)
        self._ghash_x = gf128_mul(self._ghash_x ^ ai, self._H)

    def _flush_ghash_buf(self, buf: bytearray, pad_final: bool) -> None:
        """Flush full blocks from buf through GHASH; optionally pad the last partial block."""
        while len(buf) >= BLOCK_SIZE:
            self._ghash_block_update(bytes(buf[:BLOCK_SIZE]))
            del buf[:BLOCK_SIZE]
        if pad_final and buf:
            padded = bytes(buf) + bytes(BLOCK_SIZE - len(buf))
            self._ghash_block_update(padded)
            buf.clear()

    def update_aad(self, aad: bytes) -> None:
        if self._aad_done:
            raise ValueError("AAD already finalized")
        self._aad_len += len(aad)
        self._aad_buf.extend(aad)
        self._flush_ghash_buf(self._aad_buf, pad_final=False)

    def finalize_aad(self) -> None:
        if not self._aad_done:
            self._flush_ghash_buf(self._aad_buf, pad_final=True)
            self._aad_done = True

    def _ensure_aad_finalized(self) -> None:
        if not self._aad_done:
            self.finalize_aad()

    def _get_keystream(self, n: int) -> bytes:
        """Get exactly n bytes of keystream, using buffer for continuity."""
        out = bytearray()
        while len(out) < n:
            if not self._ks_buf:
                self._ks_buf = bytearray(
                    self._encrypt_block(self._rk, bytes(self._counter))
                )
                _inc32(self._counter)
            take = min(len(self._ks_buf), n - len(out))
            out.extend(self._ks_buf[:take])
            del self._ks_buf[:take]
        return bytes(out)

    def encrypt(self, plaintext: bytes) -> bytes:
        self._ensure_aad_finalized()
        ks = self._get_keystream(len(plaintext))
        ct = xor_bytes(plaintext, ks)
        self._c_len += len(ct)
        self._ct_ghash_buf.extend(ct)
        self._flush_ghash_buf(self._ct_ghash_buf, pad_final=False)
        return ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        self._ensure_aad_finalized()
        self._c_len += len(ciphertext)
        self._ct_ghash_buf.extend(ciphertext)
        self._flush_ghash_buf(self._ct_ghash_buf, pad_final=False)
        ks = self._get_keystream(len(ciphertext))
        return xor_bytes(ciphertext, ks)

    def finish(self) -> bytes:
        self._flush_ghash_buf(self._ct_ghash_buf, pad_final=True)

        len_block = struct.pack(">QQ", self._aad_len * 8, self._c_len * 8)
        x = gf128_mul(self._ghash_x ^ bytes_to_gf128(len_block), self._H)
        mac = gf128_to_bytes(x)

        mask = self._encrypt_block(self._rk, bytes(self._j0))
        tag = xor_bytes(mac, mask)
        return tag
