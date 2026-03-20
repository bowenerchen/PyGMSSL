"""
Symmetric cipher framework – Cipher context with encryptor/decryptor.

Usage::

    from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
"""

from __future__ import annotations

from gmssl.exceptions import AlreadyFinalized, NotYetFinalized
from gmssl.hazmat.primitives.ciphers.algorithms import SM4, CipherAlgorithm
from gmssl.hazmat.primitives.ciphers.modes import CBC, CTR, ECB, GCM, Mode
from gmssl._backends._sm4 import (
    sm4_key_schedule, sm4_encrypt_block, sm4_decrypt_block,
    sm4_ecb_encrypt, sm4_ecb_decrypt,
    sm4_cbc_encrypt, sm4_cbc_decrypt,
    sm4_ctr_encrypt, BLOCK_SIZE,
)


class _CipherContext:
    """Base context implementing the update/finalize streaming pattern."""

    def __init__(self, algorithm: CipherAlgorithm, mode: Mode, encrypt: bool) -> None:
        self._algorithm = algorithm
        self._mode = mode
        self._encrypt = encrypt
        self._finalized = False
        self._buf = bytearray()

        if isinstance(algorithm, SM4):
            self._rk = sm4_key_schedule(algorithm.key)
        else:
            raise NotImplementedError(f"Algorithm {algorithm.name} not yet supported")

        if isinstance(mode, GCM):
            from gmssl._backends._gcm import GCMState
            self._gcm = GCMState(self._rk, mode.iv, sm4_encrypt_block)
            self._gcm_aad_done = False
            self._tag: bytes | None = mode.tag if not encrypt else None
            self._computed_tag: bytes | None = None
        else:
            self._gcm = None

    def authenticate_additional_data(self, data: bytes) -> None:
        if self._gcm is None:
            raise TypeError("authenticate_additional_data is only for GCM mode")
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._gcm.update_aad(data)

    def update(self, data: bytes) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")

        if self._gcm is not None:
            if not self._gcm_aad_done:
                self._gcm.finalize_aad()
                self._gcm_aad_done = True
            if self._encrypt:
                return self._gcm.encrypt(data)
            else:
                return self._gcm.decrypt(data)

        self._buf.extend(data)
        mode = self._mode
        bs = BLOCK_SIZE

        if isinstance(mode, ECB):
            n = (len(self._buf) // bs) * bs
            if n == 0:
                return b""
            to_process = bytes(self._buf[:n])
            del self._buf[:n]
            if self._encrypt:
                return sm4_ecb_encrypt(self._rk, to_process)
            else:
                return sm4_ecb_decrypt(self._rk, to_process)

        elif isinstance(mode, CBC):
            if not hasattr(self, '_cbc_iv'):
                self._cbc_iv = bytearray(mode.iv)
            n = (len(self._buf) // bs) * bs
            if not self._encrypt:
                n = max(n - bs, 0)
            if n == 0:
                return b""
            to_process = bytes(self._buf[:n])
            del self._buf[:n]
            if self._encrypt:
                result = sm4_cbc_encrypt(self._rk, bytes(self._cbc_iv), to_process)
                self._cbc_iv = bytearray(result[-bs:])
            else:
                result = sm4_cbc_decrypt(self._rk, bytes(self._cbc_iv), to_process)
                self._cbc_iv = bytearray(to_process[-bs:])
            return result

        elif isinstance(mode, CTR):
            if not hasattr(self, '_ctr'):
                self._ctr = bytearray(mode.nonce)
                self._ctr_ks_buf = bytearray()
            to_process = bytes(self._buf)
            self._buf.clear()
            result, self._ctr_ks_buf = sm4_ctr_encrypt(
                self._rk, self._ctr, to_process, self._ctr_ks_buf)
            return result

        raise NotImplementedError(f"Mode {mode.name} not supported")

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._finalized = True

        if self._gcm is not None:
            if not self._gcm_aad_done:
                self._gcm.finalize_aad()
            rest = b""
            if self._buf:
                if self._encrypt:
                    rest = self._gcm.encrypt(bytes(self._buf))
                else:
                    rest = self._gcm.decrypt(bytes(self._buf))
                self._buf.clear()
            self._computed_tag = self._gcm.finish()
            if not self._encrypt:
                if self._tag is None:
                    raise ValueError(
                        "Authentication tag must be provided when decrypting in GCM mode"
                    )
                from gmssl._backends._utils import constant_time_compare
                truncated = self._computed_tag[:len(self._tag)]
                if not constant_time_compare(truncated, self._tag):
                    from gmssl.exceptions import InvalidTag
                    raise InvalidTag("GCM tag mismatch")
            return rest

        mode = self._mode

        if isinstance(mode, ECB):
            if self._buf:
                raise ValueError("Data not block-aligned for ECB finalize")
            return b""

        elif isinstance(mode, CBC):
            if self._encrypt:
                from gmssl.hazmat.primitives.padding import PKCS7
                padder = PKCS7(128).padder()
                padded = padder.update(bytes(self._buf)) + padder.finalize()
                self._buf.clear()
                return sm4_cbc_encrypt(self._rk, bytes(self._cbc_iv), padded)
            else:
                if not self._buf:
                    raise ValueError("No final block for CBC decryption")
                pt = sm4_cbc_decrypt(self._rk, bytes(self._cbc_iv), bytes(self._buf))
                self._buf.clear()
                from gmssl.hazmat.primitives.padding import PKCS7
                unpadder = PKCS7(128).unpadder()
                return unpadder.update(pt) + unpadder.finalize()

        elif isinstance(mode, CTR):
            remaining = bytes(self._buf)
            self._buf.clear()
            if remaining:
                result, _ = sm4_ctr_encrypt(
                    self._rk, self._ctr, remaining, self._ctr_ks_buf)
                return result
            return b""

        raise NotImplementedError(f"Mode {mode.name} not supported")

    @property
    def tag(self) -> bytes:
        """The authentication tag (GCM only, available after finalize)."""
        if self._gcm is None:
            raise TypeError("tag is only available for GCM mode")
        if not self._finalized:
            raise NotYetFinalized("Tag not available until finalize() is called.")
        assert self._computed_tag is not None
        return self._computed_tag


class Cipher:
    """
    Symmetric cipher combining an algorithm and a mode of operation.

    Create an encryptor or decryptor context for streaming encryption.
    """

    def __init__(self, algorithm: CipherAlgorithm, mode: Mode) -> None:
        self._algorithm = algorithm
        self._mode = mode

    def encryptor(self) -> _CipherContext:
        return _CipherContext(self._algorithm, self._mode, encrypt=True)

    def decryptor(self) -> _CipherContext:
        return _CipherContext(self._algorithm, self._mode, encrypt=False)
