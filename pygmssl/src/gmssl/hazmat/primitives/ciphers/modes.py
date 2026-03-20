"""Block cipher modes of operation."""

from __future__ import annotations
from typing import Optional


class Mode:
    name: str


class ECB(Mode):
    name = "ECB"


class CBC(Mode):
    name = "CBC"

    def __init__(self, iv: bytes) -> None:
        if len(iv) != 16:
            raise ValueError(f"CBC IV must be 16 bytes, got {len(iv)}")
        self._iv = iv

    @property
    def iv(self) -> bytes:
        return self._iv


class CTR(Mode):
    name = "CTR"

    def __init__(self, nonce: bytes) -> None:
        if len(nonce) != 16:
            raise ValueError(f"CTR nonce must be 16 bytes, got {len(nonce)}")
        self._nonce = nonce

    @property
    def nonce(self) -> bytes:
        return self._nonce


class GCM(Mode):
    name = "GCM"

    def __init__(self, iv: bytes, tag: Optional[bytes] = None,
                 min_tag_length: int = 12) -> None:
        if not (1 <= len(iv) <= 64):
            raise ValueError(f"GCM IV must be 1-64 bytes, got {len(iv)}")
        if min_tag_length < 4:
            raise ValueError("min_tag_length must be >= 4")
        if tag is not None and len(tag) < min_tag_length:
            raise ValueError(
                f"Authentication tag must be at least {min_tag_length} bytes, got {len(tag)}"
            )
        self._iv = iv
        self._tag = tag
        self._min_tag_length = min_tag_length

    @property
    def iv(self) -> bytes:
        return self._iv

    @property
    def tag(self) -> Optional[bytes]:
        return self._tag
