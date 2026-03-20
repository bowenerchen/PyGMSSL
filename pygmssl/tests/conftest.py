"""Pytest configuration: help locate GmSSL for SM9 ctypes backend."""

import os
import sys
from pathlib import Path


def pytest_configure(config):
    if os.environ.get("PYGMSSL_GMSSL_LIBRARY"):
        return
    here = Path(__file__).resolve().parent
    root = here.parent
    if sys.platform == "darwin":
        candidate = root.parent / "GmSSL-3.1.1" / "build" / "bin" / "libgmssl.dylib"
    else:
        candidate = root.parent / "GmSSL-3.1.1" / "build" / "bin" / "libgmssl.so"
    if candidate.is_file():
        os.environ.setdefault("PYGMSSL_GMSSL_LIBRARY", str(candidate))
