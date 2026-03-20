#!/usr/bin/env python3
"""Boundary and lightweight timing checks."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_LIB = Path(__file__).resolve().parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))

from gmssl.hazmat.primitives import hashes
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
from jsonlog import CaseRecord, append_jsonl, results_dir, write_aggregate


def main() -> int:
    results_dir()
    cases: list[dict] = []

    def add(rec: CaseRecord) -> None:
        append_jsonl(rec)
        cases.append(rec.to_json_dict())

    # SM3 empty
    t0 = time.perf_counter()
    try:
        h = hashes.Hash(hashes.SM3())
        h.update(b"")
        d = h.finalize()
        ok = len(d) == 32
        err = None
    except Exception as e:
        ok, err = False, str(e)
    add(
        CaseRecord(
            id="BND-SM3-EMPTY",
            tool="pygmssl",
            inputs={},
            parsed={"duration_ms": (time.perf_counter() - t0) * 1000},
            pass_=ok,
            error=err,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    )

    # SM4 wrong key size
    t0 = time.perf_counter()
    try:
        Cipher(algorithms.SM4(b"\x00" * 15), modes.ECB())
        ok, err = False, "expected error"
    except Exception:
        ok, err = True, None
    add(
        CaseRecord(
            id="BND-SM4-KEY-15",
            tool="pygmssl",
            inputs={"key_len": 15},
            pass_=ok,
            error=err,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    )

    # SM4 GCM nonce wrong length (not 12) — may use GHASH path
    t0 = time.perf_counter()
    try:
        c = Cipher(algorithms.SM4(b"\x00" * 16), modes.GCM(b"\x00" * 8))
        e = c.encryptor()
        e.update(b"1234567890123456")
        e.finalize()
        ok, err = True, None
    except Exception as e:
        ok, err = False, str(e)
    add(
        CaseRecord(
            id="BND-SM4-GCM-IV8",
            tool="pygmssl",
            inputs={"nonce_len": 8},
            pass_=ok,
            error=err,
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    )

    # Simple perf: 256 KiB SM3
    chunk = b"\xcd" * 4096
    t0 = time.perf_counter()
    try:
        h = hashes.Hash(hashes.SM3())
        for _ in range(64):
            h.update(chunk)
        h.finalize()
        ms = (time.perf_counter() - t0) * 1000
        ok, err = True, None
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        ok, err = False, str(e)
    add(
        CaseRecord(
            id="PERF-SM3-256KIB",
            tool="pygmssl",
            inputs={"bytes": 4096 * 64},
            parsed={"duration_ms": ms},
            pass_=ok,
            error=err,
            duration_ms=ms,
        )
    )

    write_aggregate(cases, "aggregate_boundaries.json")
    failed = [c for c in cases if not c.get("pass")]
    print(json.dumps({"cases": len(cases), "failed": len(failed)}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
