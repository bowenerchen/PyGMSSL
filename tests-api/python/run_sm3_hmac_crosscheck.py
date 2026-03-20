#!/usr/bin/env python3
"""SM3 / HMAC-SM3: compare pygmssl vs eet; chunked Hash.update vs one-shot."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_LIB = Path(__file__).resolve().parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))

from gmssl.hazmat.primitives import hashes, hmac
from jsonlog import CaseRecord, append_jsonl, results_dir, timed_block, write_aggregate

EET = "eet"


def _eet_json(args: list[str]) -> dict:
    env = {**os.environ, "NO_COLOR": "1"}
    out = subprocess.check_output([EET, *args], text=True, env=env)
    return json.loads(out)


def _sm3_py(data: bytes) -> str:
    h = hashes.Hash(hashes.SM3())
    h.update(data)
    return h.finalize().hex()


def main() -> int:
    results_dir()
    cases: list[dict] = []

    def add(rec: CaseRecord) -> None:
        append_jsonl(rec)
        cases.append(rec.to_json_dict())

    lengths = [0, 1, 55, 56, 64, 65, 128, 1024, 1024 * 1024]
    for n in lengths:
        data = b"a" * n if n else b""
        with timed_block() as dur:
            try:
                py_d = _sm3_py(data)
                if n <= 4096:
                    d = _eet_json(["hash", "-a", "sm3", "-i", data.decode(), "--json"])
                else:
                    p = results_dir() / f"sm3_input_{n}.bin"
                    p.write_bytes(data)
                    d = _eet_json(
                        ["hash", "-a", "sm3", "-i", str(p), "-f", "-l", "256", "--json"]
                    )
                eet_d = d["result"]["digest"].lower()
                ok = py_d == eet_d
                err = None if ok else f"{py_d[:16]} vs {eet_d[:16]}"
            except Exception as e:
                ok, err = False, str(e)
        add(
            CaseRecord(
                id=f"SM3-LEN-{n}",
                tool="both",
                inputs={"byte_len": n},
                parsed={"digest_hex_py": py_d if ok else None},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    # 1 MiB via file + high limit
    big_path = results_dir() / "large_sm3_input.bin"
    big_path.write_bytes(b"\x5a" * (1024 * 1024 + 1))
    with timed_block() as dur:
        try:
            py_d = _sm3_py(big_path.read_bytes())
            d = _eet_json(
                ["hash", "-a", "sm3", "-i", str(big_path), "-f", "-l", "8", "--json"]
            )
            eet_d = d["result"]["digest"].lower()
            ok = py_d == eet_d
            err = None if ok else "large file mismatch"
        except Exception as e:
            ok, err = False, str(e)
    add(
        CaseRecord(
            id="SM3-LARGE-FILE",
            tool="both",
            inputs={"path": str(big_path), "size": big_path.stat().st_size},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # Chunked vs one-shot SM3
    blob = os.urandom(5000)
    with timed_block() as dur:
        try:
            h1 = hashes.Hash(hashes.SM3())
            for i in range(0, len(blob), 137):
                h1.update(blob[i : i + 137])
            d1 = h1.finalize()
            d2 = _sm3_py(blob)
            ok = d1.hex() == d2
            err = None if ok else "chunk mismatch"
        except Exception as e:
            ok, err = False, str(e)
    add(
        CaseRecord(
            id="SM3-CHUNK-5000",
            tool="pygmssl",
            inputs={"chunksize": 137},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # HMAC-SM3 fixed key
    key = b"01234567890123456789012345678901"
    msg = b"hmac-sm3-message-body"
    with timed_block() as dur:
        try:
            hm = hmac.HMAC(key, hashes.SM3())
            hm.update(msg)
            tag = hm.finalize()
            py_hex = tag.hex()
            d = _eet_json(
                [
                    "hmac",
                    "-a",
                    "sm3",
                    "-k",
                    key.decode(),
                    "-i",
                    msg.decode(),
                    "--json",
                ]
            )
            eet_hex = d["result"]["hmac"].lower()
            ok = py_hex == eet_hex
            err = None if ok else "hmac mismatch"
        except Exception as e:
            ok, err = False, str(e)
    add(
        CaseRecord(
            id="HMAC-SM3-FIXED",
            tool="both",
            inputs={"key_len": len(key), "msg_len": len(msg)},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # eet random key path: parse key from JSON if present
    with timed_block() as dur:
        try:
            import base64

            d = _eet_json(["hmac", "-a", "sm3", "-r", "-i", "random-key-msg", "--json"])
            key2 = base64.b64decode(d["result"]["key"])
            tag_eet = bytes.fromhex(d["result"]["hmac"])
            hm = hmac.HMAC(key2, hashes.SM3())
            hm.update(b"random-key-msg")
            tag_py = hm.finalize()
            ok = tag_py == tag_eet
            err = None if ok else "random key hmac mismatch"
        except Exception as e:
            ok, err = False, str(e)
    add(
        CaseRecord(
            id="HMAC-SM3-RANDOM-KEY",
            tool="both",
            inputs={"flow": "eet -r then pygmssl verify"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    write_aggregate(cases, "aggregate_sm3_hmac.json")
    failed = [c for c in cases if not c.get("pass")]
    print(json.dumps({"cases": len(cases), "failed": len(failed)}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
