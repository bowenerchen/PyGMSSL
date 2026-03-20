#!/usr/bin/env python3
"""ZUC-128 vs eet; ZUC-256 vectors (pygmssl only)."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

_LIB = Path(__file__).resolve().parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))

from gmssl._backends._zuc import ZUC256State, ZUCState
from jsonlog import CaseRecord, append_jsonl, results_dir, timed_block, write_aggregate

EET = "eet"


def _eet_json(args: list[str]) -> dict:
    env = {**os.environ, "NO_COLOR": "1"}
    out = subprocess.check_output([EET, *args], text=True, env=env)
    return json.loads(out)


def main() -> int:
    results_dir()
    cases: list[dict] = []

    def add(rec: CaseRecord) -> None:
        append_jsonl(rec)
        cases.append(rec.to_json_dict())

    key = b"0123456789012345"
    iv = b"0123456789012345"
    for pt in [b"short", b"zuc-test-plain", b"x" * 100]:
        with timed_block() as dur:
            try:
                z = ZUCState(key, iv)
                py_ct = z.encrypt(pt)
                py_b64 = base64.b64encode(py_ct).decode("ascii")
                d = _eet_json(
                    [
                        "zuc",
                        "-k",
                        key.decode(),
                        "-v",
                        iv.decode(),
                        "-A",
                        "encrypt",
                        "-i",
                        pt.decode(),
                        "--json",
                    ]
                )
                eet_b64 = d["result"]["cipher"]
                ok = py_b64 == eet_b64
                err = None if ok else "zuc mismatch"
            except Exception as e:
                ok, err = False, str(e)
        add(
            CaseRecord(
                id=f"ZUC128-EET-{len(pt)}",
                tool="both",
                inputs={"pt_len": len(pt)},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    vectors = [
        (b"\x00" * 16, b"\x00" * 16, [0x27BEDE74, 0x018082DA]),
        (b"\xFF" * 16, b"\xFF" * 16, [0x0657CFA0, 0x7096398B]),
    ]
    for i, (k, v, exp) in enumerate(vectors):
        with timed_block() as dur:
            try:
                st = ZUCState(k, v)
                w = st.generate_keystream(2)
                ok = w == exp
                err = None if ok else str(w)
            except Exception as e:
                ok, err = False, str(e)
        add(
            CaseRecord(
                id=f"ZUC128-VEC-{i}",
                tool="pygmssl",
                inputs={"key": k.hex(), "iv": v.hex()},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    for label, k, v, exp4 in [
        ("ZUC256-ZERO", b"\x00" * 32, b"\x00" * 23, [0x58D03AD6, 0x2E032CE2, 0xDAFC683A, 0x39BDCB03]),
        ("ZUC256-ONES", b"\xFF" * 32, b"\xFF" * 23, [0x3356CBAE, 0xD1A1C18B, 0x6BAA4FFE, 0x343F777C]),
    ]:
        with timed_block() as dur:
            try:
                st = ZUC256State(k, v)
                w = st.generate_keystream(4)
                ok = w == exp4
                err = None if ok else str([hex(x) for x in w])
            except Exception as e:
                ok, err = False, str(e)
        add(
            CaseRecord(
                id=label,
                tool="pygmssl",
                inputs={"note": "no eet counterpart for ZUC-256"},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    write_aggregate(cases, "aggregate_zuc.json")
    failed = [c for c in cases if not c.get("pass")]
    print(json.dumps({"cases": len(cases), "failed": len(failed)}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
