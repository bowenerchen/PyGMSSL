#!/usr/bin/env python3
"""SM4: CBC/GCM match eet; ECB/CTR + GM/T vector self-tests."""

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

from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

    # --- CBC cross eet ---
    key = b"0123456789012345"
    iv = b"0123456789012345"
    cbc_cases = [
        ("SM4-CBC-EMPTY", b""),
        ("SM4-CBC-1", b"a"),
        ("SM4-CBC-STD", b"hello-sm4-cbc"),
        ("SM4-CBC-17", b"x" * 17),
    ]
    for cid, pt in cbc_cases:
        with timed_block() as dur:
            try:
                cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
                enc = cipher.encryptor()
                py_ct = enc.update(pt) + enc.finalize()
                py_b64 = base64.b64encode(py_ct).decode("ascii")
                if len(pt) == 0:
                    # eet v2.5.0 rejects empty -i for sm4 encrypt
                    ok, err = True, None
                    parsed = {"cipher_b64_py": py_b64, "eet": "skipped_empty_input"}
                else:
                    d = _eet_json(
                        [
                            "sm4",
                            "-m",
                            "cbc",
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
                    err = None if ok else f"mismatch py={py_b64[:40]} eet={eet_b64[:40]}"
                    parsed = {"cipher_b64": py_b64 if ok else None}
            except Exception as e:
                ok = False
                err = str(e)
                parsed = None
        add(
            CaseRecord(
                id=cid,
                tool="both" if len(pt) else "pygmssl",
                inputs={"pt_len": len(pt), "key": key.hex(), "iv": iv.hex()},
                parsed=parsed,
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    # --- GCM cross eet (ct||tag) ---
    key = b"0123456789012345"
    nonce = b"012345678901"
    aad = b"tests-api-aad"
    gcm_cases = [
        ("SM4-GCM-EMPTY", b""),
        ("SM4-GCM-SHORT", b"gcm-plain"),
        ("SM4-GCM-50", b"y" * 50),
    ]
    for cid, pt in gcm_cases:
        with timed_block() as dur:
            try:
                cipher = Cipher(algorithms.SM4(key), modes.GCM(nonce))
                enc = cipher.encryptor()
                enc.authenticate_additional_data(aad)
                ct = enc.update(pt) + enc.finalize()
                tag = enc.tag
                combined = base64.b64encode(ct + tag).decode("ascii")
                if len(pt) == 0:
                    ok, err = True, None
                    parsed = {"cipher_tag_b64_py": combined, "eet": "skipped_empty_input"}
                else:
                    d = _eet_json(
                        [
                            "sm4",
                            "-m",
                            "gcm",
                            "-k",
                            key.decode(),
                            "-v",
                            nonce.decode(),
                            "--aad",
                            aad.decode(),
                            "-A",
                            "encrypt",
                            "-i",
                            pt.decode(),
                            "--json",
                        ]
                    )
                    eet_b64 = d["result"]["cipher"]
                    ok = combined == eet_b64
                    err = None if ok else "gcm mismatch"
                    parsed = None
            except Exception as e:
                ok = False
                err = str(e)
                parsed = None
        add(
            CaseRecord(
                id=cid,
                tool="both" if len(pt) else "pygmssl",
                inputs={"pt_len": len(pt), "nonce": nonce.hex(), "aad": aad.decode()},
                parsed=parsed,
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    # --- ECB GM/T block ---
    USER_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    PLAINTEXT = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    EXPECTED_CT = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")
    with timed_block() as dur:
        try:
            cipher = Cipher(algorithms.SM4(USER_KEY), modes.ECB())
            enc = cipher.encryptor()
            ct = enc.update(PLAINTEXT) + enc.finalize()
            assert ct == EXPECTED_CT
            dec = Cipher(algorithms.SM4(USER_KEY), modes.ECB()).decryptor()
            pt = dec.update(ct) + dec.finalize()
            assert pt == PLAINTEXT
            ok, err = True, None
        except Exception as e:
            ok, err = False, str(e)
    add(
        CaseRecord(
            id="SM4-ECB-GMT",
            tool="pygmssl",
            inputs={"vector": "GM/T 0002-2012 single block"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- CTR roundtrip ---
    with timed_block() as dur:
        try:
            k = b"\xab" * 16
            n = b"\x00" * 16
            data = os.urandom(100)
            c = Cipher(algorithms.SM4(k), modes.CTR(n))
            e = c.encryptor()
            ct = e.update(data) + e.finalize()
            d = Cipher(algorithms.SM4(k), modes.CTR(n)).decryptor()
            pt = d.update(ct) + d.finalize()
            assert pt == data
            ok, err = True, None
        except Exception as e:
            ok, err = False, str(e)
    add(
        CaseRecord(
            id="SM4-CTR-RT",
            tool="pygmssl",
            inputs={"len": 100},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- GCM bad tag ---
    with timed_block() as dur:
        try:
            from gmssl.exceptions import InvalidTag

            k = b"\x00" * 16
            iv = b"\x00" * 12
            c = Cipher(algorithms.SM4(k), modes.GCM(iv))
            e = c.encryptor()
            ct = e.update(b"hello world12345") + e.finalize()
            bad = b"\xff" * 16
            dctx = Cipher(algorithms.SM4(k), modes.GCM(iv, bad)).decryptor()
            dctx.update(ct)
            dctx.finalize()
            ok, err = False, "expected InvalidTag"
        except InvalidTag:
            ok, err = True, None
        except Exception as e:
            ok, err = False, str(e)
    add(
        CaseRecord(
            id="SM4-GCM-BADTAG",
            tool="pygmssl",
            inputs={"expect": "InvalidTag"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    write_aggregate(cases, "aggregate_sm4.json")
    failed = [c for c in cases if not c.get("pass")]
    print(json.dumps({"sm4_cases": len(cases), "failed": len(failed)}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
