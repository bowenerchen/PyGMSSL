#!/usr/bin/env python3
"""SM2：按密文格式分项测试（pygmssl 往返 + fixture 公钥加密后 eet 解密）。"""

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

from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives.serialization import load_pem_public_key
from gmssl._backends._sm2_ciphertext import SM2_EET_CIPHERTEXT_FORMATS
from jsonlog import CaseRecord, append_jsonl, results_dir, timed_block, write_aggregate

EET = "eet"
FIX_PUB = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_public.pem"
FIX_PRIV = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_private.pem"
FIX_PASSWORD = "ApiTestPwd01"

# 与 eet -m 一致；默认布局单独测
EET_MODES = sorted(SM2_EET_CIPHERTEXT_FORMATS)
PT_CROSS = "sm2-cipher-format-eet-cross"
PT_RT = b"sm2-cipher-format-rt"


def _eet_json(cmd: list[str]) -> dict:
    env = {**os.environ, "NO_COLOR": "1"}
    out = subprocess.check_output(cmd, text=True, env=env)
    return json.loads(out)


def main() -> int:
    results_dir()
    cases: list[dict] = []

    def add(rec: CaseRecord) -> None:
        append_jsonl(rec)
        cases.append(rec.to_json_dict())

    # --- 各格式：内存密钥 encrypt/decrypt 往返 ---
    key = sm2.generate_private_key()
    pub = key.public_key()

    with timed_block() as dur:
        ct = b""
        try:
            ct = pub.encrypt(PT_RT, ciphertext_format=None)
            assert key.decrypt(ct, ciphertext_format=None) == PT_RT
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-CFMT-RT-DEFAULT",
            tool="pygmssl",
            inputs={"ciphertext_format": None, "flow": "encrypt/decrypt roundtrip"},
            parsed={"ciphertext_len": len(ct) if ok else None},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    for mode in EET_MODES:
        with timed_block() as dur:
            ct = b""
            try:
                ct = pub.encrypt(PT_RT, ciphertext_format=mode)
                assert key.decrypt(ct, ciphertext_format=mode) == PT_RT
                ok = True
                err = None
            except Exception as e:
                ok = False
                err = str(e)
        add(
            CaseRecord(
                id=f"SM2-CFMT-RT-{mode}",
                tool="pygmssl",
                inputs={"ciphertext_format": mode, "flow": "encrypt/decrypt roundtrip"},
                parsed={"ciphertext_len": len(ct) if ok else None},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    # --- fixture 公钥 -> pygmssl 加密 -> eet 解密（四种 -m）---
    pk_fix = load_pem_public_key(FIX_PUB.read_bytes())

    for mode in EET_MODES:
        with timed_block() as dur:
            try:
                ct = pk_fix.encrypt(PT_CROSS.encode(), ciphertext_format=mode)
                b64 = base64.b64encode(ct).decode("ascii")
                dec = _eet_json(
                    [
                        EET,
                        "sm2",
                        "decrypt",
                        "-f",
                        str(FIX_PRIV),
                        "-i",
                        b64,
                        "-m",
                        mode,
                        "-p",
                        FIX_PASSWORD,
                        "--json",
                    ]
                )
                assert dec["result"]["plain"] == PT_CROSS
                ok = True
                err = None
            except Exception as e:
                ok = False
                err = str(e)
        add(
            CaseRecord(
                id=f"SM2-CFMT-XEET-{mode}",
                tool="both",
                inputs={
                    "ciphertext_format": mode,
                    "flow": "pygmssl encrypt (fixture pub) -> eet decrypt",
                },
                parsed={"eet_plain_ok": ok},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    # --- 负例：加密格式与解密格式不一致应失败 ---
    with timed_block() as dur:
        ok = False
        err: str | None = None
        try:
            ct_bad = pub.encrypt(PT_RT, ciphertext_format="C1C3C2")
            key.decrypt(ct_bad, ciphertext_format="C1C2C3")
            err = "expected decrypt failure"
        except ValueError:
            ok = True
            err = None
        except Exception as e:
            err = str(e)
    add(
        CaseRecord(
            id="SM2-CFMT-NEG-MISMATCH",
            tool="pygmssl",
            inputs={
                "encrypt_as": "C1C3C2",
                "decrypt_as": "C1C2C3",
                "expect": "ValueError",
            },
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    write_aggregate(cases, "aggregate_sm2_cipher_formats.json")
    failed = [c for c in cases if not c.get("pass")]
    print(
        json.dumps(
            {"sm2_cipher_format_cases": len(cases), "failed": len(failed)}, indent=2
        )
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
