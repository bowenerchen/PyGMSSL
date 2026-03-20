#!/usr/bin/env python3
"""SM2：签名格式 RS / RS_ASN1 分项测试（pygmssl 往返与 eet 验签）。"""

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
from gmssl.hazmat.primitives.serialization import (
    decode_sm2_signature_der,
    encode_sm2_signature_der,
    load_pem_public_key,
)
from interop_pem import write_sm2_public_pem_for_eet
from jsonlog import CaseRecord, append_jsonl, results_dir, timed_block, write_aggregate

EET = "eet"
FIX_PUB = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_public.pem"


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

    key = sm2.generate_private_key()
    pub = key.public_key()
    msg_rt = b"sig-format-roundtrip"

    # --- 默认 RS（None）往返 ---
    with timed_block() as dur:
        try:
            sig = key.sign(msg_rt, signature_format=None)
            assert len(sig) == 64
            pub.verify(sig, msg_rt, signature_format=None)
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-RT-DEFAULT",
            tool="pygmssl",
            inputs={"signature_format": None, "flow": "sign/verify RS"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- 显式 RS ---
    with timed_block() as dur:
        try:
            sig = key.sign(msg_rt, signature_format="RS")
            pub.verify(sig, msg_rt, signature_format="RS")
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-RT-RS",
            tool="pygmssl",
            inputs={"signature_format": "RS"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- RS_ASN1 往返 ---
    with timed_block() as dur:
        try:
            der = key.sign(msg_rt, signature_format="RS_ASN1")
            assert der[0] == 0x30
            pub.verify(der, msg_rt, signature_format="RS_ASN1")
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-RT-RS_ASN1",
            tool="pygmssl",
            inputs={"signature_format": "RS_ASN1"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- encode_sm2_signature_der / decode_sm2_signature_der 与 API 一致 ---
    with timed_block() as dur:
        try:
            rs = key.sign(msg_rt)
            der = encode_sm2_signature_der(rs)
            assert decode_sm2_signature_der(der) == rs
            pub.verify(der, msg_rt, signature_format="RS_ASN1")
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-CODEC-DER",
            tool="pygmssl",
            inputs={"flow": "encode_sm2_signature_der / decode_sm2_signature_der + verify RS_ASN1"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- pygmssl RS -> eet verify -m RS ---
    k2 = sm2.generate_private_key()
    pub_pem_eet = write_sm2_public_pem_for_eet(k2.public_key().public_bytes_uncompressed())
    tmp_pub = results_dir() / "tmp_sm2_sigfmt_pub.pem"
    tmp_pub.write_bytes(pub_pem_eet)
    msg_eet = b"eet-verify-rs-asn1-body"

    with timed_block() as dur:
        try:
            sig64 = k2.sign(msg_eet, signature_format="RS")
            sb64 = base64.b64encode(sig64).decode("ascii")
            v = _eet_json(
                [
                    EET,
                    "sm2",
                    "verify",
                    "-f",
                    str(tmp_pub),
                    "-i",
                    msg_eet.decode(),
                    "-s",
                    sb64,
                    "-m",
                    "RS",
                    "--json",
                ]
            )
            ok = v["result"]["valid"] is True
            err = None if ok else "eet verify false"
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-XEET-RS",
            tool="both",
            inputs={"signature_format": "RS", "eet_mode": "RS"},
            parsed={"eet_valid": ok},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- pygmssl RS_ASN1 -> eet verify -m RS_ASN1 ---
    with timed_block() as dur:
        try:
            der = k2.sign(msg_eet, signature_format="RS_ASN1")
            sb64 = base64.b64encode(der).decode("ascii")
            v = _eet_json(
                [
                    EET,
                    "sm2",
                    "verify",
                    "-f",
                    str(tmp_pub),
                    "-i",
                    msg_eet.decode(),
                    "-s",
                    sb64,
                    "-m",
                    "RS_ASN1",
                    "--json",
                ]
            )
            ok = v["result"]["valid"] is True
            err = None if ok else "eet verify false"
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-XEET-RS_ASN1",
            tool="both",
            inputs={"signature_format": "RS_ASN1", "eet_mode": "RS_ASN1"},
            parsed={"eet_valid": ok},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- fixture 公钥：eet RS_ASN1 签名 -> pygmssl verify RS_ASN1 ---
    pk_fix = load_pem_public_key(FIX_PUB.read_bytes())
    FIX_PRIV = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_private.pem"
    FIX_PASSWORD = "ApiTestPwd01"
    msg_fix = "fixture-sigfmt-verify"

    with timed_block() as dur:
        try:
            s = _eet_json(
                [
                    EET,
                    "sm2",
                    "sign",
                    "-f",
                    str(FIX_PRIV),
                    "-p",
                    FIX_PASSWORD,
                    "-i",
                    msg_fix,
                    "--json",
                ]
            )
            der = base64.b64decode(s["result"]["signature"])
            pk_fix.verify(der, msg_fix.encode(), signature_format="RS_ASN1")
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-XEET-TO-PY-RS_ASN1",
            tool="both",
            inputs={"flow": "eet sign (default DER) -> pygmssl verify RS_ASN1"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- 负例：RS 签名按 RS_ASN1 验签应失败 ---
    with timed_block() as dur:
        try:
            sig64 = key.sign(msg_rt)
            pub.verify(sig64, msg_rt, signature_format="RS_ASN1")
            ok = False
            err = "expected InvalidSignature"
        except Exception:
            ok = True
            err = None
    add(
        CaseRecord(
            id="SM2-SIG-NEG-RS-AS-ASN1",
            tool="pygmssl",
            inputs={"mismatch": "sign RS, verify as RS_ASN1"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- 非法 signature_format ---
    with timed_block() as dur:
        try:
            key.sign(msg_rt, signature_format="NOPE")
            ok = False
            err = "expected ValueError"
        except ValueError:
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SIG-NEG-BAD-FORMAT",
            tool="pygmssl",
            inputs={"signature_format": "NOPE"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    write_aggregate(cases, "aggregate_sm2_signature_formats.json")
    failed = [c for c in cases if not c.get("pass")]
    print(
        json.dumps(
            {"sm2_signature_format_cases": len(cases), "failed": len(failed)}, indent=2
        )
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
