#!/usr/bin/env python3
"""SM2: adapter self-tests, sign/verify cross with eet fixture public key, subprocess eet sign/verify."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

# tests-api/python/lib
_LIB = Path(__file__).resolve().parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))

from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives.serialization import load_pem_public_key
from interop_pem import write_sm2_public_pem_for_eet
from jsonlog import CaseRecord, append_jsonl, results_dir, timed_block, write_aggregate
from sm2_format_adapters import (
    pygmssl_raw_to_eet_c1c2c3,
    pygmssl_raw_to_eet_c1c3c2,
    raw_c1c3c2_from_asn1_der,
    raw_c1c3c2_from_c1c2c3,
    raw_c1c3c2_from_c1c3c2_eet_raw,
)

EET = "eet"
FIX_PUB = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_public.pem"
FIX_PRIV = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_private.pem"
FIX_PASSWORD = "ApiTestPwd01"


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

    # --- Adapter roundtrip from pygmssl ciphertext ---
    key = sm2.generate_private_key()
    pub = key.public_key()
    pt = b"sm2-adapter-roundtrip-pt"
    raw_ct = pub.encrypt(pt)

    with timed_block() as dur:
        try:
            eet_c1c3c2 = pygmssl_raw_to_eet_c1c3c2(raw_ct)
            back = raw_c1c3c2_from_c1c3c2_eet_raw(eet_c1c3c2)
            assert back == raw_ct
            pt2 = key.decrypt(back)
            assert pt2 == pt
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-ADP-001",
            tool="pygmssl",
            inputs={"flow": "raw<->eet C1C3C2 (64-byte C1)"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    with timed_block() as dur:
        try:
            eet_c1c2c3 = pygmssl_raw_to_eet_c1c2c3(raw_ct)
            back = raw_c1c3c2_from_c1c2c3(eet_c1c2c3)
            assert back == raw_ct
            assert key.decrypt(back) == pt
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-ADP-002",
            tool="pygmssl",
            inputs={"flow": "raw<->eet C1C2C3"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # ASN.1 layouts (parse only — build from captured eet output below)
    for oid, order in [("SM2-ADP-003", "c1c3c2"), ("SM2-ADP-004", "c1c2c3")]:
        with timed_block() as dur:
            try:
                mode = "C1C3C2_ASN1" if order == "c1c3c2" else "C1C2C3_ASN1"
                d = _eet_json(
                    [
                        EET,
                        "sm2",
                        "encrypt",
                        "-f",
                        str(FIX_PUB),
                        "-i",
                        pt.decode(),
                        "-m",
                        mode,
                        "--json",
                    ]
                )
                der = base64.b64decode(d["result"]["cipher"])
                raw = raw_c1c3c2_from_asn1_der(der, order)
                # Cross-decrypt requires private on pygmssl — only check structure + eet decrypt roundtrip
                dec = _eet_json(
                    [
                        EET,
                        "sm2",
                        "decrypt",
                        "-f",
                        str(FIX_PRIV),
                        "-i",
                        d["result"]["cipher"],
                        "-m",
                        mode,
                        "-p",
                        FIX_PASSWORD,
                        "--json",
                    ]
                )
                assert dec["result"]["plain"] == pt.decode()
                ok = True
                err = None
            except Exception as e:
                ok = False
                err = str(e)
        add(
            CaseRecord(
                id=oid,
                tool="both",
                inputs={"eet_cipher_mode": mode, "plaintext_len": len(pt)},
                parsed={"eet_decrypt_ok": ok},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    # --- pygmssl sign -> eet verify (RS) ---
    k2 = sm2.generate_private_key()
    pub_pem_eet = write_sm2_public_pem_for_eet(k2.public_key().public_bytes_uncompressed())
    tmp_pub = results_dir() / "tmp_sm2_cross_pub.pem"
    tmp_pub.write_bytes(pub_pem_eet)
    msg = b"cross-verify-body"
    sig64 = k2.sign(msg)

    with timed_block() as dur:
        try:
            sb64 = base64.b64encode(sig64).decode("ascii")
            v = _eet_json(
                [
                    EET,
                    "sm2",
                    "verify",
                    "-f",
                    str(tmp_pub),
                    "-i",
                    msg.decode(),
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
            id="SM2-SV-001",
            tool="both",
            inputs={"message": msg.decode()},
            parsed={"eet_valid": ok},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- eet sign (RS_ASN1 default) -> pygmssl verify ---
    pk_fix = load_pem_public_key(FIX_PUB.read_bytes())
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
                    "fixture-sign-message",
                    "--json",
                ]
            )
            sig_b64 = s["result"]["signature"]
            der = base64.b64decode(sig_b64)
            pk_fix.verify(der, b"fixture-sign-message", signature_format="RS_ASN1")
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SV-002",
            tool="both",
            inputs={"fixture": str(FIX_PUB)},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- RS_ASN1 sign/verify pygmssl ---
    with timed_block() as dur:
        try:
            der = k2.sign(b"der-test", signature_format="RS_ASN1")
            k2.public_key().verify(der, b"der-test", signature_format="RS_ASN1")
            ok = True
            err = None
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-SV-003",
            tool="pygmssl",
            inputs={"flow": "RS_ASN1 sign/verify (pygmssl)"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- Boundaries ---
    for label, fn in [
        ("SM2-BND-001", lambda: key.public_key().encrypt(b"")),
        ("SM2-BND-002", lambda: key.public_key().encrypt(b"x" * 256)),
    ]:
        with timed_block() as dur:
            try:
                fn()
                ok = False
                err = "expected failure"
            except Exception:
                ok = True
                err = None
        add(
            CaseRecord(
                id=label,
                tool="pygmssl",
                inputs={"expect": "ValueError"},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    write_aggregate(cases, "aggregate_sm2.json")
    failed = [c for c in cases if not c.get("pass")]
    print(json.dumps({"sm2_cases": len(cases), "failed": len(failed)}, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
