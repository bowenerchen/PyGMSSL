#!/usr/bin/env python3
"""SM2 PKCS#8 encrypted PEM: pygmssl <-> eet (PBES2 + PBKDF2-HMAC-SM3 + SM4-CBC)."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_LIB = Path(__file__).resolve().parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))

from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    encode_sm2_private_key_pkcs8_encrypted,
    _pem_encode,
)
from interop_pem import write_sm2_public_pem_for_eet
from jsonlog import CaseRecord, append_jsonl, results_dir, timed_block, write_aggregate

EET = "eet"
FIX_PUB = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_public.pem"
FIX_PRIV = Path(__file__).resolve().parents[1] / "shell" / "fixtures" / "test_sm2_sm2_private.pem"
FIX_PASSWORD = "ApiTestPwd01"
# Lower than eet default 65536 to keep CI time reasonable; eet parses iterations from DER.
_FAST_ITER = 4096


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

    # --- EET fixture -> pygmssl load, public coordinates match ---
    with timed_block() as dur:
        try:
            pem_priv = FIX_PRIV.read_bytes()
            pem_pub = FIX_PUB.read_bytes()
            key = load_pem_private_key(pem_priv, FIX_PASSWORD.encode())
            pub = key.public_key()
            pub2 = load_pem_public_key(pem_pub)
            ok = pub.x == pub2.x and pub.y == pub2.y
            err = None if ok else "public mismatch"
        except Exception as e:
            ok = False
            err = str(e)
    add(
        CaseRecord(
            id="SM2-PKCS8-EET-001",
            tool="both",
            inputs={"flow": "eet fixture ENCRYPTED PRIVATE KEY -> pygmssl load_pem_private_key"},
            pass_=ok,
            error=err,
            duration_ms=dur[0],
        )
    )

    # --- pygmssl encrypted PEM -> eet sign -> pygmssl verify ---
    k = sm2.generate_private_key()
    pwd = b"CrossPkcs8Pwd01"
    msg = b"sm2-pkcs8-eet-sign-roundtrip"
    enc_der = encode_sm2_private_key_pkcs8_encrypted(
        k.private_bytes(),
        k.public_key().public_bytes_uncompressed(),
        pwd,
        iterations=_FAST_ITER,
    )
    priv_pem = _pem_encode(enc_der, "ENCRYPTED PRIVATE KEY")
    pub_pem_eet = write_sm2_public_pem_for_eet(k.public_key().public_bytes_uncompressed())

    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        p_priv = tdir / "enc_priv.pem"
        p_priv.write_bytes(priv_pem)

        with timed_block() as dur:
            try:
                s = _eet_json(
                    [
                        EET,
                        "sm2",
                        "sign",
                        "-f",
                        str(p_priv),
                        "-p",
                        pwd.decode(),
                        "-i",
                        msg.decode(),
                        "--json",
                    ]
                )
                der = base64.b64decode(s["result"]["signature"])
                k.public_key().verify(der, msg, signature_format="RS_ASN1")
                ok = True
                err = None
            except Exception as e:
                ok = False
                err = str(e)
        add(
            CaseRecord(
                id="SM2-PKCS8-EET-002",
                tool="both",
                inputs={
                    "flow": "pygmssl encrypted PKCS#8 PEM -> eet sm2 sign -> pygmssl verify RS_ASN1",
                    "pbkdf2_iterations": _FAST_ITER,
                },
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

        # --- pygmssl sign -> eet verify (encrypted key only on py side; eet uses pub PEM) ---
        p_pub = tdir / "pub.pem"
        p_pub.write_bytes(pub_pem_eet)
        sig_rs_asn1 = k.sign(msg, signature_format="RS_ASN1")
        sb64 = base64.b64encode(sig_rs_asn1).decode("ascii")

        with timed_block() as dur:
            try:
                v = _eet_json(
                    [
                        EET,
                        "sm2",
                        "verify",
                        "-f",
                        str(p_pub),
                        "-i",
                        msg.decode(),
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
                id="SM2-PKCS8-EET-003",
                tool="both",
                inputs={
                    "flow": "pygmssl sign (in-memory key) -> eet verify; key material from encrypted PEM roundtrip",
                    "pbkdf2_iterations": _FAST_ITER,
                },
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

        # --- load same PEM in pygmssl after eet signed (sanity: PEM readable) ---
        with timed_block() as dur:
            try:
                k2 = load_pem_private_key(priv_pem, pwd)
                ok = k2.private_key_int == k.private_key_int
                err = None if ok else "loaded key mismatch"
            except Exception as e:
                ok = False
                err = str(e)
        add(
            CaseRecord(
                id="SM2-PKCS8-EET-004",
                tool="pygmssl",
                inputs={"flow": "reload encrypted PEM from disk"},
                pass_=ok,
                error=err,
                duration_ms=dur[0],
            )
        )

    write_aggregate(cases, "aggregate_sm2_pkcs8_encrypted.json")
    failed = [c for c in cases if not c.get("pass")]
    print(
        json.dumps(
            {"sm2_pkcs8_encrypted_cases": len(cases), "failed": len(failed)},
            indent=2,
        )
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
