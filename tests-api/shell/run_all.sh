#!/usr/bin/env bash
# 运行全部 eet 样例 shell + Python 交叉脚本，并合并聚合 JSON
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.venv"
PY="$VENV/bin/python"
export NO_COLOR=1
mkdir -p "$ROOT/results"
rm -f "$ROOT/results/cases.jsonl"

echo "=== eet shell samples ==="
bash "$ROOT/shell/run_sm2_eet.sh"
bash "$ROOT/shell/run_sm4_eet.sh"
bash "$ROOT/shell/run_sm3_eet.sh"
bash "$ROOT/shell/run_hmac_eet.sh"
bash "$ROOT/shell/run_zuc_eet.sh"

echo "=== python crosschecks ==="
"$PY" "$ROOT/python/run_sm2_crosscheck.py"
"$PY" "$ROOT/python/run_sm2_cipher_formats.py"
"$PY" "$ROOT/python/run_sm2_signature_formats.py"
"$PY" "$ROOT/python/run_sm2_pkcs8_encrypted_pem.py"
"$PY" "$ROOT/python/run_sm4_crosscheck.py"
"$PY" "$ROOT/python/run_sm3_hmac_crosscheck.py"
"$PY" "$ROOT/python/run_zuc_crosscheck.py"
"$PY" "$ROOT/python/run_boundaries.py"

echo "=== merge aggregate ==="
ROOT_JSON="$ROOT" "$PY" <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ["ROOT_JSON"])
parts = [
    "aggregate_sm2.json",
    "aggregate_sm2_cipher_formats.json",
    "aggregate_sm2_signature_formats.json",
    "aggregate_sm2_pkcs8_encrypted.json",
    "aggregate_sm4.json",
    "aggregate_sm3_hmac.json",
    "aggregate_zuc.json",
    "aggregate_boundaries.json",
]
all_cases = []
for name in parts:
    p = root / "results" / name
    if p.exists():
        data = json.loads(p.read_text(encoding="utf-8"))
        for c in data.get("cases", []):
            c["source_file"] = name
            all_cases.append(c)
out = {
    "total": len(all_cases),
    "passed": sum(1 for c in all_cases if c.get("pass")),
    "failed": sum(1 for c in all_cases if not c.get("pass")),
    "cases": all_cases,
}
(root / "results" / "aggregate_all.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
)
print(json.dumps({"aggregate_all": out["total"], "failed": out["failed"]}))
PY

echo "Done. See results/aggregate_all.json"
