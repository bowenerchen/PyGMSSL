#!/usr/bin/env bash
# eet SM4 CBC / GCM 示例（与 Python 侧相同 key/iv/nonce/AAD）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/results/eet_sm4_samples.jsonl"
mkdir -p "$ROOT/results"
export NO_COLOR=1
echo "# eet SM4 samples" >"$OUT"

echo "## eet sm4 -m cbc -k '0123456789012345' -v '0123456789012345' -A encrypt -i 'hello-sm4-cbc' --json" >>"$OUT"
eet sm4 -m cbc -k '0123456789012345' -v '0123456789012345' -A encrypt -i 'hello-sm4-cbc' --json >>"$OUT"
echo >>"$OUT"

CT="$(eet sm4 -m cbc -k '0123456789012345' -v '0123456789012345' -A encrypt -i 'cbc-dec' --json | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['cipher'])")"
echo "## eet sm4 -m cbc ... -A decrypt -i '<cipher>' -e --json" >>"$OUT"
eet sm4 -m cbc -k '0123456789012345' -v '0123456789012345' -A decrypt -i "$CT" -e --json >>"$OUT"
echo >>"$OUT"

echo "## eet sm4 -m gcm ... --aad tests-api-aad -i 'gcm-plain'" >>"$OUT"
eet sm4 -m gcm -k '0123456789012345' -v '012345678901' --aad 'tests-api-aad' -A encrypt -i 'gcm-plain' --json >>"$OUT"
echo >>"$OUT"

GCT="$(eet sm4 -m gcm -k '0123456789012345' -v '012345678901' --aad 'tests-api-aad' -A encrypt -i 'gcm-dec' --json | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['cipher'])")"
eet sm4 -m gcm -k '0123456789012345' -v '012345678901' --aad 'tests-api-aad' -A decrypt -i "$GCT" -e --json >>"$OUT"

echo "Wrote $OUT"
