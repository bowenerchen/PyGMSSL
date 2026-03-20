#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/results/eet_hmac_samples.jsonl"
mkdir -p "$ROOT/results"
export NO_COLOR=1
echo "# eet hmac SM3" >"$OUT"
echo "## eet hmac -a sm3 -k '01234567890123456789012345678901' -i 'msg' --json" >>"$OUT"
eet hmac -a sm3 -k '01234567890123456789012345678901' -i 'msg' --json >>"$OUT"
echo >>"$OUT"
echo "## eet hmac -a sm3 -r -i 'random-key-msg' --json" >>"$OUT"
eet hmac -a sm3 -r -i 'random-key-msg' --json >>"$OUT"
echo "Wrote $OUT"
