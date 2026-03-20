#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/results/eet_sm3_samples.jsonl"
mkdir -p "$ROOT/results"
export NO_COLOR=1
echo "# eet hash SM3" >"$OUT"
echo "## eet hash -a sm3 -i '' --json" >>"$OUT"
eet hash -a sm3 -i '' --json >>"$OUT"
echo >>"$OUT"
echo "## eet hash -a sm3 -i 'abc' -l 2 --json" >>"$OUT"
eet hash -a sm3 -i 'abc' -l 2 --json >>"$OUT"
echo "Wrote $OUT"
