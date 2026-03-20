#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/results/eet_zuc_samples.jsonl"
mkdir -p "$ROOT/results"
export NO_COLOR=1
echo "# eet zuc" >"$OUT"
echo "## eet zuc -k '0123456789012345' -v '0123456789012345' -A encrypt -i 'zuc-line' --json" >>"$OUT"
eet zuc -k '0123456789012345' -v '0123456789012345' -A encrypt -i 'zuc-line' --json >>"$OUT"
echo "Wrote $OUT"
