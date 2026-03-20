#!/usr/bin/env bash
# 若 fixture 不存在则生成 SM2 密钥对（eet v2.5.0）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/shell/fixtures"
PUB="$FIX/test_sm2_sm2_public.pem"
PRIV="$FIX/test_sm2_sm2_private.pem"
if [[ -f "$PUB" && -f "$PRIV" ]]; then
  echo "fixtures already present: $PUB"
  exit 0
fi
mkdir -p "$FIX"
cd "$FIX"
# 完整命令行（输出写入标准输出，便于记录）
echo "Running: eet sm2 generate -f test_sm2 -p 'ApiTestPwd01' --json"
NO_COLOR=1 eet sm2 generate -f test_sm2 -p 'ApiTestPwd01' --json
