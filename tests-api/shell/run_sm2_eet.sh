#!/usr/bin/env bash
# eet SM2 示例调用：加密（多密文模式）、解密、签名（RS/RS_ASN1）、验签
# 每条命令在注释中完整保留；JSON 单行写入 results/eet_sm2_samples.jsonl
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/shell/fixtures"
OUT="$ROOT/results/eet_sm2_samples.jsonl"
mkdir -p "$ROOT/results"
PUB="$FIX/test_sm2_sm2_public.pem"
PRIV="$FIX/test_sm2_sm2_private.pem"
PASS="ApiTestPwd01"
export NO_COLOR=1

{
  echo "# eet SM2 samples — command then JSON line"
  for MODE in C1C3C2_ASN1 C1C3C2 C1C2C3_ASN1 C1C2C3; do
    echo "# eet sm2 encrypt -f \"$PUB\" -i 'boundary-sm2-msg' -m $MODE --json"
    eet sm2 encrypt -f "$PUB" -i 'boundary-sm2-msg' -m "$MODE" --json
  done

  CT="$(eet sm2 encrypt -f "$PUB" -i 'decrypt-sample' -m C1C3C2 --json | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['cipher'])")"
  echo "# eet sm2 decrypt -f \"$PRIV\" -i '<cipher-b64>' -m C1C3C2 -p \"$PASS\" --json"
  eet sm2 decrypt -f "$PRIV" -i "$CT" -m C1C3C2 -p "$PASS" --json

  echo "# eet sm2 sign -f \"$PRIV\" -p \"$PASS\" -i 'shell-sign-msg' -m RS --json"
  eet sm2 sign -f "$PRIV" -p "$PASS" -i 'shell-sign-msg' -m RS --json

  echo "# eet sm2 sign -f \"$PRIV\" -p \"$PASS\" -i 'shell-sign-msg-asn1' --json  (default RS_ASN1)"
  eet sm2 sign -f "$PRIV" -p "$PASS" -i 'shell-sign-msg-asn1' --json

  SIG_RS="$(eet sm2 sign -f "$PRIV" -p "$PASS" -i 'verify-me' -m RS --json | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['signature'])")"
  echo "# eet sm2 verify -f \"$PUB\" -i 'verify-me' -s '<sig-b64>' -m RS --json"
  eet sm2 verify -f "$PUB" -i 'verify-me' -s "$SIG_RS" -m RS --json
} >"$OUT"

echo "Wrote $OUT"
