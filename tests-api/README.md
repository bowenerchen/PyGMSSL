# tests-api：pygmssl 上层 API 与 eet（v2.5.0）交叉验证

本目录与主库 `pygmssl/` **解耦**：沉淀 **Python 驱动脚本**、**Shell 中完整 eet 命令**、以及 **JSON 结果**（单条用例见 `results/cases.jsonl`，分类聚合见 `aggregate_*.json`，合并见 `aggregate_all.json`）。**用例说明、评审与 fixture 正文**见仓库 **[docs/testing/](../docs/testing/README.md)**（不再在 `tests-api/` 下重复维护 Markdown）。

## 环境

- Python 3.9+；建议在仓库根目录创建虚拟环境并 **editable 安装** pygmssl：

```bash
cd /path/to/GMSSL
python3 -m venv tests-api/.venv
tests-api/.venv/bin/pip install -e 'pygmssl[dev]'
```

- **eet**：要求已安装并在 `PATH` 中（验证：`eet version`，本方案针对 **v2.5.0**）。

## 一键运行

```bash
cd tests-api
bash shell/run_all.sh
```

将依次执行：

1. `shell/run_*_eet.sh`：把 **完整 eet 命令**（注释行）与 **单行 JSON 输出** 写入 `results/eet_*_samples.jsonl`。
2. `python/run_*_crosscheck.py`、`run_sm2_cipher_formats.py`（SM2 密文格式）、`run_sm2_signature_formats.py`（SM2 签名 RS/RS_ASN1）、`run_sm2_pkcs8_encrypted_pem.py`（SM2 加密 PKCS#8 PEM 与 eet）与 `run_boundaries.py`：pygmssl 与 eet 对比或自洽测试，追加 `results/cases.jsonl`，并写 `aggregate_*.json`（含 `aggregate_sm2_cipher_formats.json`、`aggregate_sm2_signature_formats.json`、`aggregate_sm2_pkcs8_encrypted.json`）。
3. 合并生成 `results/aggregate_all.json`。

单独跑 Python（不跑 shell）：

```bash
tests-api/.venv/bin/python tests-api/python/run_sm4_crosscheck.py
```

## 目录说明

| 路径 | 说明 |
|------|------|
| [docs/testing/TEST_CASES.md](../docs/testing/TEST_CASES.md) | 用例 ID 与覆盖范围（权威副本） |
| [docs/testing/REVIEW.md](../docs/testing/REVIEW.md) | pygmssl 上层 API 简要评审与 eet 能力差异 |
| [docs/testing/sm2-fixtures.md](../docs/testing/sm2-fixtures.md) | SM2 PEM fixture 与口令说明 |
| [reports/REPORT.md](reports/REPORT.md) | 测试报告模板与最近一次运行摘要 |
| [python/](python/) | 交叉验证脚本与 `lib/`（interop PEM、SM2 格式适配、json 记录） |
| [shell/](shell/) | eet 样例 Shell（含 [shell/fixtures/](shell/fixtures/) SM2 PEM） |
| [results/](results/) | 运行产物（目录内文件见 [.gitignore](.gitignore) 中 `results/*`，脚本会 `mkdir`） |

## SM2 fixture

见 [docs/testing/sm2-fixtures.md](../docs/testing/sm2-fixtures.md)（或 [shell/fixtures/README.md](shell/fixtures/README.md) 跳转）。若需重新生成：

```bash
bash tests-api/shell/gen_sm2_pem.sh
```

## 已知限制（摘要）

- **eet `sm4 encrypt` 不接受空字符串 `-i`**：空明文仅在 pygmssl 侧验证（见 `run_sm4_crosscheck.py` 注释）。
- **SM2 加密私钥 PEM**：pygmssl 支持 **PBES2 + PBKDF2-HMAC-SM3 + SM4-CBC** 的 `ENCRYPTED PRIVATE KEY`（与 eet `sm2 generate` 一致），可 `load_pem_private_key(..., password=...)`；导出 `encode_sm2_private_key_pkcs8_encrypted` 的内层 PKCS#8 与 **GmSSL/eet** 一致，便于 `eet sm2 sign -f` 读取。跨工具 **密文格式** 仍通过 `sm2_format_adapters.py` 与 **eet 解密回显** 验证。
- **eet `sm4` 仅 CBC/GCM**；ECB/CTR 仅在 Python 脚本中与 GM/T 向量或往返测试。
