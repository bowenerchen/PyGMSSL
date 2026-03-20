# 测试用例说明（ID 与范围）

> 对应自动化目录：`tests-api/`（脚本与 `results/` 产物）。本文档为 tests-api 用例索引的**权威副本**。

## SM2（`run_sm2_crosscheck.py` + `shell/run_sm2_eet.sh`）


| ID                | 说明                                                                      |
| ----------------- | ----------------------------------------------------------------------- |
| SM2-ADP-001       | pygmssl 密文 `C1||C3||C2` 与 eet 原始 `C1C3C2`（64 字节 C1）互转后解密一致              |
| SM2-ADP-002       | `C1C2C3` 与 raw 互转                                                       |
| SM2-ADP-003 / 004 | eet `C1C3C2_ASN1` / `C1C2C3_ASN1` 加密后 **eet 解密** 与明文一致（ASN.1 解析路径验证）    |
| SM2-SV-001        | pygmssl 签名（RS）→ **eet 验签**（需 [interop PEM](../../tests-api/python/lib/interop_pem.py)）  |
| SM2-SV-002        | **eet 签名（RS_ASN1）** → pygmssl `verify(..., signature_format="RS_ASN1")` |
| SM2-SV-003        | pygmssl **RS_ASN1** `sign` / `verify` 往返                                |
| SM2-BND-001 / 002 | 空明文、>255 字节明文应失败                                                        |


Shell 样例额外覆盖：`C1C3C2_ASN1`、`C1C3C2`、`C1C2C3_ASN1`、`C1C2C3` 加密；`C1C3C2` 解密；`RS` / 默认 `RS_ASN1` 签名；`RS` 验签（见 `tests-api/results/eet_sm2_samples.jsonl`）。

## SM2 加密 PKCS#8 PEM（`run_sm2_pkcs8_encrypted_pem.py`）


| ID                  | 说明                                                                 |
| ------------------- | ------------------------------------------------------------------ |
| SM2-PKCS8-EET-001   | eet fixture **ENCRYPTED PRIVATE KEY** → pygmssl `load_pem_private_key`，公钥与 fixture 公钥 PEM 一致 |
| SM2-PKCS8-EET-002   | pygmssl **加密 PKCS#8 PEM**（PBKDF2 迭代 4096，加快用例）→ **eet sm2 sign** → pygmssl `verify` **RS_ASN1** |
| SM2-PKCS8-EET-003   | pygmssl **RS_ASN1** 签名 → **eet verify**（interop 公钥 PEM）                         |
| SM2-PKCS8-EET-004   | 磁盘加密 PEM 再次 `load_pem_private_key` 与内存密钥一致                                  |

## SM2 密文格式分项（`run_sm2_cipher_formats.py`）


| ID                    | 说明                                                                                         |
| --------------------- | ------------------------------------------------------------------------------------------ |
| SM2-CFMT-RT-DEFAULT   | `ciphertext_format=None`（65B C1 的 C1||C3||C2）加解密往返                                         |
| SM2-CFMT-RT-C1C3C2 等  | 各 eet 模式字符串下 pygmssl **encrypt/decrypt 往返**（`C1C3C2`、`C1C2C3`、`C1C3C2_ASN1`、`C1C2C3_ASN1`） |
| SM2-CFMT-XEET-*       | fixture 公钥 **pygmssl 加密** → **eet decrypt**（同 `-m`），验证与 eet 线格式互通                          |
| SM2-CFMT-NEG-MISMATCH | 以 `C1C3C2` 加密、以 `C1C2C3` 解密应 **ValueError**                                                |


## SM2 签名格式分项（`run_sm2_signature_formats.py`）


| ID                                 | 说明                                                                               |
| ---------------------------------- | -------------------------------------------------------------------------------- |
| SM2-SIG-RT-DEFAULT / SM2-SIG-RT-RS | `signature_format` 为 `None` 或 `RS` 时 64 字节往返                                     |
| SM2-SIG-RT-RS_ASN1                 | **RS_ASN1**（DER）`sign` / `verify` 往返                                             |
| SM2-SIG-CODEC-DER                  | `encode_sm2_signature_der` / `decode_sm2_signature_der` 与 `verify(..., RS_ASN1)` |
| SM2-SIG-XEET-RS                    | pygmssl **RS** → **eet verify -m RS**                                            |
| SM2-SIG-XEET-RS_ASN1               | pygmssl **RS_ASN1** → **eet verify -m RS_ASN1**                                  |
| SM2-SIG-XEET-TO-PY-RS_ASN1         | **eet sign**（默认 DER）→ pygmssl `verify` **RS_ASN1**                               |
| SM2-SIG-NEG-RS-AS-ASN1             | RS 签名误用 RS_ASN1 验签应失败                                                            |
| SM2-SIG-NEG-BAD-FORMAT             | 非法 `signature_format` 应 **ValueError**                                           |


## SM4（`run_sm4_crosscheck.py` + `shell/run_sm4_eet.sh`）


| ID             | 说明                                                                                    |
| -------------- | ------------------------------------------------------------------------------------- |
| SM4-CBC-*      | 与 eet 相同 ASCII key/iv 下 CBC+PKCS7 密文 base64 一致；**EMPTY** 仅 pygmssl（eet 拒空 `-i`）       |
| SM4-GCM-*      | 与 eet 相同 key、12 字节 nonce、`tests-api-aad` 下 **ciphertext||tag** base64 一致；**EMPTY** 同上 |
| SM4-ECB-GMT    | GM/T 0002-2012 单分组向量                                                                  |
| SM4-CTR-RT     | CTR 100 字节随机明文往返                                                                      |
| SM4-GCM-BADTAG | 错误 tag 触发 `InvalidTag`                                                                |


## SM3 / HMAC（`run_sm3_hmac_crosscheck.py` + shell）


| ID                  | 说明                                                           |
| ------------------- | ------------------------------------------------------------ |
| SM3-LEN-*           | 长度 0,1,55,56,64,65,128,1024,1MiB；大报文经临时文件 + `eet hash -f -l` |
| SM3-LARGE-FILE      | 1MiB+1 字节文件                                                  |
| SM3-CHUNK-5000      | `update` 分块与一次性哈希一致                                          |
| HMAC-SM3-FIXED      | 固定 key 与 eet `hmac` hex 一致                                   |
| HMAC-SM3-RANDOM-KEY | eet `-r` 随机 key 后 pygmssl 复算 tag                             |


## ZUC（`run_zuc_crosscheck.py` + `shell/run_zuc_eet.sh`）


| ID                 | 说明                                      |
| ------------------ | --------------------------------------- |
| ZUC128-EET-*       | ZUC-128 与 eet `zuc` 密文 base64 一致        |
| ZUC128-VEC-*       | GmSSL 向量前两个 32-bit 字                    |
| ZUC256-ZERO / ONES | ZUC-256 前 4 个 keystream 字（**无 eet 对照**） |


## 边界与极简性能（`run_boundaries.py`）


| ID              | 说明                     |
| --------------- | ---------------------- |
| BND-SM3-EMPTY   | 空输入 SM3                |
| BND-SM4-KEY-15  | 错误密钥长度                 |
| BND-SM4-GCM-IV8 | 非 12 字节 nonce 的 GCM 路径 |
| PERF-SM3-256KIB | 256KiB 单次耗时（ms）        |
