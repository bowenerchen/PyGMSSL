# pygmssl 上层 API 简要评审（hazmat）

> 非正式安全审计；聚焦与 **eet v2.5.0** 对接时的行为与格式。

## 包结构

- 顶层 [`pygmssl/src/gmssl/__init__.py`](../pygmssl/src/gmssl/__init__.py) 仅版本号；算法入口在 **`gmssl.hazmat.primitives.*`**（与内置 `tests/` 一致）。

## SM2

- **实现**：[`_sm2_algo.py`](../pygmssl/src/gmssl/_backends/_sm2_algo.py) + [`_sm2_ciphertext.py`](../pygmssl/src/gmssl/_backends/_sm2_ciphertext.py) + [`_sm2_signature.py`](../pygmssl/src/gmssl/_backends/_sm2_signature.py) — 默认密文 **非压缩 C1（65B）\|\| C3（32）\|\| C2**；可选 `ciphertext_format` 与 eet `-m` 一致。明文长度 **1..255**。
- **高层**：[`asymmetric/sm2.py`](../pygmssl/src/gmssl/hazmat/primitives/asymmetric/sm2.py) — `encrypt`/`decrypt` 可选 `ciphertext_format`；`sign`/`verify` 可选 `signature_format`（**RS** / **RS_ASN1**，默认 64 字节 r\|\|s）。`encode_sm2_signature_der` / `decode_sm2_signature_der` 见 [`serialization.py`](../pygmssl/src/gmssl/hazmat/primitives/serialization.py)。
- **PEM**：`load_pem_public_key` 可加载 **eet 生成的 SUBJECT PUBLIC KEY**（`ecPublicKey` + 曲线 OID `1.2.156.10197.1.301`）。pygmssl 自生成的 SPKI 使用 **双 SM2 OID** 的 `AlgorithmIdentifier`，**eet 加密接口不接受**，测试中使用 [`interop_pem.encode_sm2_spki_for_eet`](../../tests-api/python/lib/interop_pem.py) 生成 eet 兼容公钥 PEM。
- **私钥**：`load_pem_private_key` 支持 **ENCRYPTED PRIVATE KEY**（PBES2 / PBKDF2-HMAC-SM3 / SM4-CBC，与 eet 一致）。`encode_sm2_private_key_pkcs8_encrypted` 使用 **GmSSL 兼容** 内层 PKCS#8（`id-ecPublicKey` + 曲线 OID，SEC1 中含 `[0]` 曲线、`[1]` 公钥），便于 **eet `sm2 sign -f`** 读取 pygmssl 导出的加密 PEM。明文 `PRIVATE KEY`（双 SM2 OID）与 eet 线格式仍可能不互通；与 eet 加密接口对接时优先用加密 PKCS#8 或 [interop 公钥 PEM](../../tests-api/python/lib/interop_pem.py)。

## SM4

- [`ciphers/__init__.py`](../pygmssl/src/gmssl/hazmat/primitives/ciphers/__init__.py)：CBC 在 `finalize` 使用 **PKCS#7**；GCM 见 [`_gcm.py`](../pygmssl/src/gmssl/_backends/_gcm.py)，tag 默认 **16 字节**，与 eet `sm4` **cipher\|\|tag** base64 布局一致（在相同 key/nonce/AAD 下已验证）。

## SM3 / HMAC

- [`hashes.py`](../pygmssl/src/gmssl/hazmat/primitives/hashes.py) / [`_sm3.py`](../pygmssl/src/gmssl/_backends/_sm3.py)：`Hash.update` 分块与一次性哈希结果一致。
- [`hmac.py`](../pygmssl/src/gmssl/hazmat/primitives/hmac.py)：标准 HMAC；SM3 的 `block_size` 为 64，与 eet `-a sm3` 行为对齐。

## ZUC

- [`_zuc.py`](../pygmssl/src/gmssl/_backends/_zuc.py)：**ZUC-128**（16/16）与 **ZUC-256**（32/23）。eet 仅覆盖 **128** 场景。

## eet 能力对照（摘要）

| 能力 | eet | pygmssl（本测试覆盖） |
|------|-----|------------------------|
| SM4 模式 | CBC、GCM | + ECB、CTR |
| SM2 密文 | C1C3C2_ASN1（默认）、C1C3C2、C1C2C3_ASN1、C1C2C3；C1 在 raw 模式为 **64B** | 默认 65B C1；**同上四种**经 `ciphertext_format` |
| SM2 签名 | RS_ASN1（默认）、RS | **RS** / **RS_ASN1** 经 `signature_format`；另提供 DER 编解码函数 |
| SM2 私钥 PEM | 加密 PKCS#8（eet 默认） | pygmssl 可 **导入/导出** 同算法；`run_sm2_pkcs8_encrypted_pem.py` 与 eet 交叉验证 |
