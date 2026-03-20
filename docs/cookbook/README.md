# pygmssl 使用说明（Cookbook）

本目录提供**可直接复制**的代码片段，覆盖 pygmssl 中主要**国密算法**的典型用法。使用前请已安装本包（例如 `pip install -e /path/to/pygmssl` 或 `pip install pygmssl`），并确保能 `import gmssl`。

> **注意**：下列示例均基于 `gmssl.hazmat.primitives` 等公开 API；与 GmSSL C 库、测试向量对齐的细节见 **[算法说明](../algorithms/)** 与 **`pygmssl/tests/`**。

## 文档索引

| 文档 | 内容 |
|------|------|
| [sm2.md](sm2.md) | SM2：多格式加解密、RS/RS_ASN1 签名验签、ECDH、DER 辅助函数 |
| [sm3.md](sm3.md) | SM3 哈希、SM3-KDF、HMAC-SM3 |
| [kdf-sm3.md](kdf-sm3.md) | **PBKDF2-HMAC-SM3**、**HKDF / HKDF-Expand（SM3）** |
| [sm4.md](sm4.md) | SM4：CBC（PKCS#7）、GCM（含 AAD/tag）、ECB、CTR |
| [sm9.md](sm9.md) | SM9：标识签名、标识加密（依赖 libgmssl） |
| [zuc.md](zuc.md) | ZUC-128 / ZUC-256 流密码 |
| [x509-pem.md](x509-pem.md) | **X.509** 自签名证书、**CSR**、SM2 **PEM/DER** 编解码 |

## 通用导入约定

```python
# 开发时若未安装 wheel，可将 pygmssl 源码根目录下的 src 加入 PYTHONPATH：
# export PYTHONPATH=/path/to/pygmssl/src
```

PBKDF2/HKDF（SM3）与 X.509/PEM 的独立抄码页见上表；更多细节还可对照 `gmssl.hazmat.primitives.kdf`、`gmssl.x509` 源码与 `tests/`。
