# pygmssl

Python 实现的国密算法库，遵循中国国家密码管理局发布的商用密码标准。

## 与 GmSSL 的关系

**当前 Python 版实现**是在对开源项目 **GmSSL 3.1.1**（对应源码树 **GMSSL-3.1.1**）的 C 代码进行阅读、对照与**重构**的基础上完成的：算法流程、常量与大量测试向量与 GmSSL 保持一致；部分能力（例如 **SM9** 的配对、KEM、H2 等）通过动态加载 **`libgmssl`** 与 GmSSL **位级对齐**，以保证互操作性。

**GmSSL** 由 **Guan Zhi (GUANZHI) 团队**开源维护。上游仓库地址：

**<https://github.com/guanzhi/GmSSL>**

使用本库时请同时遵守 GmSSL 与 pygmssl 各自的许可证及致谢要求。

## 特性

- **SM2**：椭圆曲线数字签名、公钥加密、密钥交换（ECDH）
- **SM3**：密码杂凑算法（哈希）
- **SM4**：分组密码，支持 ECB/CBC/CTR/GCM 模式
- **SM9**：基于身份的密码学（签名、加密）
- **ZUC**：流密码（ZUC-128、ZUC-256，用于 4G/5G）
- **HMAC-SM3**：消息认证码
- **PBKDF2/HKDF**：基于 SM3 的密钥派生
- **X.509**：证书与 CSR 创建、PEM/DER 编解码

API 风格参考 Python 的 [cryptography](https://cryptography.io/) 库。

## 安装

```bash
pip install pygmssl
```

**依赖**：`gmpy2>=2.1.0`（用于 SM2/SM9 大整数运算）

## 快速示例

### SM3 哈希

```python
from gmssl.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SM3())
digest.update(b"hello")
result = digest.finalize()
```

### SM4 加密（GCM 模式）

```python
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

key = os.urandom(16)
iv = os.urandom(12)
cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
enc = cipher.encryptor()
enc.authenticate_additional_data(b"aad")
ct = enc.update(b"plaintext") + enc.finalize()
tag = enc.tag
```

### SM2 签名与验证

```python
from gmssl.hazmat.primitives.asymmetric import sm2

key = sm2.generate_private_key()
sig = key.sign(b"data to sign")
key.public_key().verify(sig, b"data to sign")
```

### SM2 加密与解密

```python
ct = key.public_key().encrypt(b"secret message")
pt = key.decrypt(ct)
```

## 支持算法一览

| 算法 | 用途 | 标准 |
|------|------|------|
| SM2 | 数字签名、公钥加密、密钥交换 | GM/T 0003-2012 |
| SM3 | 哈希 | GM/T 0004-2012 |
| SM4 | 对称加密 | GM/T 0002-2012 |
| SM9 | 基于身份的签名与加密 | GM/T 0044-2016 |
| ZUC | 流密码 | 3GPP TS 35.221 |

## 开发测试

- **SM9**：签名、加密与 KEM 路径依赖 **GmSSL** 的 `libgmssl`（配对、H2、KEM 与 GmSSL 一致）。未找到库时 `tests/test_sm9.py` 会自动跳过。可将 `PYGMSSL_GMSSL_LIBRARY` 设为 `libgmssl` 的路径，或将本仓库旁的 `GmSSL-3.1.1/build/bin/libgmssl.{dylib,so}` 编译好以便自动探测。
- 其余用例可直接 `pytest`；建议 `PYTHONPATH=src`（或已安装 editable 包）。

## 文档

- [使用文档](../docs/README.md)
- [快速入门](../docs/usage/getting_started.md)
- [算法文档](../docs/algorithms/)
- [架构说明](../docs/architecture.md)

## 许可证

Apache-2.0
