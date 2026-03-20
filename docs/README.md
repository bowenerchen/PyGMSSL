# GmSSL Python SDK 文档

GmSSL Python SDK 是采用 Python 实现的中国商用密码算法库，遵循 Python `cryptography` 库的 API 风格，提供 SM2、SM3、SM4、SM9、ZUC 等国密算法支持。

**实现渊源**：当前 Python 代码系在 **GmSSL 3.1.1**（GMSSL-3.1.1 源码树）基础上**对照重构**而来。**GmSSL** 由 **Guan Zhi (GUANZHI) 团队**开源，仓库：<https://github.com/guanzhi/GmSSL>。

## 项目简介

本 SDK 实现国家密码管理局发布的商用密码算法标准，适用于国密合规应用的开发与集成。API 采用 cryptography 风格的分层设计，便于上手和集成。

| 算法 | 标准 | 用途 |
|------|------|------|
| SM2 | GM/T 0003-2012 | 椭圆曲线数字签名、公钥加密、密钥交换 |
| SM3 | GM/T 0004-2012 | 密码杂凑算法（哈希） |
| SM4 | GM/T 0002-2012 | 分组密码（对称加密） |
| SM9 | GM/T 0044-2016 | 基于身份的密码学 |
| ZUC | 3GPP TS 35.221 | 流密码（4G/5G 加密） |

## 算法说明

- [SM2 算法说明](algorithms/sm2.md) - 椭圆曲线公钥密码算法
- [SM3 算法说明](algorithms/sm3.md) - 密码杂凑算法
- [SM4 算法说明](algorithms/sm4.md) - 分组密码
- [SM9 算法说明](algorithms/sm9.md) - 基于身份的密码
- [ZUC 算法说明](algorithms/zuc.md) - 祖冲之流密码

## 架构说明

- [架构文档](architecture.md) - 模块划分、后端实现与设计理念

## 使用指南

### 快速开始

- [快速入门](usage/getting_started.md) - 安装与快速示例

### 功能指南

- [哈希](usage/hashing.md) - SM3 哈希、流式哈希、SHA 系列
- [对称加密](usage/symmetric_encryption.md) - SM4 ECB/CBC/CTR/GCM、ZUC 流密码
- [数字签名](usage/digital_signatures.md) - SM2 密钥生成、签名与验证
- [非对称加密](usage/asymmetric_encryption.md) - SM2 公钥加密、SM9 基于身份加密
- [密钥派生](usage/key_derivation.md) - HMAC、PBKDF2、HKDF、SM3-KDF
- [证书](usage/certificates.md) - X.509 证书、CSR、密钥序列化

## 快速参考

```python
# SM3 哈希
from gmssl.hazmat.primitives import hashes
digest = hashes.Hash(hashes.SM3())
digest.update(b"hello")
result = digest.finalize()

# SM4 对称加密
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
enc = cipher.encryptor()
ct = enc.update(pt) + enc.finalize()

# SM2 数字签名与公钥加密
from gmssl.hazmat.primitives.asymmetric import sm2
key = sm2.generate_private_key()
sig = key.sign(b"data")
key.public_key().verify(sig, b"data")
ct = key.public_key().encrypt(b"secret")
pt = key.decrypt(ct)
```

更多示例与说明请参见各功能指南。
