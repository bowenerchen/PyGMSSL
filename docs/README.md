# GmSSL / pygmssl 文档中心

本目录为仓库**统一文档入口**，按类别组织。实现代码主要在 **`pygmssl/`**；与 **eet** 的交叉验证在 **`tests-api/`**。

← 返回仓库总览：**[根目录 README.md](../README.md)**

**实现渊源**：Python 实现系在 **GmSSL 3.1.1** 基础上对照重构；上游：<https://github.com/guanzhi/GmSSL>。

---

## 文档地图（分类）

### 1. 项目概览与算法原理

| 资源 | 说明 |
|------|------|
| [算法 · SM2](algorithms/sm2.md) | 椭圆曲线公钥密码（签名、加密、ECDH、PKCS#8 加密私钥与 eet） |
| [算法 · SM3](algorithms/sm3.md) | 密码杂凑 |
| [算法 · SM4](algorithms/sm4.md) | 分组密码 |
| [算法 · SM9](algorithms/sm9.md) | 基于身份的密码 |
| [算法 · ZUC](algorithms/zuc.md) | 祖冲之流密码 |
| [架构说明](architecture.md) | 模块划分、后端与设计理念 |

### 2. 使用指南（概念与流程）

| 资源 | 说明 |
|------|------|
| [快速入门](usage/getting_started.md) | 安装与最小示例 |
| [哈希](usage/hashing.md) | SM3、流式哈希、SHA 系列 |
| [对称加密](usage/symmetric_encryption.md) | SM4 模式、ZUC |
| [数字签名](usage/digital_signatures.md) | SM2 签名与验证 |
| [非对称加密](usage/asymmetric_encryption.md) | SM2 加密、SM9 IBE |
| [密钥派生](usage/key_derivation.md) | HMAC、PBKDF2、HKDF、SM3-KDF |
| [证书](usage/certificates.md) | X.509、CSR、密钥序列化 |

### 3. 实践手册（Cookbook，可复制代码）

面向 **`gmssl.hazmat`** 的**逐算法抄码页**，便于直接粘贴到业务项目：

| 文档 | 内容 |
|------|------|
| [Cookbook 索引](cookbook/README.md) | 总览 |
| [SM2](cookbook/sm2.md) | 加解密格式、签名 RS/RS_ASN1、ECDH、PEM |
| [SM3](cookbook/sm3.md) | 哈希、SM3-KDF、HMAC-SM3 |
| [KDF（PBKDF2/HKDF + SM3）](cookbook/kdf-sm3.md) | 国密 KDF 示例 |
| [SM4](cookbook/sm4.md) | CBC/GCM/ECB/CTR |
| [SM9](cookbook/sm9.md) | 标识密码（依赖 libgmssl） |
| [ZUC](cookbook/zuc.md) | ZUC-128 / ZUC-256 |
| [X.509 / PEM](cookbook/x509-pem.md) | 证书、CSR、SM2 PEM/DER（含加密私钥） |

### 4. 测试与互操作（tests-api）

| 资源 | 说明 |
|------|------|
| [测试用例 ID 说明](testing/TEST_CASES.md) | 各 `run_*` 脚本用例索引 |
| [API 评审与 eet 对照](testing/REVIEW.md) | hazmat 行为与 eet v2.5.0 差异摘要 |
| [SM2 fixture 说明](testing/sm2-fixtures.md) | eet 生成的 PEM 与测试口令 |

运行测试与聚合报告：见 **[tests-api/README.md](../tests-api/README.md)**。

---

## 快速参考

```python
from gmssl.hazmat.primitives import hashes
digest = hashes.Hash(hashes.SM3())
digest.update(b"hello")
result = digest.finalize()

from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
enc = cipher.encryptor()
ct = enc.update(pt) + enc.finalize()

from gmssl.hazmat.primitives.asymmetric import sm2
key = sm2.generate_private_key()
sig = key.sign(b"data")
key.public_key().verify(sig, b"data")
```

更多示例见 [Cookbook](cookbook/README.md) 与 [使用指南](usage/getting_started.md)。

---

## 算法一览

| 算法 | 标准 | 用途 |
|------|------|------|
| SM2 | GM/T 0003-2012 | 签名、公钥加密、密钥交换 |
| SM3 | GM/T 0004-2012 | 杂凑 |
| SM4 | GM/T 0002-2012 | 对称分组密码 |
| SM9 | GM/T 0044-2016 | 基于身份的密码 |
| ZUC | 3GPP TS 35.221 | 流密码（4G/5G） |
