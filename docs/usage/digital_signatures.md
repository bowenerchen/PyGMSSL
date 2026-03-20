# 数字签名使用指南

本文档介绍 GmSSL Python SDK 中的 SM2 椭圆曲线数字签名功能。

## SM2 密钥生成

```python
from gmssl.hazmat.primitives.asymmetric import sm2

private_key = sm2.generate_private_key()
public_key = private_key.public_key()
```

## 签名与验签

### 基本用法

```python
from gmssl.hazmat.primitives.asymmetric import sm2

private_key = sm2.generate_private_key()
public_key = private_key.public_key()

data = b"待签名的消息"
signature = private_key.sign(data)

# 验签
public_key.verify(signature, data)  # 验签成功则不抛出异常
```

若验签失败，会抛出 `InvalidSignature` 异常。

### 自定义用户 ID

SM2 签名使用用户 ID（默认值为 `"1234567812345678"`）参与 Z 值计算。可自定义以增强安全性：

```python
from gmssl.hazmat.primitives.asymmetric import sm2

private_key = sm2.generate_private_key()
custom_id = b"alice@example.com"

sig = private_key.sign(data, uid=custom_id)
public_key.verify(sig, data, uid=custom_id)
```

> **注意**：签名和验签必须使用相同的 `uid`，否则验签会失败。

## 签名格式

SM2 签名为 64 字节的原始格式：

- 前 32 字节：r（大端序）
- 后 32 字节：s（大端序）

```python
signature = private_key.sign(data)
assert len(signature) == 64
r = int.from_bytes(signature[:32], 'big')
s = int.from_bytes(signature[32:], 'big')
```

## 密钥序列化

详见 [证书与密钥序列化](certificates.md#密钥序列化) 文档。简要示例：

```python
from gmssl.hazmat.primitives import serialization

# 私钥导出
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# 公钥导出
pub_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

## SM9 基于身份的签名

SM9 支持基于身份的签名，无需证书。详见 [非对称加密](asymmetric_encryption.md#sm9-基于身份的加密) 中的 SM9 概述及 `sm9` 模块文档。

```python
from gmssl.hazmat.primitives.asymmetric import sm9

master = sm9.generate_sign_master_key()
user_key = master.extract_key("alice@example.com")
sig = user_key.sign(b"data")
master.public_key().verify(sig, b"data", "alice@example.com")
```

## 相关文档

- [算法介绍：SM2](../algorithms/sm2.md)
- [非对称加密](asymmetric_encryption.md)
- [证书与 X.509](certificates.md)
