# 证书与 CSR

本文档介绍 GmSSL Python SDK 中 X.509 证书、证书签名请求（CSR）及密钥序列化的用法。

## 概述

SDK 支持：

- **X.509 证书**：创建、解析、PEM/DER 编码
- **证书签名请求（CSR）**：创建、PEM/DER 编码
- **密钥序列化**：SM2 密钥的 PEM/DER 格式

证书和 CSR 使用 SM2 算法进行签名。

---

## X.509 证书创建

使用 `CertificateBuilder` 以链式调用创建自签名或 CA 签发证书。

```python
from gmssl.x509 import CertificateBuilder, Certificate, Name, NameAttribute
from gmssl.x509.name import OID_CN, OID_O, OID_C
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization

# 生成 SM2 密钥对
key = sm2.generate_private_key()

# 构建主题名称
subject = Name([
    NameAttribute(OID_C, "CN"),           # 国家
    NameAttribute(OID_O, "Example Org"),  # 组织
    NameAttribute(OID_CN, "example.com"),  # 通用名
])

# 创建自签名证书
cert = (
    CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)           # 自签名：颁发者与主题相同
    .public_key(key.public_key())
    .serial_number(1234567890)
    .not_valid_before("250101000000Z")  # UTC 时间
    .not_valid_after("350101000000Z")
    .sign(key)
)

# cert 为 Certificate 对象
```

### 常用 OID

| 常量 | 含义 |
|------|------|
| `OID_CN` | 通用名 |
| `OID_O` | 组织 |
| `OID_OU` | 组织单元 |
| `OID_C` | 国家 |
| `OID_ST` | 州/省 |
| `OID_L` | 地区 |
| `OID_EMAIL` | 邮箱 |

---

## PEM 与 DER 编码

### 证书输出

```python
# DER 格式（二进制）
der_bytes = cert.public_bytes(serialization.Encoding.DER)

# PEM 格式（Base64 文本）
pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
```

### 从 PEM/DER 加载证书

```python
# 从 PEM 加载
cert2 = Certificate.from_pem(pem_bytes)

# 从 DER 加载
cert3 = Certificate.from_der(der_bytes)
```

---

## 证书签名请求（CSR）

CSR 用于向 CA 申请证书，包含主题信息和公钥，并由私钥签名。

```python
from gmssl.x509 import CertificateSigningRequestBuilder, CertificateSigningRequest
from gmssl.x509 import Name, NameAttribute
from gmssl.x509.name import OID_CN, OID_O

key = sm2.generate_private_key()
subject = Name([
    NameAttribute(OID_CN, "client.example.com"),
    NameAttribute(OID_O, "Client Org"),
])

csr = (
    CertificateSigningRequestBuilder()
    .subject_name(subject)
    .sign(key)
)

# DER 格式
der_csr = csr.public_bytes(serialization.Encoding.DER)

# PEM 格式
pem_csr = csr.public_bytes(serialization.Encoding.PEM)
# PEM 标签为 "CERTIFICATE REQUEST"
```

---

## 密钥序列化

### 私钥导出

```python
from gmssl.hazmat.primitives import serialization

# PKCS#8 DER 格式
priv_der = serialization.encode_sm2_private_key_pkcs8(
    key.private_bytes(),
    key.public_key().public_bytes_uncompressed(),
)

# PKCS#8 PEM 格式
pem_private = serialization._pem_encode(priv_der, "PRIVATE KEY")
```

### 公钥导出

```python
public_key = key.public_key()

# 非压缩点格式（65 字节：0x04 + x + y）
raw_bytes = public_key.public_bytes_uncompressed()

# SubjectPublicKeyInfo DER 格式
spki_der = serialization.encode_sm2_public_key_spki(raw_bytes)

# SubjectPublicKeyInfo PEM 格式
pem_public = serialization._pem_encode(spki_der, "PUBLIC KEY")
```

### 从 PEM 加载密钥

```python
from gmssl.hazmat.primitives import serialization

# 加载私钥
private_key = serialization.load_pem_private_key(pem_private_data, password=None)

# 加载公钥
public_key = serialization.load_pem_public_key(pem_public_data)
```

---

## 完整示例：自签名证书

```python
from gmssl.x509 import CertificateBuilder, Certificate, Name, NameAttribute
from gmssl.x509.name import OID_CN, OID_O, OID_C
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization

# 1. 生成密钥
key = sm2.generate_private_key()

# 2. 构建主题
subject = Name([
    NameAttribute(OID_C, "CN"),
    NameAttribute(OID_O, "Test CA"),
    NameAttribute(OID_CN, "ca.example.com"),
])

# 3. 创建自签名 CA 证书
cert = (
    CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(1)
    .not_valid_before("250101000000Z")
    .not_valid_after("350101000000Z")
    .sign(key)
)

# 4. 保存为 PEM
with open("ca.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# 5. 保存私钥
priv_der = serialization.encode_sm2_private_key_pkcs8(
    key.private_bytes(),
    key.public_key().public_bytes_uncompressed(),
)
with open("ca_key.pem", "wb") as f:
    f.write(serialization._pem_encode(priv_der, "PRIVATE KEY"))
```

---

## 时间格式

`not_valid_before` 和 `not_valid_after` 使用 UTC 时间字符串：

- 格式：`YYMMDDHHMMSSZ`
- 示例：`250101000000Z` 表示 2025-01-01 00:00:00 UTC
