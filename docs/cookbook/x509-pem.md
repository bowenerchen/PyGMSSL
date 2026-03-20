# X.509 与 SM2 PEM/DER（pygmssl）

涵盖：**SM2 私钥/公钥 PEM** 编解码（含 **PBES2 加密私钥**）、**自签名证书**、**CSR** 的 PEM/DER 导出。实现位于 `gmssl.x509` 与 `gmssl.hazmat.primitives.serialization`。

- **明文** `PRIVATE KEY`：`load_pem_private_key(pem, password=None)`。
- **加密** `ENCRYPTED PRIVATE KEY`（PBES2 + PBKDF2-HMAC-SM3 + SM4-CBC，与 **eet** / GmSSL 一致）：`load_pem_private_key(pem, password=b"...")`。导出见 `encode_sm2_private_key_pkcs8_encrypted`（[sm2.md §2.2](sm2.md)）。

---

## 1. SM2 私钥 / 公钥：DER 与 PEM

使用 **PKCS#8**（私钥）与 **SubjectPublicKeyInfo**（公钥）。PEM 封装通过 `serialization._pem_encode` / `_pem_decode`（与测试、X.509 模块一致）。

```python
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization

key = sm2.generate_private_key()
pub = key.public_key()

# --- 私钥 PKCS#8 DER → PEM ---
priv_der = serialization.encode_sm2_private_key_pkcs8(
    key.private_bytes(),
    pub.public_bytes_uncompressed(),
)
priv_pem = serialization._pem_encode(priv_der, "PRIVATE KEY")

# --- 从 PEM 加载私钥 ---
loaded = serialization.load_pem_private_key(priv_pem)
assert loaded.private_key_int == key.private_key_int

# --- 公钥 SPKI DER → PEM ---
spki_der = serialization.encode_sm2_public_key_spki(pub.public_bytes_uncompressed())
pub_pem = serialization._pem_encode(spki_der, "PUBLIC KEY")

loaded_pub = serialization.load_pem_public_key(pub_pem)
assert loaded_pub.x == pub.x and loaded_pub.y == pub.y
```

**加密私钥 PEM**（与 `eet sm2 generate` 互读时，内层 PKCS#8 为 GmSSL 兼容结构；详见 sm2 文档）：

```python
pwd = b"ApiTestPwd01"
enc_der = serialization.encode_sm2_private_key_pkcs8_encrypted(
    key.private_bytes(),
    key.public_key().public_bytes_uncompressed(),
    pwd,
)
enc_pem = serialization._pem_encode(enc_der, "ENCRYPTED PRIVATE KEY")
same = serialization.load_pem_private_key(enc_pem, pwd)
assert same.private_key_int == key.private_key_int
```

`Encoding` 枚举在 `serialization` 中用于证书/CSR（见下文）；**裸密钥 PEM** 如上使用 `_pem_encode` 即可。

---

## 2. 自签名 SM2 证书（DER / PEM）

```python
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization
from gmssl.x509 import Certificate, CertificateBuilder, Name, NameAttribute
from gmssl.x509.name import OID_CN, OID_O, OID_C

key = sm2.generate_private_key()
subject = Name([
    NameAttribute(OID_C, "CN"),
    NameAttribute(OID_O, "Example Org"),
    NameAttribute(OID_CN, "sm2.example.com"),
])

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

cert_der = cert.public_bytes(serialization.Encoding.DER)
cert_pem = cert.public_bytes(serialization.Encoding.PEM)

# PEM 读回
cert2 = Certificate.from_pem(cert_pem)
assert cert2.public_bytes(serialization.Encoding.DER) == cert_der
```

证书签名值为 **SM2 签名 DER**（`encode_sm2_signature_der`），与 GmSSL 习惯一致。

---

## 3. 证书签名请求（CSR）

```python
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization
from gmssl.x509 import CertificateSigningRequestBuilder, Name, NameAttribute
from gmssl.x509.name import OID_CN, OID_O

key = sm2.generate_private_key()
subject = Name([
    NameAttribute(OID_CN, "app.example.com"),
    NameAttribute(OID_O, "My Company"),
])

csr = (
    CertificateSigningRequestBuilder()
    .subject_name(subject)
    .sign(key)
)

csr_pem = csr.public_bytes(serialization.Encoding.PEM)
csr_der = csr.public_bytes(serialization.Encoding.DER)
assert b"BEGIN CERTIFICATE REQUEST" in csr_pem
```

---

## 4. Distinguished Name（Name）常用 OID

在 `gmssl.x509.name` 中定义，例如：`OID_CN`、`OID_O`、`OID_OU`、`OID_C`、`OID_ST`、`OID_L`、`OID_EMAIL`。  
`NameAttribute(OID_C, "CN")` 使用 **PrintableString**；其余属性默认 **UTF8String**。

---

## 5. 相关模块

| 用途 | 模块 / 符号 |
|------|----------------|
| 证书 | `gmssl.x509.Certificate`, `CertificateBuilder` |
| CSR | `gmssl.x509.CertificateSigningRequest`, `CertificateSigningRequestBuilder` |
| DN | `gmssl.x509.Name`, `NameAttribute`, `gmssl.x509.name` 下 OID |
| 编码 | `gmssl.hazmat.primitives.serialization`（`Encoding`, `encode_sm2_*`, `load_pem_*`, `_pem_encode`） |

完整解析链校验、CRL、路径验证等**未**在本库范围内；当前侧重**创建与 PEM/DER 往返**。
