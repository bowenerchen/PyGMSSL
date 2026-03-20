# 快速入门

本文介绍如何安装 GmSSL Python SDK 并快速体验主要功能。

## 安装

### 使用 pip 安装

```bash
pip install pygmssl
```

### 依赖

- **Python**：>= 3.9
- **gmpy2**：>= 2.1.0（SM2、SM9 大整数运算依赖）

gmpy2 为 SM2、SM9 提供高性能多精度整数与模逆运算。若安装 gmpy2 遇到问题，可参考官方文档或使用预编译 wheel。

### 源码安装

```bash
cd pygmssl
pip install -e .
```

## 快速示例

### SM3 哈希

```python
from gmssl.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SM3())
digest.update(b"hello")
result = digest.finalize()
print(result.hex())  # 32 字节 SM3 摘要
```

### SM4 对称加密

**CBC 模式（带 PKCS7 填充）：**

```python
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b'\x00' * 16   # 16 字节密钥
iv = b'\x00' * 16    # 16 字节 IV

cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
enc = cipher.encryptor()
ct = enc.update(b"Hello SM4!") + enc.finalize()

dec = cipher.decryptor()
pt = dec.update(ct) + dec.finalize()
assert pt == b"Hello SM4!"
```

**CTR 模式：**

```python
cipher = Cipher(algorithms.SM4(key), modes.CTR(nonce))
enc = cipher.encryptor()
ct = enc.update(b"data") + enc.finalize()
```

**GCM 模式（AEAD，带认证）：**

```python
iv = os.urandom(12)
cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
enc = cipher.encryptor()
enc.authenticate_additional_data(b"aad")
ct = enc.update(b"secret") + enc.finalize()
tag = enc.tag  # 认证标签，解密时需传入

dec = cipher.decryptor()
dec = Cipher(algorithms.SM4(key), modes.GCM(iv, tag=tag)).decryptor()
dec.authenticate_additional_data(b"aad")
pt = dec.update(ct) + dec.finalize()
```

### SM2 签名与验证

```python
from gmssl.hazmat.primitives.asymmetric import sm2

key = sm2.generate_private_key()
sig = key.sign(b"message to sign")
key.public_key().verify(sig, b"message to sign")  # 验证通过则不抛出异常
```

### SM2 加密与解密

```python
ct = key.public_key().encrypt(b"secret message")
pt = key.decrypt(ct)
assert pt == b"secret message"
```

### HMAC

```python
from gmssl.hazmat.primitives import hashes, hmac

h = hmac.HMAC(key, hashes.SM3())
h.update(b"message")
mac = h.finalize()

# 或使用 verify 进行恒定时间比对
h2 = hmac.HMAC(key, hashes.SM3())
h2.update(b"message")
h2.verify(mac)  # 不匹配则抛出 InvalidSignature
```

### PBKDF2 密钥派生

```python
from gmssl.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gmssl.hazmat.primitives import hashes

salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SM3(),
    length=32,
    salt=salt,
    iterations=100000
)
key = kdf.derive(b"password")
```

### HKDF 密钥派生

```python
from gmssl.hazmat.primitives.kdf.hkdf import HKDF
from gmssl.hazmat.primitives import hashes

hkdf = HKDF(
    algorithm=hashes.SM3(),
    length=32,
    salt=salt,
    info=b"context-info"
)
key = hkdf.derive(input_key_material)
```

### X.509 证书创建

```python
from gmssl.x509 import CertificateBuilder, Certificate, Name, NameAttribute
from gmssl.x509.name import OID_CN, OID_O, OID_C
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization

key = sm2.generate_private_key()
subject = Name([
    NameAttribute(OID_C, "CN"),
    NameAttribute(OID_O, "Test Org"),
    NameAttribute(OID_CN, "example.com"),
])
cert = (
    CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(12345)
    .not_valid_before("250101000000Z")
    .not_valid_after("350101000000Z")
    .sign(key)
)
# cert 为 Certificate 对象
pem = cert.public_bytes(serialization.Encoding.PEM)
der = cert.public_bytes(serialization.Encoding.DER)
```

更多用法详见各功能文档。
