# SM2 使用说明（pygmssl）

椭圆曲线公钥密码：数字签名、公钥加解密、ECDH。默认用户标识 `uid` 为 `b"1234567812345678"`（可用 `sm2.DefaultID`）。

---

## 1. 密钥生成

```python
from gmssl.hazmat.primitives.asymmetric import sm2

private_key = sm2.generate_private_key()
public_key = private_key.public_key()
```

---

## 2. 密钥导入与导出

### 2.1 PKCS#8 私钥、SPKI 公钥（DER / PEM）

与 [x509-pem.md](x509-pem.md) 一致。明文私钥 PEM 使用标签 `PRIVATE KEY`；**加密私钥**使用 `ENCRYPTED PRIVATE KEY`（见 2.2）。

```python
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization

key = sm2.generate_private_key()
pub = key.public_key()

# ----- 导出私钥（PKCS#8 DER + PEM）-----
priv_der = serialization.encode_sm2_private_key_pkcs8(
    key.private_bytes(),
    pub.public_bytes_uncompressed(),
)
priv_pem = serialization._pem_encode(priv_der, "PRIVATE KEY")

# ----- 从 PEM / DER 导入私钥 -----
key2 = serialization.load_pem_private_key(priv_pem)
# 若手头已是 DER：先包一层 PEM，或自行解析后见 2.3 原始标量导入
assert key2.private_key_int == key.private_key_int

# ----- 导出公钥（SubjectPublicKeyInfo DER + PEM）-----
spki_der = serialization.encode_sm2_public_key_spki(pub.public_bytes_uncompressed())
pub_pem = serialization._pem_encode(spki_der, "PUBLIC KEY")

# ----- 从 PEM 导入公钥 -----
pub2 = serialization.load_pem_public_key(pub_pem)
assert pub2.x == pub.x and pub2.y == pub.y
```

仅保存 **DER** 时：`priv_der` / `spki_der` 可直接写入文件；读回后 `load_pem_private_key` 需要 PEM 包装，或见下节从原始字节恢复。

### 2.2 带口令的 PKCS#8（`ENCRYPTED PRIVATE KEY`，与 eet / GmSSL 一致）

- **算法**：PBES2 → PBKDF2（PRF 为国密 **HMAC-SM3**，OID `1.2.156.10197.1.401.2`）+ **SM4-CBC**（PKCS#7 填充）；默认 PBKDF2 迭代次数 **65536**（与 `eet sm2 generate` 一致）。
- **明文结构**：解密后的内层 PKCS#8 使用 **`id-ecPublicKey` + SM2 命名曲线 OID**，且 SEC1 `ECPrivateKey` 中含 **`[0]` 曲线 OID** 与 **`[1]` 公钥**，以便 `eet sm2 sign` 等命令可直接读取你导出的加密 PEM。
- **明文 `PRIVATE KEY`**（`encode_sm2_private_key_pkcs8`）仍为 **双 SM2 OID** 的 `AlgorithmIdentifier`；与 eet 线工具互操作时，优先使用本节加密导出，或单独使用 [interop PEM](x509-pem.md) 中的公钥写法。

```python
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives import serialization

key = sm2.generate_private_key()
pub = key.public_key()
password = b"your-secret"

enc_der = serialization.encode_sm2_private_key_pkcs8_encrypted(
    key.private_bytes(),
    pub.public_bytes_uncompressed(),
    password,
    # iterations=65536,  # 默认；测试时可改小以加快 PBKDF2
)
enc_pem = serialization._pem_encode(enc_der, "ENCRYPTED PRIVATE KEY")

loaded = serialization.load_pem_private_key(enc_pem, password)
assert loaded.private_key_int == key.private_key_int
```

### 2.3 原始私钥标量（32 字节）与未压缩公钥（65 字节）

- **私钥导出**：`private_bytes()` → 大端 256 bit 标量 `d`  
- **公钥导出**：`public_bytes_uncompressed()` → `0x04 || x(32) || y(32)`

```python
from gmssl.hazmat.primitives.asymmetric import sm2

key = sm2.generate_private_key()
pub = key.public_key()

d_bytes = key.private_bytes()
assert len(d_bytes) == 32

pub_bytes = pub.public_bytes_uncompressed()
assert len(pub_bytes) == 65 and pub_bytes[0] == 0x04
```

**从 65 字节公钥构造**（无 PEM 时）：

```python
def sm2_public_key_from_uncompressed(buf: bytes) -> sm2.SM2PublicKey:
    if len(buf) != 65 or buf[0] != 0x04:
        raise ValueError("need 65-byte uncompressed point (04||x||y)")
    x = int.from_bytes(buf[1:33], "big")
    y = int.from_bytes(buf[33:65], "big")
    return sm2.SM2PublicKey(x, y)

pub3 = sm2_public_key_from_uncompressed(pub_bytes)
assert pub3.x == pub.x
```

**从 32 字节私钥标量构造**（需由 `d` 推算公钥点）：

```python
from gmpy2 import mpz
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl._backends._sm2_field import SM2_G, scalar_multiply


def sm2_private_key_from_scalar(d_bytes: bytes) -> sm2.SM2PrivateKey:
    if len(d_bytes) != 32:
        raise ValueError("SM2 private scalar must be 32 bytes")
    d = int.from_bytes(d_bytes, "big")
    P = scalar_multiply(mpz(d), SM2_G)
    x, y = P.to_affine()
    return sm2.SM2PrivateKey(d, int(x), int(y))


key4 = sm2_private_key_from_scalar(d_bytes)
assert key4.private_key_int == key.private_key_int
```

导入后请确认 `d` 落在 SM2 合法范围内（本库生成密钥已保证）；外部导入的弱钥、全零等需自行校验。

---

## 3. 公钥加解密与密文格式

- **默认**（`ciphertext_format=None`）：`C1(65 字节，0x04||x||y) || C3(32) || C2`
- **与 eet `sm2 encrypt -m` 对齐**：`C1C3C2`、`C1C2C3`、`C1C3C2_ASN1`、`C1C2C3_ASN1`

明文长度：**1～255 字节**（GM/T 0003 单分组上限）。

```python
from gmssl.hazmat.primitives.asymmetric import sm2

key = sm2.generate_private_key()
pub = key.public_key()
plaintext = b"hello-sm2"

# --- 默认格式（65 字节 C1）---
ct_default = pub.encrypt(plaintext)
assert key.decrypt(ct_default) == plaintext

# --- eet 兼容：raw C1 为 64 字节（x||y）---
ct_c1c3c2 = pub.encrypt(plaintext, ciphertext_format="C1C3C2")
assert key.decrypt(ct_c1c3c2, ciphertext_format="C1C3C2") == plaintext

ct_c1c2c3 = pub.encrypt(plaintext, ciphertext_format="C1C2C3")
assert key.decrypt(ct_c1c2c3, ciphertext_format="C1C2C3") == plaintext

# --- ASN.1 DER SEQUENCE（INTEGER x, INTEGER y, OCTET STRING, OCTET STRING）---
ct_asn1 = pub.encrypt(plaintext, ciphertext_format="C1C3C2_ASN1")
assert key.decrypt(ct_asn1, ciphertext_format="C1C3C2_ASN1") == plaintext

ct_asn1_2 = pub.encrypt(plaintext, ciphertext_format="C1C2C3_ASN1")
assert key.decrypt(ct_asn1_2, ciphertext_format="C1C2C3_ASN1") == plaintext
```

**要点**：加密与解密必须使用**同一** `ciphertext_format`；库不会自动识别线格式。

---

## 4. 签名与验签格式

- **RS**（默认，`signature_format=None` 或 `"RS"`）：64 字节 `r || s`（各 32 字节大端）
- **RS_ASN1**（`"RS_ASN1"`）：DER `SEQUENCE { INTEGER r, INTEGER s }`（与 eet 默认签名输出一致）

```python
from gmssl.hazmat.primitives.asymmetric import sm2

key = sm2.generate_private_key()
pub = key.public_key()
message = b"document-bytes"

# --- RS（64 字节）---
sig_rs = key.sign(message)
assert len(sig_rs) == 64
pub.verify(sig_rs, message)

# 显式指定 RS（与默认等价）
sig_rs2 = key.sign(message, signature_format="RS")
pub.verify(sig_rs2, message, signature_format="RS")

# --- RS_ASN1（DER）---
sig_der = key.sign(message, signature_format="RS_ASN1")
pub.verify(sig_der, message, signature_format="RS_ASN1")
```

### 自定义用户标识（Z 值）

```python
uid = b"user-identity-utf8-ok"
sig = key.sign(message, uid=uid)
pub.verify(sig, message, uid=uid)
```

### DER 编解码（与 X.509 / 外部工具互转）

```python
from gmssl.hazmat.primitives import serialization

rs = key.sign(message)
der = serialization.encode_sm2_signature_der(rs)
rs2 = serialization.decode_sm2_signature_der(der)
assert rs2 == rs
pub.verify(der, message, signature_format="RS_ASN1")
```

---

## 5. ECDH（原始共享点坐标）

`exchange` 返回 **64 字节**：`x || y`（各 32 字节大端），**不经** SM3-KDF；与 GM/T 完整「密钥交换协议」不是同一概念。

```python
from gmssl.hazmat.primitives.asymmetric import sm2

alice = sm2.generate_private_key()
bob = sm2.generate_private_key()

s_a = alice.exchange(bob.public_key())
s_b = bob.exchange(alice.public_key())
assert s_a == s_b
```

若需从共享坐标派生会话密钥，可再配合 `gmssl.hazmat.primitives.kdf.sm3kdf.sm3_kdf` 等。

---

## 6. 底层模块（可选）

与 `cryptography` 风格一致的高阶 API 在 `gmssl.hazmat.primitives.asymmetric.sm2`；底层实现见 `gmssl._backends._sm2_algo`、密文格式 `gmssl._backends._sm2_ciphertext`、签名格式 `gmssl._backends._sm2_signature`。
