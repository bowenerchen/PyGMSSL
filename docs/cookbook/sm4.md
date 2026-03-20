# SM4 使用说明（pygmssl）

分组长度 **128 bit（16 字节）**。支持 **ECB、CBC、CTR、GCM**。

---

## 1. 公共导入

```python
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes
```

密钥：**16 字节**。

---

## 2. CBC 模式（加密侧 PKCS#7 填充，`finalize` 时补齐）

IV：**16 字节**。

```python
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
iv = b"\x00" * 16
plaintext = b"any length data, e.g. 7 bytes"

cipher_enc = Cipher(algorithms.SM4(key), modes.CBC(iv))
encryptor = cipher_enc.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

cipher_dec = Cipher(algorithms.SM4(key), modes.CBC(iv))
decryptor = cipher_dec.decryptor()
recovered = decryptor.update(ciphertext) + decryptor.finalize()
assert recovered == plaintext
```

---

## 3. GCM 模式（AEAD：认证加密）

IV（nonce）：**1～64 字节**（常用 **12 字节**）。认证标签默认 **16 字节**，解密时通过 `modes.GCM(iv, tag=...)` 传入。

### 3.1 无附加认证数据（AAD）

```python
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
iv = bytes.fromhex("000012345678000000000000")  # 12 字节示例
plaintext = bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")

cipher_enc = Cipher(algorithms.SM4(key), modes.GCM(iv))
encryptor = cipher_enc.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag  # finalize 之后可用

cipher_dec = Cipher(algorithms.SM4(key), modes.GCM(iv, tag=tag))
decryptor = cipher_dec.decryptor()
recovered = decryptor.update(ciphertext) + decryptor.finalize()
assert recovered == plaintext
```

### 3.2 带 AAD（附加认证数据）

```python
import os
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)   # 示例：随机密钥
iv = os.urandom(12)
plaintext = b"secret payload"
aad = b"context-bound-aad"

cipher_enc = Cipher(algorithms.SM4(key), modes.GCM(iv))
encryptor = cipher_enc.encryptor()
encryptor.authenticate_additional_data(aad)
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag

cipher_dec = Cipher(algorithms.SM4(key), modes.GCM(iv, tag=tag))
decryptor = cipher_dec.decryptor()
decryptor.authenticate_additional_data(aad)
recovered = decryptor.update(ciphertext) + decryptor.finalize()
assert recovered == plaintext
```

> `authenticate_additional_data` 须在 `update` 明文**之前**调用（与 `cryptography` 习惯一致）。标签错误会抛出 `gmssl.exceptions.InvalidTag`。

---

## 4. ECB 模式（整块 16 字节，无填充）

```python
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
block = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")

cipher = Cipher(algorithms.SM4(key), modes.ECB())
enc = cipher.encryptor()
ct = enc.update(block) + enc.finalize()

dec = cipher.decryptor()
pt = dec.update(ct) + dec.finalize()
assert pt == block
```

---

## 5. CTR 模式

计数器块（nonce）：**16 字节**（内部按 GmSSL 语义作为 CTR 初值使用）。

```python
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"\x00" * 16
nonce = b"\x00" * 16
data = b"arbitrary length plaintext"

cipher_enc = Cipher(algorithms.SM4(key), modes.CTR(nonce))
enc = cipher_enc.encryptor()
ct = enc.update(data) + enc.finalize()

cipher_dec = Cipher(algorithms.SM4(key), modes.CTR(nonce))
dec = cipher_dec.decryptor()
pt = dec.update(ct) + dec.finalize()
assert pt == data
```

---

## 6. 与 eet 等工具对齐时的提示

- **CBC**：本库在 `finalize` 使用 **PKCS#7** 填充。
- **GCM**：密文与 **tag** 的布局需与对端约定一致；本库 `encryptor.tag` 为完整计算标签，常见做法为线上传输 **`ciphertext || tag`**（与仓库 tests-api 中 eet 对照一致）。
