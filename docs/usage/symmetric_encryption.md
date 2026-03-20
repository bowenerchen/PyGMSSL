# 对称加密使用指南

本文档介绍 GmSSL Python SDK 中的对称加密功能，包括 SM4 分组密码的多种工作模式以及 ZUC 流密码。

## SM4 分组密码

SM4 是中国国家密码标准（GM/T 0002-2012）指定的 128 位分组密码，密钥长度为 128 位（16 字节）。

### SM4-ECB 模式

ECB（Electronic Codebook）模式将明文按块独立加密，相同明文块产生相同密文块。**不推荐用于安全敏感场景**，建议仅在需要 ECB 兼容性时使用。

```python
import os
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
plaintext = b"Hello World!"  # 必须为 16 字节的整数倍

cipher = Cipher(algorithms.SM4(key), modes.ECB())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
assert decrypted == plaintext
```

> **注意**：ECB 模式下 `finalize()` 前数据必须按 16 字节对齐，否则会抛出 `ValueError`。

### SM4-CBC 模式与 PKCS7 填充

CBC（Cipher Block Chaining）模式使用初始化向量（IV），支持任意长度明文。SDK 自动处理 PKCS7 填充。

```python
import os
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
iv = os.urandom(16)
plaintext = b"任意长度的明文数据"

cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
assert decrypted == plaintext
```

### SM4-CTR 模式

CTR（Counter）模式将分组密码转化为流密码，无需填充，支持任意长度数据。

```python
import os
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
nonce = os.urandom(16)  # CTR 模式的 nonce，16 字节
plaintext = b"任意长度的数据，无需填充"

cipher = Cipher(algorithms.SM4(key), modes.CTR(nonce))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# 解密使用相同 key 和 nonce
decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
assert decrypted == plaintext
```

### SM4-GCM 模式（AEAD）

GCM（Galois/Counter Mode）提供认证加密（AEAD），同时保证机密性和完整性。支持附加认证数据（AAD）。

```python
import os
from gmssl.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
iv = os.urandom(12)  # GCM 通常使用 12 字节 IV
plaintext = b"机密数据"
aad = b"可选的附加认证数据（如头部信息）"

cipher = Cipher(algorithms.SM4(key), modes.GCM(iv))
encryptor = cipher.encryptor()
encryptor.authenticate_additional_data(aad)
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag

# 解密
dec_cipher = Cipher(algorithms.SM4(key), modes.GCM(iv, tag=tag))
decryptor = dec_cipher.decryptor()
decryptor.authenticate_additional_data(aad)
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
assert decrypted == plaintext
```

> **重要**：解密时必须传入正确的 `tag`，否则 `finalize()` 会抛出 `InvalidTag` 异常。

> **AAD 与标签**：首次对密文/明文调用 `update()` 时会 **隐式结束 AAD**；之后不能再追加 AAD。`modes.GCM` 支持 `min_tag_length`（默认 12），验证时会把计算出的标签 **截断到与传入 `tag` 相同长度** 再比较；短标签会降低安全性，生产环境建议使用 **16 字节** 完整标签。

## ZUC 流密码

ZUC 是 3GPP 标准指定的流密码，用于 4G/5G 移动通信加密。支持 ZUC-128 和 ZUC-256 两种变体。

### ZUC-128

- 密钥：16 字节
- IV：16 字节

```python
from gmssl._backends._zuc import ZUCState

key = b'\x00' * 16
iv = b'\x00' * 16
plaintext = b"Hello ZUC stream cipher!"

state = ZUCState(key, iv)
ciphertext = state.encrypt(plaintext)

# 解密：ZUC 是对称的，再次加密即解密
state2 = ZUCState(key, iv)
decrypted = state2.encrypt(ciphertext)
assert decrypted == plaintext
```

### ZUC-256

- 密钥：32 字节
- IV：23 字节

```python
from gmssl._backends._zuc import ZUC256State

key = b'\x00' * 32
iv = b'\x00' * 23
plaintext = b"ZUC-256 流密码测试数据"

state = ZUC256State(key, iv)
ciphertext = state.encrypt(plaintext)

state2 = ZUC256State(key, iv)
decrypted = state2.encrypt(ciphertext)
assert decrypted == plaintext
```

### 生成密钥流

若只需密钥流用于自定义加密逻辑：

```python
from gmssl._backends._zuc import ZUCState

key = bytes.fromhex("3d4c4be96a82fdaeb58f641db17b455b")
iv = bytes.fromhex("84319aa8de6915ca1f6bda6bfbd8c766")
state = ZUCState(key, iv)
# 每次生成 4 字节（1 个 32 位字）
words = state.generate_keystream(2)  # [0x14f1c272, 0x3279c419]
```

## 流式加密

所有基于 `Cipher` 的模式均支持流式处理：

```python
cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
encryptor = cipher.encryptor()

output = b""
for chunk in chunks:
    output += encryptor.update(chunk)
output += encryptor.finalize()
```

## 相关文档

- [算法介绍：SM4](../algorithms/sm4.md)
- [算法介绍：ZUC](../algorithms/zuc.md)
- [快速入门](getting_started.md)
