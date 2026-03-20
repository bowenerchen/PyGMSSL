# 密钥派生

本文档介绍 GmSSL Python SDK 中基于 SM3 的密钥派生函数（KDF）用法。

## 概述

密钥派生函数用于从主密钥或密码等材料派生出指定长度的密钥。SDK 支持以下 KDF：

| 函数 | 用途 |
|------|------|
| HMAC-SM3 | 消息认证码，也可用于密钥派生 |
| PBKDF2-SM3 | 从密码派生密钥（抗暴力破解） |
| HKDF-SM3 | HMAC 基础密钥派生（RFC 5869） |
| SM3-KDF | GM/T 0003-2012 国密标准 KDF |

---

## HMAC-SM3

HMAC（Hash-based Message Authentication Code）基于哈希的消息认证码，可用于消息完整性校验，也可作为密钥派生的基础。

```python
from gmssl.hazmat.primitives import hashes, hmac

key = b"my-secret-key"  # 任意长度
h = hmac.HMAC(key, hashes.SM3())
h.update(b"message to authenticate")
mac = h.finalize()

# 验证 MAC
h2 = hmac.HMAC(key, hashes.SM3())
h2.update(b"message to authenticate")
h2.verify(mac)  # 成功则无异常；失败则抛出 InvalidSignature
```

### 流式 MAC 计算

```python
h = hmac.HMAC(key, hashes.SM3())
for chunk in chunks:
    h.update(chunk)
mac = h.finalize()
```

### copy 复制上下文

```python
h = hmac.HMAC(key, hashes.SM3())
h.update(b"common prefix")
h2 = h.copy()
h.update(b"path1")
h2.update(b"path2")
mac1 = h.finalize()
mac2 = h2.finalize()
```

---

## PBKDF2-SM3

PBKDF2（Password-Based Key Derivation Function 2）用于从密码派生密钥，通过迭代次数提高抗暴力破解能力。

```python
from gmssl.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gmssl.hazmat.primitives import hashes
import os

salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SM3(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = kdf.derive(b"user-password")
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `algorithm` | 哈希算法，通常为 `hashes.SM3()` |
| `length` | 派生密钥长度（字节） |
| `salt` | 随机盐，通常 16 字节 |
| `iterations` | 迭代次数，建议 ≥ 100000 |

### 验证派生密钥

```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SM3(),
    length=32,
    salt=salt,
    iterations=100000,
)
kdf.verify(b"user-password", stored_key)  # 不匹配时抛出 InvalidKey
```

> **注意**：`PBKDF2HMAC` 实例只能使用一次，`derive` 或 `verify` 调用后不能再次使用。

---

## HKDF-SM3

HKDF（HMAC-based Key Derivation Function）基于 HMAC 的密钥派生，适用于已有高熵输入密钥材料的场景。

```python
from gmssl.hazmat.primitives.kdf.hkdf import HKDF
from gmssl.hazmat.primitives import hashes

salt = b"application-specific-salt"
info = b"session-key-v1"
hkdf = HKDF(
    algorithm=hashes.SM3(),
    length=32,
    salt=salt,
    info=info,
)
key = hkdf.derive(input_key_material)
```

### 仅 Expand 阶段（已有 PRK）

```python
from gmssl.hazmat.primitives.kdf.hkdf import HKDFExpand

hkdf_expand = HKDFExpand(
    algorithm=hashes.SM3(),
    length=32,
    info=b"expand-context",
)
key = hkdf_expand.derive(prk)
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `salt` | 盐，可为 `None`（使用全零） |
| `info` | 上下文信息，区分不同用途的派生密钥 |
| `length` | 派生密钥长度，不超过 255 × digest_size |

---

## SM3-KDF

SM3-KDF 是 GM/T 0003-2012 中定义的密钥派生函数，常用于 SM2 密钥协商等场景。

```python
from gmssl.hazmat.primitives.kdf.sm3kdf import sm3_kdf

# Z 为共享信息或种子材料（如 ECDH 协商结果）
z = b"shared-secret-or-seed"
klen = 32  # 所需密钥长度（字节）
key = sm3_kdf(z, klen)
```

### 使用示例

```python
from gmssl.hazmat.primitives.asymmetric import sm2
from gmssl.hazmat.primitives.kdf.sm3kdf import sm3_kdf

# 使用 SM2 ECDH 协商的共享点派生会话密钥
alice_key = sm2.generate_private_key()
bob_key = sm2.generate_private_key()

shared_alice = alice_key.exchange(bob_key.public_key())
shared_bob = bob_key.exchange(alice_key.public_key())
assert shared_alice == shared_bob

# 从共享点派生 32 字节密钥
session_key = sm3_kdf(shared_alice, 32)
```

---

## 快速参考

| 场景 | 推荐方案 |
|------|----------|
| 用户密码派生 | PBKDF2-SM3 |
| 已有高熵密钥派生 | HKDF-SM3 |
| SM2 ECDH 后派生 | SM3-KDF |
| 消息认证 | HMAC-SM3 |
