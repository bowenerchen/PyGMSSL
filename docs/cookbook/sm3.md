# SM3 与 HMAC-SM3、SM3-KDF（pygmssl）

---

## 1. SM3 哈希（流式 update / finalize）

```python
from gmssl.hazmat.primitives import hashes

h = hashes.Hash(hashes.SM3())
h.update(b"hello")
h.update(b" world")
digest = h.finalize()
assert len(digest) == 32
```

### 复制中间状态（可选）

```python
h = hashes.Hash(hashes.SM3())
h.update(b"partial")
h2 = h.copy()
h.update(b"rest")
d1 = h.finalize()
h2.update(b"rest")
d2 = h2.finalize()
assert d1 == d2
```

---

## 2. HMAC-SM3

```python
from gmssl.hazmat.primitives import hashes, hmac

key = b"shared-secret-key"
mac = hmac.HMAC(key, hashes.SM3())
mac.update(b"authenticated message")
tag = mac.finalize()

# 验证（不一致会抛 InvalidSignature）
mac2 = hmac.HMAC(key, hashes.SM3())
mac2.update(b"authenticated message")
mac2.verify(tag)
```

---

## 3. SM3-KDF（GM/T 0003 附录，SM2 加密用 KDF）

由共享比特串 `Z` 派生指定长度密钥材料（按 32 字节块用 SM3 拼接）。

```python
from gmssl.hazmat.primitives.kdf.sm3kdf import sm3_kdf

z = b"\x00" * 64  # 例如 SM2 共享点的 x||y 等
key_material = sm3_kdf(z, klen=16)
assert len(key_material) == 16
```

---

## 4. 相关模块位置

- 哈希：`gmssl.hazmat.primitives.hashes`
- HMAC：`gmssl.hazmat.primitives.hmac`
- SM3-KDF：`gmssl.hazmat.primitives.kdf.sm3kdf`

PBKDF2-HMAC-SM3、HKDF（SM3）的完整示例见 **[kdf-sm3.md](kdf-sm3.md)**。
