# PBKDF2 / HKDF（基于 SM3）（pygmssl）

本库在 KDF 中通过 `hashes.SM3()` 指定 **HMAC-SM3** 作为 PRF，与常见「PBKDF2-HMAC-SHA256」用法平行。

> **注意**：`PBKDF2HMAC` / `HKDF` / `HKDFExpand` 实例 **`derive` / `verify` 只能调用一次**（用后即弃，需再派生请新建对象）。

---

## 1. PBKDF2-HMAC-SM3

```python
import os
from gmssl.hazmat.primitives import hashes
from gmssl.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = b"user-password"
salt = os.urandom(16)
iterations = 100_000

kdf = PBKDF2HMAC(
    algorithm=hashes.SM3(),
    length=32,
    salt=salt,
    iterations=iterations,
)
derived_key = kdf.derive(password)
```

### 校验派生结果（可选）

```python
from gmssl.exceptions import InvalidKey

kdf2 = PBKDF2HMAC(
    algorithm=hashes.SM3(),
    length=32,
    salt=salt,
    iterations=iterations,
)
kdf2.verify(password, derived_key)  # 不匹配则抛 InvalidKey
```

---

## 2. HKDF（Extract + Expand，RFC 5869）

`salt=None` 时，实现上使用 **长度为 digest_size 的全零 salt**（与 RFC 5869 一致）。

```python
import os
from gmssl.hazmat.primitives import hashes
from gmssl.hazmat.primitives.kdf.hkdf import HKDF

ikm = b"input-key-material-from-ecdh-or-random"
salt = os.urandom(16)          # 或 None
info = b"context-label-v1"    # 区分不同用途/协议版本

hkdf = HKDF(
    algorithm=hashes.SM3(),
    length=48,
    salt=salt,
    info=info,
)
okm = hkdf.derive(ikm)
```

### 校验（可选）

```python
from gmssl.exceptions import InvalidKey

hkdf_v = HKDF(
    algorithm=hashes.SM3(),
    length=48,
    salt=salt,
    info=info,
)
hkdf_v.verify(ikm, okm)
```

---

## 3. HKDF-Expand（已有 PRK 时）

当你已经完成 Extract、只需求 Expand 时使用。

```python
from gmssl.hazmat.primitives import hashes
from gmssl.hazmat.primitives.kdf.hkdf import HKDFExpand

prk = b"\x00" * 32  # 长度应等于 SM3 输出长度（32）或与你的协议一致
info = b"tls13 derived key"

expand = HKDFExpand(
    algorithm=hashes.SM3(),
    length=32,
    info=info,
)
subkey = expand.derive(prk)
```

最大可派生长度：`255 * hash_len`（SM3 时为 `255 * 32`）。

---

## 4. 模块路径

- `gmssl.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`
- `gmssl.hazmat.primitives.kdf.hkdf.HKDF`、`HKDFExpand`

国密场景下的 **SM3-KDF**（Z || 计数器，用于 SM2 等）见 [sm3.md](sm3.md) 中的 `sm3_kdf`。
