# 哈希算法使用指南

本文档介绍 GmSSL Python SDK 中的哈希功能，包括 SM3 国密哈希算法以及通过标准 `hashlib` 提供的 SHA 系列算法。

## SM3 哈希

SM3 是中国国家密码标准（GM/T 0004-2012）指定的密码杂凑算法，输出 256 位（32 字节）摘要。

### 基本用法

```python
from gmssl.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SM3())
digest.update(b"hello")
result = digest.finalize()
# result 为 32 字节摘要
```

### 流式哈希（分块更新）

对于大文件或流式数据，可使用 `update()` 多次传入数据：

```python
from gmssl.hazmat.primitives import hashes

h = hashes.Hash(hashes.SM3())
h.update(b"第一部分")
h.update(b"第二部分")
h.update(b"第三部分")
result = h.finalize()
```

### 哈希复制（Fork 中间状态）

`Hash` 支持 `copy()` 方法，可在计算中途复制上下文，用于实现并行哈希或增量验证：

```python
from gmssl.hazmat.primitives import hashes

h = hashes.Hash(hashes.SM3())
h.update(b"共同前缀")
h2 = h.copy()
h.update(b"分支 A")
h2.update(b"分支 B")
result_a = h.finalize()
result_b = h2.finalize()
# result_a 与 result_b 不同
```

### SM3 算法属性

| 属性       | 值  |
|------------|-----|
| `name`     | `"sm3"` |
| `digest_size` | 32 字节 |
| `block_size`  | 64 字节 |

## SHA-256 / SHA-384 / SHA-512 / SHA-224

SDK 通过 `hashlib` 提供标准 SHA 算法，API 与 SM3 一致：

```python
from gmssl.hazmat.primitives import hashes

# SHA-256（32 字节）
h = hashes.Hash(hashes.SHA256())
h.update(b"data")
digest_256 = h.finalize()

# SHA-384（48 字节）
h = hashes.Hash(hashes.SHA384())
h.update(b"data")
digest_384 = h.finalize()

# SHA-512（64 字节）
h = hashes.Hash(hashes.SHA512())
h.update(b"data")
digest_512 = h.finalize()

# SHA-224（28 字节）
h = hashes.Hash(hashes.SHA224())
h.update(b"data")
digest_224 = h.finalize()
```

### 算法属性

| 算法   | digest_size | block_size |
|--------|--------------|------------|
| SHA224 | 28           | 64         |
| SHA256 | 32           | 64         |
| SHA384 | 48           | 128        |
| SHA512 | 64           | 128        |

## 注意事项

1. **一次性**：`Hash` 上下文在调用 `finalize()` 后不能再次使用，否则会抛出 `AlreadyFinalized`。
2. **不可逆**：哈希为单向函数，无法从摘要恢复原文。
3. **碰撞抵抗**：SM3 与 SHA-256 等算法设计上具有抗碰撞性，适用于数字签名、消息认证等场景。

## 相关文档

- [算法介绍：SM3](../algorithms/sm3.md)
- [HMAC 与消息认证](key_derivation.md#hmac-sm3)
- [快速入门](getting_started.md)
