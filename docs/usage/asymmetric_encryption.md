# 非对称加密使用指南

本文档介绍 GmSSL Python SDK 中的公钥加密功能，包括 SM2 椭圆曲线公钥加密和 SM9 基于身份加密的概览。

## SM2 公钥加密

SM2 支持公钥加密、私钥解密，适用于密钥交换或小数据加密。

### 加密与解密

```python
from gmssl.hazmat.primitives.asymmetric import sm2

private_key = sm2.generate_private_key()
public_key = private_key.public_key()

plaintext = b"秘密消息"
ciphertext = public_key.encrypt(plaintext)

decrypted = private_key.decrypt(ciphertext)
assert decrypted == plaintext
```

### 适用场景

- 加密的明文长度有限，适合密钥、会话密钥等小数据
- 大数据加密建议使用 SM4 对称加密，用 SM2 加密会话密钥

### ECDH 密钥交换

SM2 支持椭圆曲线 Diffie-Hellman 密钥交换：

```python
from gmssl.hazmat.primitives.asymmetric import sm2

alice_priv = sm2.generate_private_key()
bob_priv = sm2.generate_private_key()

# Alice 与 Bob 交换公钥后
shared_alice = alice_priv.exchange(bob_priv.public_key())
shared_bob = bob_priv.exchange(alice_priv.public_key())
assert shared_alice == shared_bob  # 64 字节共享点 (x || y)
```

> **语义说明**：`exchange()` 仅输出 **原始共享点坐标 `x‖y`**，**不是** GM/T 0003 附录中的完整密钥交换协议（无固定协议消息、无确认值）。若协议要求标准协商流程，需在应用层自行实现。

可使用 SM3-KDF 从共享点派生会话密钥：

```python
from gmssl.hazmat.primitives.kdf.sm3kdf import sm3_kdf

shared = alice_priv.exchange(bob_priv.public_key())
session_key = sm3_kdf(shared, 16)
```

## SM9 基于身份的加密（概览）

SM9 使用用户身份（如邮箱、ID）作为公钥，无需证书。支持签名和加密。

### SM9 加密主密钥

```python
from gmssl.hazmat.primitives.asymmetric import sm9

# 生成加密主密钥
master = sm9.generate_enc_master_key()
public_key = master.public_key()

# 根据身份为用户提取解密私钥
user_id = "alice@example.com"
user_key = master.extract_key(user_id)
```

### 加密与解密

```python
# 加密：使用公钥和接收者身份
plaintext = b"机密数据"
ciphertext = public_key.encrypt(plaintext, user_id)

# 解密：使用用户私钥和自身身份
decrypted = user_key.decrypt(ciphertext, user_id)
assert decrypted == plaintext
```

### 特点

- **无需证书**：身份即公钥
- **密钥提取**：主密钥持有者为用户根据身份派生私钥
- **密钥管理简化**：适合封闭系统、物联网等场景
- **依赖 libgmssl**：当前 pygmssl 的 SM9 签名与加密实现通过 ctypes 调用 GmSSL；未安装/未配置动态库时相关 API 不可用（参见 [SM9 算法说明](../algorithms/sm9.md)）。

## 相关文档

- [算法介绍：SM2](../algorithms/sm2.md)
- [算法介绍：SM9](../algorithms/sm9.md)
- [数字签名](digital_signatures.md)
- [密钥派生](key_derivation.md)
