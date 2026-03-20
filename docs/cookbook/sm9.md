# SM9 使用说明（pygmssl）

基于身份的密码：**数字签名**与**公钥加密**（IBE）。实现依赖本机可加载的 **libgmssl**（与 GmSSL 构建产物位级对齐）；若库不可用，相关函数会失败。

---

## 1. 检查原生后端是否可用

```python
from gmssl.hazmat.primitives.asymmetric import sm9

if not sm9.gmssl_backend_available():
    raise RuntimeError("需要安装/配置 libgmssl，详见 pygmssl README")
```

---

## 2. 标识数字签名

```python
from gmssl.hazmat.primitives.asymmetric import sm9

if not sm9.gmssl_backend_available():
    raise SystemExit("skip: no libgmssl")

# 签名主密钥（PKG）
master = sm9.generate_sign_master_key()
mpk = master.public_key()

# 为用户标识签发私钥
user_id = "alice@example.com"
user_sign_key = master.extract_key(user_id)

# 签名 / 验签（验签方只需主公钥 + 用户标识）
message = b"contract-payload"
signature = user_sign_key.sign(message)
assert len(signature) == 96  # h(32) || S.x(32) || S.y(32)

mpk.verify(signature, message, user_id)
```

---

## 3. 标识加密

```python
from gmssl.hazmat.primitives.asymmetric import sm9

if not sm9.gmssl_backend_available():
    raise SystemExit("skip: no libgmssl")

# 加密主密钥
enc_master = sm9.generate_enc_master_key()
enc_mpk = enc_master.public_key()

receiver_id = "bob@example.com"
plaintext = b"confidential"

# 加密方：仅主公钥 + 接收方标识
ciphertext = enc_mpk.encrypt(plaintext, receiver_id)

# 解密方：用户加密私钥（由 PKG 用主密钥提取）
user_dec_key = enc_master.extract_key(receiver_id)
recovered = user_dec_key.decrypt(ciphertext, receiver_id)
assert recovered == plaintext
```

---

## 4. 说明

- SM9 曲线与配对运算由 **GmSSL 原生库**完成；纯 Python 环境与未安装 GmSSL 时请先编译/安装 `libgmssl` 并保证动态链接器能找到。
- 更完整的协议字段、KEM 等请参考 GmSSL 文档与 `gmssl._backends._sm9_*` 实现。
