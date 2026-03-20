# ZUC 使用说明（pygmssl）

祖冲之流密码：**ZUC-128**（4G LTE）与 **ZUC-256**（5G）。API 位于 `gmssl._backends._zuc`（与 `hazmat` 对称算法不同命名空间，仍为官方支持的国密组件）。

---

## 1. ZUC-128（密钥 16 字节，IV 16 字节）

```python
from gmssl._backends._zuc import ZUCState

key = b"\x00" * 16
iv = b"\x00" * 16
plaintext = b"Hello ZUC-128 stream cipher!"

state_enc = ZUCState(key, iv)
ciphertext = state_enc.encrypt(plaintext)

state_dec = ZUCState(key, iv)
recovered = state_dec.encrypt(ciphertext)  # 流密码：解密与加密相同
assert recovered == plaintext
```

### 取密钥流字（可选，用于调试/向量比对）

```python
from gmssl._backends._zuc import ZUCState

state = ZUCState(b"\x00" * 16, b"\x00" * 16)
words = state.generate_keystream(2)  # 若干 32-bit 大端字
assert isinstance(words, list) and len(words) == 2
```

---

## 2. ZUC-256（密钥 32 字节，IV 23 字节）

```python
from gmssl._backends._zuc import ZUC256State

key = b"\x00" * 32
iv = b"\x00" * 23
plaintext = b"ZUC-256 payload"

s1 = ZUC256State(key, iv)
ct = s1.encrypt(plaintext)

s2 = ZUC256State(key, iv)
pt = s2.encrypt(ct)
assert pt == plaintext
```

---

## 3. 模块位置

- 实现：`gmssl._backends._zuc`（`ZUCState`、`ZUC256State`）
- 测试向量参考：`pygmssl/tests/test_zuc.py`
