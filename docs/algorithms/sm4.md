# SM4 分组密码算法

## 1. 算法概述

SM4 是中国国家密码管理局发布的分组密码算法（GM/T 0002-2012），原称 SMS4。分组与密钥长度均为 128 位，采用 32 轮非平衡 Feistel 结构，轮函数包含 S 盒与线性变换 L。

| 参数 | 值 |
|------|-----|
| 分组长度 | 128 位 |
| 密钥长度 | 128 位 |
| 轮数 | 32 |

---

## 2. S 盒设计

SM4 使用 8×8 比特 S 盒，对 32 位字的每个字节分别查表替换：

\[
S(a) = S(a_{31:24}) \| S(a_{23:16}) \| S(a_{15:8}) \| S(a_{7:0})
\]

S 盒为固定 256 字节查找表（与 AES 的 S 盒不同），在 `_sm4.py` 中定义为 `_SBOX`。

---

## 3. 密钥扩展（L' 变换）

### 3.1 系统参数

- **FK**：`(0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)`
- **CK**：32 个 32 位常量（线性递推生成）

### 3.2 L' 变换

\[
L'(B) = B \oplus \mathrm{Rotl}_{13}(B) \oplus \mathrm{Rotl}_{23}(B)
\]

### 3.3 轮密钥生成流程

```mermaid
flowchart TD
    A[原始密钥 K = K0\|\|K1\|\|K2\|\|K3] --> B[K0' = K0 ⊕ FK0, ... K3' = K3 ⊕ FK3]
    B --> C[i = 0]
    C --> D[rk[i] = K0' ⊕ T'(K1' ⊕ K2' ⊕ K3' ⊕ CK[i])]
    D --> E[K0',K1',K2',K3' = K1',K2',K3',rk[i]]
    E --> F{i < 32?}
    F -->|是| D
    F -->|否| G[输出 rk[0..31]]
```

其中 T'(X) = L'(S(X))，即先 S 盒再 L' 变换。

---

## 4. 加密轮函数（T 变换与 L 变换）

### 4.1 L 变换（加密用）

\[
L(B) = B \oplus \mathrm{Rotl}_2(B) \oplus \mathrm{Rotl}_{10}(B) \oplus \mathrm{Rotl}_{18}(B) \oplus \mathrm{Rotl}_{24}(B)
\]

### 4.2 T 变换

\[
T(X) = L(S(X))
\]

对 32 位字 X 逐字节 S 盒替换后再做 L 变换。

### 4.3 单轮加密

设 (X0, X1, X2, X3) 为 4 个 32 位字，轮密钥 rk[i]：

\[
X_{i+4} = X_i \oplus T(X_{i+1} \oplus X_{i+2} \oplus X_{i+3} \oplus rk[i])
\]

32 轮后输出 (X35, X34, X33, X32) 的反序，即 (X32, X33, X34, X35)。

---

## 5. 解密

解密使用相同结构，轮密钥逆序：`rk[31], rk[30], ..., rk[0]`。

---

## 6. 工作模式

| 模式 | Python 函数 | 说明 |
|------|-------------|------|
| ECB | `sm4_ecb_encrypt`, `sm4_ecb_decrypt` | 电子密码本，需分组对齐 |
| CBC | `sm4_cbc_encrypt`, `sm4_cbc_decrypt` | 密文分组链接，需分组对齐 |
| CTR | `sm4_ctr_encrypt` | 计数器模式，加密=解密 |
| GCM | `GCMState` (via `_gcm.py`) | 认证加密，带 GHASH |

### 6.1 CBC 与填充

通过 `Cipher` + `modes.CBC` 使用时，**仅在 `finalize()` 阶段**对整块数据做 **PKCS#7** 填充或去填充；`update()` 只处理 **16 字节对齐** 的分组（与 `cryptography` 风格一致）。若与只支持「无填充」或自定义填充的遗留系统对接，需在集成层自行处理填充或选用 ECB/CTR 等模式。

### 6.2 SM4-GCM：标签长度与验证

解密时，实现将 **本地计算的完整 GHASH 标签截断到与传入 `tag` 相同的长度**，再与密文一同提供的标签做常量时间比较。`modes.GCM` 支持 **`min_tag_length`**（默认 12，且不得小于 4），因此 API 上允许使用 **短于 16 字节** 的标签。**短标签会降低认证强度**，生产环境建议使用 **完整 16 字节** 标签，除非协议明确约束长度。

### 6.3 SM4-GCM：附加认证数据（AAD）

在 **`encryptor()`/`decryptor()` 上首次调用 `update()` 处理密文/明文之前**，若曾调用 `authenticate_additional_data()`，底层会 **自动结束 AAD 阶段**；此后 **不能再追加 AAD**。这与部分库「显式 `finalize_aad()`」的用法不同，编写跨库代码时应在文档或注释中标明。

---

## 7. 轮密钥生成流程图（Mermaid）

```mermaid
flowchart LR
    subgraph 输入
        K[密钥 K]
    end

    subgraph 初始化
        FK[FK 异或]
    end

    subgraph 迭代
        T1[T' 变换]
        XOR[异或 CK[i]]
    end

    K --> FK --> T1 --> XOR --> rk[轮密钥 rk]
```

---

## 8. C 源码与 Python 模块对应

| GmSSL C 源文件 | Python 模块 | 功能 |
|----------------|-------------|------|
| `sm4_setkey.c` | `_sm4.py` :: `sm4_key_schedule` | 密钥扩展 |
| `sm4_enc.c` | `_sm4.py` :: `sm4_encrypt_block`, `sm4_decrypt_block` | 单块加解密 |
| `sm4_modes.c` | `_sm4.py` | ECB/CBC/CTR 实现 |
| `gcm.c` | `_gcm.py` | GCM AEAD |

### 函数映射

| C 函数 | Python 函数 |
|--------|-------------|
| `sm4_set_encrypt_key` | `sm4_key_schedule` (加密时正序 rk) |
| `sm4_set_decrypt_key` | `sm4_key_schedule` (解密时 rk[::-1]) |
| `sm4_encrypt` | `sm4_encrypt_block` |
| `sm4_decrypt` | `sm4_decrypt_block` |
| `sm4_cbc_encrypt` | `sm4_cbc_encrypt` |
| `sm4_cbc_decrypt` | `sm4_cbc_decrypt` |
| `sm4_ctr_encrypt` | `sm4_ctr_encrypt` |
| GCM 相关 | `GCMState` (在 `_gcm.py`) |

---

## 9. 实现说明

- **纯 Python**：无 C 扩展依赖
- **S 盒与常量**：`_SBOX`、`_FK`、`_CK` 与标准一致
- **L 与 L'**：`_l` 用于加密，`_l_prime` 用于密钥扩展
- **分组对齐**：ECB/CBC 要求数据长度为 16 的倍数，由上层 PKCS7 填充处理
