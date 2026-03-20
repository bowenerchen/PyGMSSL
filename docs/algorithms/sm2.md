# SM2 椭圆曲线算法

## 1. 算法概述

SM2 是中国国家密码管理局发布的椭圆曲线公钥密码算法（GM/T 0003-2012），用于：

- 数字签名与验证
- 公钥加密与解密
- 密钥交换（ECDH）

SM2 与 ECDSA 类似，但使用 SM3 哈希、自定义 Z 值计算和 KDF，形成完整的国密体系。

---

## 2. 数学基础

### 2.1 素域与曲线

- **素域**：Fp，p 为 256 位素数
- **曲线方程**（Weierstrass 形式）：y² = x³ + ax + b
- **阶**：n（素数，约 256 位）

### 2.2 曲线参数（GM/T 0003-2012）

| 参数 | 十六进制值 |
|------|-----------|
| p | `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF` |
| a | `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC` |
| b | `0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93` |
| n | `0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123` |
| Gx | `0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7` |
| Gy | `0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0` |

基点 G = (Gx, Gy)，阶为 n。

---

## 3. 密钥生成

```mermaid
flowchart TD
    A[随机数 d ∈ [1, n-2]] --> B[计算 P = d·G]
    B --> C[私钥: d]
    B --> D[公钥: (x, y) = P 仿射坐标]
```

私钥 d 为 [1, n-2] 内的随机整数；公钥为椭圆曲线上的点 P = d·G 的仿射坐标 (x, y)。

---

## 4. 数字签名

### 4.1 签名流程

```mermaid
flowchart TD
    A[消息 M, 私钥 d] --> B[计算 Z = SM3(ENTL\|\|ID\|\|a\|\|b\|\|xG\|\|yG\|\|xA\|\|yA)]
    B --> C[计算 e = SM3(Z\|\|M)]
    C --> D[生成随机 k ∈ [1, n-1]]
    D --> E[计算 (x1,y1) = k·G]
    E --> F[r = (e + x1) mod n]
    F --> G{s == 0?}
    G -->|是| D
    G -->|否| H[s = (1+d)^(-1)(k - r·d) mod n]
    H --> I[签名 (r, s)]
```

### 4.2 验签流程

```mermaid
flowchart TD
    A[消息 M, 公钥 (x,y), 签名 (r,s)] --> B{1 ≤ r,s < n?}
    B -->|否| REJ[拒绝]
    B -->|是| C[计算 e = SM3(Z\|\|M)]
    C --> D[t = (r + s) mod n]
    D --> E{t == 0?}
    E -->|是| REJ
    E -->|否| F[(x1,y1) = s·G + t·P]
    F --> G[x1 + e ≡ r mod n?]
    G -->|是| ACC[接受]
    G -->|否| REJ
```

### 4.3 公式

- \( r = (e + x_1) \bmod n \)，其中 (x₁, y₁) = k·G
- \( s = (1+d)^{-1}(k - r \cdot d) \bmod n \)
- 验签：\( s \cdot G + t \cdot P \) 的 x 坐标满足 \( x_1 + e \equiv r \pmod{n} \)

### 4.4 hazmat 签名线格式（与 eet `-m` 对齐）

`SM2PrivateKey.sign` / `SM2PublicKey.verify` 的 ``signature_format``：

| `signature_format` | 说明 |
|--------------------|------|
| `None`（默认） | 64 字节 **r \|\| s**（大端），同 eet **RS** |
| `RS` | 同上 |
| `RS_ASN1` | ASN.1 DER **SEQUENCE { INTEGER r, INTEGER s }**，同 eet 默认签名输出 |

DER 编解码亦可单独使用 `encode_sm2_signature_der` / `decode_sm2_signature_der`（[`serialization.py`](../../pygmssl/src/gmssl/hazmat/primitives/serialization.py)）。

---

## 5. 公钥加密

### 5.1 加密流程

```mermaid
flowchart TD
    A[明文 M, 公钥 P] --> B[随机 k ∈ [1, n-1]]
    B --> C[C1 = k·G]
    C --> D[(x2,y2) = k·P]
    D --> E[t = SM3-KDF(x2\|\|y2, len(M))]
    E --> F{t 全零?}
    F -->|是| B
    F -->|否| G[C2 = M ⊕ t]
    G --> H[C3 = SM3(x2\|\|M\|\|y2)]
    H --> I[密文 = C1 \|\| C3 \|\| C2]
```

### 5.2 解密流程

```mermaid
flowchart TD
    A[密文 C1\|\|C3\|\|C2, 私钥 d] --> B[(x2,y2) = d·C1]
    B --> C[t = SM3-KDF(x2\|\|y2, len(C2))]
    C --> D{t 全零?}
    D -->|是| ERR[异常]
    D -->|否| E[M = C2 ⊕ t]
    E --> F[u = SM3(x2\|\|M\|\|y2)]
    F --> G{u == C3?}
    G -->|是| OK[输出 M]
    G -->|否| ERR
```

密文格式：`C1(65B) || C3(32B) || C2(variable)`，其中 C1 为未压缩点（04 || x || y）。

### 5.3 与 eet 一致的密文模式（pygmssl hazmat）

`SM2PublicKey.encrypt` / `SM2PrivateKey.decrypt` 的 `ciphertext_format` 与 **eet** `sm2 encrypt` / `sm2 decrypt` 的 `-m` 对齐；默认 `None` 表示 **65 字节 C1** 的 C1→C3→C2 拼接。

| `ciphertext_format` | 说明 |
|---------------------|------|
| `None`（默认） | C1：65B 未压缩点（0x04 + x + y）；后接 C3（32B）、C2 |
| `C1C3C2` | raw：C1 为 64B（x + y），顺序为 C1、C3、C2 |
| `C1C2C3` | raw：C1 为 64B（x + y），顺序为 C1、C2、C3 |
| `C1C3C2_ASN1` | DER SEQUENCE：INTEGER x，INTEGER y，OCTET STRING C3，OCTET STRING C2 |
| `C1C2C3_ASN1` | DER SEQUENCE：INTEGER x，INTEGER y，OCTET STRING C2，OCTET STRING C3 |

### 5.4 PKCS#8 加密私钥 PEM（与 eet / GmSSL）

`gmssl.hazmat.primitives.serialization` 支持 **EncryptedPrivateKeyInfo**：**PBES2** → **PBKDF2**（PRF 为 **HMAC-SM3**，OID `1.2.156.10197.1.401.2`）+ **SM4-CBC**（PKCS#7 填充），默认 PBKDF2 迭代 **65536**，与 **eet `sm2 generate`** 一致。解密后的内层 PKCS#8 使用 **`id-ecPublicKey`（1.2.840.10045.2.1）** 与 **SM2 命名曲线 OID**，且 SEC1 `ECPrivateKey` 携带 **`[0]` 命名曲线** 与 **`[1]` 公钥**，以便 GmSSL / **eet `sm2 sign -f`** 读取 pygmssl 导出的加密 PEM。明文 `PRIVATE KEY`（双 SM2 OID 的 `AlgorithmIdentifier`）仍保留为库内默认编码；与 eet 线工具互换加密私钥时，应使用 `encode_sm2_private_key_pkcs8_encrypted` / `load_pem_private_key(..., password)`。

---

## 6. ECDH 密钥协商

基本 ECDH：双方共享点 S = d_A · P_B = d_B · P_A。

- 己方私钥 d，对方公钥 (x_B, y_B)
- 共享点 (x, y) = d · P_B
- 共享秘密通常取 x || y 经 KDF 派生密钥

### 6.1 hazmat `exchange()` 的语义（重要）

`SM2PrivateKey.exchange()` **不做** GM/T 0003 附录中的完整「密钥交换协议」（可选步骤、可选确认值、可选派生函数等）。实现上等价于 **原始 ECDH**：返回 **64 字节**的未压缩共享点坐标 **`x || y`**（各 32 字节大端），**不**经过 SM3-KDF、**不**产生确认哈希。若产品文档写「国密密钥交换」，应明确为「仅输出共享点坐标」，以免与标准中的协商协议混淆。

---

## 7. Z 值计算

用于将用户身份绑定到椭圆曲线参数，参与 e 的计算：

\[
Z = \mathrm{SM3}(\mathrm{ENTL} \| \mathrm{ID} \| a \| b \| x_G \| y_G \| x_A \| y_A)
\]

- **ENTL**：ID 的比特长度（2 字节大端）
- **ID**：用户标识（默认 `1234567812345678`）
- **(x_G, y_G)**：基点 G 的坐标
- **(x_A, y_A)**：用户公钥坐标

---

## 8. SM3-KDF 使用

公钥加密中，共享点坐标经 SM3-KDF 派生出密钥流：

\[
\mathrm{KDF}(Z, klen) = H(Z \| \mathrm{ct}_1) \| H(Z \| \mathrm{ct}_2) \| \ldots
\]

其中 ct_i 为 32 位大端计数器，从 1 递增。加密时 Z = x₂ || y₂，klen = len(M)。

---

## 9. C 源码与 Python 模块对应

| GmSSL C 源文件 | Python 模块 | 功能 |
|----------------|-------------|------|
| `sm2_lib.c`, `ec.c` | `_sm2_field.py` | 雅可比坐标点加、倍点、标量乘 |
| `sm2_alg.c`, `sm2_key.c` | `_sm2_algo.py` | 签名、验签、加解密、ECDH、compute_z |
| `sm3.c` | `_sm3.py` | SM3 哈希 |
| `sm3_kdf.c` | `sm3kdf.py` | SM3-KDF |

### 函数映射

| C 函数 | Python 函数 |
|--------|-------------|
| `sm2_do_sign` | `sm2_sign` |
| `sm2_do_verify` | `sm2_verify` |
| `sm2_do_encrypt` | `sm2_encrypt`（可选 `ciphertext_format`，见 §5.3） |
| `sm2_do_decrypt` | `sm2_decrypt`（同上） |
| `sm2_key_generate` | `sm2_generate_keypair` |
| `sm2_compute_z` | `compute_z` |
| 点运算 (ec.c) | `point_add`, `point_double`, `scalar_multiply` |

---

## 10. 实现说明

- **坐标系统**：雅可比坐标 (X, Y, Z)，仿射 (x, y) = (X/Z², Y/Z³)，避免模逆加速运算
- **大整数**：gmpy2 `mpz` 实现素域运算
- **随机数**：`os.urandom(32)` 生成 k、d
- **公钥编码**：未压缩格式 0x04 || x || y，共 65 字节

### 10.1 签名随机数 k（非 RFC 6979）

签名中的 **nonce k** 由 `os.urandom` 与拒绝采样在 **[1, n−1]** 上均匀选取，**不是** RFC 6979 的 **确定性 k**。与国标测试向量或采用 RFC 6979 的实现对比时，**签名值 (r, s) 不会逐字节一致**，这不表示实现错误，但会影响与确定性实现的互操作。若需要可复现实验室向量，需在测试中对随机源打桩或使用提供确定性 k 的内部接口（本库 hazmat 未暴露）。

---
