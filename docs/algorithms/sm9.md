# SM9 基于身份的密码算法

## 1. 算法概述

SM9 是中国国家密码管理局发布的基于身份的密码算法（GM/T 0044-2016）。与 SM2 不同，SM9 无需证书：用户公钥由其可识别身份（如邮箱）派生，私钥由密钥生成中心（KGC）提取。

支持功能：
- 基于身份的签名（IBS）
- 基于身份的加密（IBE）

### 1.1 pygmssl 实现与 `libgmssl`

- **签名/验签**：H2 使用 GmSSL 的 `sm9_sign_init` / `sm9_verify_init` 与 `sm9_do_sign` / `sm9_do_verify`（对 `0x02‖M‖w` 的双 SM3 与 `sm9_fn_from_hash`，**不是**仅用 `_sm9_hash(0x02, M‖w)` 的简化形式）。
- **加密/解密**：KEM 与 GmSSL 的 `sm9_kem_encrypt` / `sm9_kem_decrypt` 一致；**C3** 为 **HMAC-SM3**（密钥为 KDF 输出的后 32 字节），与 GmSSL `sm9_do_encrypt` 一致。下文流程图中若将 C3 写作「SM3」仅为示意，以代码为准。
- **G2 与 ctypes**：扭曲点 `sm9_fp2_t` 的字节序为 **`[a[1]‖a[0]]`**（见 `sm9_fp2_to_bytes`）；hazmat 的 `Fp2(c0,c1)` 常量与 GmSSL 的 **a[0]/a[1]** 对应关系在 `_g2_to_c` 中显式交换，切勿混用未经验证的纯 Python G2 标量乘与 libgmssl 配对结果。
- **运行要求**：未加载 `libgmssl` 时，上述签名与加密 API 不可用（会抛出 `RuntimeError`）。测试在找不到库时跳过 SM9 用例；可将 `PYGMSSL_GMSSL_LIBRARY` 指向动态库，或在本仓库旁构建 `GmSSL-3.1.1/build/bin/libgmssl.{dylib,so}`。

---

## 2. BN 曲线参数

| 参数 | 含义 |
|------|------|
| p | 256 位特征，素域模数 |
| n | 曲线有理点群的阶（素数） |
| t | 迹参数，用于配对计算 |
| b | 曲线方程 y² = x³ + b 中的常数，b = 5 |

曲线：E(Fp): y² = x³ + 5

---

## 3. 扩域塔（Extension Field Tower）

```mermaid
graph TD
    Fp[Fp 素域 256 位]
    Fp2[Fp2 = Fp[u] / u²+2=0]
    Fp4[Fp4 = Fp2[v] / v²-u=0]
    Fp12[Fp12 = Fp4[w] / w³-v=0]

    Fp --> Fp2
    Fp2 --> Fp4
    Fp4 --> Fp12
```

| 域 | 不可约多项式 | 元素形式 |
|----|-------------|----------|
| Fp2 | u² + 2 = 0 | c0 + c1·u |
| Fp4 | v² - u = 0 | c0 + c1·v，c0,c1 ∈ Fp2 |
| Fp12 | w³ - v = 0 | c0 + c1·w + c2·w²，c0,c1,c2 ∈ Fp4 |

- **G1**：E(Fp) 上的有理点群
- **G2**：扭曲曲线 E'(Fp2) 上的有理点群
- **配对**：R-ate 配对 e: G1 × G2 → Fp12*

---

## 4. R-ate 双线性配对

R-ate 配对用于将 G1、G2 上的点映射到 Fp12*，满足双线性性。实现包括：

- Miller 循环（基于参数 a）
- Frobenius 自同态
- 最终指数运算 f^((p^12 - 1)/n)

---

## 5. 签名协议

### 5.1 签名流程

```mermaid
flowchart TD
    subgraph KGC
        A[主私钥 ks] --> B[主公钥 Ppubs = ks·G2]
    end

    subgraph 用户密钥提取
        C[ID 用户身份] --> D[H1 = H(0x01, ID\|\|hid_sign)]
        D --> E[t1 = H1 + ks]
        E --> F[dA = ks/t1 · G1]
    end

    subgraph 签名
        G[消息 M] --> H[随机 r]
        H --> I[w = e(G1, Ppubs)^r]
        I --> J[h = H(0x02, M\|\|w)]
        J --> K[S = (r-h)·dA]
        K --> L[输出 (h, S)]
    end
```

### 5.2 验签流程

```mermaid
flowchart TD
    A[消息 M, 签名 (h,S), 主公钥 Ppubs, 用户 ID] --> B[H1 = H(0x01, ID\|\|hid_sign)]
    B --> C[P = H1·G2 + Ppubs]
    C --> D[t = e(S, P)]
    D --> E[g_h = e(G1, Ppubs)^h]
    E --> F[w' = t * g_h]
    F --> G[h2 = H(0x02, M\|\|w')]
    G --> H{h2 == h?}
    H -->|是| ACC[接受]
    H -->|否| REJ[拒绝]
```

---

## 6. 加密协议

### 6.1 加密流程

```mermaid
flowchart TD
    A[明文 M, 用户 ID, 主公钥 Ppube] --> B[QB = H1(ID\|\|hid_enc)·G1 + Ppube]
    B --> C[随机 r]
    C --> D[C1 = r·QB]
    D --> E[w = e(Ppube, G2)^r]
    E --> F[K = KDF(C1\|\|w\|\|ID, len(M)+32)]
    F --> G[K1 = K[:len(M)], K2 = K[len(M):]]
    G --> H{C1 非零?}
    H -->|否| C
    H -->|是| I[C2 = M ⊕ K1]
    I --> J[C3 = SM3(C2\|\|w\|\|ID)]
    J --> K[密文 = C1 \|\| C3 \|\| C2]
```

### 6.2 解密流程

```mermaid
flowchart TD
    A[密文 C1\|\|C3\|\|C2, 用户私钥 de, 用户 ID] --> B[w = e(C1, de)]
    B --> C[K = KDF(C1\|\|w\|\|ID, len(C2)+32)]
    C --> D[K1 = K[:len(C2)]]
    D --> E[M = C2 ⊕ K1]
    E --> F[u = SM3(C2\|\|w\|\|ID)]
    F --> G{u == C3?}
    G -->|是| OK[输出 M]
    G -->|否| ERR[失败]
```

密文格式：`C1(65B) || C3(32B) || C2(variable)`，C1 为 G1 点未压缩编码。

---

## 7. 用户密钥提取

### 7.1 签名私钥

\[
d_A = \frac{k_s}{H_1(\mathrm{ID} \| \mathrm{hid}_{\mathrm{sign}}) + k_s} \cdot G_1
\]

### 7.2 加密私钥

\[
d_e = \frac{k_e}{H_1(\mathrm{ID} \| \mathrm{hid}_{\mathrm{enc}}) + k_e} \cdot G_2
\]

hid_sign = 0x01，hid_enc = 0x03。

---

## 8. H1 / H2 哈希函数

SM9 哈希 H_v(ct_byte, data, n) 将任意数据映射到 [1, n-1]：

\[
H_a = \mathrm{SM3}(\mathrm{ct\_byte} \| \mathrm{data} \| 0x00000001) \| \mathrm{SM3}(\mathrm{ct\_byte} \| \mathrm{data} \| 0x00000002)
\]

\[
h = (\mathrm{int}(H_a[:40]) \bmod (n-1)) + 1
\]

- **H1**：ct_byte = 0x01，用于密钥提取
- **H2**：ct_byte = 0x02，用于签名中的 h

---

## 9. C 源码与 Python 模块对应

| GmSSL C 源文件 | Python 模块 | 功能 |
|----------------|-------------|------|
| `sm9_lib.c`, `sm9_alg.c` | `_sm9_gmssl_native.py`（ctypes） | 配对、Fp12、`sm9_kem_*`、`sm9_do_sign`/`verify`、G1/G2 标量乘 |
| `sm9_key.c`（逻辑对齐） | `_sm9_algo.py` | H1、主密钥/用户密钥提取（标量与哈希在 Python；基点乘可走 lib） |
| `sm9_field.py`（纯 Python） | `_sm9_field.py` | Fp2/Fp12 等（无 lib 时备用；G2 与 lib 不对拍） |

### 函数映射（要点）

| C API（GmSSL） | Python |
|----------------|--------|
| `sm9_sign_master_key_generate` | `sm9_sign_master_key_generate`（Python 随机数 + `native_g2_mul_generator`） |
| `sm9_sign_master_key_extract_key`（逻辑） | `sm9_sign_user_key_extract` |
| `sm9_sign_init` / `update` + `sm9_do_sign` | `native_sm9_do_sign` → `sm9_sign` |
| `sm9_verify_init` / `update` + `sm9_do_verify` | `native_sm9_do_verify` → `sm9_verify` |
| `sm9_kem_encrypt` + HMAC | `native_sm9_kem_encrypt` + hazmat HMAC-SM3 → `sm9_encrypt` |
| `sm9_kem_decrypt` + HMAC | `native_sm9_kem_decrypt` + hazmat HMAC-SM3 → `sm9_decrypt` |
| `sm9_hash1`（逻辑） | `_sm9_hash(0x01, …)` |

---

## 10. 实现说明

- **gmpy2**：H1 与主私钥随机数、Fp 运算等。
- **G1**：用户签名私钥 **dA = t2·P1** 在能加载 lib 时使用 `sm9_point_mul_generator`（`native_g1_mul_generator`）。
- **G2**：主签名公钥 **Ppubs = ks·P2**、加密私钥 **de = t2·P2** 使用 `native_g2_mul_generator` / `native_g2_mul`；与 lib 交换时使用修正后的 `_g2_to_c`。
- **KEM 密钥长度**：与 GmSSL 一致为 **255 + 32** 字节（最大明文 + SM3 输出长度），再截取明文长度与 MAC 密钥。
