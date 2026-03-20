# ZUC 流密码算法

## 1. 算法概述

ZUC（祖冲之）流密码由中国科学院等单位设计，被 3GPP 采纳用于 4G/5G 移动通信（如 SNOW 3G 的后续）。本实现支持：

- **ZUC-128**：128 位密钥，128 位 IV，用于 LTE 加密
- **ZUC-256**：256 位密钥，184 位 IV，用于 5G 等增强场景

算法核心：16 级 31 位 LFSR + 比特重组 + 非线性 F 函数。

---

## 2. LFSR 结构

16 级 LFSR，每个单元为 31 位整数，模数为 2³¹ - 1。初始化后进入工作模式。

### 2.1 初始化模式（32 轮）

每轮：比特重组 → F 函数（输出丢弃）→ LFSR 以 u = F_output >> 1 作为反馈更新。

### 2.2 工作模式

每轮：比特重组 → F 函数 → 密钥字 Z = X3 ⊕ F_output，然后 LFSR 按工作模式反馈更新（无 F 输出参与）。

---

## 3. 比特重组

从 LFSR 状态 S[0..15] 中抽取 4 个 32 位字：

\[
X0 = (S[15]_{H} \ll 1) \| S[14]_L
\]
\[
X1 = S[11]_L \| S[9]_H
\]
\[
X2 = S[7]_L \| S[5]_H
\]
\[
X3 = S[2]_L \| S[0]_H
\]

下标 H 表示高 16 位，L 表示低 16 位。

---

## 4. F 函数（L1、L2、S 盒）

### 4.1 结构

F 函数输入：X0、X1、X2 以及内部寄存器 R1、R2。

\[
W = (X0 \oplus R1) \boxplus R2
\]
\[
W1 = R1 \boxplus X1,\quad W2 = R2 \oplus X2
\]

然后通过 L1、L2 线性变换和 S0、S1 两个 8×8 S 盒更新 R1、R2，输出 W 作为 F 的输出（初始化模式下 W>>1 参与 LFSR，工作模式下 Z = X3 ⊕ W）。

### 4.2 L1、L2 变换

\[
L1(X) = X \oplus \mathrm{Rotl}_2(X) \oplus \mathrm{Rotl}_{10}(X) \oplus \mathrm{Rotl}_{18}(X) \oplus \mathrm{Rotl}_{24}(X)
\]

\[
L2(X) = X \oplus \mathrm{Rotl}_8(X) \oplus \mathrm{Rotl}_{14}(X) \oplus \mathrm{Rotl}_{22}(X) \oplus \mathrm{Rotl}_{30}(X)
\]

### 4.3 S 盒

- S0、S1：各 256 字节，在 `_zuc.py` 中定义
- R1、R2 的更新：对 L1、L2 输出的 32 位字按字节查 S0、S1 后重排

---

## 5. 初始化模式 vs 工作模式

```mermaid
flowchart TD
    subgraph 初始化模式["初始化模式（32 轮）"]
        A1[加载 key, iv 到 LFSR] --> B1[比特重组 → X0,X1,X2]
        B1 --> C1[F 函数 → W, 更新 R1,R2]
        C1 --> D1[u = W >> 1]
        D1 --> E1[LFSR 反馈 = f(LFSR) + u]
        E1 --> F1{32 轮完成?}
        F1 -->|否| B1
        F1 -->|是| G1[进入工作模式]
    end

    subgraph 工作模式["工作模式"]
        A2[比特重组 → X0,X1,X2,X3] --> B2[F 函数 → W]
        B2 --> C2[Z = X3 ⊕ W 输出密钥字]
        C2 --> D2[LFSR 反馈 = f(LFSR), 无 u]
        D2 --> E2[继续生成下一字]
    end

    G1 --> A2
```

---

## 6. ZUC-256 扩展

- **密钥**：32 字节
- **IV**：23 字节
- **D 常量**：ZUC-256 使用 4 组 16 字节 D 常量（按 MAC 比特等选择），流密码模式使用 `ZUC256_D[0]`
- **LFSR 加载**：与 ZUC-128 不同，将 key、IV、D 按特定方式装入 16 个 LFSR 单元
- **初始化与工作**：初始化 32 轮、工作模式生成密钥字的流程与 ZUC-128 一致

---

## 7. 密钥流生成

每生成一个密钥字：

1. 比特重组得到 X0、X1、X2、X3
2. F(X0, X1, X2) → W，并更新 R1、R2
3. Z = X3 ⊕ W
4. LFSR 工作模式推进

密钥流按 32 位大端输出，与明文/密文异或完成加解密（加解密对称）。

---

## 8. C 源码与 Python 模块对应

| GmSSL C 源文件 | Python 模块 | 功能 |
|----------------|-------------|------|
| `zuc.c` | `_zuc.py` | ZUC-128、ZUC-256、LFSR、F、S 盒 |

### 函数映射

| C 函数/结构 | Python 实现 |
|-------------|-------------|
| `zuc_init` (ZUC-128) | `ZUCState.__init__` |
| `zuc_init` (ZUC-256) | `ZUC256State.__init__` |
| `zuc_generate_keystream` | `generate_keyword` / `generate_keystream` |
| `zuc_encrypt` | `ZUCState.encrypt` |
| LFSR 加载 | `self.lfsr[i] = ...` |
| `ADD31` | `_add31` |
| `ROT31` | `_rot31` |
| `L1`, `L2` | `_l1`, `_l2` |
| `F` | `_f` |
| `S0`, `S1` | `S0`, `S1` |
| `KD` (ZUC-128) | `KD` |
| `ZUC256_D` | `ZUC256_D` |

---

## 9. 实现说明

- **纯 Python**：无 C 扩展
- **31 位运算**：LFSR 使用 `& 0x7FFFFFFF` 保证 31 位
- **32 位运算**：F 函数、比特重组使用 32 位
- **加密接口**：`encrypt(data)` 对 data 逐 4 字节异或密钥流，末尾不足 4 字节部分按实际长度异或
