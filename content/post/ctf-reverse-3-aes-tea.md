+++
date = '2026-05-27T12:00:00+08:00'
draft = false
title = 'CTF 逆向入门(三)：AES高级加密标准与TEA系列分组加密'
tags = ['CTF', '逆向', 'AES', 'TEA', 'XTEA', 'XXTEA', '加密算法']
categories = ['逆向']
+++

> CTF 逆向系列第三篇，深入两种重要的分组加密算法：AES（高级加密标准）和 TEA 家族（TEA/XTEA/XXTEA）。每种算法先讲原理和识别特征，再用实际题目演示完整的解题过程。

---

## 一、AES 高级加密标准

### 1.1 算法概述

AES（Advanced Encryption Standard）是目前最广泛使用的对称加密算法。CTF 中遇到的通常是 **AES-128-ECB** 模式（128 位密钥，ECB 模式）。

AES 加密过程涉及 4 种操作：

| 操作 | 英文 | 说明 | 逆操作 |
|------|------|------|--------|
| 字节替代 | SubBytes | 通过 S 盒完成字节映射 | InvSubBytes（逆 S 盒） |
| 行移位 | ShiftRows | 每行循环左移不同偏移量 | InvShiftRows |
| 列混淆 | MixColumns | 对每列做矩阵乘法 | InvMixColumns |
| 轮密钥加 | AddRoundKey | 状态矩阵与轮密钥 XOR | 同操作（XOR 自逆） |

### 1.2 AES 的识别特征

在 IDA 中看到 **标准 S 盒**（首字节 `0x63`），基本可以确认是 AES：

```c
// AES S-Box（256 字节，首字节 0x63 是最显著的识别标志）
static const uint8_t Sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // ... 完整 256 字节
};
```

如果看到 **逆 S 盒**（首字节 `0x52`），说明程序中包含解密操作。

### 1.3 实战题目：简化 AES 解密

**题目来源**：`1-XDX-HB-AES/3`

CTF 中的 AES 题通常会做简化（减少轮数、自定义密钥扩展等）。本题使用 2 轮 AES + 自定义密钥扩展。

**Step 1：IDA 分析**

在 IDA 中找到：
- S 盒常量（首字节 `0x63`）→ 确认 AES
- 密钥字符串：`"do_you_konw_SYC?"`
- 密文：`e0056ec26e9968457d1f3ff997763b922f440667a8ebec4a6fe835f9aca78c71`
- 自定义密钥扩展逻辑

**Step 2：完整解密脚本**

```python
# AES S-Box（完整 256 字节）
Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# 构建逆 S-Box
InvSbox = [0] * 256
for i in range(256):
    InvSbox[Sbox[i]] = i

def inv_sub_bytes(block):
    """逆 S 盒替换"""
    return [InvSbox[x] for x in block]

def inv_shift_rows(block):
    """逆行移位：将每行的字节移回原位"""
    s = list(block)
    r0 = s[0:4]
    r1 = [s[7], s[4], s[5], s[6]]   # 第 2 行右移 1 字节
    r2 = [s[10], s[11], s[8], s[9]]  # 第 3 行右移 2 字节
    r3 = [s[13], s[14], s[15], s[12]] # 第 4 行右移 3 字节
    return r0 + r1 + r2 + r3

def inv_transform(block):
    """逆转置 + 逆 S 盒"""
    tmp = inv_sub_bytes(block)
    res = [0] * 16
    for row in range(4):
        for col in range(4):
            res[row * 4 + col] = tmp[col * 4 + row]
    return res

def decrypt_block(block, K0, K1):
    """2 轮 AES 解密（逆序执行各操作）"""
    state = [b ^ k for b, k in zip(block, K1)]  # 轮密钥加
    state = inv_shift_rows(state)                 # 逆行移位
    state = inv_sub_bytes(state)                  # 逆 S 盒
    state = [b ^ k for b, k in zip(state, K0)]   # 轮密钥加
    state = inv_transform(state)                  # 逆转置 + 逆 S 盒
    state = inv_shift_rows(state)                 # 逆行移位
    state = inv_sub_bytes(state)                  # 逆 S 盒
    return state

# 密钥扩展（题目中的自定义逻辑）
key_str = "do_you_konw_SYC?"
key_base = [ord(c) for c in key_str]
buf = list(key_base) + [0] * 256

for n in range(1, 11):
    for ii in range(32):
        val = buf[16 * n - 16 + ii]
        buf[16 * n + ii] = val ^ Sbox[val]

K0 = buf[0:16]
K1 = buf[16:32]

# 解密密文（32 字节 = 2 个 AES 块）
ciphertext_hex = 'e0056ec26e9968457d1f3ff997763b922f440667a8ebec4a6fe835f9aca78c71'
ciphertext = list(bytes.fromhex(ciphertext_hex))

plain_a = decrypt_block(ciphertext[0:16], K0, K1)
plain_b = decrypt_block(ciphertext[16:32], K0, K1)

flag = ''.join(chr(x) for x in plain_a + plain_b)
print(f"Flag: {flag}")
```

### 1.4 解题要点

- CTF 中的 AES 通常是 **简化版**（轮数减少、自定义密钥扩展、自定义 S 盒）
- 重点识别：S 盒特征常量（首字节 `0x63`）、逆 S 盒（首字节 `0x52`）、轮密钥加的 XOR 操作、4x4 字节矩阵操作
- 如果是标准 AES 且密钥未知，考虑从密钥生成逻辑入手（如 MD5(key) 的前 16 字节）

---

## 二、TEA 分组加密

### 2.1 算法原理

TEA（Tiny Encryption Algorithm）是一种轻量级分组加密算法，密钥 128 位，明文 64 位，主要做 32 轮变换。

**TEA 加密源码：**

```c
void encrypt(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x9E3779B9;  // 黄金比例常数，最显著的识别标志
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    v[0] = v0;
    v[1] = v1;
}
```

**TEA 解密源码：**

```c
void decrypt(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;
    uint32_t delta = 0x9E3779B9;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}
```

### 2.2 识别特征

| 特征 | 说明 |
|------|------|
| 常量 `0x9E3779B9` | 黄金比例常数，TEA 系列算法最显著的标志 |
| 常量 `0x61C88647` | `0x9E3779B9` 的负数形式，同样标志 TEA |
| 常量 `0xC6EF3720` | 解密时 sum 的初始值（`delta * 32`） |
| 32 轮循环 | 标准 TEA 固定 32 轮 |
| 64 位分组 | 明文分为两个 32 位整数 v0、v1 |

### 2.3 实战题目 1：魔改 TEA

**题目来源**：`6-TEA/1`

本题的 delta 被改为 `0xd33b470`（不是标准的 `0x9E3779B9`），密钥为 `{1, 2, 3, 4}`。

**解密脚本（C 语言）：**

```c
#include <stdio.h>
#include <stdint.h>

void decrypt(uint32_t* v, uint32_t* k) {
    uint32_t delta = 0xd33b470;               // 魔改的 delta
    uint32_t v0 = v[0], v1 = v[1], sum = 32 * delta;
    for (int i = 0; i < 32; i++) {
        v1 -= ((v0<<4) + k[2]) ^ (v0 + sum) ^ ((v0>>5) + k[3]);
        v0 -= ((v1<<4) + k[0]) ^ (v1 + sum) ^ ((v1>>5) + k[1]);
        sum -= delta;
    }
    v[1] = v1;
    v[0] = v0;
}

int main() {
    uint32_t k[4] = {1, 2, 3, 4};
    int8_t input[33] = {
        0x17, 0x65, 0x54, 0x89, 0xed, 0x65, 0x46, 0x32,
        0x3d, 0x58, 0xa9, 0xfd, 0xe2, 0x5e, 0x61, 0x97,
        0xe4, 0x60, 0xf1, 0x91, 0x73, 0xe9, 0xe9, 0xa2,
        0x59, 0xcb, 0x9a, 0x99, 0xec, 0xb1, 0xe1, 0x7d
    };
    for (int i = 0; i < 32; i += 8) {
        uint32_t v[2] = {*(uint32_t*)&input[i], *(uint32_t*)&input[i+4]};
        decrypt(v, k);
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 4; k++) {
                printf("%c", v[j] & 0xff);
                v[j] >>= 8;
            }
        }
    }
    printf("\n");
    return 0;
}
```

运行后输出的十六进制用 `hex.py` 转换即可得到 flag。

### 2.4 实战题目 2：XTEA

**题目来源**：`6-TEA/2`

XTEA 是 TEA 的改进版，密钥调度不同。本题密钥为 `{13, 0, 7, 33}`。

```c
void decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = 32 * delta;
    for (int i = 0; i < 32; i++) {
        v1 -= (v0 + ((v0 >> 5) ^ (16 * v0))) ^ (k[(sum >> 11) & 3] + sum);
        sum -= delta;
        v0 -= (v1 + ((v1 >> 5) ^ (16 * v1))) ^ (k[sum & 3] + sum);
    }
    v[1] = v1;
    v[0] = v0;
}
```

**Flag**：`NSSCTF{xtea_is_also_delicious!!}`

### 2.5 TEA 家族变体对比

| 变体 | 轮数 | delta 值 | 特点 |
|------|------|----------|------|
| TEA | 32 | `0x9E3779B9` | 最基础版本 |
| XTEA | 32 | `0x9E3779B9` | 密钥调度不同，用 `sum >> 11` 选择密钥 |
| XXTEA | 6+52/n | `0x9E3779B9` | 支持任意长度分组，轮数可变 |

---

## 三、XXTEA 与多层混淆

### 3.1 实战题目：XXTEA + 滚动异或 + 乱序重排

**题目来源**：`6-TEA/3`

这道题是本系列中最复杂的题目，包含**三层混淆** + XXTEA 加密：

```
密钥生成 → XXTEA 加密 → 滚动异或(Rolling XOR) → 乱序重排(Shuffle) → 最终密文
```

**逆向步骤**：

**Step 1：提取 24 字节最终密文**

```c
unsigned char raw_data[24] = {
    0xCE, 0xBC, 0x40, 0x6B, 0x7C, 0x3A, 0x95, 0xC0,
    0xEF, 0x9B, 0x20, 0x20, 0x91, 0xF7, 0x02, 0x35,
    0x23, 0x18, 0x02, 0xC8,
    0xE7, 0x56, 0x56, 0xFA
};
```

**Step 2：逆向乱序重排（Shuffle）**

每 4 字节一组，按 `[1, 3, 0, 2]` 模式重排：

```c
for (int i = 0; i < 24; i += 4) {
    sorted_bytes[i+0] = chunk[1];
    sorted_bytes[i+1] = chunk[3];
    sorted_bytes[i+2] = chunk[0];
    sorted_bytes[i+3] = chunk[2];
}
```

**Step 3：逆向滚动异或（Rolling XOR）**

从第 2 个字节开始，每个字节与前一个字节异或：

```c
while (size_2 < size_1) {
    int limit = size_2 / 3;
    if (limit > 0) {
        unsigned char var = *ptr;
        for (int i = 0; i < limit; i++) {
            var ^= key_stream[i];
            *ptr = var;
        }
    }
    size_2++;
    ptr++;
}
```

**Step 4：XXTEA 解密 + 密钥爆破**

XXTEA 的密钥是明文的前 4 字节，因此可以爆破：

```c
// XXTEA 解密函数
void xxtea_decrypt(uint32_t *v, int n, const uint32_t k[4]) {
    if (n < 2) return;
    uint32_t z = v[n - 1], y = v[0];
    uint32_t sum = DELTA * (6 + 52 / n);
    for (uint32_t i = 0; i < (6 + 52 / n); i++) {
        uint32_t e = (sum >> 2) & 3;
        uint32_t p;
        for (p = n - 1; p > 0; p--) {
            z = v[p - 1];
            v[p] -= ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (sum ^ y) + (k[(p & 3) ^ e] ^ z);
            y = v[p];
        }
        z = v[n - 1];
        v[0] -= ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (sum ^ y) + (k[(0 & 3) ^ e] ^ z);
        y = v[0];
        sum -= DELTA;
    }
}

// 爆破密钥（4 字节，字符集 a-z0-9）
const char *charset = "qwertyuiopasdfghjklzxcvbnm1234567890";
// 四重循环爆破 charset[i] * charset[j] * charset[k] * charset[m]
// 校验条件：decrypted[0] == key_val && decrypted[19] == 0
```

**Flag**：`flag{CXX_and_++tea}`

### 3.2 解题经验

这道题的关键教训：

1. **Trust Code Not Comments**：反编译器的注释可能误导，要看实际代码逻辑
2. **Snapshot the Stream**：先提取完整密文再分析，不要边看边解
3. **Check Your Loops**：滚动异或的循环边界容易搞错
4. **Verify the Key**：密钥 = 明文前 4 字节，这个漏洞允许爆破

---

## 四、算法速查表

| 算法 | 类型 | 识别特征 | 解密关键 |
|------|------|----------|----------|
| AES | 块密码 | S 盒首字节 `0x63` / 逆 S 盒首字节 `0x52` | 逆 S 盒 + 逆行移位 + 逆列混合 |
| TEA | 块密码 | 常量 `0x9E3779B9` | 逆轮函数，32 轮 |
| XTEA | 块密码 | 常量 `0x9E3779B9` + `sum >> 11` 选密钥 | 逆轮函数，密钥调度不同 |
| XXTEA | 块密码 | 常量 `0x9E3779B9` + 轮数 `6+52/n` | 逆轮函数，支持任意长度 |

---

> 本文所有解题脚本均可直接运行，算法原理基于实际 CTF 题目还原。如有疑问欢迎交流。
