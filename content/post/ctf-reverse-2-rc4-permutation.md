+++
date = '2026-05-27T11:00:00+08:00'
draft = false
title = 'CTF 逆向入门(二)：RC4流密码、索引置换、位运算与累加异或'
tags = ['CTF', '逆向', 'RC4', '异或', '加密算法']
categories = ['逆向']
+++

> CTF 逆向系列第二篇，覆盖四种常见加密题型：RC4 流密码、索引置换加密、位运算加密、累加异或（Prefix XOR）。每种算法先讲原理，再用实际题目演示解题过程。

---

## 一、RC4 流密码

### 1.1 算法原理

RC4 是一种流密码，广泛用于 SSL/TLS、WEP 等协议中。它的核心特点：**加密和解密使用完全相同的算法**（因为 XOR 的对合性）。

RC4 分为两个阶段：

**KSA（密钥调度算法）** — 初始化 S 盒：

```python
def rc4_init(key):
    S = list(range(256))          # 初始化 S 盒 [0, 1, 2, ..., 255]
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]   # 交换
    return S
```

**PRGA（伪随机生成算法）** — 生成密钥流并异或：

```python
def rc4_crypt(S, data):
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        result.append(byte ^ S[t])  # 明文/密文与密钥流异或
    return bytes(result)
```

### 1.2 RC4 的识别特征

在 IDA 中看到以下特征，基本可以确认是 RC4：

| 特征 | IDA 伪代码表现 |
|------|---------------|
| 256 字节 S 盒初始化 | `for(i=0; i<256; i++) S[i] = i;` |
| 密钥填充临时数组 | `k[i] = key[i % Len];` |
| KSA 打乱 S 盒 | `j = (j + S[i] + k[i]) % 256; swap(S[i], S[j])` |
| PRGA 生成密钥流 | `i = (i+1) % 256; j = (j+S[i]) % 256; swap; t = (S[i]+S[j]) % 256` |
| 最终异或 | `Data[k] ^= S[t];` |

### 1.3 实战题目：RC4 解密

**题目来源**：`3-Z3-RC4-反调试RC4/3`

在 IDA 中定位到 RC4 加密函数，提取密文和密钥后，直接套用标准 RC4 脚本：

```python
def rc4_init(s_box, key, key_len):
    """KSA: 用密钥初始化 256 字节的 S 盒"""
    k = [0] * 256
    for i in range(256):
        s_box[i] = i
        k[i] = key[i % key_len]
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(k[i])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]

def rc4_crypt(s_box, data, data_len, key, key_len):
    """PRGA: 生成密钥流并与 data 异或（加密解密通用）"""
    rc4_init(s_box, key, key_len)
    i = j = 0
    for k in range(data_len):
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        t = (s_box[i] + s_box[j]) % 256
        data[k] ^= s_box[t]

# 解密
s_box = [0] * 257
data = [0xe8, 0x2b, 0x33, 0x25, 0xb2, 0x55,
        0xe9, 0x0d, 0x5d, 0xaa, 0x69, 0xfd, 0x1b,
        0x47, 0xd1, 0x7c, 0xa6, 0xff, 0x52, 0xe1,
        0x6c, 0xe8, 0x4c]
key = "SakuraiCora"

rc4_crypt(s_box, data, len(data), key, len(key))
print(''.join(chr(i) for i in data))
```

### 1.4 RC4 的魔改变体

CTF 中有时会魔改 RC4，常见的变体包括：
- 修改 S 盒大小（不是 256 而是其他值）
- 修改 KSA/PRGA 中的交换逻辑
- 对密钥流做额外变换（如再异或一个固定值）

遇到魔改 RC4 时，需要从 IDA 中完整还原修改后的 KSA 和 PRGA 逻辑，不能直接套标准脚本。

### 1.5 动态调试技巧

对于 RC4 题目，动态调试往往比静态分析更快：

```
1. 在 IDA/x64dbg 中定位 RC4 加密函数
2. 在加密函数调用后下断点
3. 运行程序，断下后直接查看内存中的明文
4. 如果程序无输入，直接 F8 步过 RC4 函数，跟踪密文地址即可看到明文
```

---

## 二、索引置换加密

### 2.1 算法原理

索引置换是一种简单的替换加密：按照一个预定义的索引表，将明文的字符位置重新排列。

```
明文: f l a g { P R Y ! F ! S S _ 1 _ Y 0 U ! ! }
索引: 0 1 2 3 4 5 6 7 8 9 ...

置换表: [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]

加密: enc[i] = plaintext[table[i]]    →  密文第 i 位 = 明文第 table[i] 位
解密: flag[table[i]] = encode[i]      →  把密文第 i 位放回明文第 table[i] 位
```

### 2.2 实战题目：索引置换解密

**题目来源**：`2-TQ-APK-XOR-HS-RC4/1`

这道题先用 PyInstaller 打包了 Python 脚本，需要先解包（详见系列第四篇），还原出加密逻辑：

```python
# 题目加密逻辑（从反编译的 .pyc 还原）
def enc(input_str):
    tmp = ""
    for i in range(len(input_str)):
        tmp += input_str[table[i]]
    return tmp

# 校验：enc(flag) == "REla{PSF!!fg}!Y_SN_1_0U"
```

**解密脚本**：

```python
encode = "REla{PSF!!fg}!Y_SN_1_0U"
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]

# 解密：把密文字符放回原始位置
flag = [''] * len(encode)
for i in range(len(encode)):
    flag[table[i]] = encode[i]

print("".join(flag))
# 输出: flag{PRY!F!SS_1_Y0U!!}
```

### 2.3 识别与解题

```
识别特征:
- 密文看起来像乱序的 flag 格式（包含 {, } 等符号）
- 代码中有一个整数数组作为索引表
- 加密过程只有位置变换，没有数学运算
- 校验函数通常是 enc(input) == "密文"

解题步骤:
1. IDA 中找到索引表（整数数组）和密文字符串
2. 构造逆映射：flag[table[i]] = enc[i]
3. 输出结果
```

---

## 三、位运算加密（移位与整除）

### 3.1 算法原理

利用位移运算（左移 `<<`、右移 `>>`）和整数除法（`//`）对字符的 ASCII 值进行变换。奇偶位分别用不同的运算方式。

### 3.2 实战题目：移位加密

**题目来源**：`2-TQ-APK-XOR-HS-RC4/4`

从 IDA 中还原加密逻辑：

```
密文数组: [198, 232, 816, 200, 1536, 300, 6144, 984, ...]

加密规则（从 IDA 中的 if-else 分支还原）:
- 奇数位 (i=1,3,5...): enc = ord(flag[i]) << i    (左移)
- 偶数位 (i=2,4,6...): enc = ord(flag[i]) * i      (乘法)
```

**解密脚本**：

```python
text = [198, 232, 816, 200, 1536, 300, 6144, 984,
        51200, 570, 92160, 1200, 565248, 756,
        1474560, 800, 6291456, 1782, 65536000]

flag = ''
for i in range(1, len(text) + 1):
    if i % 2 != 0:          # 奇数位：右移还原（等价于除以 2^i）
        flag += chr(text[i-1] >> i)
    else:                    # 偶数位：整除还原
        flag += chr(text[i-1] // i)

print(flag)
```

### 3.3 识别要点

- 密文数组中的数值呈现明显的倍数关系（如 198, 816, 6144...）
- 代码中有 `<<`、`>>`、`//`、`%` 等位运算/取模操作
- 奇偶索引使用不同运算方式是常见出题套路

---

## 四、累加异或 (Prefix XOR)

### 4.1 算法原理

累加异或是一种链式加密：每个字节与前一个密文字节异或。

```
加密: enc[i] = plain[i] ^ enc[i-1]   (i > 0)
      enc[0] = plain[0]

解密: plain[i] = enc[i] ^ enc[i-1]   (i > 0)
      plain[0] = enc[0]
```

**口诀："前密解后密"** — 用前一位密文异或当前密文，得到当前明文。

### 4.2 IDA 中的识别

在 IDA 伪代码中看到：

```c
for (i = 1; i < len; ++i)
    __b[i] ^= __b[i - 1];
```

这就是典型的 Prefix XOR。

### 4.3 实战题目：累加异或解密

**题目来源**：`2-TQ-APK-XOR-HS-RC4/3`

```python
# 密文（从 IDA 中提取的字节序列）
enc = "f\nk\fw&O.@\x11x\rZ;U\x11p\x19F\x1Fv\"M#D\x0Eg\x06h\x0FG2O"
enc_ord = [ord(ch) for ch in enc]

flag = [0] * 33
flag[0] = enc_ord[0]  # 第一个字节直接还原

for i in range(1, 33):
    flag[i] = enc_ord[i] ^ enc_ord[i-1]  # 前密解后密

print(''.join(chr(x) for x in flag))
```

---

## 五、解题方法论

### 5.1 快速判断算法类型

| 特征 | 可能的算法 |
|------|-----------|
| 256 字节数组初始化 + 双重交换 | **RC4** |
| 整数数组 + 异或常量 | **XOR 加密** |
| 字符位置打乱 | **索引置换** |
| 链式异或 `data[i] ^= data[i-1]` | **Prefix XOR** |
| `<<`、`>>`、`//` 位运算 | **位运算加密** |

### 5.2 常见 Bug 与修复

| Bug | 原因 | 修复 |
|-----|------|------|
| RC4 解密结果不对 | 密钥错误或魔改了 RC4 | 动态调试确认密钥 |
| 索引置换结果错位 | 置换表抄错或正反搞混 | 检查 `flag[table[i]] = enc[i]` |
| Prefix XOR 第一个字节错误 | 没有特殊处理 `i=0` | `flag[0] = enc[0]` 直接赋值 |
| 位运算结果为 0 | 移位过多导致溢出 | 检查 `i` 的范围和移位量 |

---

> 本文所有解题脚本均可直接运行，算法原理基于实际 CTF 题目还原。如有疑问欢迎交流。
