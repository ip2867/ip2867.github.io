+++
date = '2026-05-27T10:00:00+08:00'
draft = false
title = 'CTF 逆向入门(一)：XOR加密、小端序、换表Base64与Z3求解'
tags = ['CTF', '逆向', 'XOR', 'Base64', 'Z3', '小端序']
categories = ['逆向']
+++

> 本系列基于实际 CTF 逆向训练题目，系统介绍逆向工程中常见的加密算法与解题技巧。第一篇覆盖最基础的四种题型：XOR 异或加密、小端序处理、换表 Base64 编码、Z3 约束求解。

---

## 一、前置知识：逆向分析基础

### 1.1 核心工具

| 工具 | 用途 | 说明 |
|------|------|------|
| **IDA Pro** | 静态反编译 | 将二进制程序还原为伪代码（F5），逆向分析的核心工具 |
| **x64dbg** | 动态调试 | 单步执行、断点、内存查看，适合跟踪加密流程 |
| **strings** | 提取字符串 | 快速从二进制文件中找 flag、key 等关键信息 |
| **Ghidra** | 免费反编译 | NSA 开源，支持多种架构，IDA 的免费替代 |

### 1.2 通用分析思路

```
拿到程序
  │
  ├─ strings 快速搜索 → 找到 flag? → 直接提交
  │
  ├─ IDA 打开 → F5 反编译
  │   ├─ 搜索关键字符串 (flag / encrypt / check / verify)
  │   ├─ 对字符串交叉引用 → 定位关键函数
  │   ├─ 识别加密算法特征（S盒、常量、循环结构）
  │   └─ 编写解密脚本
  │
  └─ 动态调试（x64dbg / Frida）
      ├─ 在加密函数后下断点 → 查看明文
      └─ hook 关键函数 → 拦截输入输出
```

---

## 二、XOR 异或运算

### 2.1 算法原理

XOR（异或）是逆向题中最基础也最常见的加密方式，也是很多复杂加密算法的底层操作。

```
核心特性：
A ^ B = C
C ^ B = A    ← 可逆性：同一密钥异或两次恢复原文
A ^ A = 0    ← 归零性：自身异或结果为零
A ^ 0 = A    ← 恒等性：与零异或不变
```

### 2.2 实战题目：逐字节异或 + 小端序

**题目信息**

| 项目 | 内容 |
|------|------|
| 文件名 | challenge_1_xor |
| 格式 | ELF 64-bit / Binary |
| 题型 | 逆向 — XOR 加密 + 小端序字节序 |
| 附件下载 | [challenge_1_xor](/files/ctf-reverse-1/challenge_1_xor) |
| 解题脚本 | [solve_xor.py](/files/ctf-reverse-1/solve_xor.py) |

用 IDA 打开题目二进制文件，F5 反编译后看到如下逻辑：

```c
int array[] = {0x75553A1E, 0x7B583A03, 0x4D58220C, 0x7B50383D, 0x736B3819};
int xor_key = 0x12345678;
for (i = 0; i < 5; i++) {
    array[i] ^= xor_key;
}
```

程序将一个整数数组与固定密钥 `0x12345678` 逐元素异或，然后按字节输出。

**解题思路**：

1. 异或运算可逆，再异或一次就能还原
2. 整数需要按**小端序**（Little Endian）转为字节，因为 x86 架构使用小端序存储

**解密脚本**：

```python
import struct

array = [0x75553A1E, 0x7B583A03, 0x4D58220C, 0x7B50383D, 0x736B3819]
xor_key = 0x12345678

flag = []
for val in array:
    temp = val ^ xor_key              # 异或解密
    char_bytes = struct.pack('<I', temp)  # 小端序转字节（关键！）
    flag.append(char_bytes)

print(b''.join(flag).decode())
# 输出: flag{llittl_Endian_a...
```

### 2.3 小端序详解

计算机存储多字节数据时有两种字节序：

```
数值: 0x67616C66

大端序 (Big Endian):    67 61 6C 66  →  高位在前（网络字节序）
小端序 (Little Endian): 66 6C 61 67  →  低位在前（x86/x64 默认）
```

在 Python 中使用 `struct` 模块处理：

```python
import struct

# 整数 → 小端序字节
struct.pack('<I', 0x67616C66)  # b'flag'

# 整数 → 大端序字节
struct.pack('>I', 0x67616C66)  # b'galf'  ← 反了！
```

> **关键点**：`struct.pack('<I', temp)` 中的 `<` 表示小端序，`I` 表示 4 字节无符号整数。例如 `0x67616c66` 小端序存储为 `0x66, 0x6c, 0x61, 0x67`，即 ASCII 的 `f, l, a, g`。

### 2.4 常见陷阱

```python
# ❌ 错误1：用值做索引
for i in array:
    temp = array[i] ^ xor_key  # array[i] 用的是值作为索引，逻辑错误

# ❌ 错误2：int + str 类型错误
flag += temp  # TypeError: unsupported operand type(s) for +: 'int' and 'str'

# ❌ 错误3：忽略小端序
flag += chr(temp)  # 0x67616c66 的 chr 是一个超大 Unicode，不是 'flag'

# ✅ 正确写法
for val in array:
    temp = val ^ xor_key
    flag.append(struct.pack('<I', temp))
print(b''.join(flag).decode())
```

---

## 三、换表 Base64 (Custom Base64)

### 3.1 标准 Base64

Base64 不是加密算法，是一种编码方式。它将每 3 字节（共 24bit）按照每 6bit 分成一组，变成 4 个小于 64 的索引值，然后通过索引表映射为 4 个可见字符。

```
标准索引表: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

**识别特征**：密文只包含上述 64 个字符，长度是 4 的倍数，末尾可能有 `=` 填充。

### 3.2 换表 Base64 原理

CTF 中最常见的 Base64 变体——**替换索引表**。出题者用一张自定义的 64 字符表替换了标准表。

**在 IDA 中的识别**：在 `.data` 或 `.rdata` 段看到一个 64 字节的字符串，与标准表不同，就是换表 Base64。编码函数中会出现 `>> 2`、`& 0x3F`、`<< 4` 等位运算操作。

### 3.3 解密脚本

在 IDA 中找到自定义表和密文后，编写解密脚本：

```python
import base64

def decode_custom_base64(ciphertext, custom_table):
    """换表 Base64 解密：自定义表 → 映射回标准表 → 标准 Base64 解码"""
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # 创建映射：自定义表的第 i 个字符 → 标准表的第 i 个字符
    trans_map = str.maketrans(custom_table, standard_table)

    # 替换密文中的字符
    std_ciphertext = ciphertext.translate(trans_map)

    # 标准 Base64 解码
    return base64.b64decode(std_ciphertext)

# ================= 配置区域 =================
# 在 IDA 中找到的自定义表（通常在 .data 段）
custom_table = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0987654321/+"
# 密文（从 IDA 的数据段或函数参数中提取）
ciphertext = "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI=="

result = decode_custom_base64(ciphertext, custom_table)
print(result.decode('utf-8'))
```

### 3.4 解题步骤

```
1. IDA 中搜索 64 字节长的字符串 → 找到自定义表
2. 对字符串交叉引用 → 定位编码函数，找到密文
3. 用 str.maketrans() 映射回标准表
4. base64.b64decode() 解码得到 flag
```

---

## 四、Z3 约束求解器

### 4.1 什么是 Z3

Z3 是微软开发的 SMT（Satisfiability Modulo Theories）求解器。在 CTF 逆向中，当题目将 flag 的各字符代入一组线性方程进行校验时，Z3 可以自动求解。

### 4.2 适用场景

- 题目用 flag 字符的 ASCII 值构建多元一次方程组
- 手动解方程太复杂（10 个未知数、10 个方程）
- 方程数 >= 未知数个数

### 4.3 实战题目：从 IDA 伪代码到 Z3 求解

**题目信息**

| 项目 | 内容 |
|------|------|
| 文件名 | z3_challenge |
| 格式 | ELF 64-bit / Binary |
| 题型 | 逆向 — Z3 约束求解 |
| 附件下载 | [z3_challenge](/files/ctf-reverse-1/z3_challenge) |
| 解题脚本 | [solve_z3.py](/files/ctf-reverse-1/solve_z3.py) |

**Step 1：在 IDA 中找到校验方程**

```c
if (-85*v9 + 58*v8 + 97*v6 + v7 + -45*v5 + 84*v4 + 95*v2 - 20*v1 + 12*v3 == 12613
    && 30*v11 + -70*v9 + -122*v6 + -81*v7 + ... == -54400
    && ...)
```

**Step 2：自动化求解脚本**

手动复制方程容易出错。以下脚本可以直接从 IDA 的伪代码文本中解析方程并求解：

```python
import re
from z3 import *

ida_code = """
 -85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 + 84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613
  && 30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400
  && -103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 + 78 * v1 - 41 * v2 + 31 * v5 - (v6 << 6) - 120 * v9 == -10283
  && 71 * v6 + (v7 << 7) + 99 * v5 + -111 * v3 + 85 * v1 + 79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855
  && 5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944
  && -54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 - 11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222
  && -83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 - 18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258
  && 81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 + 95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559
  && 101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308
  && 99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697
"""

# 预处理：位移运算转乘法  (v6 << 6) → v6 * 64
s = ida_code.replace('\n', ' ')
s = re.sub(r'\(?(v\d+)\s*<<\s*(\d+)\)?',
           lambda m: f"({m.group(1)} * {1 << int(m.group(2))})", s)

# 分割方程
equations = [x.strip() for x in s.replace('&&', '||').split('||') if x.strip()]

# 变量格式化：v1 → v[1]
equations = [re.sub(r'v(\d+)', lambda m: f"v[{m.group(1)}]", eq) for eq in equations]

# Z3 求解
v = [Int(f'v{i}') for i in range(20)]
solver = Solver()
for eq in equations:
    solver.add(eval(eq))

if solver.check() == sat:
    m = solver.model()
    res = {f'v{i}': m[v[i]].as_long() for i in range(20) if m[v[i]] is not None}
    print("求解成功！", res)
    # 根据题目中的变量映射关系还原 flag
    flag_ascii = [res['v2'], res['v1'], res['v3'], res['v4'], res['v5'],
                  res['v7'], res['v6'], res['v8'], res['v9'], res['v11']]
    print("Flag:", ''.join(chr(x) for x in flag_ascii))
else:
    print("无解！请检查方程是否抄错。")
```

### 4.4 注意事项

- **脚本文件名不能叫 `z3.py`**，会导致 Python 导入冲突（`import z3` 会导入自身）
- Z3 只能解线性方程组；如果方程包含非线性运算（如 `v1 * v2`），需要用 `BitVec` 代替 `Int`
- `__readfsqword(0x28)` 是 Linux/ELF 的栈金丝雀（Stack Canary），与 flag 无关，忽略即可
- 变量映射关系（v1 对应 s[1] 还是 s[0]）需要从 IDA 顶部的赋值语句确认

### 4.5 XOR 校验算法补充

有些题目不用方程组，而是用简单的 XOR 累加校验：

```c
// IDA 伪代码
int check = 9;
for (i = 0; i < len; i++) {
    check ^= flag[i];
}
if (check == 73) { /* correct */ }
```

这种情况下，已知 flag 前缀（如 `actf{`），可以逐字节推导或直接用 Z3 求解。

---

## 五、解题方法论

### 5.1 快速判断算法类型

| 特征 | 可能的算法 |
|------|-----------|
| 整数数组 + 异或常量 | **XOR 加密** |
| 密文只有字母数字 `+/=` | **Base64** |
| 多元一次方程组 | **Z3 求解** |
| 256 字节数组初始化 + 双重交换 | **RC4** |
| S 盒首字节 `0x63` | **AES** |
| 常量 `0x9E3779B9` | **TEA / XTEA / XXTEA** |

### 5.2 常见 Bug 与修复

| Bug | 原因 | 修复 |
|-----|------|------|
| `TypeError: int + str` | 混淆了整数和字符串操作 | 用 `chr()` 转换 |
| 输出乱码 | 没处理小端序 | 用 `struct.pack('<I', val)` |
| Z3 无解 | 方程抄错或变量映射错误 | 逐个检查方程，确认变量编号 |
| `import z3` 失败 | 脚本文件名冲突 | 重命名为 `solve.py` 等 |

---

> 本文所有解题脚本均可直接运行，算法原理基于实际 CTF 题目还原。如有疑问欢迎交流。
