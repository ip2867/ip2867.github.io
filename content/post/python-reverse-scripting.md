+++
date = '2026-05-26T12:30:00+08:00'
draft = false
title = 'Python 逆向脚本编程手册（CTF 解题版）'
tags = ['逆向', 'Python', 'CTF', '脚本', 'pwntools']
categories = ['逆向']
+++

## 前言

CTF 逆向题的最终目标是写出解密脚本。本文覆盖写脚本时 95% 会用到的 Python 知识，每条都附带**逆向实战场景**，遇到题目直接查。

---

## 一、Bytes vs String（90% 报错的根源）

Python 3 严格区分文本（str）和字节（bytes），**逆向只认 bytes**。

| 类型 | 写法 | 本质 | 适用场景 |
|------|------|------|---------|
| **str** | `'hello'` | 给人看的文本，含编码 | 打印、文件名 |
| **bytes** | `b'hello'` | 给机器看的原始数值 `[0x68,0x65,...]` | Payload、内存数据、加密运算 |

```python
# ❌ 报错：str 和 bytes 不能相加
payload = "AAAA" + struct.pack('<I', 0x1234)

# ✅ 正确：加 b 前缀
payload = b"AAAA" + struct.pack('<I', 0x1234)
```

**互转方法：**

```python
s = "hello"
b = s.encode()        # str → bytes (默认 UTF-8)
s = b.decode()        # bytes → str
s = b.hex()           # bytes → hex 字符串 "68656c6c6f"
b = bytes.fromhex("68656c6c6f")  # hex 字符串 → bytes
```

---

## 二、进制与类型转换

### 2.1 基础转换速查

```python
hex(255)              # → '0xff'
int('0xff', 16)       # → 255
bin(10)               # → '0b1010'
chr(65)               # → 'A'
ord('A')              # → 65
```

### 2.2 int ↔ bytes（推荐用法）

```python
# int → bytes
num = 0x12345678
b = num.to_bytes(4, 'little')    # b'\x78\x56\x34\x12'
b = num.to_bytes(4, 'big')       # b'\x12\x34\x56\x78'

# bytes → int
num = int.from_bytes(b'\x78\x56\x34\x12', 'little')  # 305419896
num = int.from_bytes(b'\x78\x56\x34\x12', 'big')     # 2018915346
```

### 2.3 超长整数（RSA/Crypto 场景）

当数字大到 `struct` 处理不了（如 1024 位 RSA 密钥）：

```python
number = 123456789123456789...

# 自动计算所需字节数
b_data = number.to_bytes((number.bit_length() + 7) // 8, 'big')

# 还原
number = int.from_bytes(b_data, 'big')
```

---

## 三、位运算与溢出模拟

### 3.1 运算符速查

| 符号 | 名称 | 例子 | 逆向用途 |
|------|------|------|---------|
| `&` | 按位与 | `x & 0xFF` | **截断取低8位**，模拟溢出 |
| `\|` | 按位或 | `x \| 0x80` | 置位特定位 |
| `^` | 异或 | `x ^ key` | **加密/解密** |
| `~` | 取反 | `~x` | 按位取反 |
| `<<` | 左移 | `x << 1` | 乘 2，移位拼接 |
| `>>` | 右移 | `x >> 1` | 除 2，取高位 |

### 3.2 模拟 C 语言溢出（核心）

Python 整数无限大不会溢出，但 C 语言的 `unsigned int` 超过最大值会回绕。**必须手动截断**：

```python
# 32 位溢出
res = (a + b) & 0xFFFFFFFF

# 64 位溢出
res = (a + b) & 0xFFFFFFFFFFFFFFFF

# 8 位溢出
res = (a + b) & 0xFF
```

### 3.3 无符号 → 有符号转换

```python
def to_signed_32(n):
    n = n & 0xFFFFFFFF
    return n if n < 0x80000000 else n - 0x100000000

def to_signed_64(n):
    n = n & 0xFFFFFFFFFFFFFFFF
    return n if n < 0x8000000000000000 else n - 0x10000000000000000
```

### 3.4 优先级陷阱

**位运算优先级低于 `==` 和 `+`，永远加括号！**

```python
# ❌ 错误：先算了 0xff == 0x10
if a & 0xff == 0x10: ...

# ✅ 正确
if (a & 0xff) == 0x10: ...
```

---

## 四、struct 与字节序

### 4.1 格式字符速查

| 格式 | C 类型 | 字节数 | 备注 |
|------|--------|--------|------|
| `B` | unsigned char | 1 | 0~255 |
| `H` | unsigned short | 2 | 0~65535 |
| `I` | unsigned int | 4 | 32位常用 |
| `Q` | unsigned long long | 8 | 64位常用 |
| `<` | - | - | **小端序**（x86/x64） |
| `>` | - | - | 大端序（网络/MIPS） |

### 4.2 Pack 与 Unpack

```python
import struct

# Pack：数字 → 字节（构造 payload）
payload = struct.pack('<I', 0xdeadbeef)    # b'\xef\xbe\xad\xde'
payload = struct.pack('<Q', 0x1234567890)  # 8字节

# Unpack：字节 → 数字（读取内存）
data = b'\xef\xbe\xad\xde'
value = struct.unpack('<I', data)[0]        # 0xdeadbeef
# 注意：unpack 返回元组，必须 [0] 取值
```

### 4.3 小端序直觉

IDA 中看到 `0x12345678`，内存中存储为 `78 56 34 12`——**低位在前**。

```
IDA 显示:    0x12345678
内存布局:    78 56 34 12
                ↑ 低位字节在低地址
```

---

## 五、常见编码转换

### 5.1 Base64

```python
import base64

encoded = base64.b64encode(b'flag{test}')   # b'ZmxhZ3t0ZXN0fQ=='
decoded = base64.b64decode(encoded)          # b'flag{test}'

# 变种：URL-safe Base64
encoded = base64.urlsafe_b64encode(b'\xfb\xff')

# 无 padding 的 Base64（手动补 =）
import base64
raw = base64.b64decode(s + '=' * (-len(s) % 4))
```

### 5.2 Hex 字符串 ↔ Bytes

```python
# Wireshark 抓包数据 / IDA 机器码
hex_str = "606EA290"
b_data = bytes.fromhex(hex_str)       # b'\x60\x6e\xa2\x90'

# 反转
hex_str = b_data.hex()                # "606ea290"
```

### 5.3 逗号分隔的 hex 数据（常见于 IDA 导出）

```python
hex_data = "0x6d, 0x6f, 0x65, 0x63, 0x74, 0x66"
decoded = "".join([chr(int(h.strip(), 16)) for h in hex_data.split(',')])
# → "moectf"
```

---

## 六、逆向循环方向判断

解密脚本最容易出错的地方：**正向循环还是逆向循环？**

### 类型一：独立操作（正序即可）

每个元素的变换只依赖自己的原始值：

```c
// 加密：a[i] = (16 * a[i]) | (a[i] >> 4)
// 解密：逆运算，每个 a[i] 独立处理，顺序无所谓
for i in range(len(data)):
    data[i] = reverse_transform(data[i])
```

### 类型二：依赖传播（必须逆序）

元素的变换依赖邻居的值，形成数据依赖链：

```c
// 加密：a[i] += a[i+1]  （从左到右）
// 解密：必须从右到左
for i in range(len(data) - 2, -1, -1):
    data[i] -= data[i + 1]
```

**判断方法**：看加密时 `a[i]` 的新值是否用到了 `a[i-1]` 或 `a[i+1]`。用了就必须逆序。

---

## 七、Pwntools（CTF 瑞士军刀）

`pip install pwntools`，一行顶十行。

### 7.1 数据打包/解包

```python
from pwn import *

# 替代 struct.pack / struct.unpack
payload = p32(0xdeadbeef)       # 32位小端序打包
payload = p64(0x1234567890)     # 64位小端序打包
value = u32(b'\xef\xbe\xad\xde')  # 32位解包 → 0xdeadbeef
value = u64(data[0:8])         # 64位解包，自动补零
```

### 7.2 异或（自动循环密钥）

```python
from pwn import *

# 手动写法
cipher = bytes([x ^ 0x55 for x in b'hello'])

# pwntools 写法（支持长短不一的密钥自动循环）
cipher = xor(b'hello', 0x55)
cipher = xor(b'hello world', b'KEY')  # KEY 自动循环填充
```

### 7.3 连接远程服务

```python
from pwn import *

io = remote('192.168.1.100', 1337)
io.recvuntil(b'Password: ')
io.sendline(b'my_flag')
io.interactive()  # 交还控制权
```

### 7.4 分析 ELF 文件

```python
from pwn import *

elf = ELF('./challenge')

# 获取地址
main_addr = elf.symbols['main']
puts_plt = elf.plt['puts']
printf_got = elf.got['printf']
binsh_addr = next(elf.search(b'/bin/sh'))

# Patch 二进制
elf.asm(elf.symbols['check'], 'mov eax, 1; ret')
elf.save('./patched')
```

### 7.5 flat（快速构造 payload）

```python
from pwn import *

# 自动处理偏移和地址拼接
payload = flat(
    b'A' * 112,          # padding
    p64(0xdeadbeef),     # saved rbp
    p64(0x401234),       # return address
)
```

---

## 八、z3 约束求解（逆向神器）

当验证逻辑是一堆线性方程或位运算时，不用手算，直接丢给 z3。

```python
from z3 import *

# 定义未知变量（每个字节一个变量）
flag = [BitVec(f'f{i}', 8) for i in range(32)]

s = Solver()

# 添加约束条件（从 IDA 反编译中抄）
s.add(flag[0] ^ 0x37 == 0x50)
s.add(flag[1] + flag[2] == 200)
s.add(flag[3] << 2 == 0x1fc)
# ... 把所有验证条件都加进去

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[f].as_long()) for f in flag)
    print(result)
```

> **适用场景**：验证逻辑是方程组、位运算、线性变换，但手动逆向太复杂时。

---

## 九、常见加密特征速查

| 特征 | 算法 | 识别方法 |
|------|------|---------|
| `0x9E3779B9` / `0x61C88647` | TEA 系列 | 黄金比例常量 |
| `0x67452301, 0xEFCDAB89,...` | MD5 / SHA | 初始向量 |
| S-Box（256字节置换表） | AES / RC4 | 查表操作 |
| `0x010001, 0x...` 大整数 | RSA | 公钥指数 |
| Base64 字母表变种 | 自定义 Base64 | 字母表不是标准 `A-Za-z0-9+/` |
| `ptrace(PTRACE_TRACEME)` | 反调试 | 检测调试器 |

---

## 十、实战代码模板

### 模板 1：XOR 解密

```python
ciphertext = bytes.fromhex('1a2b3c4d...')
key = 0x5f
flag = bytes([x ^ key for x in ciphertext])
print(flag)
```

### 模板 2：爆破单字节密钥

```python
cipher = b'\x12\x34\x56...'
known = b'flag{'  # 已知明文前缀

for key in range(256):
    if all(cipher[i] ^ key == known[i] for i in range(len(known))):
        print(f"Key: {key}")
        flag = bytes([x ^ key for x in cipher])
        print(flag)
        break
```

### 模板 3：读写二进制文件

```python
with open('challenge.bin', 'rb') as f:
    data = f.read()

# 处理...
decrypted = bytes([x ^ 0x37 for x in data])

with open('flag.bin', 'wb') as f:
    f.write(decrypted)
```

### 模板 4：64位分块解密

```python
import struct

raw_key = [0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
           0x42,0x9,0x4a,0x49,0x35,0x43,0xa,0x41,
           0xf0,0x19,0xe6,0xb,0xf5,0xf2,0xe,0xb,
           0x2b,0x28,0x35,0x4a,0x6,0x3a,0xa,0x4f]

target = b"zer0pts{********CENSORED********}"
flag = b""

for i in range(0, len(raw_key), 8):
    k_val = struct.unpack('<Q', bytes(raw_key[i:i+8]))[0]
    t_val = struct.unpack('<Q', target[i:i+8])[0]
    f_val = (t_val + k_val) & 0xFFFFFFFFFFFFFFFF
    flag += struct.pack('<Q', f_val)

print(flag.decode())
```

### 模板 5：hex 逗号列表 → 字符串

```python
hex_data = "0x6d,0x6f,0x65,0x63,0x74,0x66,0x7b,0x54"
print("".join(chr(int(h, 16)) for h in hex_data.split(',')))
# → "moectf{T"
```

### 模板 6：自定义字母表解码

```python
alphabet = "wabcdefglhijkmqnoprvstuzxy_!{}.1234567890 "
encoded = [(0,0,0), (1,1,1), (2,21,2), (3,5,3)]  # (dest, idx, xor)

result = [0] * 51
for dest, idx, xor_val in encoded:
    result[dest] = ord(alphabet[idx]) ^ xor_val

flag = "".join(chr(result[i] ^ i) for i in range(51))
print(flag)
```

---

## 附：速查流程图

写逆向脚本时的思考顺序：

```
1. 分析算法 → 识别加密类型（XOR/TEA/AES/自定义）
2. 提取数据 → 从 IDA 获取密文、密钥、常量
3. 确定方向 → 独立操作正序，依赖传播逆序
4. 模拟溢出 → 每次运算后 & 0xFF / 0xFFFFFFFF
5. 转换格式 → bytes ↔ int ↔ str，注意字节序
6. 输出 flag → decode() 或 chr() 转可读字符串
```

> **记住**：逆向脚本的核心流程 = **切块 → 解包 → 运算 → 打包 → 拼接**。
