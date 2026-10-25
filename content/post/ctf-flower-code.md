+++
date = '2026-06-06T11:00:00+08:00'
draft = false
title = 'CTF 逆向入门(五)：花指令识别与去除'
tags = ['CTF', '逆向', '花指令', 'opaque predicate', 'IDA', '反混淆']
categories = ['逆向']
+++

> CTF 逆向系列第五篇，介绍花指令（Junk Code / Opaque Predicate）的识别与去除。花指令是出题者在程序中插入的无用代码，目的是干扰 IDA 的反编译引擎，让 F5 输出变成一堆 goto 或无法反编译。本文先讲知识点，再通过四道实战题目演示不同类型的花指令解法。

参考文章：[花指令学习笔记（CSDN）](https://blog.csdn.net/Sciurdae/article/details/133750478)

---

## 一、知识点：什么是花指令

### 1.1 定义

花指令（Junk Code）是插入到程序中的**永远不会执行**的垃圾代码。它的作用是：

```
正常代码流程
    |
    +-- 插入花指令（永远不会执行的垃圾字节）
    |       |
    |       +-- IDA 误认为这是有效代码
    |       +-- F5 反编译结果混乱（大量 goto、无法反编译）
    |
    +-- 继续正常执行
```

花指令利用了**线性反汇编器**的弱点：反汇编器按顺序逐条解析指令，花指令插入的垃圾字节会被误解析为"合法"指令，导致后续真正的指令解析错位。

### 1.2 花指令的核心原理

```
                    +----------+
                    | 条件跳转  |  （永远为真或永远为假）
                    +----+-----+
                         |
            +------------+------------+
            |                         |
     条件为真（正常路径）        条件为假（永远不会执行）
            |                         |
            v                         v
    +---------------+        +----------------+
    | 正常代码       |        | 垃圾字节        |
    +---------------+        | 被 IDA 误解析为  |
                             | "合法" 指令      |
                             +----------------+
```

关键点：**条件跳转永远只走一个方向**，但 IDA 不知道这一点，它会把两个分支都解析为有效代码。

### 1.3 常见花指令类型

| 类型 | 原理 | 特征 |
|------|------|------|
| **永真/永假条件跳转** | `jz`/`jnz` 条件永远成立 | `cmp reg, reg` + `jz` |
| **call + ret 混淆** | 用 call 压入地址，ret 弹出跳转 | call 后紧跟垃圾字节 |
| **jmp 短跳 + 垃圾字节** | `jmp +1` 跳过一个字节 | 单字节垃圾 |
| **push + ret** | push 一个地址，ret 跳转到该地址 | 等价于 `jmp` |
| **异常处理混淆** | 触发异常，在异常处理程序中执行真正逻辑 | `__try/__except` 或 SEH |
| **不透明谓词** | 利用数学恒等式（如 `x*(x+1)%2==0`） | 条件表达式看起来复杂但结果恒定 |

### 1.4 在 IDA 中的识别特征

看到以下现象，基本可以确认有花指令：

```
F5 反编译结果出现：
+-- 大量 goto 语句（goto LABEL_XXX）
+-- 无法 F5 反编译（"too big" 或 "analysis failed"）
+-- 函数中出现 __asm { } 内联汇编块
+-- 明显无意义的指令序列（如连续的 push/pop）
+-- 代码中出现永远不会到达的分支
```
---

## 二、知识点：花指令去除方法

### 2.1 方法一：IDA 手动 Patch（最常用）

核心思路：**把花指令的跳转改为无条件跳转，把垃圾字节改为 nop**。

```
原始代码：
    cmp eax, eax       ; 永真条件
    jz  short normal    ; 永远跳转
    db  0xE8            ; 垃圾字节（被 IDA 误解析为 call）

Patch 后：
    jmp short normal    ; 改为无条件跳转
    nop                 ; 垃圾字节改为 nop
```

**IDA Patch 步骤**：
1. 在 IDA 中定位花指令位置
2. Edit -> Patch program -> Change byte
3. 将条件跳转改为 `jmp`（`0xEB` 短跳，`0xE9` 近跳）
4. 将垃圾字节改为 `0x90`（nop）
5. File -> Produce file -> Create DUMP file 保存
6. 重新用 IDA 打开，F5 反编译

### 2.2 方法二：IDAPython 脚本自动化

当花指令模式固定且重复出现时，写脚本批量去除：

```python
import ida_bytes

def patch_nop(start_ea, end_ea):
    """将地址范围内的字节全部改为 nop"""
    for ea in range(start_ea, end_ea):
        ida_bytes.patch_byte(ea, 0x90)

def fix_jmp(ea, target):
    """将指定地址改为 jmp near"""
    ida_bytes.patch_byte(ea, 0xE9)
    offset = target - ea - 5
    ida_bytes.patch_dword(ea + 1, offset)
```

### 2.3 方法三：Shift+F2 IDC 脚本

在 IDA 中按 Shift+F2 打开 IDC 脚本窗口：

```c
// 将垃圾字节 nop 掉
patch_byte(0x401007, 0x90);
patch_byte(0x401008, 0x90);

// 将条件跳转改为无条件跳转
patch_byte(0x401005, 0xEB);  // jmp short
patch_byte(0x401006, 0x10);  // 跳转偏移
```

### 2.4 方法四：动态调试绕过

花指令太复杂时，用动态调试：

```
1. x64dbg 在花指令前下断点
2. 单步执行（F8），观察实际跳转方向
3. 记录真实执行路径，只分析该路径
```

### 2.5 方法五：反混淆工具

| 工具 | 说明 |
|------|------|
| **D-810** | IDA 插件，自动去除常见花指令 |
| **GOOMBA** | 基于 angr 的自动化反混淆 |
| **Hex-Rays** | 商业版对部分花指令有更好的处理 |
---

## 三、实战一：简单 XOR + 花指令

### 3.1 题目信息

| 项目 | 内容 |
|------|------|
| 文件名 | 1.exe |
| 格式 | PE32 (x86, console) |
| 题型 | 花指令 + XOR 加密 + 位交换 |
| 来源 | NSSCTF |
| 附件下载 | [1.zip](/files/ctf-flower-code/1.zip) |

### 3.2 解题过程

**Step 1：IDA 打开，F5 反编译**

程序中有花指令干扰，F5 结果不正常。需要先识别并去除花指令。

**Step 2：定位花指令**

在 IDA 中找到花指令位置，分析跳转模式：

```
; 花指令模式：永真条件跳转 + 垃圾字节
cmp eax, eax        ; eax == eax 永真
jz  short real_code  ; 永远跳转
db  0xE8             ; 垃圾字节，被 IDA 误解析为 call
real_code:
; ... 正常代码 ...
```

**Step 3：Patch 去除花指令**

1. 将条件跳转改为 `jmp`（`0xEB`）
2. 将垃圾字节改为 `nop`（`0x90`）
3. 保存并重新分析，F5 反编译恢复正常

**Step 4：分析加密逻辑**

去除花指令后，F5 清晰地展示了加密过程：

```c
// 1. XOR 解密（密钥 48）
for (i = 0; i < len; i++) {
    s[i] ^= 48;
}

// 2. 相邻两两交换
for (j = 0; j < len/2; j++) {
    swap(s[2*j], s[2*j+1]);
}
```

**Step 5：编写解密脚本**

```python
s = "c~scvdzKCEoDEZ[^roDICUMC"
flag = []
for i in range(len(s)):
    flag.append(chr(ord(s[i]) ^ 48))
for j in range(len(s) // 2):
    flag[2*j], flag[2*j+1] = flag[2*j+1], flag[2*j]
print("".join(flag))
# NSSCTF{Just_junk_Bytess}
```

### 3.3 知识点总结

| 知识点 | 说明 |
|--------|------|
| **永真条件跳转** | `cmp eax, eax` + `jz` 永远跳转，跳过垃圾字节 |
| **IDAPython Patch** | 用 `patch_byte()` 批量修改字节 |
| **XOR + 位交换** | 常见的简单加密组合 |

---

## 四、实战二：简单花指令（直接可见 flag）

### 4.1 题目信息

| 项目 | 内容 |
|------|------|
| 文件名 | 2.exe |
| 格式 | PE32 (x86, console) |
| 题型 | 花指令（最简类型） |
| 来源 | NSSCTF |
| 附件下载 | [2.zip](/files/ctf-flower-code/2.zip) |

### 4.2 解题过程

**快速解法**：这道题的花指令非常简单，`strings` 命令就能直接看到 flag：

```bash
$ strings 2.exe | grep -i flag
NSSCTF{Jump_b9_jump!}
```

**分析花指令结构**：

程序使用了 `RegOpenKeyExW` / `RegCloseKey` 进行反调试检测，配合简单的跳转花指令：

```
; 简单的 jmp 花指令
jmp short skip_junk   ; 跳过垃圾字节
db 0x66, 0x90         ; 垃圾字节
skip_junk:
; 正常代码
```

### 4.3 知识点总结

| 知识点 | 说明 |
|--------|------|
| **strings 快速解题** | 简单花指令题中，flag 可能直接以明文存储 |
| **jmp 短跳花指令** | `jmp +1` 跳过单字节垃圾，最简单的花指令形式 |
| **注册表反调试** | `RegOpenKeyExW` 常用于检测调试器注册表键值 |
---

## 五、实战三：复杂加密 + 花指令

### 5.1 题目信息

| 项目 | 内容 |
|------|------|
| 文件名 | 3.exe |
| 格式 | PE32 (x86, console) |
| 题型 | 花指令 + 原地修改加密 + 取模还原 |
| 来源 | NSSCTF |
| 附件下载 | [3.zip](/files/ctf-flower-code/3.zip) |

### 5.2 解题过程

**Step 1：去除花指令**

与前两题类似，先在 IDA 中定位并 patch 掉花指令，恢复 F5 反编译。

**Step 2：分析加密逻辑**

去除花指令后，看到一个**原地修改**的加密算法：

```c
char cipher[] = "~4G~M:=WV7iX,zlViGmu4?hJ0H-Q*";

for (i = 0; i < 29; i++) {
    idx = (i * i + 123) % 21;
    for (j = 0; j < 4; j++) {
        if (i > idx) {
            sum = (cipher[i] - 32) + j * 96 - cipher[idx];
            if (32 <= sum && sum <= 127) {
                flag[i] = sum;
                break;
            }
        }
    }
}
```

**Step 3：理解加密难点**

两个关键难点：

1. **原地修改（In-place Modification）**：`cipher[i]` 在计算过程中会被修改，不是使用原始值
2. **取模运算 `% 96`**：`A = B % 96` 会丢失信息，需要通过 `j` 循环遍历所有可能的 `B` 值（`R + 0*96`, `R + 1*96`, `R + 2*96`...），用 ASCII 范围约束筛选唯一解

**Step 4：编写解密脚本**

```python
s = list("~4G~M:=WV7iX,zlViGmu4?hJ0H-Q*")
flag = []
for i in range(len(s)-1, -1, -1):
    idx = (i * i + 123) % 21
    for j in range(4):
        if i > idx:
            ascnum = (ord(s[i]) - 32) + j * 96 - ord(s[idx])
            if 32 <= ascnum <= 127:
                flag.append(chr(ascnum))
                break
        else:
            index_in_reversed = len(s) - 1 - idx
            ascnum_reversed = ord(flag[index_in_reversed])
            ascnum = (ord(s[i]) - 32) + j * 96 - ascnum_reversed
            if 32 <= ascnum <= 127:
                flag.append(chr(ascnum))
                break
print("".join(flag)[::-1])
# NSSCTF{Jump_b9_jump!_r3V3n9e}
```

### 5.3 知识点总结

| 知识点 | 说明 |
|--------|------|
| **原地修改加密** | 加密过程中修改了输入本身，解密需要从后往前 |
| **取模还原** | `% 96` 丢失信息，用 `j` 循环 + ASCII 范围约束还原 |
| **花指令嵌套** | 复杂加密 + 花指令双重干扰，先去花指令再分析算法 |

---

## 六、实战四：Patch 反编译 + 花指令

### 6.1 题目信息

| 项目 | 内容 |
|------|------|
| 文件名 | 4.exe |
| 格式 | PE32 (x86, console) |
| 题型 | 花指令 + NtGlobalFlag 反调试 + 高低 4 位交换 |
| 来源 | moectf |
| 附件下载 | [4.zip](/files/ctf-flower-code/4.zip) |

### 6.2 解题过程

**Step 1：IDA 打开**

程序输出 `"Come on! Give me your flag:"`，但 F5 反编译结果被花指令严重干扰。

**Step 2：Shift+F2 脚本注释去除花指令**

这道题的花指令使用了 **NtGlobalFlag 反调试**配合：

```
; 读取 PEB 中的 NtGlobalFlag
mov eax, fs:[30h]      ; 获取 PEB
mov eax, [eax+68h]     ; NtGlobalFlag 偏移
; 检测调试标志，执行不同的花指令路径
```

使用 IDC 脚本（Shift+F2）批量 patch 花指令。

**Step 3：分析加密逻辑**

去除花指令后，看到加密过程：

```c
// 1. 每个字节高低 4 位交换
for (i = 0; i < len; i++) {
    n = cipher[i];
    result[i] = ((n << 4) | (n >> 4)) & 0xFF;
}

// 2. 从后往前累加异或（差分）
for (j = len-2; j >= 0; j--) {
    result[j] = (result[j] - result[j+1]) & 0xFF;
}
```

**Step 4：编写解密脚本**

```python
s = [0xcd, 0x4d, 0x8c, 0x7d, 0xad, 0x1e, 0xbe, 0x4a,
     0x8a, 0x7d, 0xbc, 0x7c, 0xfc, 0x2e, 0x2a, 0x79,
     0x9d, 0x6a, 0x1a, 0xcc, 0x3d, 0x4a, 0xf8, 0x3c,
     0x79, 0x69, 0x39, 0xd9, 0xdd, 0x9d, 0xa9, 0x69,
     0x4c, 0x8c, 0xdd, 0x59, 0xe9, 0xd7]

flag = []
for i in range(len(s)):
    n = s[i]
    flag.append(((n << 4) | (n >> 4)) & 0xFF)

for j in range(len(s) - 2, -1, -1):
    flag[j] = (flag[j] - flag[j + 1]) & 0xFF

print("".join(chr(x) for x in flag))
# moectf{p4tch_pr0gr4m_t0_d3c0mpi1e_it!}
```

### 6.3 知识点总结

| 知识点 | 说明 |
|--------|------|
| **NtGlobalFlag 反调试** | `PEB.NtGlobalFlag` 偏移 0x68，调试状态下有标志位 |
| **Shift+F2 IDC 脚本** | IDA 内置脚本窗口，快速批量 patch |
| **高低 4 位交换** | `(n << 4) | (n >> 4)` 是常见位操作加密 |
| **差分加密** | `result[i] -= result[i+1]`，从后往前累加 |
---

## 七、解题方法论总结

### 7.1 花指令题的通用解法

```
拿到带花指令的程序
|
+-- 1. strings 快速搜索 flag（简单题可能直接有）
|
+-- 2. IDA 打开 -> F5 反编译
|       正常? -> 直接分析
|       异常? -> 继续
|
+-- 3. 定位花指令
|       +-- 查看函数开头的 cmp/jz/jnz 模式
|       +-- 查找 __asm { } 内联汇编块
|       +-- 查找永远不会执行的分支
|
+-- 4. 去除花指令
|       +-- 方法A: IDA 手动 Patch（Edit -> Patch program）
|       +-- 方法B: IDAPython 脚本批量 patch
|       +-- 方法C: Shift+F2 IDC 脚本
|       +-- 方法D: 动态调试确认真实执行路径
|
+-- 5. 保存修改后的文件 -> 重新 IDA 打开 -> F5
|
+-- 6. 分析加密逻辑 -> 编写解密脚本 -> 拿到 flag
```

### 7.2 快速判断花指令类型

| 看到什么 | 花指令类型 | 去除方法 |
|----------|-----------|----------|
| `cmp reg, reg` + `jz` | 永真条件跳转 | 改 `jmp`，nop 垃圾字节 |
| `call` 后紧跟垃圾字节 | call + ret 混淆 | nop 掉 call 和垃圾字节 |
| `jmp +1` 单字节跳 | 简单 jmp 花指令 | nop 掉垃圾字节 |
| `push addr` + `ret` | push/ret 跳转 | 改为 `jmp addr` |
| `fs:[30h]` + `[eax+68h]` | NtGlobalFlag 反调试 | patch 反调试检测 |
| 复杂条件表达式 | 不透明谓词 | 分析恒等式，简化条件 |

### 7.3 常见坑点

| 坑 | 原因 | 解决方案 |
|----|------|----------|
| F5 无法反编译 | 花指令导致分析失败 | 手动 Patch 后重新分析 |
| Patch 后程序运行异常 | Patch 位置或字节写错 | 用 x64dbg 单步验证 |
| flag 格式不对 | 加密解密脚本逻辑错误 | 对照 IDA 伪代码逐行还原 |
| 花指令位置找不到 | 花指令在子函数中 | 搜索所有函数，逐个检查 |

---

## 八、工具速查

| 工具 | 用途 | 说明 |
|------|------|------|
| **IDA Pro** | 静态分析 + Patch | Edit -> Patch program -> Change byte |
| **IDAPython** | 批量 Patch 脚本 | `ida_bytes.patch_byte(ea, 0x90)` |
| **Shift+F2 (IDC)** | 快速脚本窗口 | `patch_byte(addr, value)` |
| **x64dbg** | 动态验证 Patch | 单步跟踪确认跳转方向 |
| **D-810** | 自动反混淆 IDA 插件 | GitHub 开源 |
| **Detect It Easy** | 查壳 | 确认是否有壳干扰 |

---

## 九、总结

花指令的本质是**干扰反汇编器的线性分析**，核心解法就是 **Patch + 重新分析**：

```
识别花指令模式 -> Patch 跳转和垃圾字节 -> 重新 F5 -> 分析真正逻辑
```

四道题从简到难覆盖了花指令的主要类型：
- **题一**：永真条件跳转 + XOR 位交换
- **题二**：最简 jmp 花指令（strings 直接出 flag）
- **题三**：花指令 + 原地修改加密 + 取模还原
- **题四**：NtGlobalFlag 反调试 + 高低 4 位交换 + 差分加密

> 本文解题过程基于 NSSCTF / moectf 平台题目。花指令题的核心在于耐心 Patch，建议多练习识别不同的跳转模式。如有疑问欢迎交流。
