+++
date = '2026-05-26T12:45:00+08:00'
draft = false
title = 'Linux ptrace 反调试详解 + CTF 逆向题解'
tags = ['CTF', '逆向', 'Linux', '反调试', 'ptrace']
categories = ['CTF']
+++

## 一、ptrace 是什么

`ptrace` 是 Linux 系统调用，全称 **"process trace"**，用于**一个进程监视或控制另一个进程的执行**。它是调试器（GDB、strace）的底层基础，也是 CTF 逆向题中最常见的**反调试手段**。

```c
#include <sys/ptrace.h>
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

| 参数 | 含义 |
|------|------|
| `request` | 操作类型（附着、读内存、写内存等） |
| `pid` | 目标进程 PID |
| `addr` | 内存地址（读写时用） |
| `data` | 数据指针（读写时用） |

---

## 二、核心操作

### 2.1 `PTRACE_TRACEME` — "我被追踪了"

```c
ptrace(PTRACE_TRACEME, 0, 0, 0);
```

- **由被调试的子进程调用**，告诉内核："请让我的父进程来调试我"
- 正常运行时返回 `0`
- **已被调试器附着时返回 `-1`**（因为一个进程只能被一个 tracer 附着）

这就是反调试的关键原理：

```c
// 反调试经典代码
if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
    // 被调试了！走干扰路径或退出
    printf("Don't debug me!\n");
    exit(1);
}
```

> **为什么传 `(0, 1, 0)` 而不是 `(0, 0, 0)`？**
> 第三个参数 `addr` 传 `1` 是一种变体写法，效果相同，部分题目用来增加分析难度。

### 2.2 `PTRACE_ATTACH` — "我要调试你"

```c
ptrace(PTRACE_ATTACH, target_pid, 0, 0);
```

- **由调试器（父进程）调用**，附着到目标进程
- 目标进程会被暂停（SIGSTOP）
- 之后调试器可以读写目标内存、单步执行等

### 2.3 其他常用操作

| 操作 | 用途 |
|------|------|
| `PTRACE_PEEKTEXT` | 读目标进程的内存 |
| `PTRACE_POKETEXT` | 写目标进程的内存 |
| `PTRACE_GETREGS` | 读寄存器 |
| `PTRACE_SETREGS` | 写寄存器 |
| `PTRACE_SINGLESTEP` | 单步执行一条指令 |
| `PTRACE_CONT` | 继续执行（非单步） |
| `PTRACE_DETACH` | 脱离附着 |

---

## 三、ptrace 反调试原理图

```
正常运行（无调试器）:
┌──────────┐
│  子进程   │  调用 ptrace(PTRACE_TRACEME)
│  (目标)   │  返回 0 → 继续正常逻辑
└──────────┘

用 GDB 调试时:
┌──────────┐    attach    ┌──────────┐
│  GDB     │ ──────────→ │  子进程   │
│ (tracer) │             │ (tracee)  │
└──────────┘             └────┬─────┘
                              │ ptrace(PTRACE_TRACEME)
                              │ 因为已被 GDB 附着
                              │ 返回 -1 → 走假路径/退出
```

**核心限制：一个进程同一时间只能有一个 tracer。** 如果 GDB 已经在调试你，程序自己的 `PTRACE_TRACEME` 就会失败。

---

## 四、如何绕过 ptrace 反调试

### 方法 1：直接运行（最简单）

```bash
# 不用调试器，直接运行
./attachment.team
# 输入计算出的 flag 即可
```

### 方法 2：Patch 二进制

把 `ptrace` 调用 NOP 掉或修改跳转。在 IDA 中：找到 `call ptrace` 后面的 `test eax, eax / js` 跳转，patch 成 `nop` 或 `jz`（无条件走正常路径）。

### 方法 3：LD_PRELOAD Hook

```c
// fake_ptrace.c
long ptrace(int request, int pid, void *addr, void *data) {
    return 0;  // 永远返回成功
}
```

```bash
gcc -shared -o fake_ptrace.so fake_ptrace.c
LD_PRELOAD=./fake_ptrace.so ./target
```

### 方法 4：GDB 绕过

```gdb
catch syscall ptrace
commands
  set $rax = 0
  continue
end
r
```

### 方法 5：常见变体

| 变体 | 说明 |
|------|------|
| `ptrace(PTRACE_TRACEME, 0, 1, 0)` | 标准用法，addr 传 1 |
| `syscall(__NR_ptrace, ...)` | 直接用 syscall 绕过 libc wrapper |
| 检查 `/proc/self/status` 中 `TracerPid` | 非 ptrace 方式检测调试 |
| `fork()` + `ptrace` 子进程互相检测 | 多进程反调试 |

---

## 五、CTF 题解：attachment.team

### 5.1 题目信息

| 项目 | 内容 |
|------|------|
| 文件名 | attachment.team |
| 格式 | ELF 64-bit x86-64, statically linked |
| 题型 | 逆向 — ptrace 反调试 + 自定义字母表 XOR |
| 附件下载 | [attachment.team](/files/attachment.team) |
| 解题脚本 | [my_solve.py](/files/my_solve.py) |

### 5.2 程序逻辑分析

#### 主函数

```c
void main() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        sub_102E();   // 调试路径 → 假 flag
    }
    sub_12BF();       // 正常路径 → sub_C6D → sub_92A
    exit(0);
}
```

#### 正常路径：sub_C6D

从自定义字母表 `wabcdefglhijkmqnoprvstuzxy_!{}.1234567890 `（42 字符）中取字符，XOR 索引值，构建 51 字节的 encoded buffer：

```c
v1[0]  = alphabet[0]  ^ 0;
v1[2]  = alphabet[21] ^ 2;
v1[3]  = alphabet[5]  ^ 3;
v1[6]  = alphabet[28] ^ 6;
v1[13] = alphabet[26] ^ 13;
v1[8]  = alphabet[9]  ^ 8;
v1[5]  = alphabet[18] ^ 5;
// ... 共 51 个操作
```

#### 验证函数：sub_92A

```c
// 逐字节验证: input[i] XOR i == encoded[i]
for (i = 0; i < 51; i++) {
    if (input[i] ^ i != encoded[i]) {
        puts("Sorry, incorrect password!");
        exit(0);
    }
}
puts("wooooooowwooooooow congratulatio");
```

#### 调试路径：sub_102E

使用不同的字母表 `abcdefghijklmnopqrstuvwxyz_!{} `（31 字符），构建 32 字节 encoded buffer，验证逻辑相同。通过则输出假 flag：`lol_you_thought_it_was_that_easy`

### 5.3 解题思路

验证逻辑为 `input[i] XOR i == encoded[i]`，逆向公式：

```
flag[i] = alphabet[offset] XOR xor_val XOR i
```

**步骤：**

1. IDA 反编译，定位 `ptrace(PTRACE_TRACEME)` → 识别反调试
2. 分析正常路径 `sub_C6D`，提取字母表和 51 个 `(offset, xor)` 操作
3. 用 Python 逆向计算 `flag[i] = alphabet[offset] ^ xor_val ^ i`
4. 拼接得到完整 flag

### 5.4 解题脚本

```python
s = 'wabcdefglhijkmqnoprvstuzxy_!{}.1234567890 '

def xorr(s):
    v1 = [chr(0)] * 52
    v1[0] = s[0]
    v1[2] = chr(ord(s[21]) ^ 2)
    v1[3] = chr(ord(s[5]) ^ 3)
    v1[6] = chr(ord(s[28]) ^ 6)
    v1[13] = chr(ord(s[26]) ^ 13)
    v1[8] = chr(ord(s[9]) ^ 8)
    v1[5] = chr(ord(s[18]) ^ 5)
    v1[11] = chr(ord(s[12]) ^ 0xB)
    v1[1] = chr(ord(s[1]) ^ 1)
    v1[10] = chr(ord(s[15]) ^ 0xA)
    v1[9] = chr(ord(s[34]) ^ 9)
    v1[12] = chr(ord(s[35]) ^ 0xC)
    v1[47] = chr(ord(s[5]) ^ 0x2F)
    v1[16] = chr(ord(s[3]) ^ 0x10)
    v1[15] = chr(ord(s[34]) ^ 0xF)
    v1[4] = chr(ord(s[19]) ^ 4)
    v1[20] = chr(ord(s[7]) ^ 0x14)
    v1[23] = chr(ord(s[16]) ^ 0x17)
    v1[32] = chr(ord(s[1]) ^ 0x20)
    v1[24] = chr(ord(s[18]) ^ 0x18)
    v1[14] = chr(ord(s[9]) ^ 0xE)
    v1[18] = chr(ord(s[31]) ^ 0x12)
    v1[21] = chr(ord(s[26]) ^ 0x15)
    v1[31] = chr(ord(s[9]) ^ 0x1F)
    v1[22] = chr(ord(s[6]) ^ 0x16)
    v1[7] = chr(ord(s[21]) ^ 7)
    v1[34] = chr(ord(s[12]) ^ 0x22)
    v1[17] = chr(ord(s[12]) ^ 0x11)
    v1[19] = chr(ord(s[15]) ^ 0x13)
    v1[40] = chr(ord(s[18]) ^ 0x28)
    v1[26] = chr(ord(s[20]) ^ 0x1A)
    v1[33] = chr(ord(s[3]) ^ 0x21)
    v1[25] = chr(ord(s[26]) ^ 0x19)
    v1[29] = chr(ord(s[22]) ^ 0x1D)
    v1[27] = chr(ord(s[40]) ^ 0x1B)
    v1[42] = chr(ord(s[16]) ^ 0x2A)
    v1[37] = chr(ord(s[7]) ^ 0x25)
    v1[28] = chr(ord(s[11]) ^ 0x1C)
    v1[39] = chr(ord(s[16]) ^ 0x27)
    v1[35] = chr(ord(s[10]) ^ 0x23)
    v1[36] = chr(ord(s[15]) ^ 0x24)
    v1[48] = chr(ord(s[1]) ^ 0x30)
    v1[30] = chr(ord(s[26]) ^ 0x1E)
    v1[51] = chr(0)
    v1[43] = chr(ord(s[11]) ^ 0x2B)
    v1[44] = chr(ord(s[22]) ^ 0x2C)
    v1[45] = chr(ord(s[30]) ^ 0x2D)
    v1[38] = chr(ord(s[6]) ^ 0x26)
    v1[50] = chr(ord(s[29]) ^ 0x32)
    v1[49] = chr(ord(s[13]) ^ 0x31)
    v1[41] = chr(ord(s[20]) ^ 0x29)
    v1[46] = chr(ord(s[21]) ^ 0x2E)

    # 逆向: flag[i] = encoded[i] XOR i
    v2 = ''
    for i in range(51):
        v2 += chr(ord(v1[i]) ^ i)
    return v2

if __name__ == '__main__':
    print(xorr(s))
```

### 5.5 运行结果

```
$ python my_solve.py
watevr{th4nk5_h4ck1ng_for_s0ju_hackingforsoju.team}
```

### 5.6 两条路径对比

| 路径 | 字母表 | Flag |
|------|--------|------|
| 正常（非调试） | `wabcdefglhijkmqnoprvstuzxy_!{}.1234567890 ` | `watevr{th4nk5_h4ck1ng_for_s0ju_hackingforsoju.team}` |
| 调试（被检测） | `abcdefghijklmnopqrstuvwxyz_!{} ` | `lol_you_thought_it_was_that_easy` |

> 调试路径的 `lol_you_thought_it_was_that_easy` 是出题人设置的嘲讽彩蛋——你一旦用调试器跑，它就给你一个假 flag。这正是 ptrace 反调试的典型套路。

### 5.7 知识点总结

- **ELF64 ptrace 反调试**：`ptrace(PTRACE_TRACEME)` 返回 -1 表示正在被调试
- **自定义字母表替换 + XOR 编码**：从 .rodata 段提取字母表，按索引取字符后 XOR
- **strcmp 的 null 终止特性**：验证函数用 strcmp 逐字节比较，null terminator 控制长度
- **逆向公式**：`flag[i] = alphabet[offset] ^ xor_val ^ i`

---

> **一句话总结：ptrace 反调试 = 程序检测"有没有人正在调试我"，有就走假路径。解题时静态分析正常路径即可，不需要真正去调试它。**
