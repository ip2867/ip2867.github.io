+++
date = '2026-05-26T12:00:00+08:00'
draft = false
title = 'x86/x64 汇编指令速查手册（逆向工程版）'
tags = ['逆向', '汇编', 'x86', 'x64', '速查']
categories = ['逆向']
+++

## 前言

本文面向 CTF 逆向工程方向，覆盖 x86 和 x86-64 架构下最常用的汇编指令。重点不在"怎么写汇编"，而在"在 IDA 里看到这行代码时，它在干什么"。

每条指令都附带**等价 C 伪代码**和**逆向场景**，方便直接对照 IDA 反编译输出。

---

## 一、寄存器速览

### 1.1 通用寄存器（x86-64）

```
63          31      15      7       0
┌───────────┬───────┬───────┬───────┐
│           │       │       │       │
│   RAX     │  EAX  │  AX   │AL/AH  │  累加器 / 返回值 / MUL/DIV 隐含操作数
│   RBX     │  EBX  │  BX   │BL/BH  │  基址寄存器（callee-saved）
│   RCX     │  ECX  │  CX   │CL/CH  │  计数器 / REP 前缀计数 / 第4个参数(x64)
│   RDX     │  EDX  │  DX   │DL/DH  │  数据寄存器 / MUL/DIV 高位 / 第3个参数(x64)
│   RSI     │  ESI  │  SI   │SIL    │  源索引 / 第2个参数(x64)
│   RDI     │  EDI  │  DI   │DIL    │  目的索引 / 第1个参数(x64)
│   RBP     │  EBP  │  BP   │BPL    │  栈帧基址（callee-saved）
│   RSP     │  ESP  │  SP   │SPL    │  栈指针
│   R8-R15  │R8D-R15D│R8W-R15W│R8B-R15B│  x64 扩展寄存器
└───────────┴───────┴───────┴───────┘
```

**x64 调用约定（System V AMD64 / Windows x64）：**

| 参数序号 | Linux (System V) | Windows x64 |
|---------|------------------|-------------|
| 第1个 | RDI | RCX |
| 第2个 | RSI | RDX |
| 第3个 | RDX | R8 |
| 第4个 | RCX | R9 |
| 返回值 | RAX | RAX |

> 逆向时看到 `mov edi, 1` 就知道是在给函数的第一个参数赋值（Linux 下）。

### 1.2 标志寄存器（RFLAGS/EFLAGS）

| 位 | 名称 | 含义 | 逆向中何时关注 |
|----|------|------|--------------|
| ZF | 零标志 | 结果为0时置1 | `CMP`/`TEST` 后的跳转 |
| CF | 进位标志 | 无符号溢出/借位 | `JB`/`JA` 等无符号比较 |
| OF | 溢出标志 | 有符号溢出 | `JL`/`JG` 等有符号比较 |
| SF | 符号标志 | 结果最高位为1时置1 | `JS`/`JNS` 判断正负 |
| PF | 奇偶标志 | 低8位中1的个数为偶数时置1 | 很少单独使用 |

---

## 二、数据传送指令

| 指令 | 语法 | 等价 C | 说明 |
|------|------|--------|------|
| **MOV** | `MOV dest, src` | `dest = src` | 最基础的赋值，不修改标志位 |
| **LEA** | `LEA dest, [addr]` | `dest = &arr[i]` 或 `dest = a + b*4 + 8` | **不访问内存**，纯地址计算。逆向中常被编译器用来做算术：`LEA EAX, [ECX*4+ECX]` = `EAX = ECX * 5` |
| **MOVZX** | `MOVZX r32, r8/m8` | `dest = (unsigned)src` | 零扩展，无符号数宽度提升 |
| **MOVSX** | `MOVSX r32, r8/m8` | `dest = (signed)src` | 符号扩展，有符号数宽度提升 |
| **XCHG** | `XCHG a, b` | `swap(a, b)` | 交换两个操作数的值 |

### LEA 专项（逆向高频）

LEA 是 IDA 反编译器最常出现的指令之一，编译器用它做**纯算术运算**而不影响标志位：

```asm
LEA EAX, [ECX + EDX]        ; EAX = ECX + EDX
LEA EAX, [ECX * 4 + 10]     ; EAX = ECX * 4 + 10
LEA RAX, [RBX + RSI * 8]    ; RAX = RBX + RSI * 8
LEA RAX, [RIP + 0x1234]     ; RAX = 当前指令地址 + 0x1234（位置无关代码）
```

> **逆向技巧**：在 IDA 中看到 `LEA` 且目标不是地址，大概率是编译器在做乘加运算。

---

## 三、算术运算指令

| 指令 | 语法 | 等价 C | 标志位影响 |
|------|------|--------|-----------|
| **ADD** | `ADD dest, src` | `dest += src` | ZF, OF, CF, SF |
| **SUB** | `SUB dest, src` | `dest -= src` | ZF, OF, CF, SF |
| **INC** | `INC op` | `op++` | ZF, OF, SF（**不影响 CF**） |
| **DEC** | `DEC op` | `op--` | ZF, OF, SF（**不影响 CF**） |
| **NEG** | `NEG op` | `op = -op` | ZF, OF, CF, SF |
| **CMP** | `CMP a, b` | `a - b`（只设标志位，不存结果） | ZF, OF, CF, SF |
| **MUL** | `MUL src` | `RDX:RAX = RAX * src`（无符号） | CF, OF |
| **IMUL** | `IMUL dest, src` | `dest *= src`（有符号） | CF, OF |
| **DIV** | `DIV src` | `RAX = RDX:RAX / src; RDX = 余数`（无符号） | 无定义 |
| **IDIV** | `IDIV src` | 同上，有符号 | 无定义 |

### CMP + 条件跳转模式（核心）

`CMP a, b` 之后紧跟的跳转指令决定了程序走向：

```asm
CMP EAX, 5
JE  label       ; if (EAX == 5) goto label
; 等价 C: if (EAX == 5)
```

> **逆向技巧**：`CMP` 后面的 `Jxx` 直接对应 `if` 条件。把 `CMP + Jxx` 一起读，不要分开看。

---

## 四、位运算指令

| 指令 | 语法 | 等价 C | 用途 |
|------|------|--------|------|
| **AND** | `AND dest, src` | `dest &= src` | 清零特定位 / 取模优化（AND 2^n-1） |
| **OR** | `OR dest, src` | `dest \|= src` | 置位特定位 |
| **XOR** | `XOR dest, src` | `dest ^= src` | 翻转位 / 清零 / 加密算法核心 |
| **NOT** | `NOT op` | `op = ~op` | 按位取反 |
| **TEST** | `TEST a, b` | `a & b`（只设标志位） | 测试某位是否为0 |
| **SHL/SHR** | `SHL dest, n` / `SHR dest, n` | `dest <<= n` / `dest >>= n`（逻辑移位） | 乘除 2 的幂 / 提取位字段 |
| **SAL/SAR** | `SAL dest, n` / `SAR dest, n` | `dest <<= n` / `dest >>= n`（算术移位，保留符号） | 有符号数的乘除 2 的幂 |
| **ROL/ROR** | `ROL dest, n` / `ROR dest, n` | 循环左移/右移 | 常见于加密算法 |
| **RCL/RCR** | `RCL dest, n` / `RCR dest, n` | 带进位的循环移位 | 较少出现 |

### XOR 专项（逆向最高频）

XOR 在逆向中有三大经典用途：

```asm
; 1. 寄存器清零（比 MOV EAX, 0 少1字节）
XOR EAX, EAX        ; EAX = 0

; 2. 两数交换（无临时变量）
XOR EAX, EBX
XOR EBX, EAX
XOR EAX, EBX        ; EAX <-> EBX

; 3. 加密/解密（CTF 中最常见的编码方式）
XOR AL, 0x37        ; AL ^= 0x37
XOR [RSI+RCX], CL   ; 按字节异或
```

> **逆向技巧**：看到 `XOR reg, reg` → 清零；看到 `XOR reg, imm` 或 `XOR [mem], reg` → 大概率是加密/解密循环。

### TEST 专项

`TEST` 和 `CMP` 类似，但做的是 AND 而不是 SUB：

```asm
TEST EAX, EAX       ; EAX AND EAX，结果为0说明 EAX==0
JZ  label            ; if (EAX == 0) goto label

TEST AL, 1          ; AL AND 1，检查最低位
JNZ label            ; if (AL & 1) goto label（奇数检测）

TEST EAX, 0x80      ; 检查第7位（符号位）
JNZ label            ; if (EAX & 0x80) goto label
```

> **逆向技巧**：`TEST reg, reg` + `JZ/JNZ` 等价于 `if (reg == 0)` / `if (reg != 0)`。这是编译器检查返回值、指针是否为空的标准模式。

---

## 五、栈操作指令

| 指令 | 语法 | 等价 C | 说明 |
|------|------|--------|------|
| **PUSH** | `PUSH src` | `RSP -= 8; [RSP] = src` | 压栈，RSP 减小 |
| **POP** | `POP dest` | `dest = [RSP]; RSP += 8` | 出栈，RSP 增大 |
| **PUSHF** | `PUSHFQ` | 压入 RFLAGS | 保存标志寄存器 |
| **POPF** | `POPFQ` | 弹出到 RFLAGS | 恢复标志寄存器 |

### 栈帧结构（函数调用时）

```
高地址
┌──────────────────┐
│   参数 N         │  ← 调用者压入（x64 下前6个参数用寄存器）
├──────────────────┤
│   返回地址       │  ← CALL 自动压入
├──────────────────┤  ← RBP（帧指针，可选）
│   旧的 RBP       │  ← PUSH RBP
├──────────────────┤
│   局部变量       │  ← RBP - 偏移
├──────────────────┤
│   ...            │  ← RSP（栈指针）
└──────────────────┘
低地址
```

> **逆向技巧**：IDA 中 `[rbp-8]` 是第一个局部变量，`[rbp+16]` 是第一个栈参数（x86）。x64 下前6个参数在寄存器中，多余参数才走栈。

---

## 六、程序流程控制

### 6.1 调用与返回

| 指令 | 语法 | 等价 C | 说明 |
|------|------|--------|------|
| **CALL** | `CALL target` | `target(); return_addr = next_insn` | 压入返回地址，跳转到目标函数 |
| **RET** | `RET` | `return;` | 弹出返回地址并跳转，函数返回 |
| **RET n** | `RET 8` | `return; ESP += 8` | 返回并清理栈上参数（stdcall） |
| **SYSCALL** | `SYSCALL` | `int 0x80` 的 64 位版本 | Linux 系统调用（x64） |
| **INT** | `INT 0x80` | 系统调用（x86） | 32 位 Linux 系统调用 |

### 6.2 无条件跳转

```asm
JMP label       ; goto label
JMP rax         ; 跳转到 RAX 中的地址（间接跳转/switch-case）
JMP [rax*8+table] ; 跳转表，编译器实现 switch-case 的方式
```

### 6.3 条件跳转速查表

`CMP a, b` 或 `TEST a, b` 之后使用：

#### 无符号比较（看 CF 和 ZF）

| 指令 | 含义 | 条件 | 等价 C |
|------|------|------|--------|
| **JE / JZ** | 等于 / 为零 | ZF=1 | `a == b` |
| **JNE / JNZ** | 不等于 / 不为零 | ZF=0 | `a != b` |
| **JA / JNBE** | 高于（Above） | CF=0 且 ZF=0 | `a > b`（无符号） |
| **JAE / JNB / JNC** | 高于等于 | CF=0 | `a >= b`（无符号） |
| **JB / JNAE / JC** | 低于（Below） | CF=1 | `a < b`（无符号） |
| **JBE / JNA** | 低于等于 | CF=1 或 ZF=1 | `a <= b`（无符号） |

#### 有符号比较（看 SF、OF 和 ZF）

| 指令 | 含义 | 条件 | 等价 C |
|------|------|------|--------|
| **JE / JZ** | 等于 | ZF=1 | `a == b` |
| **JNE / JNZ** | 不等于 | ZF=0 | `a != b` |
| **JG / JNLE** | 大于（Greater） | ZF=0 且 SF=OF | `a > b`（有符号） |
| **JGE / JNL** | 大于等于 | SF=OF | `a >= b`（有符号） |
| **JL / JNGE** | 小于（Less） | SF != OF | `a < b`（有符号） |
| **JLE / JNG** | 小于等于 | ZF=1 或 SF != OF | `a <= b`（有符号） |

#### 特殊跳转

| 指令 | 含义 | 条件 | 典型场景 |
|------|------|------|---------|
| **JS** | 符号为负 | SF=1 | 检查结果是否为负 |
| **JNS** | 符号为正 | SF=0 | 检查结果是否为正 |
| **JO** | 溢出 | OF=1 | 检查有符号溢出 |
| **JNO** | 无溢出 | OF=0 | |
| **JCXZ / JECXZ** | CX/ECX 为零 | CX=0 / ECX=0 | 循环计数器检查 |

> **逆向速记**：**A = Above（无符号大于），G = Greater（有符号大于）**。看到 `JA/JB` 用无符号理解，看到 `JG/JL` 用有符号理解。

### 6.4 循环模式

编译器通常不用 `LOOP` 指令，而是用 `CMP + Jxx` 实现循环：

```asm
; for (int i = 0; i < 10; i++)
    XOR ECX, ECX           ; i = 0
loop_start:
    CMP ECX, 10            ; i < 10 ?
    JGE loop_end            ; if (i >= 10) break
    ; ... loop body ...
    INC ECX                ; i++
    JMP loop_start
loop_end:
```

---

## 七、字符串/内存操作指令

| 指令 | 语法 | 功能 | 隐含操作数 |
|------|------|------|-----------|
| **MOVSB/W/D** | `REP MOVSB` | 内存复制（memcpy） | RSI=源, RDI=目的, RCX=计数 |
| **STOSB/W/D** | `REP STOSB` | 内存填充（memset） | AL=填充值, RDI=目的, RCX=计数 |
| **CMPSB/W/D** | `REPE CMPSB` | 内存比较（memcmp） | RSI=源1, RDI=源2, RCX=计数 |
| **SCASB/W/D** | `REPE SCASB` | 字符查找（strchr） | AL=查找值, RDI=目的, RCX=计数 |
| **LODSB/W/D** | `LODSB` | 从内存加载到 AL/AX/EAX | RSI=源 |

### REP 前缀族

| 前缀 | 含义 | 终止条件 |
|------|------|---------|
| **REP** | 重复 RCX 次 | RCX == 0 |
| **REPE / REPZ** | 相等时重复 | RCX == 0 或 ZF == 0 |
| **REPNE / REPNZ** | 不等时重复 | RCX == 0 或 ZF == 1 |

```asm
; memcpy(dst, src, len) 的汇编实现
MOV RDI, dst        ; 目的
MOV RSI, src        ; 源
MOV RCX, len        ; 计数
REP MOVSB           ; 逐字节复制

; strlen 的汇编实现
MOV RDI, str
XOR AL, AL          ; AL = 0 (null terminator)
MOV RCX, -1         ; 最大计数
REPNE SCASB         ; 扫描直到找到 0
NOT RCX             ; 取反得到长度
DEC RCX             ; 减去 null 自身
```

> **逆向技巧**：看到 `REP MOVSB` → memcpy；`REP STOSB` → memset；`REPNE SCASB` → strlen/strchr。

---

## 八、常见编译器模式（IDA 速查）

这是逆向中最实用的部分——看到这些模式，直接对应高级语言结构。

### 8.1 函数序言/尾声

```asm
; 函数序言（Prologue）
PUSH RBP
MOV RBP, RSP
SUB RSP, 0x30       ; 分配局部变量空间

; 函数尾声（Epilogue）
MOV RSP, RBP        ; 或 LEAVE
POP RBP
RET
```

### 8.2 if-else

```asm
CMP EAX, 5
JNE else_branch     ; if (EAX != 5) goto else
; then 分支
JMP end_if
else_branch:
; else 分支
end_if:
```

### 8.3 三目运算符

```asm
CMP EAX, 0
JNZ not_zero
MOV EBX, 10         ; result = 10
JMP done
not_zero:
MOV EBX, 20         ; result = 20
done:
; 等价 C: result = (EAX == 0) ? 10 : 20;
```

### 8.4 switch-case（跳转表）

```asm
CMP EAX, 3          ; 检查范围
JA default           ; 超出范围跳到 default
JMP [rax*8 + table]  ; 查跳转表
; 每个 case 是一个地址
```

### 8.5 循环

```asm
; while (i < n)
loop:
CMP ECX, EDX
JGE exit
; ... body ...
INC ECX
JMP loop
exit:

; do { ... } while (i < n)
loop:
; ... body ...
INC ECX
CMP ECX, EDX
JL loop
```

### 8.6 数组访问

```asm
; arr[i]，int 类型（4字节）
MOV EAX, [RBX + RCX * 4]    ; EAX = arr[i]

; arr[i]，char 类型（1字节）
MOVZX EAX, BYTE PTR [RBX + RCX]  ; EAX = (unsigned char)arr[i]
```

### 8.7 结构体访问

```asm
; obj->field，field 偏移为 0x10
MOV RAX, [RBX + 0x10]       ; RAX = obj->field

; obj.field = value
MOV DWORD PTR [RBX + 0x10], 42  ; obj.field = 42
```

### 8.8 ptrace 反调试检测

```asm
; ptrace(PTRACE_TRACEME, 0, 1, 0)
XOR EDX, EDX        ; addr = 0 (或 MOV EDX, 1)
MOV ESI, 1          ; data = 1 (或 XOR ESI, ESI)
XOR EDI, EDI        ; request = PTRACE_TRACEME
CALL ptrace
TEST EAX, EAX
JS detected          ; if (ret < 0) → 被调试
; 正常路径
JMP continue
detected:
; 假路径 / exit
continue:
```

---

## 九、系统调用速查（Linux x64）

| RAX | 功能 | RDI | RSI | RDX |
|-----|------|-----|-----|-----|
| 0 | read | fd | buf | count |
| 1 | write | fd | buf | count |
| 2 | open | filename | flags | mode |
| 3 | close | fd | - | - |
| 9 | mmap | addr | len | prot |
| 12 | brk | addr | - | - |
| 39 | getpid | - | - | - |
| 57 | fork | - | - | - |
| 59 | execve | filename | argv | envp |
| 60 | exit | status | - | - |
| 62 | kill | pid | sig | - |

```asm
; write(1, "hello", 5)
MOV RAX, 1          ; sys_write
MOV RDI, 1          ; fd = stdout
LEA RSI, [msg]      ; buf = "hello"
MOV RDX, 5          ; count = 5
SYSCALL
```

---

## 十、x86 vs x64 关键差异

| 特性 | x86 (32位) | x64 (64位) |
|------|-----------|-----------|
| 通用寄存器 | 8个 (EAX-EDI) | 16个 (RAX-R15) |
| 指针大小 | 4 字节 | 8 字节 |
| 参数传递 | 全部走栈 | 前6个用寄存器（Linux: RDI,RSI,RDX,RCX,R8,R9） |
| 返回地址 | CALL 压栈 | 同，但地址8字节 |
| 系统调用 | `INT 0x80` | `SYSCALL` |
| 默认操作数 | 32位 | 32位（即使64位模式） |
| 栈对齐 | 4字节 | **16字节**（不对齐会导致 SSE 指令崩溃） |

---

## 附：速查口诀

```
MOV 赋值不动标，LEA 算术也不改
CMP 只看不存值，TEST AND 只看标
XOR 自己是清零，NOP 爆破用得勤
JA 无符大于看，JG 有符大于看
REP 前缀配串操，MOVSB 是 memcpy
CALL 压栈 RET 弹，PUSH POP 栈操作
SYSCALL 系统调，RAX 里放功能号
```

---

> **实践建议**：光看不练等于没看。推荐用 IDA 打开一个简单的 CTF 题目，对照本文逐行分析反汇编输出，比死记硬背有效 10 倍。
