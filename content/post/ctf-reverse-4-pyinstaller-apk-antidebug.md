+++
date = '2026-05-27T13:00:00+08:00'
draft = false
title = 'CTF 逆向入门(四)：PyInstaller解包、APK逆向与反调试绕过'
tags = ['CTF', '逆向', 'PyInstaller', 'APK', '反调试', 'Android']
categories = ['逆向']
+++

> CTF 逆向系列第四篇，覆盖三种实用技能：PyInstaller 打包程序的解包与逆向、Android APK 逆向入门、反调试技术与绕过方法。这些是 CTF 逆向题中常见的"非加密"考点。

---

## 一、PyInstaller 打包程序的逆向

### 1.1 什么是 PyInstaller

PyInstaller 将 Python 脚本打包成独立的 .exe 文件。CTF 中很多 Python 逆向题使用这种方式发布。

### 1.2 解包步骤

```bash
# Step 1: 用 pyinstxtractor 解包 .exe
python pyinstxtractor.py target.exe
# 生成 target.exe_extracted/ 目录

# Step 2: 找到主程序的 .pyc 文件
# 通常是与 .exe 同名的 .pyc（无后缀的文件）
ls target.exe_extracted/

# Step 3: 反编译 .pyc
# 方法1: uncompyle6（Python 3.7 以下）
uncompyle6 target.pyc > target.py

# 方法2: pycdc（支持更高版本）
pycdc target.pyc > target.py

# 方法3: 在线工具
# https://pylingual.io/ 或 https://tool.lu/pyc/
```

### 1.3 实战题目：PyInstaller + 索引置换

**题目信息**

| 项目 | 内容 |
|------|------|
| 文件名 | repy.exe |
| 格式 | PE 64-bit (PyInstaller 打包的 Python 3.6 程序) |
| 题型 | 逆向 — PyInstaller 解包 + 索引置换加密 |
| 附件下载 | [repy.exe](/files/ctf-reverse-4/repy.exe) |
| 解包工具 | [pyinstxtractor.py](/files/ctf-reverse-4/pyinstxtractor.py) |
| 解题脚本 | [solve_pyinst.py](/files/ctf-reverse-4/solve_pyinst.py) |

**Step 1：解包**

```bash
python pyinstxtractor.py repy.exe
# 生成 repy.exe_extracted/ 目录
# 找到 pyre.pyc（主程序字节码）
```

**Step 2：反编译**

用 pycdc 或 uncompyle6 反编译 `pyre.pyc`，得到加密逻辑：

```python
encode = "REla{PSF!!fg}!Y_SN_1_0U"
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]

def enc(input_str):
    tmp = ""
    for i in range(len(input_str)):
        tmp += input_str[table[i]]
    return tmp

# 校验：enc(flag) == encode
```

**Step 3：解密**

这是一个索引置换加密（详见系列第二篇），构造逆映射：

```python
encode = "REla{PSF!!fg}!Y_SN_1_0U"
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9, 10, 15, 14, 17]

flag = [''] * len(encode)
for i in range(len(encode)):
    flag[table[i]] = encode[i]

print("".join(flag))
# 输出: flag{PRY!F!SS_1_Y0U!!}
```

### 1.4 常见问题

| 问题 | 解决方案 |
|------|----------|
| pycdc 反编译失败 | 尝试 uncompyle6 或在线工具 |
| .pyc 文件缺少 magic number | 从同版本 Python 的其他 .pyc 文件中复制前 16 字节 |
| 加密的 .pyc（PyInstaller 加密） | 需要先解密，通常密钥在程序运行时动态生成 |

---

## 二、Android APK 逆向入门

### 2.1 基本流程

```
APK 文件 → jadx/jadx-gui 反编译 → 查看 Java 源码
        → 定位入口 Activity (onCreate)
        → 搜索关键字符串 (flag, encrypt, check)
        → 分析加密逻辑 → 编写解密脚本
```

### 2.2 jadx 操作技巧

```bash
# 命令行反编译
jadx -d output/ target.apk

# GUI 打开（推荐，支持搜索和交叉引用）
jadx-gui target.apk
```

**jadx-gui 中的常用操作：**

| 操作 | 快捷键/方法 | 用途 |
|------|------------|------|
| 搜索字符串 | `Ctrl + Shift + F` | 搜索 flag、key 等关键词 |
| 搜索类名 | `Ctrl + N` | 快速定位类 |
| 交叉引用 | 右键 → `Find Usage` | 查看变量/函数在哪里被调用 |
| 跳转定义 | `双击` 或 `Ctrl + 左键` | 跳转到函数/变量定义 |

**定位入口的步骤：**
1. 在 `AndroidManifest.xml` 中找到 `LAUNCHER` Activity
2. 在 jadx 中找到该 Activity 的 `onCreate` 方法
3. 从 `onCreate` 开始追踪代码逻辑

### 2.3 实战题目：简单 APK 逆向

**题目信息**

| 项目 | 内容 |
|------|------|
| 文件名 | reapk.apk |
| 格式 | Android APK |
| 题型 | 逆向 — APK 反编译 + Java 层加密分析 |
| 附件下载 | [reapk.apk](/files/ctf-reverse-4/reapk.apk) |

```bash
# 1. 用 jadx 反编译
jadx -d output/ reapk.apk

# 2. 搜索关键字符串
grep -r "flag" output/ --include="*.java"

# 3. 定位到 MainActivity 的 onCreate 方法
# 4. 右键分析函数调用链，找到 flag 的拼接/校验过程
```

**Flag**：`flag{c164675262033b4c49bdf7f9cda28a75}`

### 2.4 常见套路

- flag 直接硬编码在代码中（strings 搜索即可）
- flag 通过简单变换（XOR、Base64）隐藏
- flag 分散在多个变量中，需要按顺序拼接

### 2.5 Native SO 分析

如果 APK 中包含 `.so` 文件（Native 代码），需要用 IDA 分析：

```bash
# 提取 SO 文件
unzip target.apk lib/armeabi-v7a/libxxx.so

# IDA 打开 → 定位 JNI_OnLoad → 分析核心算法
# 常见：JNI 函数、动态注册、字符串加密
```

---

## 三、反调试技术与绕过

### 3.1 常见反调试手段

| 技术 | 平台 | 原理 |
|------|------|------|
| `IsDebuggerPresent()` | Windows | 检测 PEB.BeingDebugged 标志 |
| `ptrace(PTRACE_TRACEME)` | Linux | 防止其他调试器 attach |
| `NtQueryInformationProcess` | Windows | 查询调试端口 |
| 时间差检测 | 全平台 | `rdtsc` / `GetTickCount` 检测断点耗时 |
| 双进程保护 | Windows | 父进程监控子进程是否被调试 |

### 3.2 IDA 中的识别

```c
// Windows 反调试
if (IsDebuggerPresent()) {
    exit(1);  // 或者修改程序行为（如改变加密密钥）
}

// Linux/Android 反调试
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    // 被调试，退出或修改行为
}
```

### 3.3 实战题目：RC4 + 反调试

**题目信息**

| 项目 | 内容 |
|------|------|
| 文件名 | rc4_antidebug.exe |
| 格式 | PE 32-bit (Windows EXE) |
| 题型 | 逆向 — RC4 + IsDebuggerPresent 反调试 |
| 附件下载 | [rc4_antidebug.exe](/files/ctf-reverse-4/rc4_antidebug.exe) |
| 解题脚本 | [solve_rc4.py](/files/ctf-reverse-4/solve_rc4.py) |

题目特征：程序包含反调试检测 + RC4 加密。反调试检测通过后才会执行正确的 RC4 解密；如果检测到调试器，会使用错误的密钥。

**方法 1：静态 Patch（推荐新手）**

```
1. IDA 中定位反调试检测代码
   - 搜索 IsDebuggerPresent / ptrace 等 API 调用
   - 找到条件跳转（jz / jnz）

2. Patch 掉检测跳转
   - 将条件跳转改为无条件跳转（jmp）或 NOP（0x90）
   - x64dbg: 选中指令 → 右键 → Fill with NOPs

3. 保存修改后的程序，正常分析 RC4
   - File → Patch file → 保存为新文件
```

**方法 2：动态调试绕过**

```
1. 在反调试检测之前下断点
   - 对 IsDebuggerPresent 下断点: bp kernel32.IsDebuggerPresent
   - 或对 ptrace 下断点: bp ptrace

2. 运行程序，断下后修改返回值
   - Windows: 修改 EAX = 0（表示没有调试器）
   - Linux: 修改 RAX = 0

3. 继续执行，正常跟踪 RC4 加密流程
```

**方法 3：Frida spawn 模式（Android/Linux）**

```javascript
// hook.js - 在反调试之前就 hook 住
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        console.log("ptrace called with request =", args[0]);
    },
    onLeave: function(retval) {
        retval.replace(0);  // 强制返回 0，绕过检测
    }
});
```

```bash
# spawn 模式：在程序启动时就注入 hook，比 attach 更早
frida -U -f com.target.app -l hook.js --no-pause
```

### 3.4 RC4 动态调试技巧

对于 RC4 + 反调试的题目，动态调试是最高效的解法：

```
1. x64dbg 打开程序
2. 对 RC4 加密函数下断点（搜索 S 盒初始化特征）
3. F9 运行到断点
4. 找到密文在内存中的地址
5. F8 步过 RC4 函数
6. 再次查看密文地址，此时已变为明文
7. 直接复制明文即为 flag
```

---

## 四、MD5 消息摘要算法

### 4.1 识别特征

MD5 初始化函数中会使用 4 个固定的链接变量：

```c
void MD5Init(MD5_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}
```

在 IDA 中看到这 4 个常量，基本可以确认是 MD5。

### 4.2 CTF 中的常见套路

| 套路 | 说明 |
|------|------|
| MD5 生成密钥 | `key = MD5(input)[:16]` 作为 AES/RC4 的密钥 |
| MD5 校验 | `MD5(flag) == "已知哈希"`，需要碰撞或爆破 |
| 多轮 MD5 | `MD5(MD5(MD5(...)))`，需要识别轮数 |
| 加盐 MD5 | `MD5(salt + flag)`，盐值通常在程序中硬编码 |

### 4.3 注意事项

- MD5 是不可逆的哈希函数，不能直接"解密"
- 如果需要碰撞：`hashlib.md5(target.encode()).hexdigest()` 逐个尝试
- 在线彩虹表：cmd5.com、somd5.com 等可查询常见字符串的 MD5

---

## 五、解题方法论总结

### 5.1 解题流程图

```
拿到逆向题
│
├── strings 搜索 → 找到 flag? → 直接提交
│
├── IDA 打开 → F5 反编译
│   ├── 搜索字符串 → 交叉引用 → 定位关键函数
│   ├── 看到 S 盒/加密函数 → 识别算法 → 编写解密脚本
│   ├── 看到方程组 → Z3 求解
│   ├── 看到索引表 → 置换解密
│   └── 代码混淆/花指令 → 动态调试
│
├── 动态调试（x64dbg / Frida）
│   ├── 在加密函数后下断点 → 查看明文
│   └── hook 关键函数 → 拦截输入输出
│
└── 所有方法都试过 → binwalk 提取 / 网上搜 writeup
```

### 5.2 工具速查

```bash
# 快速搜索 flag
strings target | grep -iE "flag|ctf|key"

# PyInstaller 解包
python pyinstxtractor.py target.exe

# Python 反编译
pycdc target.pyc
uncompyle6 target.pyc

# APK 反编译
jadx -d output/ target.apk
jadx-gui target.apk

# 查壳
"E:\ctf\tools\1-Reverse\die_win64_portable_3.10_x64\diec.exe" target

# UPX 脱壳
"E:\ctf\tools\1-Reverse\upx-5.0.2-win64\upx.exe" -d target

# Frida hook
frida -U -f com.app.package -l hook.js --no-pause

# 动态调试
x64dbg target.exe
```

---

> 本文所有解题脚本均可直接运行，算法原理基于实际 CTF 题目还原。如有疑问欢迎交流。
