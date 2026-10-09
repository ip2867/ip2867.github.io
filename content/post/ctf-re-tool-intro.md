+++
date = '2026-10-09T22:40:00+08:00'
draft = false
title = 'CTF-RE-TOOL：把逆向工作流装进一个桌面工具'
tags = ['CTF', '逆向', '工具', 'Electron', 'Frida', 'IDA', 'AI']
categories = ['逆向']
+++

> 一个基于 Electron 的 CTF 逆向工程辅助工具：集成 AI 分析引擎、一键调用逆向工具、Frida 自动 Hook、解密脚本生成，内置 11 个逆向方法论 Skills 与可检索知识库，并通过 MCP 实时接入 IDA / JEB / Burp。
>
> 项目地址：<https://github.com/ip2867/ctf-re-tool>　·　下载：[Releases](https://github.com/ip2867/ctf-re-tool/releases)（`CTF-RE-TOOL.exe`，便携单文件，双击即用）

---

## 一、为什么要写这个工具

做 CTF 逆向，真正消耗时间的往往不是某一道题本身，而是反复的**环境切换**：

- 拖一个文件进来，先 `file` / DIE 查壳，再确定是 PE、ELF 还是 APK；
- 打开了 IDA，又要在 JEB、jadx、apktool、pycdc 之间来回切，路径每次都要重新点；
- 静态走不通，想上 Frida，又要开模拟器、起 frida-server、查进程、写 hook 脚本；
- 好不容易抓到一段密文，还得手写解密脚本，来回试算法。

这些动作本身没有智力含量，却占了整个解题过程的一大半。**CTF-RE-TOOL** 想做的，就是把这些动作收敛到一个窗口里，让注意力尽量留在"算法怎么还原"上。

## 二、它长什么样

工具是一个三栏布局的桌面应用：

![主界面](/images/ctf-re-tool.png)

> 左侧是文件分析与工具区，中间是 AI 对话，右侧是输出日志 / Frida Hook / 快速操作。

核心能力大致分这几块：

| 模块 | 说明 |
|---|---|
| **文件识别** | 支持 APK、EXE/PE（含 .NET）、ELF/SO、DEX、PYC（全版本魔数）、JAR/.class、Lua 字节码、WASM、Mach-O；ZIP 按内容精确区分 APK / JAR / 普通 ZIP |
| **一键调用工具** | IDA / DIE / JEB / jadx / UPX / apktool / pycdc / pycdas 等，路径在设置里配置一次 |
| **Frida 自动 Hook** | 自动生成 Hook 模板（Cipher / String / MessageDigest / SharedPreferences / Base64 / Native），支持 Java 层与 Native 层 |
| **解密脚本生成** | 覆盖 AES、DES/3DES、TEA/XTEA/XXTEA、RC4、XOR、Base64（含自定义码表）、CRC32、SM4，以及 RSA 攻击手架、Z3 求解、angr 符号执行 |
| **AI 分析引擎** | 兼容 CCSwitch / GLM 的 Anthropic `/v1/messages` 接口，流式输出，Tool Use 循环（工具结果自动截断防止爆上下文） |
| **Skills + Wiki** | 11 个中文方法论技能（Android / 二进制 / IoT 固件 / 反调试 / Frida / JS 逆向 / 密码学识别 …）+ 可检索知识库（`wiki_search` / `wiki_read`） |
| **MCP 接入** | 实时连接 IDA MCP、JEB MCP、Burp MCP，AI 可直接调用反编译、交叉引用、抓包历史 |
| **CASE 证据体系** | 每道题自动建 `cases/<题名>_<md5前8>/`，含 `evidence/`、`scripts/`、`timeline.jsonl`、`findings.json` |
| **反调试绕过** | Android（ptrace / TracerPid / Debuggable / Frida 检测 / System.exit）与 Windows PE（IsDebuggerPresent / PEB / NtGlobalFlag / NtQueryInformationProcess） |
| **题解双轨** | 模板轨 + AI 轨，一键生成 Markdown writeup |

## 三、实战一：字节码虚拟机（`2.exe`）

第一道题是一个 105 KB 的 PE 控制台程序——**MinGW/GCC 编译，没有壳，但核心校验藏在一个自实现的字节码虚拟机里**。

### 3.1 自动分析

把 `2.exe` 拖进工具，自动识别为 PE 并建好 CASE 目录。程序本身很小，关键字符串一眼可见：

```text
0x404000  "string:"
0x40400b  "WRONG! \nwhat a shame..."
0x404058  "good,The answer format is:flag {}"
```

`scanf` 读入后先判断长度是否为 15：不是就直接 `WRONG!`，是才进入真正的校验。真正的逻辑在 `0x401553`——一个 switch 分发 0~12 号操作码的解释器，跳表在 `0x404024`，程序体是 `0x403040` 处 114 个 dword。

### 3.2 还原指令语义

工具用 capstone 复刻了每个 handler 的语义（按栈帧偏移对齐 ebp）：

| op | 语义 |
|---|---|
| 10 | 读取输入（触发 `scanf`） |
| 2 / 3 / 4 / 5 | `T = R[i] ± /^/* operand`（模 256） |
| 11 / 12 | `T = R[i] - 1` / `T = R[i] + 1` |
| 8 | 把 T 写回缓冲 `e5[iC] = T` |
| 1 | 输出到 `buf81[i18] = T` |
| 7 | **逐字节比对** `signed(buf81[i14]) == operand`，不等即 `WRONG` |
| 6 | NOP |

关键坑有两点：**`case 8` 的写回会覆盖输入缓冲区**（所以后面读到的可能已不是原始输入），且 `T` 是 `char`，所有运算都要按 8 位（模 256 + 有符号比较）处理。

### 3.3 求解

字节码尾部 15 条是 `[CMP, 目标值]` 序列，目标为：

```text
[34, 63, 52, 50, 114, 51, 24, 167, 49, 241, 40, 132, 193, 30, 122]
```

由于每个输入字节只影响输出缓冲的同一下标，可以**逐位独立爆破**。工具生成并运行了解题脚本，得到：

```text
[+] 关键输入 = 757515121f3d478
[+] 复刻 VM 校验通过 = True => flag{757515121f3d478}
```

再用工具实际运行二进制验证：

```bat
> echo 757515121f3d478| 2.exe
string:good,The answer format is:flag {}
```

**flag = `flag{757515121f3d478}`**

完整脚本见附件 [solve_vm.py](/files/ctf-re-tool-intro/solve_vm.py)，题目样本 [2.exe](/files/ctf-re-tool-intro/2.exe)。

## 四、实战二：多阶段 + Native 校验（`app-release.apk`）

第二道题（`com.nctf.hookmysecret`）是典型的**三阶段 Android 题**，而我是直接点"运行 Hook"解的。

### 4.1 运行 Hook 抓状态

工具自动生成并注入了 Frida Hook 脚本，运行输出里能看到应用的真实执行流（截取）：

```text
[HIT] NativeBridge.encryptStage2 hooked
[HIT] Cipher hooked
[HIT] String.equals false: "robolectric" == "samsung/SM-S9110/marlin:9/..."
[HIT] Arrays.equals(int[]) [] vs [] -> true
[DATA] ARRAY MATCH [16842910,16843597,0,0]
[HIT] String.equals true: ".../databases/config.db" == ".../databases/config.db"
```

从这里能直接读出题目的结构：

- 有三阶段，状态存在 `SharedPreferences("challenge_state")`，键是 `stage1Passed / stage2Key / stage2Passed`；
- Stage2 走的是 **native**：`NativeBridge.encryptStage2(String)` 返回值与某个 `int[]` 常量比对；
- IV 之类常量藏在 SQLite（`SQLiteOpenHelper.onCreate`），本机是 `M0/a`。

### 4.2 静态定位

工具用 apktool 解包后，直接按常量串反查最快。R8 把包名压成了单字母（`N0`、`C`、`K0`、`M0`），但常量串藏不住：

```bat
findstr /S /I /M /C:"stage3_iv" /C:"stage2Key" smali\*.smali
```

- 校验回调（`OnClickListener`）→ `N0/d`
- 常量类（`fill-array-data` 的 `int[]`）→ `K0/a`
- `SQLiteOpenHelper`（IV 初始化）→ `M0/a`

`N0/d.smali` 里确认了 Stage3 用的是 `AES/CBC/PKCS5Padding`，密文硬编码为 `jSaMnziall55Tdr+IZc7EKUNm/N4uwrZw1QFPw6DuirfYFJZg88j6GKLhWfNljAB`，key 来自 `stage2Key`，IV 来自 SQLite。

### 4.3 Native key 反演

Stage2 的 native 变换经 IDA 反编译后是一个逐字节滚动状态：

```c
v26 = ROL8(v25 ^ S ^ ((13*i + 66) & 0xff), 3) + i + 7*S;
S   = (S + v25) + (i ^ v26);
```

其中 `S` 初值 81，常量只出现 `81 / 13 / 66`。用目标常量 `[0xFA,0x71,...,0x5F]` 反推即可还原 stage2Key，并用 `forward(inverse(TARGET)) == TARGET` 自检：

```text
[stage2] 反演出的 key = b'k7Xm2Pq9Wv4N8bRt'
```

### 4.4 拼起来

拿到 key 后，Stage3 就是一个普通的 AES/CBC：

```python
iv = base64.b64decode("VmVyaWZ5VmVjdG9yMTIzNA==")   # -> VerifyVector1234
ct = base64.b64decode("jSaMnziall55Tdr+IZc7EKUNm/N4uwrZw1QFPw6DuirfYFJZg88j6GKLhWfNljAB")
pt = unpad(AES.new(b"k7Xm2Pq9Wv4N8bRt", AES.MODE_CBC, iv).decrypt(ct), 16)
```

**flag = `NCTF{a680107e-a49b-43e1-915b-cedd25e7835a}`**

完整脚本见附件 [solve_apk.py](/files/ctf-re-tool-intro/solve_apk.py)，Hook 脚本 [hook.js](/files/ctf-re-tool-intro/hook.js)，题目样本 [app-release.apk](/files/ctf-re-tool-intro/app-release.apk)。

> **经验沉淀**：这道题最优解其实是纯静态——反查常量串定位校验点（`N0/d`）+ native 反演 key + AES 解密，全程不需要模拟器。工具会把这类"踩坑 + 正解"自动写入经验库，下次遇到同类题自动注入提示词。

## 五、一些工程细节

工具本身也是按"安全工具"的标准写的：

- **渲染层加固**：`sandbox: true` + `contextIsolation`，渲染层只有 `contextBridge` 暴露的白名单 API；外链一律走系统浏览器。
- **IPC 参数化**：命令执行走 `run-tool-args`（argv 数组 + `shell:false`），避免字符串拼接带来的注入面；zip 探目录、目录检索改用纯 Node 实现，替掉了原来的 PowerShell 拼接。
- **路径边界**：文件写入限定在允许根（userData / 应用目录 / 临时目录 / 当前题目目录）之内；打包后 asar 只读，运行期产物统一落到 `userData`。
- **CASE 与隐私**：每题的证据、脚本、时间线独立成目录，`cases/`、`HANDOFF.md` 等含答案/本机信息的文件默认不入库。

## 六、小结

`CTF-RE-TOOL` 不是要替代 IDA / Frida / JEB——真正的分析永远得靠它们。它想解决的是**"把工具串起来"这件事的摩擦**：识别、调用、Hook、解密、验证、沉淀，尽量自动化，让人专注于算法本身。

上面两道题，一道是纯静态的字节码虚拟机，一道要靠动态 Hook 定位再静态求解——正好覆盖了逆向里最常见的两种节奏。

- 项目地址：<https://github.com/ip2867/ctf-re-tool>
- 下载试用：[Releases](https://github.com/ip2867/ctf-re-tool/releases)

> 适用范围：CTF 竞赛、授权渗透测试、自有系统的安全研究。请勿用于未授权目标。
