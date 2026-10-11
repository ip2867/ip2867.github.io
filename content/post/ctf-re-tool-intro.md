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
- 静态走不通想上 Frida：开模拟器、push frida-server、查进程名、写 hook 脚本、过滤日志噪音……每一步都是体力活；
- 好不容易抓到一段密文，还得手写解密脚本，来回试算法。

这些动作本身没有智力含量，却占了整个解题过程的一大半。**CTF-RE-TOOL** 想做的，就是把这些动作收敛到一个窗口里，并且按一条固定的"流水线"执行，让注意力尽量留在"算法怎么还原"上。

## 二、整体架构：一条解题流水线

工具的核心不是"又一个 AI 聊天框"，而是一条**带验证闭环的流水线**。拖入文件后自动走完这几步：

![主界面](/images/ctf-re-tool.png)

> 三栏布局：左侧文件分析与工具区，中间 AI 对话，右侧输出日志 / Frida Hook / 快速操作。

```text
拖入文件
  │
  ├─ 魔数识别（APK / PE / ELF / DEX / PYC / JAR / Lua / WASM / Mach-O）
  ├─ 建立 CASE 证据目录（cases/<题名>_<md5前8>/：evidence + scripts + timeline + findings）
  │
  ├─ 按类型走自动分析流水线
  │     PE  ：查壳 → IDA+MCP → 反调试检测 → 算法识别 → 生成解密脚本
  │     APK ：查壳 → JEB+MCP → SO提取+IDA → 模拟器 → 装APK → frida-server → 生成Hook脚本
  │
  ├─ AI Tool-Use 求解循环（读技能 → bash/run_python → 反编译 → 还原算法）
  │     └─ 输出契约：[FLAG]...[/FLAG] + [VERIFY]{算法,密钥,密文}[/VERIFY]
  │
  ├─ 验证闭环：工具在本地复现 [VERIFY]，通过才算 verified；失败则枚举 [HYPOTHESES] 兜底
  ├─ （需要动态证据时）Frida 自动 Hook + 界面驱动 + 进程内解密
  │
  └─ 经验沉淀：踩坑与正则写入经验库，下次同类题自动注入提示词
```

几个关键设计：

**① MCP 不是"连上就算"，而是真的取数。** IDA MCP 连上后会枚举导出函数、定位 JNI 函数并反编译，把伪代码喂给后续 AI——否则等于白连。

**② AI 的输出是契约，不是散文。** AI 按约定输出 `[VERIFY]{"algo":"aes_cbc","key":"...","ciphertext":"...","iv":"..."}`，工具解析后用本地 Python 复现一遍：解出来能匹配 `expected` 才标记 `verified`。AI 说对了不算数，**本地跑通了才算**。

**③ 失败有兜底。** 验证不过时，AI 会被要求给出 `[HYPOTHESES]`（多个候选算法 × 密钥 × 字节序组合），工具本地枚举，命中即记录。

**④ 每道题都是一个案件。** 反编译产物、Hook 脚本、验证输出、时间线全部落盘到 `CASE` 目录，写 WP 时直接引用。

## 三、实战一：`2.exe` —— 自动分析流水线完整走一遍

题目是一个 105 KB 的 PE 控制台程序，MinGW/GCC 4.9.2 编译，无壳，但核心校验藏在一个**自实现的字节码虚拟机**里。这道题走的是纯静态流水线。

### 3.1 拖入 → 识别 → 建案

拖入文件后，工具读魔数识别为 `PE`，算出 MD5/SHA256，随后建立 CASE 目录并记录时间线。这一步的产出是后面一切工作的"案卷"。

### 3.2 PE 五步流水线

点"分析文件"后，工具按固定顺序执行：

1. **DIE 查壳**——确认无壳，排除脱壳流程；
2. **启动 IDA 并自动连接 MCP**——端口轮询等待（最长 180s），而不是固定 2 秒就判失败，因为 IDA 冷启动 + 插件自启监听需要时间；
3. **反调试特征检测**；
4. **算法特征识别**——扫描 `0x9E3779B9`（TEA）、AES S盒、SM4 S盒等特征常量；
5. **生成解密脚本框架**。

### 3.3 AI Tool-Use：从"找到 main"到"还原 VM"

接下来是 AI 的 Tool-Use 循环（最多 25 轮）：AI 先读 `ctf-reverse-binary` 技能拿到方法论，然后用 `ida_decompile` 通过 MCP 拉伪代码。工具的 CASE 里留了它拉回来的真实反编译结果：

```c
// ==== main ====
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int dst_[117]; // [esp+18h] [ebp-1D4h] BYREF

  __main();
  qmemcpy(dst_, &src_, 0x1C8u);   // 456 字节 = 114 个 dword，正是字节码程序
  vm_operad(dst_, 114);           // 虚拟机入口，程序长度 114
  puts("good,The answer format is:flag {}");
  return 0;
}
```

`main` 干的事一目了然：把 `0x403040` 处 114 个 dword 拷到栈上，交给 `vm_operad` 解释执行。继续拉 `vm_operad` 的伪代码：

```c
int __cdecl vm_operad(int *dst, int n114)
{
  char Str[200];  // [ebp-E5h]：输入区 Str[0..99] + 输出区 Str[100..199] 共用一块内存
  char v4;        // 累加器 T
  int  v5, v6, v7, v8;
  int  pc = 0;

  while (1) {
    if (pc >= n114) return pc;
    switch (dst[pc]) {
      case 1:  Str[v6 + 100] = v4;            ++pc; ++v6; ++v8; break; // 输出区写入
      case 2:  v4 = dst[pc+1] + Str[v8];      pc += 2;          break; // ADD
      case 3:  v4 = Str[v8] - LOBYTE(dst[pc+1]); pc += 2;       break; // SUB
      case 4:  v4 = dst[pc+1] ^ Str[v8];      pc += 2;          break; // XOR
      case 5:  v4 = dst[pc+1] * Str[v8];      pc += 2;          break; // MUL
      case 6:  ++pc;                                            break; // NOP
      case 7:  if (Str[v7 + 100] != dst[pc+1]) {   // 逐字节比对
                 printf("what a shame..."); exit(0);
               }
               ++v7; pc += 2;                                    break;
      case 8:  Str[v5] = v4;                  ++pc; ++v5;       break; // ⚠ 写回输入区
      case 10: read(Str);                     ++pc;             break; // 读输入
      case 11: v4 = Str[v8] - 1;              ++pc;             break; // DEC
      case 12: v4 = Str[v8] + 1;              ++pc;             break; // INC
    }
  }
}
```

`read` 里藏着第一个约束：`scanf` 读入后 `strlen != 15` 直接 `WRONG!`——**flag 长度必为 15**。

两个坑在这里看得非常清楚：

- **`case 8` 写回的是输入区**。`Str` 是 200 字节的一块内存，`Str[0..99]` 放输入、`Str[100..199]` 放输出；`case 8` 的 `Str[v5] = v4` 从下标 0 开始写，会把还没读的原始输入覆盖掉，所以后面 `Str[v8]` 读到的可能已经不是原始字符。模拟时必须忠实复刻这一点，否则逐位爆破的结果是错的。
- **`v4` 是 `char`**。所有运算都要按 8 位（模 256）处理，`case 7` 的比较发生在有符号域（`0xA7` 以 `-89` 参与）。

### 3.4 求解与验证闭环

程序尾部 15 条 `[7, 目标值]` 就是全部校验点：

```text
[34, 63, 52, 50, 114, 51, 24, 167, 49, 241, 40, 132, 193, 30, 122]
```

由于每个输入字节只影响输出缓冲的同一下标，可以**逐位独立枚举**可打印字符。工具生成模拟脚本并运行：

```text
[+] 关键输入 = 757515121f3d478
[+] 复刻 VM 校验通过 = True => flag{757515121f3d478}
```

随后 AI 按契约输出 `[VERIFY]`（`algo: custom` + 一段 `decrypt(data, key)` 代码），工具在本地用 Python 复现这段代码、比对 `expected`，日志出现 `[HIT] ... flag=flag{757515121f3d478}`，flag 才被标记为已验证。

最后用二进制本身做终审：

```bat
> echo 757515121f3d478| 2.exe
string:good,The answer format is:flag {}

> echo 000000000000000| 2.exe
string:what a shame...
```

**flag = `flag{757515121f3d478}`**

完整脚本见附件 [solve_vm.py](/files/ctf-re-tool-intro/solve_vm.py)，题目样本 [2.exe](/files/ctf-re-tool-intro/2.exe)。

## 四、实战二：`app-release.apk` —— Frida Hook 全流程

第二道题（`com.nctf.hookmysecret`）是典型的**三阶段 Android 题**：手势图案 → native 校验 → AES 终验。这道题我主要靠"运行 Hook"解，所以把 Hook 链路完整拆开讲。

### 4.1 APK 七步自动分析

APK 的流水线比 PE 多几步，每步都有明确的失败处理：

```text
[1/7] DIE 查壳
[2/7] JEB 分析 Java 层
        ├─ 先探测 16161 端口：已在监听 = JEB+MCP 插件在跑 → 直接复用
        │   （避免重复启动第二个 JEB——第二个绑不上端口，同工程被占会卡死）
        └─ 未运行 → 启动 JEB，30 秒内轮询 MCP 握手
[3/7] 检查 Native SO
        ├─ 按内容查 ZIP 条目（顺便检测 Unity IL2CPP 的 global-metadata.dat）
        ├─ 提取 SO → IDA 打开 → MCP 等待就绪（180s）
        └─ 连上后立刻取数：枚举导出 → 定位 Java_* JNI 函数 → 反编译
[4/7] 检查模拟器状态（未连上会自动尝试拉起）
[5/7] 安装 APK 到模拟器
[6/7] 启动 frida-server（27042）
[7/7] 生成 Frida Hook 脚本 → 进入自动求解
```

### 4.2 静态定位：R8 混淆下按常量串反查

R8 把包名压成了单字母（`N0`、`C`、`K0`、`M0`），Activity 名倒是完整的，但**校验逻辑都在 OnClickListener 里**。这时候类名不可靠，常量串才可靠——工具用参数化的目录检索（纯 Node 实现，不走 PowerShell 拼接）直接搜：

```bat
findstr /S /I /M /C:"stage3_iv" /C:"stage2Key" smali\*.smali
```

三发命中：

| 命中 | 位置 | 角色 |
|---|---|---|
| `stage2Key` / `NativeBridge` | `N0/d.smali` | 校验回调本体 |
| `encryptStage2` + `int[]` 常量 | `K0/a.smali` + `libhookmysecret.so` | Stage2 native 校验 |
| `stage3_iv` + `SELECT v FROM app_cfg` | `M0/a.smali` | SQLiteOpenHelper，IV 藏在这 |

`N0/d.smali` 里能直接确认 Stage3 的算法与参数来源：

```smali
const-string v2, "AES/CBC/PKCS5Padding"        # 算法
invoke-static {v2}, Ljavax/crypto/Cipher;->getInstance(...)
const-string v12, "stage3_iv"                   # IV 来自 SQLite
const-string v9, "-"                            # key 先去分隔符
const-string v3, "jSaMnziall55Tdr+IZc7EKUNm/N4uwrZw1QFPw6DuirfYFJZg88j6GKLhWfNljAB"
```

### 4.3 native 反演：从 IDA 伪代码到 key

Stage2 的 `encryptStage2` 是 native 方法。工具自动提取 `libhookmysecret.so` 交给 IDA，反编译出的核心是一个逐字节滚动的状态机：

```c
v26 = __ROL1__(v25 ^ S ^ (13*i + 66), 3) + i + 7*S;   // S 初值 81
v44 = S + v25;
v45 = i ^ v26;
S    = v45 + v44;    // 状态滚动：每一步的 S 依赖上一步的真实输出
```

三个魔数 `0x51 / 0x0D / 0x42`（81、13、66）与式子一一对应。反演时**必须按"每步实际 v 值推进滚动状态"**，不能当独立字节算。工具写出正演 + 反演一对函数，用 `forward(inverse(TARGET)) == TARGET` 自检：

```python
def native_inverse(target):
    S = 81; key = bytearray()
    for i, t in enumerate(target):
        x = ror8((t - i - 7 * S) & 0xff, 3)
        b = (x ^ S ^ ((13 * i + 66) & 0xff)) & 0xff
        key.append(b)
        S = (S + b + (i ^ t)) & 0xff          # 状态滚动
    return bytes(key)
```

```text
[stage2] 反演出的 key = b'k7Xm2Pq9Wv4N8bRt'
自检 forward(inverse(TARGET)) == TARGET : True
```

### 4.4 Hook 脚本是怎么生成的

到这里静态已经能解了，但工具还是走了一遍动态——因为**多阶段题的静态推断需要运行时证据交叉确认**。Hook 脚本不是手写的，是 AI 按契约生成的，提示词里写死了几条硬规矩：

1. **降噪必须严格**：hook `String.equals` 时只打印"长度 ≥8 且命中 `flag|ctf|NCTF|key|secret|token` 或是 ≥20 位 hex/base64"的比较。只按长度过滤会漏——AndroidX、`res/*.xml`、绝对路径这些噪音长度都在 6 以上。
2. **绝不过早收尾**：只有确认命中校验数据（flag 形态字符串、加密函数实参/返回、SP 写入 key/密文）才 `send("[done]")`。工具用**滚动窗口**抓取：每来一条数据续 60s，连续 60s 无数据才结束（绝对上限 10 分钟），所以脚本里不许写固定超时。
3. **必须主动触发**：spawn 后如果不操作界面，App 停在首页，Stage2/3 的加密代码根本不会执行（见 4.5）。
4. **内部类写法**：`Java.use('android.app.SharedPreferencesImpl$EditorImpl')`——写成 `SharedPreferencesImpl.EditorImpl` 会拿到 `undefined`。

生成后工具先做**静态语法预检**（AI 生成的正则常含未转义的 `/`，会让 frida 报 `invalid regular expression flags` 整脚本不加载、白等 25 秒），自动修复或回退到内置模板；然后**前置注入"进程内解密"段**——既然 key/IV/密文已经反演出来了，就别让 Hook 只当 passive 旁听，直接在 App 进程里解出 flag 打印 `[FLAG]`。

```javascript
// 生成脚本的关键 hook 点（节选）
Java.perform(function () {
    // native 校验函数：看输入与返回的 int[]
    var NB = Java.use('com.nctf.hookmysecret.nativebridge.NativeBridge');
    NB.encryptStage2.overload('java.lang.String').implementation = function (s) {
        var r = this.encryptStage2(s);
        console.log('[HIT] encryptStage2("' + s + '") = ' + JSON.stringify(r));
        return r;
    };
    // AES 参数：key / IV / 明文一次拿全
    Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
        console.log('[Cipher] init key=' + bytesToHex(key.getEncoded()));
        return this.init(mode, key);
    };
    // 阶段状态机：stage1Passed / stage2Passed / stage2Key 写入点
    var Ed = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    Ed.putString.implementation = function (k, v) {
        console.log('[DATA] putString ' + k + ' = ' + v);
        return this.putString(k, v);
    };
    // SQLite：IV 常量的来源
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
        .implementation = function (sql, args) {
            console.log('[SQL] ' + sql + ' args=' + JSON.stringify(args));
            return this.rawQuery(sql, args);
        };
});
```

完整脚本见附件 [hook.js](/files/ctf-re-tool-intro/hook.js)。

### 4.5 最大坑：App 停在首页，校验代码永不执行

spawn 模式拉起后如果没人操作界面，App 停在手势页——Stage2/3 的加密根本不会跑，Hook 抓到的全是启动噪音。工具的对策是**Hook 与界面驱动并行**：

- **主动驱动**：每轮 `dump UI → 挑可点击节点 → 操作 → 再 dump` 逐屏推进（点开始 → 画手势 → 填输入 → 提交），输入值先用占位值触发分支；
- **滚动抓取**：Hook 窗口 5 秒等启动 + 30 秒驱动期间持续有数据就不断续期，不会因为操作慢被硬停；
- **抓取窗口必须长于驱动窗口**，否则校验真正发生时窗口已经关了。

### 4.6 Hook 抓到了什么

Frida 17.9.8 attach 到 `127.0.0.1:27042`，spawn `com.nctf.hookmysecret` 后的真实输出（节选 + 注解）：

```text
[HIT] NativeBridge.encryptStage2 hooked          ← native 校验函数已挂钩
[HIT] Cipher hooked                              ← AES 参数点已挂钩
[HIT] Arrays.equals(int[]) [] vs [] -> true      ← 手势校验在进行（int[] 比较节点序列）
[DATA] ARRAY MATCH [16842910,16843597,0,0]
[HIT] Arrays.equals(int[]) [16842910,16843597,0,0] vs [16842910,16843547,16843597,0,0] -> false
[HIT] Arrays.equals(int[]) [16842910,16843547,16843597,0,0] vs [16842909,16842910,16843547,16843597,0,0] -> false
[HIT] String.equals true: ".../databases/config.db" == ".../databases/config.db"
```

这几行信息量很大：`int[]` 数组在**逐个节点变长**——那是界面驱动在画手势、`Arrays.equals` 在拿节点序列做比对，证实了 Stage1 是图案校验；`config.db` 命中则坐实了"IV 藏在 SQLite"的静态推断。`[HIT]` 表示"校验/关键函数被调用"，`[DATA]` 表示"抓到含 key/密文/正确值的数据"——AI 拿到的是**已经按这两个前缀筛过的关键行**，而不是几万字符的原始噪音（直接 `slice(0,6000)` 会把真正的命中行截掉，这是实测踩过的坑）。

### 4.7 进程内解密直接出 flag

因为 key/IV/密文都已就位，注入的解密段直接在 App 进程里跑 `AES/CBC/PKCS5Padding`，打印：

```text
[FLAG]NCTF{a680107e-a49b-43e1-915b-cedd25e7835a}[/FLAG]
```

工具对 `[FLAG]` 的处理是**最硬证据通道**：正则收割 → `looksLikeFlag` 校验 → 直接 `recordFlag(verified=true)`，不等 AI 复述。Hook 输出随后回灌 AI 做最终结论，AI 再次给出同一 flag 与 `[VERIFY]` 契约，本地复现再次通过。

### 4.8 四路证据交叉验证

这道题最终在 `findings.json` 里的记录是：

```json
{ "flag": "NCTF{a680107e-a49b-43e1-915b-cedd25e7835a}",
  "verified": true,
  "source": "ai, verify-contract, ai-deep, frida-flag" }
```

四个独立来源指向同一个答案：AI 静态推理、验证契约本地复现、深度分析、Frida 进程内解密。**flag 不是"AI 说它对"，而是四条互相独立的证据链都收敛**。

完整脚本见附件 [solve_apk.py](/files/ctf-re-tool-intro/solve_apk.py)，题目样本 [app-release.apk](/files/ctf-re-tool-intro/app-release.apk)。

> **经验沉淀**：这道题的最优解其实是纯静态——反查常量串定位校验点（`N0/d`）+ native 反演 key + AES 解密，全程不需要模拟器。动态 Hook 的价值在于**证据交叉确认**与**触发真实流程**。工具把这类"踩坑 + 正解"自动写入经验库，下次遇到同类题自动注入提示词。

## 五、一些工程细节

工具本身也是按"安全工具"的标准写的：

- **渲染层加固**：`sandbox: true` + `contextIsolation`，渲染层只有 `contextBridge` 暴露的白名单 API；外链一律走系统浏览器。
- **IPC 参数化**：命令执行走 `run-tool-args`（argv 数组 + `shell:false`），杜绝命令注入；zip 条目枚举、目录内容检索改用纯 Node 实现，替掉了 PowerShell 字符串拼接。
- **路径边界**：文件写入限定在允许根（userData / 应用目录 / 临时目录 / 当前题目目录）之内；打包后 asar 只读，运行期产物统一落 `userData`。
- **CASE 与隐私**：每题证据独立成目录，`cases/`、`HANDOFF.md` 等含答案/本机信息的文件默认不入库。
- **成本控制**：脚本生成这类模式化任务走快速模型，重推理才走主力模型。

## 六、小结

`CTF-RE-TOOL` 不是要替代 IDA / Frida / JEB——真正的分析永远得靠它们。它解决的是**"把工具串起来"这件事的摩擦**，并且坚持两条原则：

1. **AI 的结论必须过本地验证**——`[VERIFY]` 契约复现不过就不算数；
2. **动态证据与静态推断互相交叉**——单一来源的 flag 不标 verified。

上面两道题，一道是纯静态的字节码虚拟机（自动分析流水线全程），一道要靠动态 Hook 定位、静态反演收尾（Hook 与界面驱动并行）——正好覆盖了逆向里最常见的两种节奏。

- 项目地址：<https://github.com/ip2867/ctf-re-tool>
- 下载试用：[Releases](https://github.com/ip2867/ctf-re-tool/releases)

> 适用范围：CTF 竞赛、授权渗透测试、自有系统的安全研究。请勿用于未授权目标。
