+++
date = '2026-10-20T14:50:00+08:00'
draft = false
title = 'CTF-RE-TOOL v1.8：让 AI 真的会用调试器'
tags = ['CTF', '逆向', '工具', '动态调试', 'IDA', 'AI', 'Electron']
categories = ['逆向']
+++

> 上一篇写这个工具时，我说核心是「AI 自主调用工具解题」。十多天过去，我发现这句话有个漏洞：
> **工具"能调用"和工具"能解题"之间，隔着几个必须靠实测才能发现的坑。**

v1.8.0 只做两件事：把动态调试真正打通，把知识库真正接进解题链路。

---

## 一、动态调试：从"看起来能用"到"实测能用"

之前工具已经能 `start` 调试器、能读寄存器、能读写内存。截图看着一切正常。

但真正要下断点单步时，全是失败：

```
dbg_step_over  → Failed to step over
dbg_run_to     → Failed to run to address
dbg_continue   → 停在 0x77b8123c（系统 DLL）
```

我一度以为是 IDA 9 的异步调试器限制，甚至怀疑过 ScyllaHide 插件冲突。都不是。

### 坑一：进程状态语义判反了

`idaapi.get_process_state()` 的返回值，我一直理解错了：

| 返回值 | 我原以为 | 实际含义 |
|---|---|---|
| `-1` | 无状态 / 未初始化 | **已暂停** |
| `1` | 已暂停 | **正在运行** |
| `0` | — | 无进程 |

于是所有判断都反了：程序明明已经停在入口，我却当成"无进程"；程序还在加载 DLL，
我却当成"可以单步"。表现就是 `Failed to step over`。

改对之后，同一个目标立刻正常：

```
start → EIP=0x4012d0  state=-1
step_over → 0x4012d1
step_into → 0x4012d3
```

### 坑二：`continue` 是异步投递

`dbg_continue` 返回的 IP，是**命令发出之前**的旧值。

```
continue → 返回 ip=0x4012d1
实际：进程还在跑，几秒后才命中或进入消息循环
```

拿这个旧 IP 去单步，当然失败。正确做法是轮询状态直到真正停下：

```js
while (Date.now() - t0 < timeout) {
  const st = await getProcessState();
  if (st === -1) return { stopped: true };  // 已暂停
  if (st === 2)  return { exited: true };
  await sleep(150);
}
```

这里有个反直觉的点：**GUI 程序 continue 后 STATE 会一直是 1**。
它不是"卡住了"，而是在消息循环里等用户输入。这时候不该报错，
该告诉 AI："进程在等输入，你可以 suspend 固定它，或者喂数据触发校验。"

### 坑三：空路径启动会静默失败

这个是"本地调试时好时坏"的真正原因，藏得最深。

`start_process("", ...)` 在路径为空时返回 **0（启动被取消）**，不是报错。

那为什么以前有时能跑起来？因为 IDA 的进程选项是**全局持久**的：
上一次调试的目标路径会残留。所以：

- 从没调试过 → 空路径 → 失败
- 刚调试过 PE → 残留 PE 路径 → 碰巧能启动
- 刚做过一次 Linux 远程调试 → 残留 `/tmp/probe_xxx` → 本地启动稳定失败

这个残留路径就躺在 `get_process_options()` 里：

```python
('/tmp/probe_1792474307521', '', '/tmp', '192.168.230.129', '200512', 23946)
```

只清 host/pass/port 是不够的，path 还在。现在本地启动会显式回落：

```python
_p = idaapi.get_input_file_path()   # 空路径时用当前加载的数据库文件
_rc = idaapi.start_process(_p, args, cwd)
```

### 远程调试：三处与本地不同

跑通远程（Kali 上 IDA 自带的 `dbgsrv/linux_server`，**不是 gdbserver**）之后，
发现本地经验会误导人：

| | 本地 win32 | 远程 linux |
|---|---|---|
| start 后 | 自动停在入口 | **不停**，直接跑，必须主动 suspend |
| 断点地址 | 静态地址即可 | PIE 必须用**重定位后**的地址 |
| 断点 API | 都行 | `dbg_add_bp` 恒返回 False，必须用 `idaapi.add_bpt` |

那个 `dbg_add_bp` 恒 False 的问题，服务端日志里其实是成功的：

```
add_bpt(ea=555555555174 type=4 len=0) => BPT_OK
```

只是插件走的是 `ida_idd` 那条路，返回值对远程段不适用。

### 实测结果

**本地 PE（32 位 WOW64）：10/10**

```
start → state=-1, EIP=0x4012d0
step_over → 0x4012d0 → 0x4012d1
run_to 0x4012d3 → 命中
continue → 正确识别 still-running（GUI 等输入）
suspend → state=-1
写内存 → 读回 4142434445464748494a4b4c4d4e4f50
```

**远程 ELF（Kali linux_server，PIE + 符号）：11/11**

```
load_debugger("linux", True) → RC 1
自动 suspend → state=-1
重定位符号：IMAGEBASE 0x555555554000，main 0x555555555174
idaapi.add_bpt → BPT_OK
continue → 命中 main（RIP=0x555555555174）
step_over → 0x555555555175
continue → 命中 check（RIP=0x555555555159）
读内存 / 写内存读回
```

---

## 二、知识库：从"写了"到"用得上"

上一篇我说内置了 50 条可检索知识库。这次审计时发现一个尴尬的事实：

**方法论页写完了，但自动预取根本拉不到它。**

我用真实题面特征测了一遍，5 个场景全部落榜：

| 场景 | 实际检索词 | 结果 |
|---|---|---|
| SMC 自修改 | `xor 自解码 virtualprotect native` | 未命中 |
| 反调试 | `isdebuggerpresent native` | 未命中 |
| GUI CrackMe | `dialogbox winmain native` | 未命中 |
| 时间校验 | `tickcount getsystemtime native` | 未命中 |

原因有三层，每一层单独都足以让知识失效：

1. **特征词表里没有动态调试信号**。题面一出现 SMC/反调试/GUI，选词就退化成 `native`，
   而 `native-key-inversion.md` 每篇命中 22 次，稳定霸榜，方法论一律被挤出前 4。
2. **提示词的知识库清单只列非 `reverse/` 页面**。7 篇方法论全在 `reverse/` 下，
   AI 只看到"另有 40+ 篇题库"，不会想到里面还有方法论。
3. **技能描述没提动态调试**。AI 选技能只看 description，没提就不会加载。

修复后实测：

```
SMC 自修改      → 方法论页第 1 位（89 分）
反调试          → 第 1 位（83）
GUI CrackMe     → 第 1 位（92）
时间相关校验    → 第 1 位（67）
ELF ptrace      → 第 1 位
普通算法题 RC4  → 不命中（正确，避免污染提示词）
```

---

## 三、动态调试的正确姿势

修完这些坑之后，我给工具写了一条硬性纪律：

> **动态调试是取证手段，不是探索手段。**
> 它只回答"这个值运行时是多少"，不回答"这段代码在干什么"——后者反编译更便宜、更可复现。

四条入场条件全满足，才允许启动调试器：

1. 有函数清单
2. 候选函数说得清职责（读输入 / 做变换 / 比对 / 解壳）
3. **写得出调试假设**：断点地址 + 命中后读哪个表达式 + 期望值 + 判定方式
4. 有办法把流程逼到那里

**写不出第 3 条 = 静态还没读够，回反编译。**

配套的经验：

**断点选址优先级**

| 优先级 | 位置 | 理由 |
|---|---|---|
| 高 | 变换函数入口/出口 | 各断一次即得"输入原值→输出值"整段映射 |
| 高 | `memcmp`/`strcmp` 调用点 | 直接看到"期望 vs 实际" |
| 中 | 解密循环内部 | 只在需要轮密钥/中间态时 |
| 避免 | 消息循环 / sleep / CRT 初始化 | 断在这里等于没断 |

**窗口期**：断点"设了却不命中"的首要原因不是断点错，而是目标早就跑过去了。
三种应对：入口先下断再 continue、选有 sleep 或等输入的目标、start 后立刻 suspend。

**一次命中的取数清单**：寄存器 + 函数参数（按调用约定）+ 关键内存 + 调用栈。
不要在同一个断点上来回单步几十次——单条指令的语义反编译已经给了。

**离线复算**：运行时值必须用自己的脚本复算并逐字节比对。
不一致时按"断点位置 → 栈帧偏移 → 字节序/宽度 → 调用约定"排查。

---

## 四、其它新增

- **离线加解密**：AES / SM4 / DES / 3DES / RC4 / TEA 系 / 哈希 / HMAC，数据不出本机。
  标准向量自测 35/35（NIST AES、GB/T SM4、RFC 4231 HMAC）。
- **变换链**：CyberChef 式，一次调用跑完 base64→xor→反转→解压，每层给 printable/entropy/hex。
- **GUI 输入闭环**：标准控件喂输入 + 回读校验，返回 `sent-verified` / `unverified` 而不是"应该成功了"。
- **Kali 远程执行**：SSH 透传退出码，失败按 TIMEOUT / AUTH / REFUSED / UNCONFIGURED 分类。

---

## 五、下载

[v1.8.0 Release](https://github.com/ip2867/ctf-re-tool/releases/tag/v1.8.0)

`CTF-RE-TOOL.exe`，74.11 MB，便携单文件，双击即用，无需安装 / 无需 Node.js。

```
SHA256 = 0b81078183312a1e8acb31ab1c4f784ad430284c7423ed64b8d3d29ed32ee167
```

首次运行请在「设置」页填写 IDA / JEB / jadx 等外部工具路径——本工具是调度框架，不含这些工具。

---

## 六、一点感想

这次最深的体会不是"修了几个 bug"，而是：

**能力写进文档 ≠ 能力可用，能力可用 ≠ AI 会去用。**

动态调试的坑，全部是在真实下断点时才暴露的；知识库的坑，是模拟真实题面特征做检索时才暴露的。
只跑单元测试、只看截图，这两个问题都发现不了。

所以 v1.8 的验收标准是：本地 10/10、远程 11/11、5 类题面特征检索命中、普通题不误命中。
全部可复现，脚本留在 `tests/manual_dbg_*.js` 和 `tests/test_knowledge_reachability.js` 里。

---

> 适用范围：CTF 竞赛、授权渗透测试、自有系统的安全研究。请勿用于未授权目标。
