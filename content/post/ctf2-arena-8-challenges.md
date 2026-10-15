+++
date = '2026-10-16T10:30:00+08:00'
draft = false
title = 'AI 自动解题实录：CTF-RE-TOOL 在 CTF² 平台 8 连破（附完整 WP 与工具进化史）'
tags = ['CTF', '逆向', 'AI', 'Writeup', '自动化', 'IDA', '验证闭环']
categories = ['逆向']
+++

> 把 CTF-RE-TOOL 接入 CTF² Agent Arena 真实解题：**8 道逆向题全部解出并提交通过**——从 Hard 的 Excel 神经网络校验器到 15 秒全自动拿分的 satellite 题。本文是完整 Writeup + 期间暴露并修复的 9 个工具缺陷 + 方法论沉淀。工具在实战里进化，而不是在想象里设计。
>
> 项目地址：<https://github.com/ip2867/ctf-re-tool>　·　[工具介绍](/post/ctf-re-tool-intro/)　·　下载：[Releases](https://github.com/ip2867/ctf-re-tool/releases)

---

## 零、TL;DR：两天战绩

| # | 题目 | 难度 | 载体 | 核心考点 | AI 求解耗时* | 提交方式 |
|---|------|------|------|---------|---------|---------|
| 1 | time-travel | Hard | ELF | 定点数 Laplace 行列式递归 | 457s | 工具解出，人工提交 |
| 2 | not-baby-parallelism | Hard | ELF | Blelloch 并行前缀扫描反演 | 4 轮（跨日） | 工具解出，人工提交 |
| 3 | parallelism | Medium | ELF(MPI) | 三级置换网络静态反演 | 22s | 工具解出，人工提交 |
| 4 | ExceLLM | Hard | XLSX | Excel 公式神经网络校验器 | 63s | 工具解出，人工提交 |
| 5 | RomanRomance | Easy | TXT | Caesar +1 移位 | 48s | 工具解出，人工提交 |
| 6 | PalatinePack | Medium | ELF+BIN | 三层 nibble 展开 + flipBits | 321s | 工具解出，人工提交 |
| 7 | missioncritical1 | Easy | ELF | sprintf 拼接 + strcmp | **5.8s** | **全自动提交 +100** |
| 8 | PlutoChat | Medium | ELF+PCAP | LCG 密钥派生 + RC4 | 152s | 工具解出，人工提交 |

\* AI 分析阶段时长（CASE 目录 timeline 口径，不含下载与 IDA 冷启动）。

最有价值的趋势是最后一行数据的变化：**人工干预从第 1 题的全程辅助，收敛到第 7 题的零干预全自动**——下载、IDA 分析、AI 求解、本地验证、平台提交、进程清理，15 秒一条龙。期间工具暴露了 9 个真实缺陷，全部当日修复并回归验证（见第十章）。这些缺陷没有一个是靠"想"出来的：xlsx 解压器不认 xlsx、验证脚本不认单参函数、RC4 明文被协议头坑掉——全部是真实数据砸出来的。

---

## 一、time-travel — 定点数 Laplace 行列式

**附件**：`time_travel`（ELF x64）+ `input.bin`

### 静态侦察

main 的反编译只有 11 行，逻辑一目了然：

```c
input = read_input(argv[1]);
for (n63 = 0; n63 <= 63; ++n63) {              // 64 个矩阵
    v7 = sub_1423(*input);                      // 分配 N×N 指针数组
    for (i = 0; i < *input; ++i)
        memcpy(*(void **)(8LL*i + v7), &input[650*n63 + 1 + 36*i], 0x90u);
    v8 = sub_1638(v7, *input);                  // ← 核心函数
    putchar((char)(*(_QWORD *)&input[650*n63 + 649] - v8) + n63);
}
```

三个关键观察：

1. **输入布局**：每矩阵 650 个 dword = 1（N）+ 36×18（矩阵数据）+ 1（目标值）；`0x90` 字节/行 = 18 个 qword → N=18，**元素按 64 位定点数处理**
2. **输出公式**：`putchar(target_qword - det(矩阵) + n63)` —— 明文字符 = 目标值 − 行列式 + 索引
3. `sub_1638` 是核心行列式函数

### 算法分析

`sub_1638` 是教科书级的 **Laplace 余子式递归**：对每列删行删列（`sub_1570` 构造子矩阵）→ 递归求 det → 符号交替；递归基 1×1 返回唯一元素；所有元素按 qword 定点数参与乘加。

### 反演与验证

flag 第 n 字符满足 `flag[n] = (target_n - det_n + n) & 0xff`。AI 写 Python 按同样布局解析 64 个矩阵（每矩阵取前 18×18 个 qword + 末尾目标 qword），逐个求行列式后按公式拼出 64 字节明文。正向复算 `target_qword == flag[n] + det_n - n`，64 个矩阵全部对上，无歧义。

```text
dice{d3t4rm1n1NanT5_c4n_b3_F4sT_1a7sN2j1867327mA6jmapc817jgd6m0}
```

> **工具视角**：这道题是"开局人工辅助"的典型——工具流水线当时还没有把伴生 `input.bin` 自动喂给 AI 的完整链路，矩阵布局的判定靠人工搭了第一把手。这个缺口正是后来 §修复 #7（伴生文件全量登记）的诱因之一。

---

## 二、not-baby-parallelism — Blelloch 并行前缀扫描

**附件**：`pppp`（ELF x64，C++ 多线程）+ `flag.out`（51 个整数）

这道题跨了 4 轮，是**成长闭环最完整的案例**：前 3 轮失败的方向被逐条存档，第 4 轮 AI 带着完整的"已排除路"清单一次解出。

### 前几轮为什么失败（工具存档的真实记录）

| 轮次 | 误判 | 实际 |
|------|------|------|
| 1 | `flag.out` 首值 100 被当成"元素个数" | 100 是 ASCII `'d'`，是**数据本身** |
| 2 | worker 被当成朴素并行 `out[i] = op(data[i-1])` | 是 **Blelloch work-efficient scan**（up-sweep + down-sweep 两阶段树形扫描） |
| 3 | 预算烧在复现 glibc rand() 上 | 洗牌结果对任意种子恒为 `['xor','add','mul']`，**根本不用复现 rand** |

### 静态侦察（最终轮）

main 骨架：getopt 解析 `-n`(线程数)/`-i`(输入)/`-o`(输出) → 读 N 个整数 → `srand(threads ^ N)` 洗牌 3 个算子 → 计时调用核心扫描 → 写出结果。三个算子反编译直接可读：`sub_330A = a+b`、`sub_3323 = a*b`、`sub_333A = a^b`。

核心函数藏在 **C++ lambda 深链**里：`off_7D10`（vtable）→ 槽位 0x4a18（invoke）→ sub_4A18/4A44 → 4A64 → 4A80 → 4ADB → 4B18 → **sub_336C**。顺着 vtable 槽位一路追才找到真身——这也是前几轮放弃的原因之一。

### 核心算法（sub_336C）

```text
每层 stride i（1,2,4,...）：算子 = table[round(log2(i)) % 3] = ['xor','add','mul'] 交替
up-sweep:   for k: u = 2*i*k - 1;  if (i+u < n) a[i+u] = op(a[u], a[i+u])
down-sweep: for k: u = 2*i*k - 1;  a[u] = op(a[u-i], a[u])
```

标准 **Blelloch work-efficient prefix scan**：up-sweep 归约建树，down-sweep 下扫求前缀。

### 反演

`flag.out` 的 51 个值就是扫描输出。反演 = **逆 down-sweep（按 up 层级顺序）→ 逆 up-sweep（按 down 层级顺序）**，每步用伙伴元素反解：`add` 逆 = 减、`xor` 逆 = 再异或、`mul` 逆 = 整除（需除数非零检查）。线程数未知 → 暴力 1..64，配合"结果全可打印 ASCII"约束锁定唯一明文。

AI 交出的 [VERIFY] 契约用 Python 实现了精确逆过程：

```python
tbl = ['xor','add','mul']
lv  = lambda i: int(round(math.log2(i))) % 3
def decrypt(out):
    a = out[:]; n = len(a)
    for i in levels_up(n):                 # 逆 down-sweep
        invf = inv[tbl[lv(i)]]; k = 1
        while 2*i*k-1 < n:
            u = 2*i*k-1
            if i+u < n: a[i+u] = invf(a[i+u], a[u])
            k += 1
    for i in reversed(levels_up(n)):       # 逆 up-sweep
        invf = inv[tbl[lv(i)]]; k = 1
        while 2*i*k-1 < n:
            u = 2*i*k-1; a[u] = invf(a[u], a[u-i]); k += 1
    return bytes(a)
```

正向回验：反演结果重跑 Blelloch 扫描，51 个输出逐一复现 `flag.out` ✓。

```text
dice{p4r411el_pref1x_sc4ns_w0rk_efficient_but_sl0w}
```

> **工具视角**：失败档案机制在这里兑现了设计初衷——每轮失败的"方向结论"注入下一轮提示词，AI 不再重复烧预算在已排除的路上。这 4 轮的失败记录后来沉淀成知识库的[运行型反演方法论](https://github.com/ip2867/ctf-re-tool/blob/main/wiki/reverse/method_runtime_challenges.md)。

---

## 三、parallelism — MPI 三级置换网络

**附件**：`parallelism`（ELF x64，链接 libmpi）。题面直接给出用法：`mpirun --oversubscribe -np 8 ./parallelism`。

### 静态侦察

main（1118 字符）非常短：`MPI_Comm_size==8` 后串联三个校验函数，全过则 rank 0 打印 `Correct!`。

| 阶段 | 函数 | 逻辑 |
|------|------|------|
| Stage 1 | `sub_1369` | 输入 64 字符；常量表 `v4[32]` 做 32 次 `s[n] ↔ s[v4[n]+31]` 交换（固定置换） |
| Stage 2 | `sub_1625` | 10000 轮环形搬运：rank R 从 `(R+n)%8` 号进程取 slot `n%8` 写入本地 slot `n%8` —— 全局确定性置换 P |
| Stage 3 | `sub_179C` | `MPI_Gather` 汇总后 `memcmp` 目标常量 `m_ERpmfrNkekU4_...` |

### 反演（不模拟真实 MPI）

关键洞察：Stage 2 虽然跑了 10000 轮跨进程通信，但**它是确定性置换**——用"单位标签"（0..63 依次编号）跑一遍同样的轮次逻辑即可得到 `perm_out`，无需真的起 8 个进程：

```python
def sim(data):                      # 用标签数组模拟 10000 轮
    rb = [list(data[i*8:(i+1)*8]) for i in range(8)]
    for n in range(10000):
        new = [None]*8
        for R in range(8): new[R] = rb[(R+n)%8][n%8]
        for R in range(8): rb[R][n%8] = new[R]
    return [c for r in rb for c in r]

perm_out = sim(list(range(64)))     # 置换表
def inv_stage2(out):
    res = [None]*64
    for k in range(64): res[perm_out[k]] = out[k]
    return res

def inv_stage1(s):                  # 逆 Stage 1：反向重做同一交换
    for n in range(31, -1, -1):
        idx = v4[n]+31; s[n], s[idx] = s[idx], s[n]
    return s

flag = inv_stage1(inv_stage2(list(target)))
```

正向 `encrypt(flag) == target` 逐字符 64/64 匹配，字节级复算 mismatch = 0。

### 一个值得记录的工具缺陷

AI 的正向复现已完全匹配，但 [VERIFY] 契约里 `decrypt(target)` 是**单参**函数、`expected` 只写了 flag 前 54 字符——工具按双参调用 + 全等比对判「无命中」，拒绝自动提交。这就是后文 §修复 #2/#3 的直接来源（修复后回归同一契约直接命中）。

```text
dice{P4ral1isM_m4kEs_eV3ryt4InG_sUp3r_f4ST_aND_s3CuRE_a17m4k9l4}
```

---

## 四、ExceLLM — 用 Excel 公式搭的神经网络

**附件**：`ExceLLM.xlsx`（27.8 KB，4 个 sheet：LLM / BITS / WEIGHTS / VERIFY，后三个隐藏）

### 解压与定位

xlsx 本质是 OOXML zip。解压后按"公式数"定位主战场：

| 文件 | 内容 | 判定 |
|------|------|------|
| `xl/workbook.xml` | sheet 清单：LLM(可见)、BITS/WEIGHTS/VERIFY(hidden) | 结构 |
| `sheet1.xml` | 2.5KB，只有 `IF(VERIFY!Z1=1,"Correct","Incorrect")` | 展示壳（1 个公式） |
| `sheet2.xml` | 58KB，216 个公式 | BITS（位展开） |
| `sheet3.xml` | 164KB，纯常量 | WEIGHTS |
| `sheet4.xml` | 57KB，**244 个公式** | VERIFY（校验器）← 主文件 |

### 把 Excel 当反汇编读

BITS 表把每个输入字符按 ASCII 展开 8 位（MSB first）：`MOD(QUOTIENT(CODE(MID(LLM!B2, pos, 1)), 2^k), 2)`。VERIFY 表是三层网络：

```text
C{row} = MAX(0, (SUMPRODUCT(BITS!B{8位区间}, WEIGHTS!列k) + WEIGHTS!A{bias}) / 100)
H{row} = --( (SUMPRODUCT(C{8行组}, W2) + b2) / 100 > 0 )
Z1     = --( SUM(H10, H30, ..., H530) = 27 )
```

对照机器学习语义：`SUMPRODUCT` = 全连接层矩阵乘，`MAX(0,·)` = **ReLU**，`--(·>0)` = **阶跃激活**，`Z1` = 要求 27 组输出神经元全部为 1。

### 反演（逐字符独立枚举）

关键结构：每组校验**只依赖该位置字符的 8 位**，组间无耦合 → 每位暴力枚举 32..126 的可打印 ASCII，H(该组)=1 的唯一字符即答案。27 次独立枚举，无需全局搜索。

AI 在此踩了一个关键坑并自我修正：**WEIGHTS 表是列主序 + 每组固定 stride=26 行**（W1 8 行 + bias 8 行 + W2 8 行 + H-bias 1 行）。最初误用 stride=20 时每个位置的候选集爆炸（0~95 个解）；改从 VERIFY 公式里的行号锚点（C10→A2:A9/A10，C30→A28:A35/A36，差 26）反推后，**每组恰好剩唯一解**——解集是否唯一本身就是 stride 正确性的判据。

### 验证

拼出 27 字符 flag 后前向复算：27 个 H 全为 1，`SUM=27`，与 `VERIFY!Z1=1` 一致。

```text
sun{n0t_qu1t3_ch4t_GPT_l0l}
```

> **工具视角**：这题的工具进化密度最高——xlsx 被解压器拒收（§#4）、主文件选错到元数据（§#5）、XML 误进固件流程白烧 60 秒（§#6）、最后 AI 自己 read_file 伴生 sheet 完成全部分析。一轮 Hard 题砸出了三个修复。

---

## 五、RomanRomance — Caesar 移位

**附件**：`enc.txt`（34 B）+ `romanromance`（ELF）。题面 "When in Rome..."（暗示 Caesar），并注明非标准前缀 `sunshine{...}`。

密文 34 字符：`tvotijof|lO1x`z1v5`s1nAo`iJ6u1sZ~`

单字节移位全扫（±1..32）+ flag 前缀匹配，**+1 移位**命中：`tvotijof` +1 = `sunshine`，整段可读，无歧义。

```text
sunshine{kN0w_y0u4_r0m@n_hI5t0rY}
```

> **工具视角**：这题暴露了整场实战**最隐蔽**的缺陷——共享下载目录让 AI 把**上一题 ExceLLM 的 sheet 和 flag** 当成本题结论（§#7）。修复后每题附件进独立子目录 + 提示词加"题目边界"声明，此类串扰再未复发。

---

## 六、PalatinePack — 三层 nibble 展开 + flipBits

**附件**：`palatinepack.zip` → `palatinepack`（ELF）+ `flag.txt`（296 B 密文）

### 静态侦察与方向判定

```c
stream = fopen("palatinepackflag.txt", "r");   // ← 读"密码"（真 flag 是输入！）
n = ftell(stream) + 1;                          // = 37
fgets(s_, n, stream);
flipBits(s, n);                                 // 自逆变换
s_1  = expand(s,  n);                           // n  → 2n
s_2  = expand(s_1, 2*n);                        // 2n → 4n
ptr  = expand(s_2, 4*n);                        // 4n → 8n（37→74→148→296）
anti_debug();
fwrite(ptr, 1, 8*n, fopen("flag.txt", "wb"));   // 写出 296B 密文
```

题目给的是程序**输出**，真 flag 是程序**输入**——必须逆变换。

### 变换语义

- `flipBits`（0x1565）：交替「偶索引逐字节取反 / 奇索引异或流 `n105 += 32`（初值 105）」，**自逆**
- `expand`（0x16b9）：每字节拆 2 字节，nibble 按 `v4` 交替摆放，伴随状态 `n105 = n105*11 mod 256`，初值 105
- 干扰项：`doWeedStuff` / `rotate_block_left` / `SBOX`（AES S 盒）在 main 里**无 xrefs**，纯干扰——先查 xrefs 再决定要不要逆
- 关键坑：`teehee` 函数用 `mprotect` 试图把 expand 里的立即数 `0x69`（105）打补丁成 `0x01`——**但正向复现证明运行态仍是 105**。反推结果用 {105, 1} 两值分别回验，只有 105 能 100% 复现 flag.txt 全部 296 字节

### 反演与验证

逆 `expand` 三次（读 nibble 重组）→ 逆 `flipBits`（自逆，再做一遍）→ 得 `sunshine{...}\0`。正向回验：三层变换对 flag 正向展开，输出与 flag.txt **296 字节逐字节一致**。

```text
sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}
```

---

## 七、missioncritical1 — 全自动闭环示范（15 秒从下载到提交）

**附件**：`chall`（ELF x64，14.1 KB）

main 只有 15 行，校验逻辑直接写在 `sprintf` 里：

```c
sprintf(s_, "sun{%s_%s_%s}\n", "e4sy", "s4t3ll1t3", "3131");
printf("Enter satellite command: ");
fgets(s, 50, stdin);
if (!strcmp(s, s_)) puts("Access Granted!");
else                puts("Access Denied!");
```

三个片段直接来自字符串表（`a3131`、`aS4t3ll1t3`、`aE4sy`），AI 一轮分析即拼出完整 flag。

### 闭环时间线

```text
17:38:33  平台拉题 → 下载 chall → 识别 ELF
17:38:34  IDA 启动 → 17:38:40 MCP 连接（6 秒冷启动）
17:38:41  阶段1 采集（函数列表/字符串/反编译/全局表）
17:38:47  AI 5.8 秒出结论 + [VERIFY] 契约
17:38:47  本地复现 [HIT] → flag 标记已验证 → 自动沉淀经验入库
17:38:47  自动提交平台 → {"accepted":true, "earned_points":100}
17:38:49  题后清理 IDA/java 进程
```

**从拉题到平台判对共 15 秒，全程零人工干预。** 验证闭环（[VERIFY] 契约本地复现）在此题一次通过，"flag 未验证不提交"的防线也完整走通。

```text
sun{e4sy_s4t3ll1t3_3131}
```

---

## 八、PlutoChat — LCG 密钥派生 + RC4 聊天记录

**附件**：`plutochat`（ELF）+ evidence.pcap（聊天流量）

### 静态侦察

main 是个 TCP 客户端（`socket` + `connect 127.0.0.1:31337`），但真 flag 不在本地校验里——在**加密的聊天记录**里。AI 从二进制抽出完整密码学链路：

| 函数 | 语义 |
|------|------|
| `sub_1389` + `sub_1452` + `sub_12E5` + `sub_1285` | 标准 **RC4**（KSA / swap / PRGA） |
| `sub_1510` | 80 字节 RC4 key 派生：seed 经 `ROL32(x, x&0xf)` 递推填 20 个 int → `byte_4100` 置换表 → `byte_4120` 表 XOR 传播链 |
| 包格式 | `[4B seed][4B len][RC4 密文]` |

### 关键坑：未初始化的 v9

`sub_1510` 的 XOR 传播链用**未初始化的栈变量 v9** 作初值（`rbp-1`）——反编译默认值不可信。AI 用**已知明文攻击**锁定：登录成功消息首字节类型 = 1，爆破 v9 初值，`v9_0 = 0` 时 RC4 首字节恰好解出 `1`，唯一命中。

### 解密与取证

用 `gen_key(seed) + RC4` 解开 pcap 里全部消息，聊天记录完全可读：用户 `topsecretengineer`（密码 `PlutoMars23!`）与 `givemethemoney`（密码 `Sellurdata12!`）对话，后者询问敏感 key，前者回复：

```text
Of course! It's: sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}
```

> **工具视角**：解密明文带 `\x03\x11` 协议头（`[类型][len 用户名]` 封装），`printable()` 整段判"不可打印"回退成 hex，flag 被埋进 hex 里导致验证闭环无命中——修复"剥首尾控制字符"（§#8）后重跑同一契约直接 `[HIT]`。

---

## 九、方法论沉淀（已入工具知识库，自动检索复用）

以下条目已写入 CTF-RE-TOOL 的可检索知识库（`wiki/reverse/method_*.md`，含 attack_chain 与 failed_attempts），下次同类题工具会**在分析前自动把攻略内联进 AI 提示词**：

- **并行扫描/置换网络**：Blelloch up/down-sweep 精确逆序（错一层全盘错）；MPI 环形搬运 = 确定性置换，用单位标签模拟求逆，别模拟真实运行时
- **Excel 公式逆向**：`SUMPRODUCT`=矩阵乘、`MAX(0,.)`=ReLU、`--(...)`=布尔；先读 `workbook.xml.rels` 搞清 sheet 映射；权重表 stride 从公式行号锚点反推（解集唯一 = stride 正确的判据）
- **方向判定**：输入→变换→输出型（读 x 写 y）的题，**flag 往往是输入不是输出**，拿到密文先判方向
- **自改代码不可信**：`mprotect` 打补丁的立即数反编译不可信，对候选常量（105/1）逐一正向回验择真
- **短密文分诊**：先单字节 XOR/移位全扫 + flag 前缀匹配（含非标准前缀 sunshine/sun/dice），30 秒内出结果再考虑复杂算法
- **RC4 密钥流题**：先找 LCG/置换/XOR 链常量表定 seed 关系；key 派生读未初始化变量时用已知明文爆破初值
- **干扰项识别**：无 xrefs 的花函数（AES S 盒等）= 纯干扰，先查 xrefs 再决定要不要逆

## 十、实战暴露的 9 个工具缺陷与修复

全部当日修复并回归验证（custom 契约命中率 0/3 → 3/3）：

| # | 缺陷 | 根因 → 修复 |
|---|------|------------|
| 1 | 下载器目录碰撞（EISDIR 整轮中止） | 附件与同名目录冲突 → 写入前 statSync 检查，自动改名重试 |
| 2 | 验证契约只试双参调用 | AI 常写单参 `decrypt(target)` → 按 `inspect.signature` 自动尝试五种调用形态 |
| 3 | expected 截断全等必败 | AI 只给 flag 前缀 → 命中判定改双向包含，优先取 FLAG_RE 完整匹配 |
| 4 | xlsx 被拒解压 | 白名单只有 .zip → 扩到 OOXML 全家 + PK 魔数兜底 |
| 5 | OOXML 主文件挑错（元数据/展示壳） | 无语义打分 → docProps 沉底 + 公式数主导因子 |
| 6 | XML/TXT 误进 Kali 固件流程（白烧 60s） | 类型不识别 → 新增 XML/TXT 两类 + `analyzeXMLText()` 直读求解 |
| 7 | **跨题文件串扰**（AI 拿上题结论答本题） | 共享下载目录 + workdir=根目录 → 每题独立子目录 + 多附件主文件权重 + 提示词题目边界 |
| 8 | `printable()` 控制字符吞 flag | 协议头 `\x03\x11` 致整段回退 hex → 剥首尾控制符再判可打印 |
| 9 | 经验跨题注入（预防性） | 上题经验进下题提示词 → 由 #7 的边界声明兜住：经验只作方法参考 |

修复过程遵循一个原则：**每个缺陷都来自真实解题数据，修完必须用当时的真实契约回归**。比如 #2/#3/#8 修复后，用 parallelism、PlutoChat 的原契约重跑全部 `[HIT]`。

## 结语

这轮实战最说明问题的不是 8/8 的战绩，而是两个收敛：

1. **人工干预收敛**：第 1 题人工辅助反汇编 → 第 7 题 15 秒全自动拿分。工具在真实数据里暴露缺陷、当场修复、立刻在下一题受益。
2. **知识沉淀收敛**：4 轮失败换来的 Blelloch 反演经验没有停留在聊天记录里——它进了知识库，被检索、被注入、被下一次解题直接复用。

AI 解题的天花板不在于模型多聪明，而在于**喂给它的数据链路有多完整、验证闭环有多严格、失败能不能变成资产**。

> 工具开源：<https://github.com/ip2867/ctf-re-tool>　·　本文涉及的方法论页面在仓库 `wiki/reverse/` 目录
