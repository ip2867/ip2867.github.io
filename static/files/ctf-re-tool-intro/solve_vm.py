#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2.exe 题解 —— 字节码虚拟机逆向
------------------------------------------------
2.exe 是一个 32 位 PE 控制台程序（MinGW/GCC）：读入 15 个字符，
把一段 114 个 dword 的"字节码"交给内置解释器逐条执行，最后逐字节比对。
本脚本用纯 Python 复刻该解释器，并按字节独立求解出正确输入。

用法:  python solve_vm.py
"""
import struct

# ---------- 从 2.exe 中提取的两段数据 ----------
# 0x403040 处 114 个 dword 的字节码程序
CODE = [
    10, 4, 16, 8, 3, 5, 1, 4, 32, 8, 5, 3, 1, 3, 2, 8, 11, 1, 12, 8,
    4, 4, 1, 5, 3, 8, 3, 33, 1, 11, 8, 11, 1, 4, 9, 8, 3, 32, 1, 2,
    81, 8, 4, 36, 1, 12, 8, 11, 1, 5, 2, 8, 2, 37, 1, 2, 54, 8, 4, 65,
    1, 2, 32, 8, 5, 1, 1, 5, 3, 8, 2, 37, 1, 4, 9, 8, 3, 32, 1, 2,
    65, 8, 12, 1, 7, 34, 7, 63, 7, 52, 7, 50, 7, 114, 7, 51, 7, 24,
    7, -89, 7, 49, 7, -15, 7, 40, 7, -124, 7, -63, 7, 30, 7, 122,
]

# 最后 15 个 op7(CMP) 的期望值（模 256）
TARGET = [c & 0xff for c in CODE[-29::2]]


def emulate(code, inp):
    """忠实复刻 0x401553 处的 VM 解释器。inp 为 15 字节输入，返回 15 字节输出缓冲。"""
    R = bytearray(32)          # e5：输入/工作缓冲
    B = bytearray(32)          # buf81：输出缓冲
    R[:len(inp)] = inp
    pc = rIdx = cB = wB = wR = 0   # 指令指针 / 读输入索引 / 比对索引 / 写输出索引
    T = 0                      # 累加器（char，模 256）
    while pc < len(code):
        op = code[pc]
        if op == 10:                      # READ：触发输入
            pc += 1
        elif op == 1:                     # STORE_R：B[wB++]=T
            B[wB] = T & 0xff; wB += 1; rIdx += 1; pc += 1
        elif op == 2:                     # T = R[rIdx] + imm
            T = (R[rIdx] + code[pc + 1]) & 0xff; pc += 2
        elif op == 3:                     # T = R[rIdx] - imm
            T = (R[rIdx] - code[pc + 1]) & 0xff; pc += 2
        elif op == 4:                     # T = R[rIdx] ^ imm
            T = (R[rIdx] ^ (code[pc + 1] & 0xff)) & 0xff; pc += 2
        elif op == 5:                     # T = R[rIdx] * imm
            T = (R[rIdx] * code[pc + 1]) & 0xff; pc += 2
        elif op == 6:                     # NOP
            pc += 1
        elif op == 7:                     # CMP：逐字节比对，失败即 WRONG
            if B[cB] != (code[pc + 1] & 0xff):
                return B, False
            cB += 1; pc += 2
        elif op == 8:                     # STORE_OUT：R[wR++]=T
            R[wR] = T; wR += 1; pc += 1
        elif op == 11:                    # T = R[rIdx] - 1
            T = (R[rIdx] - 1) & 0xff; pc += 1
        elif op == 12:                    # T = R[rIdx] + 1
            T = (R[rIdx] + 1) & 0xff; pc += 1
        else:
            break
    return B, True


def solve():
    """每个输入字节只影响输出缓冲的同一下标 → 逐位独立枚举可打印字符。"""
    flag = []
    for i in range(len(TARGET)):
        for ch in range(0x20, 0x7f):
            inp = bytearray(15)
            inp[i] = ch
            B, _ = emulate(CODE, bytes(inp))
            if B[i] == TARGET[i]:
                flag.append(chr(ch))
                break
    return ''.join(flag)


if __name__ == '__main__':
    ans = solve()
    print('[+] 关键输入 =', ans)
    B, ok = emulate(CODE, ans.encode())
    print('[+] 复刻 VM 校验通过 =', ok, '=> flag{%s}' % ans)
