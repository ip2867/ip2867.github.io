#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app-release.apk 题解 —— 多阶段校验（native + AES）
--------------------------------------------------------
com.nctf.hookmysecret 是一道三阶段题：
  Stage1  手势图案 → SHA-256 比对（本脚本不涉及，属前置）
  Stage2  NativeBridge.encryptStage2(String) 为 native 实现（libhookmysecret.so），
          返回值与 int[] 常量 K0.a.a 比对；由该常量反演即可还原 stage2Key
  Stage3  AES/CBC/PKCS5Padding，key=stage2Key（去 '-'），
          IV 来自 SQLite app_cfg.stage3_iv（base64），密文硬编码

本脚本纯静态复现：反演 native key → AES 解密 → 得到 flag。

用法:  python solve_apk.py
"""
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ---------- Stage2：反演 native encryptStage2 ----------
# IDA 反编译得到的逐字节变换（状态量 S 初始 81，每步滚动）：
#   v26 = ROL8(v25 ^ S ^ ((13*i + 66) & 0xff), 3) + i + 7*S
#   S   = (S + v25) + (i ^ v26)
# 目标常量来自 K0/a 的 int[] 常量
TARGET = [0xFA, 0x71, 0x57, 0xB9, 0x06, 0x7D, 0xA7, 0x9C,
          0x04, 0x00, 0xE5, 0xEF, 0x77, 0x9B, 0xBB, 0x5F]


def rol8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff


def ror8(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff


def native_forward(data):
    """正演 native 变换（用于自检）。"""
    S = 81
    out = bytearray()
    for i, b in enumerate(data):
        v = (rol8(b ^ S ^ ((13 * i + 66) & 0xff), 3) + i + 7 * S) & 0xff
        out.append(v)
        S = (S + b + (i ^ v)) & 0xff
    return bytes(out)


def native_inverse(target):
    """由目标密文常量反演输入字符串（即 stage2Key）。"""
    S = 81
    key = bytearray()
    for i, t in enumerate(target):
        x = ror8((t - i - 7 * S) & 0xff, 3)
        b = (x ^ S ^ ((13 * i + 66) & 0xff)) & 0xff
        key.append(b)
        S = (S + b + (i ^ t)) & 0xff
    return bytes(key)


# ---------- Stage3：AES/CBC 解密 ----------
IV_B64 = "VmVyaWZ5VmVjdG9yMTIzNA=="                                  # app_cfg.stage3_iv
CT_B64 = "jSaMnziall55Tdr+IZc7EKUNm/N4uwrZw1QFPw6DuirfYFJZg88j6GKLhWfNljAB"


def main():
    key = native_inverse(TARGET)
    assert native_forward(key) == bytes(TARGET), "native key 反演自检失败"
    print("[stage2] 反演出的 key =", key)

    iv = base64.b64decode(IV_B64)
    ct = base64.b64decode(CT_B64)
    pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    print("[stage3] 最终校验通过")
    print("[flag]  ", pt.decode())


if __name__ == "__main__":
    main()
