#密文："f\nk\fw&O.@\x11x\rZ;U\x11p\x19F\x1Fv\"M#D\x0Eg\x06h\x0FG2O"
'''  for ( i = 1; i < 33; ++i )
    __b[i] ^= __b[i - 1];
'''
enc = "f\nk\fw&O.@\x11x\rZ;U\x11p\x19F\x1Fv\"M#D\x0Eg\x06h\x0FG2O"
enc_ord = [ord(ch) for ch in enc]
flag = [0] * 33
flag[0] = enc_ord[0]
for i in range(1,33):
    flag[i] = enc_ord[i]^enc_ord[i-1]

print(''.join(chr(x) for x in flag))