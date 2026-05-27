# array  75553A1Eh, 7B583A03h, 4D58220Ch, 7B50383Dh, 736B3819h

#原代码
'''
array = [0x75553A1E, 0x7B583A03, 0x4D58220C, 0x7B50383D, 0x736B3819]
flag = ""
for i in array:
    temp = array[i]^0x12345678
    flag+=temp
print(flag)
'''
'''import struct
#代码
array = [0x75553A1E, 0x7B583A03, 0x4D58220C, 0x7B50383D, 0x736B3819]
flag = []
xor = 0x12345678
for i in array:
    # 1. 进行异或运算
    # 2. 将整数转换为4个字节（Little-Endian 小端序 '<I'）
    # 这一步会自动把 0x67616c66 转成 "flag"
    temp = i ^ xor
    print(hex(temp))
    char_temp = struct.pack('<I',temp)
    flag.append(char_temp)
print(''.join(chr(x) for x in flag))'''
import struct

array = [0x75553A1E, 0x7B583A03, 0x4D58220C, 0x7B50383D, 0x736B3819]
xor = 0x12345678

flag = [] 

for i in array:
    # 1. 异或运算
    temp = i ^ xor
    
    # 2. 将整数转为4字节（小端序）
    # 结果类似 b'flag'
    char_temp = struct.pack('<I', temp)
    
    flag.append(char_temp)

# 【改正这里】
# flag 现在是 [b'flag', b'{lli', b'ttl_', ...]
# 1. b''.join(flag): 把它们拼成一个长字节串 b'flag{llittl_...'
# 2. .decode(): 把字节串变成我们可以读的字符串
print(b''.join(flag).decode())
