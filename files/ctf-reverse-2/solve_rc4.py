def rc4_init(s_box, key, key_len):  # rc4初始化函数，产生s_box
    k = [0] * 256
    i = j = 0
    for i in range(256):
        s_box[i] = i
        k[i] = key[i % key_len]
    for i in range(256):
        j = (j + s_box[i] + ord(k[i])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
def rc4_crypt(s_box, data, data_len, key, key_len):  # rc4算法，由于异或运算的对合性，RC4加密解密使用同一套算法，加解密都是它
    rc4_init(s_box, key, key_len)
    i = j = 0
    for k in range(data_len):
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        t = (s_box[i] + s_box[j]) % 256
        data[k] ^= s_box[t]
 
if __name__ == '__main__':
    s_box = [0] * 257  # 定义存放s_box数据的列表
 
    # 此处的data即要解密的密文，需要定义成列表形式，其中的元素可以是十六进制或十进制数
    # 如果题目给出的是字符串，需要你自己先把数据处理成列表形式再套用脚本
    data = [0xe8, 0x2b, 0x33, 0x25, 0xb2, 0x55, 
            0xe9, 0xd, 0x5d, 0xaa, 0x69, 0xfd, 0x1b, 
            0x47, 0xd1, 0x7c, 0xa6, 0xff, 0x52, 0xe1, 
            0x6c, 0xe8, 0x4c]  
    #key一定要字符串
    key = "SakuraiCora"
 
    rc4_crypt(s_box, data, len(data), key, len(key))
    for i in data:
        print(chr(i), end='')