#include<stdint.h>
#include<stdio.h>
#include <string.h>
#include <stdlib.h> // for malloc/free
#define DELTA 0x9E3779B9 
// XXTEA 解密函数
void xxtea_decrypt(uint32_t *v, int n, const uint32_t k[4]) {
    // 如果数组大小 n 小于 2，不进行解密，直接返回
    if (n < 2) return;

    // 初始化 z 和 y，z 为数组最后一个元素，y 为第一个元素
    uint32_t z = v[n - 1], y = v[0];
    
    // 初始化累加器 sum，为加密的总和，解密时从最大值开始递减
    uint32_t sum = DELTA * (6 + 52 / n);

    // 外层循环执行轮数次，与加密时的轮数相同
    for (uint32_t i = 0; i < (6 + 52 / n); i++) {
        // 计算 e，用于密钥选择
        uint32_t e = (sum >> 2) & 3;
        
        // 内层循环处理 n-1 个数据块，从数组末尾往前遍历
        uint32_t p;
        for (p = n - 1; p > 0; p--) {
            z = v[p - 1];  // 前一个块的值
            // 更新当前块的值，使用 z 和 y 进行解密操作
            v[p] -= ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (sum ^ y) + (k[(p & 3) ^ e] ^ z);
            y = v[p];  // 更新 y 为当前块
        }
        
        // 第一个数据块的解密操作
        z = v[n - 1];  // 最后一个块的值
        v[0] -= ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ (sum ^ y) + (k[(0 & 3) ^ e] ^ z);
        y = v[0];  // 更新 y 为第一个块
        
        // 累加器 sum 减少 DELTA 值，与加密时相反
        sum -= DELTA;
    }
}
void xxtea_ciphertext(uint32_t *output_cipher)
{
    unsigned char raw_data[24] = {
        // v30 (low): 0xC0953A7C6B40BCCE -> CE BC 40 6B 7C 3A 95 C0
        0xCE, 0xBC, 0x40, 0x6B, 0x7C, 0x3A, 0x95, 0xC0,
        // v30 (high): 0x3502F79120209BEF -> EF 9B 20 20 91 F7 02 35
        0xEF, 0x9B, 0x20, 0x20, 0x91, 0xF7, 0x02, 0x35,
        // v31: -939386845 (0xC8016823) -> 23 18 02 C8
        0x23, 0x18, 0x02, 0xC8,
        // v32: -95004953 (0xFA5636E7) -> E7 56 56 FA
        0xE7, 0x56, 0x56, 0xFA
    };
    unsigned char key_stream[24] ;
    memcpy(key_stream,raw_data,24);

    int size_1 = 24;
    int size_2 = 1;
    unsigned char *ptr = raw_data + 1;
    while (size_2 < size_1)
    {
        int limit = (size_2/3);
        if(limit > 0)
        {
            unsigned char var = *ptr;
            for(int i = 0;i<limit; i++)
            {
                var ^= key_stream[i];
                *ptr = var;
            }
        }
        size_2++;
        ptr++;
    }
    unsigned char sorted_bytes[24];
    for(int i = 0;i<24; i+=4)
    {
        unsigned char *chunk = raw_data + i;
        sorted_bytes[i+0] = chunk[1];
        sorted_bytes[i+1] = chunk[3];
        sorted_bytes[i+2] = chunk[0];
        sorted_bytes[i+3] = chunk[2];
    }
    memcpy(output_cipher, sorted_bytes, 24);
    printf("[+] Ciphertext calculated successfully.\n");
}
void xxtea_key(const uint32_t *target_cipher)
{
    const char *charset = "qwertyuiopasdfghjklzxcvbnm1234567890";
    int len = strlen(charset);
    uint32_t temp_cipher[6];
    uint32_t key[4] = {0};
    char guess_str[5] = {0};

    for (int i = 0; i < len; i++) {
        for (int j = 0; j < len; j++) {
            for (int k = 0; k < len; k++) {
                for (int m = 0; m < len; m++) {
                    guess_str[0] = charset[i];
                    guess_str[1] = charset[j];
                    guess_str[2] = charset[k];
                    guess_str[3] = charset[m];
                    
                    key[0] = *(uint32_t *)guess_str;
                    key[1] = 0, key[2] = 0, key[3] = 0;
                    
                    memcpy(temp_cipher, target_cipher, 24);
                    xxtea_decrypt(temp_cipher, 6, key);

                    if(temp_cipher[0] == key[0]){
                        char *result_str = (char *)temp_cipher;
                        if (result_str[19] == 0) {
                            printf("\n[!!!] KEY FOUND: %s\n", guess_str);
                            printf("[!!!] FLAG: %s\n", result_str);
                            return; 
                        }
                    }
                    
                }
            }
        }
    }
    printf("[-] Brute force failed.\n");
}

int main()
{
     uint32_t cipher[6];

    xxtea_ciphertext(cipher);

    xxtea_key(cipher);

    return 0;
}
