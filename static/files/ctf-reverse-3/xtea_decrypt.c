#include <stdio.h>
#include <stdint.h>
void decrypt(uint32_t* v,uint32_t* k)
{
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t dalta = 0x9E3779B9;
    uint32_t sum = 32*dalta;
    for (int i = 0; i<32; i++)
    {
        v1 -= (v0 + ((v0 >> 5) ^ (16 * v0))) ^ (k[(sum >> 11) & 3] + sum);
        sum -=dalta;
        v0 -= (v1 + ((v1 >> 5) ^ (16 * v1))) ^ (k[sum & 3] + sum);
    }
    v[1] = v1;
    v[0] = v0;
}
int main()
{
    uint32_t ciphertext[8] = {0x590d36d1, 0x6fa9b5e2, 0xda7190ad, 0xc54b0aa0, 0xada5ed54, 0x4ad07f84, 0x8a4cf3c0, 0x7fefb22f};
    uint32_t k[4] = {13,0,7,33};
    for(int i=0; i<8; i+=2)
    {
        uint32_t v[2];
        v[0] = *(uint32_t *)&ciphertext[i];
        v[1] = *(uint32_t *)&ciphertext[i+1];
        decrypt(v, k);
        char *p = (char *)v;
        for(int j=0; j <8; j++)
        {
            printf("%c",p[j]);
        }
    }
    printf("\n");
    return 0;
}