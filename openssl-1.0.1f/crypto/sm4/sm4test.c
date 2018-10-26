/* crypto/sm4/sm4test.c */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sm4.h>
#include <unistd.h>


const char *test1result = "\x68\x1E\xDF\x34\xD2\x06\x96\x5E\x86\xB3\xE9\x4F\x53\x6E\x42\x46";
const char *test2result = "\x59\x52\x98\xC7\xC6\xFD\x27\x1F\x04\x02\xF8\x04\xC3\x3D\x3F\x66";

int main(int argc, char **argv)
{
	SM4_KEY key;
	unsigned char out[16];
	
	unsigned char plaintext[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char user_key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	
	int loop;
	
	
	SM4_set_key((const unsigned char *)user_key, 16, &key);
	
	/*输出轮密钥*/
	for (loop = 0; loop < 32; loop++)
	{
		printf("\trk[%02d]=0x%08X", loop, key.key[loop]);
		if (!((loop + 1) % 4)) printf("\n");
	}
	
	SM4_encrypt((const unsigned char *)plaintext, out, &key);
	printf("SM4 Test1 verified: [%s]\n", ((!memcmp(out, test1result, 16)) ? "OK" : "ER"));
	printf("ECB Encrypt Result:[");
	for (loop = 0; loop < 16; loop++)
	{
		printf(" %02X", out[loop] & 0xff);
	}
	printf(" ]\n");
	
	SM4_decrypt((const unsigned char *)out, out, &key);
	printf("ECB Decrypt Result:[");
	for (loop = 0; loop < 16; loop++)
	{
		printf(" %02X", out[loop] & 0xff);
	}
	printf(" ]\n");
	
	memcpy(out, plaintext, 16);
	for (loop = 0; loop < 1000000; loop++)
		SM4_encrypt((const unsigned char *)out, out, &key);
	printf("SM4 Test2 verified: [%s]\n", ((!memcmp(out, test2result, 16)) ? "OK" : "ER"));
	
	printf("ECB Encrypt 1 000 0000 times Result:[");
	for (loop = 0; loop < 16; loop++)
	{
		printf(" %02X", out[loop] & 0xff);
	}
	printf(" ]\n");
	
	for (loop = 0; loop < 1000000; loop++)
		SM4_decrypt((const unsigned char *)out, out, &key);
	
	printf("ECB Decrypt 1 000 0000 times Result:[");
	for (loop = 0; loop < 16; loop++)
	{
		printf(" %02X", out[loop] & 0xff);
	}
	printf(" ]\n");
	
	return 0;
}



