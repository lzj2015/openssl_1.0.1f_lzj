/* crypto/sm3/sm3test.c */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sm3.h>

int run;


const char *test1digest = "\x66\xC7\xF0\xF4\x62\xEE\xED\xD9\xD1\xF2\xD4\x6B\xDC\x10\xE4\xE2\x41\x67\xC4\x87\x5C\xF2\xF7\xA2\x29\x7D\xA0\x2B\x8F\x4B\xA8\xE0";
const char *test2digest = "\xDE\xBE\x9F\xF9\x22\x75\xB8\xA1\x38\x60\x48\x89\xC1\x8E\x5A\x4D\x6F\xDB\x70\xE5\x38\x7E\x57\x65\x29\x3D\xCB\xA3\x9C\x0C\x57\x32";

int main(int argc, char **argv)
{
        int i;
        unsigned char digest[32];

        memset(digest, 0, sizeof(digest));
        SM3((unsigned char *)"abc", 3, digest);
        printf("SM3 Test1 verifid: [%s]\n", ((!memcmp(digest, test1digest, 32)) ? "OK" : "ER"));
        printf("abc SM3 digest: [");
        for (i = 0; i < 32; i++)
                printf(" %02X", digest[i]);

        printf(" ]\ni===================================================\n");
        memset(digest, 0, sizeof(digest));
        SM3((unsigned char *)"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 64, digest);
        printf("SM3 Test2 verifid: [%s]\n", ((!memcmp(digest, test2digest, 32)) ? "OK" : "ER"));
        printf("Test 2 Digest: [");
        for (i = 0; i < 32; i++)
                printf(" %02X", digest[i]);

        printf(" ]\n");

        return 0;

}


