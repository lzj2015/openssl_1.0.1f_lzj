/* crypto/sm3/sm3_one.c */


#include <openssl/sm3.h>
#include <string.h>

unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md)
{
    SM3_CTX c;
    static unsigned char m[SM3_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    SM3_Init(&c);
    SM3_Update(&c, d, n);
    SM3_Final(md, &c);
    /*OPENSSL_cleanse(&c, sizeof(c));*/
    memset(&c, 0, sizeof(SM3_CTX));
    return (md);
}


