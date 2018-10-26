/* crypto/sm4/sm4_ofb.c */


#include <openssl/sm4.h>
#include <openssl/modes.h>

void SM4_ofb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, int *num)
{
    CRYPTO_ofb128_encrypt(in,
        out,
        length,
        key,
        ivec,
        num,
        (block128_f) SM4_encrypt);
}


