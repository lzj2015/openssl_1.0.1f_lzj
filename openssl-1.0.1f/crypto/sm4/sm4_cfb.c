/* crypto/sm4/sm4_cfb.c */


#include <openssl/sm4.h>
#include <openssl/modes.h>

void SM4_cfb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, int *num, const int enc)
{

    CRYPTO_cfb128_encrypt(in,
        out,
        length,
        key,
        ivec,
        num,
        enc,
        (block128_f) SM4_encrypt);
}



