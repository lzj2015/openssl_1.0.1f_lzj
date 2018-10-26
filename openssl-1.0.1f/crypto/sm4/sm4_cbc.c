/* crypto/sm4/sm4_cbc.c */


#include <openssl/sm4.h>
#include <openssl/modes.h>

void SM4_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, const int enc)
{
    if (enc)
        CRYPTO_cbc128_encrypt(in,
            out,
            length,
            key,
            ivec,
            (block128_f) SM4_encrypt);
    else
        CRYPTO_cbc128_decrypt(in,
            out,
            length,
            key,
            ivec,
            (block128_f) SM4_decrypt);
}


