/* crypto/evp/e_sm4.c */


#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SM4
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/objects.h>
#include <openssl/sm4.h>
#include "evp_locl.h"

typedef struct
{
    SM4_KEY ks;
} EVP_SM4_KEY;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
    SM4_set_key(key, 16, &(dat->ks));

    return 1;
}

static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    SM4_cbc_encrypt(in, out, inl, &((EVP_SM4_KEY *)ctx->cipher_data)->ks, ctx->iv, ctx->encrypt);

    return 1;
}

static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    size_t i, bl;
    bl = ctx->cipher->block_size;
    if (inl < bl)
        return 1;
    inl -= bl;
    if (ctx->encrypt)
    {
        for (i = 0; i <= inl; i += bl)
            SM4_encrypt(in + i, out + i, &((EVP_SM4_KEY *)ctx->cipher_data)->ks);
    }
    else
    {
        for (i = 0; i <= inl; i += bl)
            SM4_decrypt(in + i, out + i, &((EVP_SM4_KEY *)ctx->cipher_data)->ks);
    }

    return 1;
}

static int sm4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    SM4_cfb_encrypt(in, out, inl, &((EVP_SM4_KEY *)ctx->cipher_data)->ks, ctx->iv, &ctx->num, ctx->encrypt);

    return 1;
}

static int sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    SM4_ofb_encrypt(in, out, inl, &((EVP_SM4_KEY *)ctx->cipher_data)->ks, ctx->iv, &ctx->num);

    return 1;
}

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t inl)
{
    unsigned int num = ctx->num;
    EVP_SM4_KEY *dat = (EVP_SM4_KEY *)ctx->cipher_data;
    SM4_ctr128_encrypt(in,out,inl,&(dat->ks), ctx->iv, ctx->buf, &num);
    ctx->num = num;
    return 1;
}


static const EVP_CIPHER sm4_ecb = {
    NID_sm4_ecb,
    SM4_BLOCK_SIZE,
    SM4_KEY_LENGTH,
    0,
    0 | EVP_CIPH_ECB_MODE,
    sm4_init_key,
    sm4_ecb_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_ecb(void)
{
    return &sm4_ecb;
}

static const EVP_CIPHER sm4_cbc = {
    NID_sm4_cbc,
    SM4_BLOCK_SIZE,
    SM4_KEY_LENGTH,
    SM4_IV_LENGTH,
    0 | EVP_CIPH_CBC_MODE,
    sm4_init_key,
    sm4_cbc_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_cbc(void)
{
    return &sm4_cbc;
}

static const EVP_CIPHER sm4_ofb = {
    NID_sm4_ofb,
    1,
    SM4_KEY_LENGTH,
    SM4_IV_LENGTH,
    0 | EVP_CIPH_OFB_MODE,
    sm4_init_key,
    sm4_ofb_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_ofb(void)
{
    return &sm4_ofb;
}

static const EVP_CIPHER sm4_cfb = {
    NID_sm4_cfb,
    1,
    SM4_KEY_LENGTH,
    SM4_IV_LENGTH,
    0 | EVP_CIPH_CFB_MODE,
    sm4_init_key,
    sm4_cfb_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_cfb(void)
{
    return &sm4_cfb;
}


static const EVP_CIPHER sm4_ctr = {
    NID_sm4_ctr,
    1,
    SM4_KEY_LENGTH,
    SM4_IV_LENGTH,
    0 | EVP_CIPH_CTR_MODE,
    sm4_init_key,
    sm4_ctr_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};
const EVP_CIPHER *EVP_sm4_ctr(void)
{
    return &sm4_ctr;
}


#endif


