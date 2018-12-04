/* crypto/evp/m_sm3.c */

#include <stdio.h>
#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_SM3

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/sm3.h>

static int init(EVP_MD_CTX *ctx)
{
    return SM3_Init(ctx->md_data);
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SM3_Update(ctx->md_data, data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SM3_Final(md, ctx->md_data);
}

static const EVP_MD sm3_md = {
    NID_sm3,
    0,
    SM3_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    init,
    update,
    final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SM3_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SM3_CTX),
};

const EVP_MD *EVP_sm3(void)
{
    return (&sm3_md);
}
#endif

