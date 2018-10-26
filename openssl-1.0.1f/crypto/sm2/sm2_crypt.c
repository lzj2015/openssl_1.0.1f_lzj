/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <string.h>

static int bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    int n;
    size_t i, lasti, j, atop, mask;
    BN_ULONG l;

    /*
     * In case |a| is fixed-top, BN_num_bytes can return bogus length,
     * but it's assumed that fixed-top inputs ought to be "nominated"
     * even for padded output, so it works out...
     */
    n = BN_num_bytes(a);
    if (tolen == -1) {
        tolen = n;
    } else if (tolen < n) {     /* uncommon/unlike case */
        BIGNUM temp = *a;

        bn_correct_top(&temp);
        n = BN_num_bytes(&temp);
        if (tolen < n)
            return -1;
    }

    /* Swipe through whole available data and don't give away padded zero. */
    atop = a->dmax * BN_BYTES;
    if (atop == 0) {
        OPENSSL_cleanse(to, tolen);
        return tolen;
    }

    lasti = atop - 1;
    atop = a->top * BN_BYTES;
    for (i = 0, j = 0, to += tolen; j < (size_t)tolen; j++) {
        l = a->d[i / BN_BYTES];
        mask = 0 - ((j - atop) >> (8 * sizeof(i) - 1));
        *--to = (unsigned char)(l >> (8 * (i % BN_BYTES)) & mask);
        i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
    }

    return tolen;
}

static size_t ec_field_size(const EC_GROUP *group)
{
    /* Is there some simpler way to do this? */
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    size_t field_size = 0;

    if (p == NULL || a == NULL || b == NULL)
       goto done;

    if (!EC_GROUP_get_curve_GFp(group, p, a, b, NULL))
        goto done;

    field_size = (BN_num_bits(p) + 7) / 8;

 done:
    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}

/* GM/T003_2012 Defined Key Derive Function */
static int KDF_GMT003_2012(unsigned char *out, size_t outlen, 
                            const unsigned char *Z, size_t Zlen, 
                            const unsigned char *SharedInfo, size_t SharedInfolen, 
                            const EVP_MD *md)
{
    EVP_MD_CTX *mctx;
    unsigned int counter;
    unsigned char ctr[4];
    size_t mdlen;
    int retval = 0;

    if (!out || !outlen){
        return retval;
    } 

    mctx = EVP_MD_CTX_create();
    if(mctx == NULL){
        return retval;
    }

    mdlen = EVP_MD_size(md);

    for (counter = 1;; counter++)
    {
        unsigned char dgst[EVP_MAX_MD_SIZE];
        if (!EVP_DigestInit_ex(mctx, md, NULL))
            goto err;

        ctr[0] = (unsigned char)((counter >> 24) & 0xFF);
        ctr[1] = (unsigned char)((counter >> 16) & 0xFF);
        ctr[2] = (unsigned char)((counter >> 8) & 0xFF);
        ctr[3] = (unsigned char)(counter & 0xFF);
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(mctx, SharedInfo, SharedInfolen))
            goto err;

        if (!EVP_DigestFinal(mctx, dgst, NULL))
            goto err;

        if (outlen > mdlen)
        {
            memcpy(out, dgst, mdlen);
            out += mdlen;
            outlen -= mdlen;
        }
        else
        {
            memcpy(out, dgst, outlen);
            memset(dgst, 0, mdlen);
            break;
        }
    }

    retval = 1;

err:
    EVP_MD_CTX_destroy(mctx);
    return retval;
}


/*SM2 Public Encrypt core function, out format is: C1 + C2 + C3*/
int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const unsigned char *msg,
                size_t msg_len, unsigned char *ciphertext_buf, size_t *ciphertext_len)
{

    int rc = 0;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    BIGNUM *order = NULL;

    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    unsigned char *msg_mask = NULL;
    unsigned char *x2y2 = NULL;
    unsigned char *C3 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_create();

    size_t field_size = ec_field_size(group);

    if (field_size == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }



    const int C3_size = EVP_MD_size(digest);
    if (hash == NULL || C3_size <= 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    const int out_size = (field_size * 2 + msg_len + C3_size);

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }


    
    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    order = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_BN_LIB);
        goto done;
    }

     if (!EC_GROUP_get_order(group, order, ctx))
    {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }

    x2y2 = OPENSSL_malloc(2 * field_size);
    C3 = OPENSSL_malloc(C3_size);

    if (x2y2 == NULL || C3 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

    if (!BN_rand_range(k, order)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates_GFp(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates_GFp(group, kP, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (bn2binpad(x2, x2y2, field_size) < 0
            || bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_malloc(msg_len);
    if (msg_mask == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!KDF_GMT003_2012(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                        digest)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    if (EVP_DigestInit(hash, digest) == 0
            || EVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVP_DigestFinal(hash, C3, NULL) == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }


   
    
    if(bn2binpad(x1, ciphertext_buf, field_size) < 0
            || bn2binpad(y1,ciphertext_buf + field_size, field_size) < 0){
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    memcpy(ciphertext_buf + (field_size * 2), msg_mask, msg_len);
    memcpy(ciphertext_buf + (field_size * 2) + msg_len, C3, C3_size);
    *ciphertext_len = out_size;

    rc = 1;

 done:
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVP_MD_CTX_destroy(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}

int sm2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const unsigned char *ciphertext,
                size_t ciphertext_len, unsigned char *ptext_buf, size_t *ptext_len)
{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    unsigned char *x2y2 = NULL;
    unsigned char *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVP_MD_size(digest);
    unsigned char *msg_mask = NULL;
    unsigned char *C2 = NULL;
    unsigned char *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

    msg_len = ciphertext_len - hash_size - field_size *2;

    if(msg_len <= 0){
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }


    hash = EVP_MD_CTX_create();
    if (hash == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (field_size == 0 || hash_size <= 0)
       goto done;

    memset(ptext_buf, 0x0, *ptext_len);

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    x1 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_BN_LIB);
        goto done;
    }

    // C1
    if(!BN_bin2bn(ciphertext, field_size, x1)
        || !BN_bin2bn(ciphertext + field_size, field_size, y1)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_BN_LIB);
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(group, C1, x1, y1, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key),
                             ctx)
            || !EC_POINT_get_affine_coordinates_GFp(group, C1, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EC_LIB);
        goto done;
    }

    C2 = OPENSSL_malloc(msg_len);
    msg_mask = OPENSSL_malloc(msg_len);
    x2y2 = OPENSSL_malloc(2 * field_size);
    computed_C3 = OPENSSL_malloc(hash_size);
    C3 = OPENSSL_malloc(hash_size);

    if (C2 == NULL || msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL
            || C3 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    memcpy(C2, ciphertext + (field_size * 2), msg_len);
    memcpy(C3, ciphertext + (field_size * 2) + msg_len, hash_size);


    if (bn2binpad(x2, x2y2, field_size) < 0
            || bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !KDF_GMT003_2012(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                               digest)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, x2y2, field_size)
            || !EVP_DigestUpdate(hash, ptext_buf, msg_len)
            || !EVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_DIGEST);
        goto done;
    }

    rc = 1;
    *ptext_len = msg_len;

 done:

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(computed_C3);
    OPENSSL_free(C2);
    OPENSSL_free(C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    EVP_MD_CTX_destroy(hash);
    return rc;
}
