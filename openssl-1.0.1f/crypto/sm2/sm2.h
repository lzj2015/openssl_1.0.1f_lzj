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

#ifndef SM2_HEADER_H
# define SM2_HEADER_H

#include <openssl/opensslconf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ossl_typ.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif // !OPENSSL_NO_ENGINE

# include <stdlib.h>
# include <stdint.h>
# include <stddef.h>

# ifndef OPENSSL_NO_SM2

#  include <openssl/ec.h>

/* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

typedef struct SM2_Ciphertext_st SM2_Ciphertext;

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Distinguishing Identifier, ISO/IEC 15946-3 */
    uint8_t *id;
    size_t id_len;
    /* id_set indicates if the 'id' field is set (1) or not (0) */
    int id_set;
} SM2_PKEY_CTX;


# ifdef __cplusplus
extern "C"
{
# endif

int sm2_compute_z_digest(unsigned char *out,
                         const EVP_MD *digest,
                         const unsigned char *id,
                         const size_t id_len,
                         const EC_KEY *key);

/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const unsigned char *id,
                       const size_t id_len,
                       const unsigned char *msg, size_t msg_len);

int sm2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *signature,
                  const unsigned char *id,
                  const size_t id_len,
                  const unsigned char *msg, size_t msg_len);

/*
 * SM2 signature generation.
 */
int sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*
 * SM2 signature verification.
 */
int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int siglen, EC_KEY *eckey);

/*
 * SM2 encryption
 */
int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const unsigned char *msg,
                size_t msg_len,
                unsigned char *ciphertext_buf, size_t *ciphertext_len);

int sm2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const unsigned char *ciphertext,
                size_t ciphertext_len, unsigned char *ptext_buf, size_t *ptext_len);

/**
 * pmeth
 */




# ifndef OPENSSL_NO_ERR

int ERR_load_SM2_strings(void);
/*
 * SM2 function codes.
 */
#  define SM2_F_PKEY_SM2_COPY                              115
#  define SM2_F_PKEY_SM2_CTRL                              109
#  define SM2_F_PKEY_SM2_CTRL_STR                          110
#  define SM2_F_PKEY_SM2_DIGEST_CUSTOM                     114
#  define SM2_F_PKEY_SM2_INIT                              111
#  define SM2_F_PKEY_SM2_SIGN                              112
#  define SM2_F_SM2_COMPUTE_MSG_HASH                       100
#  define SM2_F_SM2_COMPUTE_USERID_DIGEST                  101
#  define SM2_F_SM2_COMPUTE_Z_DIGEST                       113
#  define SM2_F_SM2_DECRYPT                                102
#  define SM2_F_SM2_ENCRYPT                                103
#  define SM2_F_SM2_PLAINTEXT_SIZE                         104
#  define SM2_F_SM2_SIGN                                   105
#  define SM2_F_SM2_SIG_GEN                                106
#  define SM2_F_SM2_SIG_VERIFY                             107
#  define SM2_F_SM2_VERIFY                                 108

/*
 * SM2 reason codes.
 */
#  define SM2_R_ASN1_ERROR                                 100
#  define SM2_R_BAD_SIGNATURE                              101
#  define SM2_R_BUFFER_TOO_SMALL                           107
#  define SM2_R_DIST_ID_TOO_LARGE                          110
#  define SM2_R_ID_NOT_SET                                 112
#  define SM2_R_ID_TOO_LARGE                               111
#  define SM2_R_INVALID_CURVE                              108
#  define SM2_R_INVALID_DIGEST                             102
#  define SM2_R_INVALID_DIGEST_TYPE                        103
#  define SM2_R_INVALID_ENCODING                           104
#  define SM2_R_INVALID_FIELD                              105
#  define SM2_R_NO_PARAMETERS_SET                          109
#  define SM2_R_USER_ID_TOO_LARGE                          106

# endif

# ifdef __cplusplus
}
# endif

# endif /* OPENSSL_NO_SM2 */
#endif
