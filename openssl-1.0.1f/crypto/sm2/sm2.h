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

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#ifndef OPENSSL_NO_SM2

#include <openssl/ec.h>
#include <openssl/evp.h>


/* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"




# ifdef __cplusplus
extern "C"
{
# endif


size_t sm2_ec_field_size(const EC_GROUP *group);

int sm2_compute_z_digest(unsigned char *out,
                         const EVP_MD *digest,
                         const unsigned char *id,
                         const size_t id_len,
                         const EC_KEY *key);

int sm2_kdf(unsigned char *out, size_t outlen, 
                            const unsigned char *Z, size_t Zlen, 
                            const unsigned char *SharedInfo, size_t SharedInfolen, 
                            const EVP_MD *md);

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


int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size);

int sm2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size);
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
 * dh
 */
int sm2_compute_key(unsigned char *out, size_t olen, const EC_POINT *Rb, const EC_KEY *dh_key,
                    const EC_KEY *a_key, const EC_POINT *b_pk,
                    const unsigned char *a_z, const size_t az_len,
                    const unsigned char *b_z, const size_t bz_len, 
                    const EVP_MD *digest);






/*dh code*/
#  define EVP_PKEY_CTRL_SM2_SET_AZ                      0x2001
#  define EVP_PKEY_CTRL_SM2_GET_AZ                      0x2002
#  define EVP_PKEY_CTRL_SM2_GET_AZ_LEN                  0x2003
#  define EVP_PKEY_CTRL_SM2_GEN_DH_KEY                  0x2004
#  define EVP_PKEY_CTRL_SM2_SET_DH_KEY                  0x2005
#  define EVP_PKEY_CTRL_SM2_GET_DH_KEY                  0x2006
#  define EVP_PKEY_CTRL_SM2_SET_BZ                      0x2007
#  define EVP_PKEY_CTRL_SM2_GET_BZ                      0x2008
#  define EVP_PKEY_CTRL_SM2_GET_BZ_LEN                  0x2009
#  define EVP_PKEY_CTRL_SM2_SET_PEER_POINT              0x200a
#  define EVP_PKEY_CTRL_SM2_GET_PEER_POINT              0x200b
#  define EVP_PKEY_CTRL_SM2_PARAMGEN_CURVE_NID          0x200c
#  define EVP_PKEY_CTRL_SM2_MD                          0x200d


#define EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(ctx, nid) \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, -1, \
        EVP_PKEY_CTRL_SM2_PARAMGEN_CURVE_NID, nid, NULL)

#define EVP_PKEY_CTX_set_sm2_md(ctx, md) \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, -1, \
        EVP_PKEY_CTRL_SM2_MD, 0, (void *)md)

#define EVP_PKEY_CTX_set_sm2_az(ctx, az, azlen) \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, -1, \
        EVP_PKEY_CTRL_SM2_SET_AZ, azlen, (void *)az)

#define EVP_PKEY_CTX_set_sm2_bz(ctx, bz, bzlen) \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, -1, \
        EVP_PKEY_CTRL_SM2_SET_BZ, bzlen, (void *)bz)

#define EVP_PKEY_CTX_gen_sm2_dh_key(ctx) \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, -1, \
        EVP_PKEY_CTRL_SM2_GEN_DH_KEY, 0, NULL)

#define EVP_PKEY_CTX_get_sm2_dh_key_pk(ctx, pk) \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, -1, \
        EVP_PKEY_CTRL_SM2_GET_DH_KEY, 0, (void *)pk)

#define EVP_PKEY_CTX_set_sm2_peer_r(ctx, r) \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, -1, \
        EVP_PKEY_CTRL_SM2_SET_PEER_POINT, 0, (void *)r)



# ifndef OPENSSL_NO_ERR
#include <openssl/err.h>
#  define ERR_LIB_SM2            80
#  define SM2err(f,r) ERR_PUT_error(ERR_LIB_SM2,(f),(r),__FILE__,__LINE__)
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
#  define SM2_F_SM2_DH                                     109  

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
#  define SM2_R_INVALID_INPUT                              107  
#  define SM2_R_GEN_KEY                                    108  

# endif

# ifdef __cplusplus
}
# endif

# endif /* OPENSSL_NO_SM2 */
#endif
