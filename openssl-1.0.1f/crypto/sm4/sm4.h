/* crypto/sm4/sm4.h */


#ifndef SM4_HEADER_H
#define SM4_HEADER_H

#include <openssl/opensslconf.h>


# ifdef OPENSSL_NO_SM4
#  error SM4 is disabled.
# endif // OPENSSL_NO_CNSM

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stddef.h>

# define SM4_KEY_LENGTH           16
# define SM4_BLOCK_SIZE           16
# define SM4_IV_LENGTH            SM4_BLOCK_SIZE
# define SM4_NUM_ROUNDS           32
# define SM4_WRAP_SIZE            8

# define SM4_ENCRYPT              1
# define SM4_DECRYPT              0

# pragma pack(1)
struct sm4_key_st
{
    uint32_t key[SM4_NUM_ROUNDS];
};
# pragma pack()
typedef struct sm4_key_st SM4_KEY;


# ifdef __cplusplus
extern "C"
{
# endif // __cplusplus

    int SM4_set_key(const unsigned char *userKey, size_t length, SM4_KEY *key);

    void SM4_encrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *key);
    void SM4_decrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *key);


    void SM4_ecb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, const int enc);
    void SM4_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, const int enc);
    void SM4_cfb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, int *num, const int enc);
    void SM4_ofb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char *ivec, int *num);
    void SM4_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, unsigned char ivec[SM4_BLOCK_SIZE],
    	 unsigned char ecount_buf[SM4_BLOCK_SIZE], unsigned int *num);


    int SM4_wrap_key(SM4_KEY *key, const unsigned char iv[SM4_WRAP_SIZE],
		unsigned char *out, const unsigned char *in, unsigned int inlen);
 
	int SM4_unwrap_key(SM4_KEY *key, const unsigned char iv[SM4_WRAP_SIZE],
		unsigned char *out, const unsigned char *in, unsigned int inlen);


    
# ifdef __cplusplus
}
# endif // __cplusplus






typedef struct GCM128_CONTEXT SM4_GCM;

# ifdef __cplusplus
extern "C"
{
# endif // __cplusplus
    SM4_GCM *SM4_GCM128_new(const unsigned char *userKey, size_t length); 
    void SM4_GCM128_setiv(SM4_GCM *ctx, const unsigned char *iv, size_t len);
    int SM4_GCM128_aad(SM4_GCM *ctx, const unsigned char *aad, size_t len);

    int SM4_GCM128_encrypt(SM4_GCM *ctx, const unsigned char *in, unsigned char *out, size_t len);
    int SM4_GCM128_decrypt(SM4_GCM *ctx, const unsigned char *in, unsigned char *out, size_t len);

    int SM4_GCM128_finish(SM4_GCM *ctx,const unsigned char *tag, size_t len);
    void SM4_GCM128_free(SM4_GCM *ctx);
# ifdef __cplusplus
}
# endif // __cplusplus



#endif // SM4_HEADER_H



