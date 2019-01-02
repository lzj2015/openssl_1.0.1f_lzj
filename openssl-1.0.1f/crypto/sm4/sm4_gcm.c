#include <openssl/sm4.h>
#include <openssl/modes.h>




void SM4_GCM128_free(SM4_GCM *ctx)
{
  	CRYPTO_gcm128_release((GCM128_CONTEXT *)ctx);
}

SM4_GCM *SM4_GCM128_new(const unsigned char *userKey, size_t length)
{
 	SM4_KEY  key;
 	SM4_set_key(userKey,length,&key);
 	return (SM4_GCM *)CRYPTO_gcm128_new(&key,(block128_f)SM4_encrypt);
}

void SM4_GCM128_setiv(SM4_GCM *ctx, const unsigned char *iv, size_t len)
{
	CRYPTO_gcm128_setiv((GCM128_CONTEXT *)ctx, iv, len);
}

int SM4_GCM128_aad(SM4_GCM *ctx, const unsigned char *aad, size_t len)
{
	return CRYPTO_gcm128_aad((GCM128_CONTEXT *)ctx, aad, len);
}

int SM4_GCM128_encrypt(SM4_GCM *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
	return CRYPTO_gcm128_encrypt((GCM128_CONTEXT *)ctx, in, out, len);
}

int SM4_GCM128_decrypt(SM4_GCM *ctx, const unsigned char *in, unsigned char *out, size_t len)
{
	return CRYPTO_gcm128_decrypt((GCM128_CONTEXT *)ctx, in, out, len);
}

int SM4_GCM128_finish(SM4_GCM *ctx,const unsigned char *tag, size_t len)
{
	return CRYPTO_gcm128_finish((GCM128_CONTEXT *)ctx, tag, len);
}