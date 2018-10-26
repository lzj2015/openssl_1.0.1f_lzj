#include "cryptlib.h"
#include <openssl/sm4.h>
#include <openssl/bio.h>

static const unsigned char default_iv[] = {
  0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
};



int SM4_wrap_key(SM4_KEY *key, const unsigned char iv[SM4_WRAP_SIZE],
		unsigned char *out, const unsigned char *in, unsigned int inlen)
	{
	unsigned char *A, B[16], *R;
	unsigned int i, j, t;
	if ((inlen & 0x7) || (inlen < 16))
		return -1;
	A = B;
	t = 1;
	memcpy(out + 8, in, inlen);
	if (!iv)
		iv = default_iv;

	memcpy(A, iv, 8);

	for (j = 0; j < 6; j++)
		{
		R = out + 8;
		for (i = 0; i < inlen; i += 8, t++, R += 8)
			{
			memcpy(B + 8, R, 8);
			SM4_encrypt(B, B, key);
			A[7] ^= (unsigned char)(t & 0xff);
			if (t > 0xff)	
				{
				A[6] ^= (unsigned char)((t >> 8) & 0xff);
				A[5] ^= (unsigned char)((t >> 16) & 0xff);
				A[4] ^= (unsigned char)((t >> 24) & 0xff);
				}
			memcpy(R, B + 8, 8);
			}
		}
	memcpy(out, A, 8);
	return inlen + 8;
	}


int SM4_unwrap_key(SM4_KEY *key, const unsigned char iv[SM4_WRAP_SIZE],
		unsigned char *out, const unsigned char *in, unsigned int inlen)
	{
	unsigned char *A, B[16], *R;
	unsigned int i, j, t;
	inlen -= 8;
	if (inlen & 0x7)
		return -1;
	if (inlen < 16)
		return -1;
	A = B;
	t =  6 * (inlen >> 3);
	memcpy(A, in, 8);
	memcpy(out, in + 8, inlen);
	for (j = 0; j < 6; j++)
		{
		R = out + inlen - 8;
		for (i = 0; i < inlen; i += 8, t--, R -= 8)
			{
			A[7] ^= (unsigned char)(t & 0xff);
			if (t > 0xff)	
				{
				A[6] ^= (unsigned char)((t >> 8) & 0xff);
				A[5] ^= (unsigned char)((t >> 16) & 0xff);
				A[4] ^= (unsigned char)((t >> 24) & 0xff);
				}
			memcpy(B + 8, R, 8);
			SM4_decrypt(B, B, key);
			memcpy(R, B + 8, 8);
			}
		}
	if (!iv)
		iv = default_iv;
	if (memcmp(A, iv, 8))
		{
		OPENSSL_cleanse(out, inlen);
		return 0;
		}
	return inlen;
	}

