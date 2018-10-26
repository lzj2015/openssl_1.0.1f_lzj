#include <openssl/sm4.h>
#include <openssl/modes.h>


void SM4_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const SM4_KEY *key,
			unsigned char ivec[SM4_BLOCK_SIZE],
			unsigned char ecount_buf[SM4_BLOCK_SIZE],
			unsigned int *num) {

	CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num,
		 (block128_f)SM4_encrypt);
}
