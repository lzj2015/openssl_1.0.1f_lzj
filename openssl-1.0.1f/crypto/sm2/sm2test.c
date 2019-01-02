
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

EC_KEY *genkey()
{
    EC_KEY *sm2key = NULL;
    char *out = NULL;
    sm2key = EC_KEY_new_by_curve_name(OBJ_sn2nid("SM2"));

    if (!sm2key)
    {
        printf("Create SM2 Key Object error.\n");
        goto err;
    }

    if (EC_KEY_generate_key(sm2key) == 0)
    {
        printf("Error Of Generate SM2 Key.\n");
        goto err;
    }

    const EC_GROUP *sm2group = EC_KEY_get0_group(sm2key);

    out = BN_bn2hex(EC_KEY_get0_private_key(sm2key));
    if (!out)
    {
        printf("Error Of Output SM2 Private key.\n");
        goto err;
    };

    printf("Generated SM2 Private Key: [%s]\n", out);

    OPENSSL_free(out);
    out = NULL;

    out = EC_POINT_point2hex(sm2group, EC_KEY_get0_public_key(sm2key), POINT_CONVERSION_UNCOMPRESSED, NULL);
    if (!out)
    {
        printf("Error Of Output SM2 Public key.\n");
        goto err;
    }
    printf("              Public Key: [%s]\n", out);

    OPENSSL_free(out);
    return sm2key;
err:
    if (sm2key)
        EC_KEY_free(sm2key);
    if (out)
        OPENSSL_free(out);

    return NULL;
}

void encrypto(EC_KEY *sm2key, const char *msg, unsigned char *out, size_t *outlen)
{

    /*Encrypt*/
    if (!sm2key)
    {
        printf("Error Of Calculate SM2 Public Key.\n");
        return;
    }
    int sm2enc = sm2_encrypt(sm2key, EVP_sm3(), (const unsigned char *)msg, (size_t)strlen(msg), out, outlen);
    if (!sm2enc)
    {
        printf("Error Of en calculate cipher text length.\n");
        return;
    }
    size_t retval = 0;
    for (; retval < *outlen; retval++)
        printf("%02X", out[retval]);
    printf("\n");
}

void decrypto(EC_KEY *sm2key, const unsigned char *in, size_t inlen, char *msg, size_t *msglen)
{

    if (!sm2key)
    {
        printf("Error Of Calculate SM2 Public Key.\n");
        return;
    }

    int sm2de = sm2_decrypt(sm2key, EVP_sm3(), in, inlen, (unsigned char *)msg, msglen);

    if (!sm2de)
    {
        printf("Error Of de calculate cipher text length.\n");
        return;
    }

    printf("crypto function ok %s\n", msg);
}

void testcrypt()
{

    const char *msg = "hello world";
    unsigned char *out = NULL;
    unsigned char *msgs = NULL;
    size_t outlen;
    size_t msglen;

    EC_KEY *sm2key = genkey();

    sm2_ciphertext_size(sm2key, EVP_sm3(), strlen(msg), &outlen);

    out = OPENSSL_malloc(outlen);
    encrypto(sm2key, msg, out, &outlen);

    sm2_plaintext_size(sm2key, EVP_sm3(), outlen, &msglen);
    msgs = OPENSSL_malloc(msglen);

    decrypto(sm2key, out, outlen, (char *)msgs, &msglen);

    EC_KEY_free(sm2key);
    if (out != NULL)
        OPENSSL_free(out);
    if (msgs != NULL)
        OPENSSL_free(msgs);
}

void testsign()
{
    const char *msg = "hello world";
    unsigned char *out = NULL;
    unsigned int outlen;
    int re;

    /* code */
    EC_KEY *sm2key = genkey();

    outlen = sm2_sign_size(sm2key);
    out = OPENSSL_malloc(outlen);

    re = sm2_sign((unsigned char *)msg, strlen(msg), out, &outlen, sm2key);

    if (re > 0)
    {
        printf("sm2  signature ok\n");
    }

    re = sm2_verify((unsigned char *)msg, strlen(msg), out, outlen, sm2key);

    if (re > 0)
    {
        printf("sm2  signature  verify ok\n");
    }

    EC_KEY_free(sm2key);
    if (out != NULL)
        OPENSSL_free(out);
}

int main(int argc, char const *argv[])
{

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    testcrypt();
    testsign();

    ERR_print_errors_fp(stderr);
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    CRYPTO_mem_leaks_fp(stderr);

    return 0;
}
