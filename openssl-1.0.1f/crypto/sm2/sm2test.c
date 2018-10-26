
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <string.h>

EC_KEY *genkey()
{
     EC_KEY *sm2key = NULL;
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

    char *out =  BN_bn2hex(EC_KEY_get0_private_key(sm2key));
    if (!out)
    {
        printf("Error Of Output SM2 Private key.\n");
        goto err;
    };

    printf("Generated SM2 Private Key: [%s]\n", out);

    out = EC_POINT_point2hex(sm2group, EC_KEY_get0_public_key(sm2key), POINT_CONVERSION_UNCOMPRESSED, NULL);
    if (!out)
    {
        printf("Error Of Output SM2 Public key.\n");
        goto err;
    }
    printf("              Public Key: [%s]\n", out);

    return sm2key;
err:
    if (sm2key) EC_KEY_free(sm2key);
    if (out) OPENSSL_free(out);

     return sm2key;
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
        printf("Error Of calculate cipher text length.\n");
        return;
    }
    for (size_t retval = 0; retval < *outlen; retval++)
        printf("%02X", out[retval]);
    printf("\n");
}



void decrypto(EC_KEY *sm2key,const unsigned char *in, size_t inlen, char * msg,size_t *msglen)
{

    if (!sm2key)
    {
        printf("Error Of Calculate SM2 Public Key.\n");
        return;
    }

    int sm2de= sm2_decrypt(sm2key, EVP_sm3(), in, inlen, msg, msglen);

    if(!sm2de)
    {
        printf("Error Of calculate cipher text length.\n");
        return;
    }

   printf("%s\n", msg);
}



int main(int argc, char const *argv[])
{
    const char *msg="hello world";
    const char *id = "lzj";
    unsigned char out[1024]={0};
    unsigned char msgs[1024]={0};
    size_t outlen;
    size_t msglen;
    /* code */
    EC_KEY *sm2key = genkey();
    encrypto(sm2key, msg, out, &outlen);
    decrypto(sm2key, out, outlen, msgs, &msglen);


    ECDSA_SIG *sing = sm2_do_sign(sm2key, EVP_sm3(), id, strlen(id), msg, strlen(msg));

    int re =  sm2_do_verify(sm2key, EVP_sm3(), sing, id, strlen(id), msg, strlen(msg));

    if (re)
    {
        printf("sm2 signature ok\n");
    }
    

    return 0;
}
