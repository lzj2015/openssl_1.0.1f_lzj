#include <openssl/opensslconf.h>

#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>
#include "evp_locl.h"


typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Distinguishing Identifier, ISO/IEC 15946-3 */
    unsigned char *az;
    size_t az_len;
    /*ephemeral dh key ,using in computer key*/
    EC_KEY *dh_key;
    /*to store peer ephemeral point,using in computer key */
    EC_POINT *peer_point;
    unsigned char *bz;
    size_t bz_len;

} SM2_PKEY_CTX;

static int pkey_sm2_init(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *smctx;

    if ((smctx = OPENSSL_malloc(sizeof(SM2_PKEY_CTX))) == NULL) {
        SM2err(SM2_F_PKEY_SM2_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    smctx->gen_group = NULL;
    smctx->md = NULL;
    smctx->az = NULL;
    smctx->az_len = 0;
    smctx->dh_key = NULL;
    smctx->peer_point = NULL;
    smctx->bz = NULL;
    smctx->bz_len = 0;
    ctx->data = (void *)smctx;
    return 1;
}

static void pkey_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *smctx = ctx->data;

    if (smctx != NULL) {
        EC_GROUP_free(smctx->gen_group);
        EC_KEY_free(smctx->dh_key);
        EC_POINT_free(smctx->peer_point);
        if(smctx->az)OPENSSL_free(smctx->az);
        if(smctx->bz)OPENSSL_free(smctx->bz);
        OPENSSL_free(smctx);
        ctx->data = NULL;
    }
}


static int pkey_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    SM2_PKEY_CTX *dctx, *sctx;

    if (!pkey_sm2_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group != NULL) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (dctx->gen_group == NULL) {
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }
    if (sctx->az != NULL) {
        dctx->az = OPENSSL_malloc(sctx->az_len);
        if (dctx->az == NULL) {
            SM2err(SM2_F_PKEY_SM2_COPY, ERR_R_MALLOC_FAILURE);
            pkey_sm2_cleanup(dst);
            return 0;
        }
        memcpy(dctx->az, sctx->az, sctx->az_len);
    }

    if (sctx->dh_key != NULL) {
        dctx->dh_key = EC_KEY_dup(sctx->dh_key);
        if (dctx->dh_key == NULL){
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }

    if (sctx->peer_point != NULL) {
        dctx->peer_point = EC_POINT_dup(sctx->peer_point,sctx->gen_group);
        if (dctx->peer_point == NULL){
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }

    if (sctx->bz != NULL) {
        dctx->bz = OPENSSL_malloc(sctx->bz_len);
        if (dctx->bz == NULL) {
            SM2err(SM2_F_PKEY_SM2_COPY, ERR_R_MALLOC_FAILURE);
            pkey_sm2_cleanup(dst);
            return 0;
        }
        memcpy(dctx->bz, sctx->bz, sctx->bz_len);
    }

    dctx->az_len = sctx->az_len;
    dctx->bz_len = sctx->bz_len;
    dctx->md = sctx->md;

    return 1;
}

static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    int ret;
    unsigned int sltmp;
    EC_KEY *ec = ctx->pkey->pkey.ec;
    const int sig_sz = ECDSA_size(ctx->pkey->pkey.ec);

    if (sig_sz <= 0) {
        return 0;
    }

    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        SM2err(SM2_F_PKEY_SM2_SIGN, SM2_R_BUFFER_TOO_SMALL);
        return 0;
    }

    ret = sm2_sign(tbs, tbslen, sig, &sltmp, ec);

    *siglen = (size_t)sltmp;
    
    return ret;
}



static int pkey_sm2_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *dgst, size_t dgstlen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;

    return sm2_verify(dgst, dgstlen, sig, siglen, ec);
}


static int pkey_sm2_encrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!sm2_ciphertext_size(ec, md, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return sm2_encrypt(ec, md, in, inlen, out, outlen);
}


static int pkey_sm2_decrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!sm2_plaintext_size(ec, md, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return sm2_decrypt(ec, md, in, inlen, out, outlen);
}


static int pkey_sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
    {
    EC_KEY *ec = NULL;
    if (ctx->pkey == NULL)
        {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
        }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
        return 0;
    return EC_KEY_generate_key(pkey->pkey.ec);
    }


static int pkey_sm2_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
    {
    EC_KEY *ec = NULL;
    SM2_PKEY_CTX *dctx = ctx->data;
    int ret = 0;
    if (dctx->gen_group == NULL)
        {
        ECerr(EC_F_PKEY_EC_PARAMGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
        }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    ret = EC_KEY_set_group(ec, dctx->gen_group);
    if (ret)
        EVP_PKEY_assign_EC_KEY(pkey, ec);
    else
        EC_KEY_free(ec);
    return ret;
    }


static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SM2_PKEY_CTX *smctx = ctx->data;
    EC_GROUP *group;
    unsigned char *tmp_id;

    switch (type) {
    case EVP_PKEY_CTRL_SM2_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            SM2err(SM2_F_PKEY_SM2_CTRL, SM2_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(smctx->gen_group);
        smctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_SM2_MD:
        smctx->md = (p2 == NULL) ? EVP_sm3() : p2;
        return 1;

    case EVP_PKEY_CTRL_SM2_SET_AZ:
        if (p1 > 0) {
            tmp_id = OPENSSL_malloc(p1);
            if (tmp_id == NULL) {
                SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(tmp_id, p2, p1);
            OPENSSL_free(smctx->az);
            smctx->az = tmp_id;
        } else {
            /* set null-ID */
            OPENSSL_free(smctx->az);
            smctx->az = NULL;
        }
        smctx->az_len = (size_t)p1;
        return 1;
    
    case EVP_PKEY_CTRL_SM2_GET_AZ:
        if((p1 < smctx->az_len) || (p2 == NULL)){
            SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(p2, smctx->az, smctx->az_len);
        return 1;

    case EVP_PKEY_CTRL_SM2_GET_AZ_LEN:
        *(size_t *)p2 = smctx->az_len;
        return 1;


    case EVP_PKEY_CTRL_SM2_GEN_DH_KEY:
        smctx->dh_key = EC_KEY_new();
        if (smctx->dh_key == NULL)
        {
            SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!EC_KEY_set_group(smctx->dh_key,smctx->gen_group)
             || !EC_KEY_generate_key(smctx->dh_key))
        {
            SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        return 1;

    case EVP_PKEY_CTRL_SM2_SET_DH_KEY:
        EC_KEY_free(smctx->dh_key);
        if(p2 !=NULL)
        {
            smctx->dh_key = EC_KEY_dup((const EC_KEY *)p2);
            if (smctx->dh_key == NULL)
            { 
                SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            return 1;
        }
        
        smctx->dh_key = NULL;
        return 1;

    case EVP_PKEY_CTRL_SM2_GET_DH_KEY:
         EC_KEY_free(*(EC_KEY **)p2);
         if(smctx->dh_key == NULL)
         {
            p2 = NULL;
            return 1;
         }

         (*(EC_KEY **)p2) = EC_KEY_dup(smctx->dh_key);
         if (p2 == NULL)
         {
            SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
         }

        return 1;

    case EVP_PKEY_CTRL_SM2_SET_BZ:
        if (p1 > 0) {
            tmp_id = OPENSSL_malloc(p1);
            if (tmp_id == NULL) {
                SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(tmp_id, p2, p1);
            OPENSSL_free(smctx->bz);
            smctx->bz = tmp_id;
        } else {
            /* set null-ID */
            OPENSSL_free(smctx->bz);
            smctx->bz = NULL;
        }
        smctx->bz_len = (size_t)p1;
        return 1;
    
    case EVP_PKEY_CTRL_SM2_GET_BZ:
        if(p1 < smctx->bz_len){
            SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(p2, smctx->bz, smctx->bz_len);
        return 1;

    case EVP_PKEY_CTRL_SM2_GET_BZ_LEN:
        *(size_t *)p2 = smctx->bz_len;
        return 1;

    case EVP_PKEY_CTRL_SM2_SET_PEER_POINT:
        EC_POINT_free(smctx->peer_point);
        if(p2 !=NULL)
        {
            smctx->peer_point = EC_POINT_dup((const EC_POINT *)p2, 
                (const EC_GROUP *)smctx->gen_group);
            if (smctx->peer_point == NULL)
            { 
                SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            return 1;
        }
        
        smctx->peer_point = NULL;
        return 1;

    case EVP_PKEY_CTRL_SM2_GET_PEER_POINT:
         EC_POINT_free(*(EC_POINT **)p2);
         if(smctx->peer_point == NULL)
         {
            p2 = NULL;
            return 1;
         }

         (*(EC_POINT **)p2) = EC_POINT_dup((const EC_POINT *)smctx->peer_point,
             (const EC_GROUP *)smctx->gen_group);
         if (p2 == NULL)
         {
            SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
            return 0;
         }

        return 1;   
    case EVP_PKEY_CTRL_PEER_KEY:
        /* Default behaviour is OK */
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;     
    default:
        return -2;
    }
}

static int pkey_sm2_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (strcmp(type, "ec_paramgen_curve") == 0) {
        int nid = NID_undef;

        if (((nid = OBJ_sn2nid(value)) == NID_undef)
            && ((nid = OBJ_ln2nid(value)) == NID_undef)) {
            SM2err(SM2_F_PKEY_SM2_CTRL_STR, SM2_R_INVALID_CURVE);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
        }
    return -2;
}

static int pkey_sm2_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
    {
    int ret = 0;
    size_t outlen;
    const EC_POINT *pubkey = NULL;
    SM2_PKEY_CTX *smctx = ctx->data;
    if (!ctx->pkey || !smctx || !ctx->peerkey)
    {
        ECerr(EC_F_PKEY_EC_DERIVE, EC_R_KEYS_NOT_SET);
        goto done;
    }

    if (!key)
    {
        const EC_GROUP *group;
        group = EC_KEY_get0_group(ctx->pkey->pkey.ec);
        *keylen = (EC_GROUP_get_degree(group) + 7)/8;
        goto done;
    }

    pubkey = EC_KEY_get0_public_key(ctx->peerkey->pkey.ec);

  
    outlen = *keylen;
        
    *keylen = sm2_compute_key(key, outlen, smctx->peer_point, smctx->dh_key,
                    ctx->pkey->pkey.ec, pubkey, smctx->az, smctx->az_len, 
                    smctx->bz, smctx->bz_len, smctx->md);
    ret =  *keylen;

done:
    return ret;
    }


const EVP_PKEY_METHOD sm2_pkey_meth = {
    EVP_PKEY_SM2,
    0,
    pkey_sm2_init,
    pkey_sm2_copy,
    pkey_sm2_cleanup,

    0,
    pkey_sm2_paramgen,  

    0,
    pkey_sm2_keygen,   

    0,
    pkey_sm2_sign,

    0,
    pkey_sm2_verify,

    0, 0,

    0, 0, 0, 0,

    0,
    pkey_sm2_encrypt,

    0,
    pkey_sm2_decrypt,

    0,
    pkey_sm2_derive,     

    pkey_sm2_ctrl,
    pkey_sm2_ctrl_str
};

