#include <openssl/sm2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

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


static int sm2_get_point_str_xy(unsigned char*out, size_t field_size, const EC_GROUP *group, const EC_POINT *V)
{
    BN_CTX *ctx = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int re = 0;

    ctx = BN_CTX_new();

    if (ctx == NULL) {
        SM2err(SM2_F_SM2_DH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL) {
        SM2err(SM2_F_SM2_DH, ERR_R_BN_LIB);
        goto done;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, V, x, y, ctx)) {
        SM2err(SM2_F_SM2_DH, ERR_R_EC_LIB);
        goto done;
    }

    if (bn2binpad(x, out, field_size) < 0
            || bn2binpad(y, out + field_size, field_size) < 0) {
        SM2err(SM2_F_SM2_DH, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    re = 1;

done:
    BN_CTX_free(ctx);
    return re;
}


int sm2_compute_key(unsigned char *out, size_t olen, const EC_POINT *Rb, const EC_KEY *dh_key,
                    const EC_KEY *a_key, const EC_POINT *b_pk,
                    const unsigned char *a_z, const size_t az_len,
                    const unsigned char *b_z, const size_t bz_len, 
                    const EVP_MD *digest)
{
	int ret = -1;
	unsigned int w;
    size_t field_size;
    size_t buflen;
    unsigned char *buf=NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *xa = NULL;
	BIGNUM *xb = NULL;
	BIGNUM *n = NULL;
	BIGNUM *pw = NULL;
    BIGNUM *t = NULL;
    BIGNUM *h = NULL;
    EC_POINT *V = NULL;
	const BIGNUM *da;
	const BIGNUM *ra;
    const EC_GROUP *group;

	if (a_key == NULL || b_pk == NULL || a_z == NULL || b_z == NULL || Rb == NULL)
	{
		SM2err(SM2_F_SM2_DH, SM2_R_INVALID_INPUT);
		goto done;
	}

    group = EC_KEY_get0_group(a_key);

    if ((ctx = BN_CTX_new()) == NULL) 
    {
        SM2err(SM2_F_SM2_DH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    n = BN_CTX_get(ctx);
    pw = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    xb = BN_CTX_get(ctx);
    xa = BN_CTX_get(ctx);

	if (xa == NULL) 
	{
        SM2err(SM2_F_SM2_DH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

	// caculate w
    if(!EC_GROUP_get_order(group, n, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
    {
    	SM2err(SM2_F_SM2_DH, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    w = (BN_num_bits(n) + 1) / 2 - 1;
    // pw = 2^w
    if (!BN_lshift(pw, BN_value_one(), w))
    {
        SM2err(SM2_F_SM2_DH, ERR_R_BN_LIB);
        goto done;
    }
	
	// get xa from dh_key
	// get xb form Rb
    if(!EC_POINT_get_affine_coordinates_GFp(group, EC_KEY_get0_public_key(dh_key), xa, NULL, ctx)
    	|| !EC_POINT_get_affine_coordinates_GFp(group, Rb, xb, NULL, ctx))
    {
 		SM2err(SM2_F_SM2_DH, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    //x =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    if (!BN_nnmod(xa, xa, pw, ctx) 
    	|| !BN_add(xa, xa, pw)
    	|| !BN_nnmod(xb, xb, pw, ctx)
    	|| !BN_add(xb, xb, pw))
    {
        SM2err(SM2_F_SM2_DH, ERR_R_BN_LIB);
        goto done;
    }

    // t = da + xa * ra
    // get private key
    if ((da = EC_KEY_get0_private_key(a_key)) == NULL
    	 || (ra = EC_KEY_get0_private_key(dh_key)) == NULL)
    {
        SM2err(SM2_F_SM2_DH, ERR_R_EC_LIB);
        goto done;
    }

    if (!BN_mod_mul(t, xa, ra, n, ctx)
         || !BN_mod_add(t, t, da, n, ctx)
         || !BN_mul(t, t, h, ctx))
    {
        SM2err(SM2_F_SM2_DH, ERR_R_BN_LIB);
        goto done;
    }

    //calculate v
    V = EC_POINT_new(group);
    if (!EC_POINT_mul(group, V, NULL, Rb, xb, ctx)
         || !EC_POINT_add(group, V, V, b_pk, ctx)
         || !EC_POINT_mul(group, V, NULL, V, t, ctx))
    {
        SM2err(SM2_F_SM2_DH, ERR_R_EC_LIB);
        goto done;
    }

     /* Detect V is in */
    if (EC_POINT_is_at_infinity(group, V))
    {
        SM2err(SM2_F_SM2_DH, ERR_R_EC_LIB);
        goto done;
    }

    field_size = sm2_ec_field_size(group);
    buflen = 2 * field_size + bz_len + az_len;
    buf = OPENSSL_malloc(buflen + 1);
    if(!buf || !sm2_get_point_str_xy(buf,field_size,group,V))
    {
        SM2err(SM2_F_SM2_DH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memcpy(buf + 2 * field_size, b_z, bz_len);
    memcpy(buf + 2 * field_size + bz_len, a_z, az_len);

    if (!sm2_kdf(out, olen, buf, buflen, NULL, 0, digest)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }
    ret = olen;

done:
    BN_CTX_free(ctx);
    OPENSSL_free(buf);
    EC_POINT_free(V);

	return ret;


}