#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../e_os.h"
#include <openssl/opensslconf.h>	/* for OPENSSL_NO_ECDH */
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#ifdef OPENSSL_NO_SM2
int main(int argc, char *argv[])
{
    printf("No SM2DH support\n");
    return(0);
}
#else
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

static const char rnd_seed[] = "string to make the random number generator think it has entropy";
static const char *a_id = "ALICE123@YAHOO.COM";
static const unsigned int a_id_len = 18;
static const char *b_id = "BILL456@YAHOO.COM";
static const unsigned int b_id_len = 17;

#define AX "3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655"
#define AY "3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B"
#define APR "6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE"

#define ARX "6CB5633816F4DD560B1DEC458310CBCC6856C09505324A6D23150C408F162BF0"
#define ARY "0D6FCF62F1036C0A1B6DACCF57399223A65F7D7BF2D9637E5BBBEB857961BF1A"
#define ARPR "83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563"

#define BX "245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43"
#define BY "53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C"
#define BPR "5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53"

#define BRX "1799B2A2C778295300D9A2325C686129B8F2B5337B3DCF4514E8BBC19D900EE5"
#define BRY "54C9288C82733EFDF7808AE7F27D0E732F7C73A7D9AC98B7D8740A91D0DB3CF4"
#define BRPR "33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80"

static void set_key_str(EC_KEY *key, BN_CTX *ctx, const EC_GROUP *group,
				 const char*cx, const char *cy, const char *cpr)
{
	BIGNUM *x=NULL, *y=NULL, *pr=NULL;
	EC_POINT *po;
	x = BN_new();
	y = BN_new();
	pr = BN_new();
	po = EC_POINT_new(group);

	BN_hex2bn(&x, cx);
	BN_hex2bn(&y, cy);
	BN_hex2bn(&pr, cpr);

	EC_POINT_set_affine_coordinates_GFp(group, po, x, y, ctx);
	EC_KEY_set_public_key(key,po);
	EC_KEY_set_private_key(key,pr);

	BN_free(x);
	BN_free(y);
	BN_free(pr);
	EC_POINT_free(po);
}


static int test_sm2_curve(const char *text, BN_CTX *ctx, BIO *out)
{
	EC_KEY *a=NULL;
	EC_KEY *ra=NULL;
	EC_KEY *rb=NULL;
	EC_KEY *b=NULL;
	unsigned char a_z[32]={0};
	unsigned char b_z[32]={0};
	unsigned char *abuf=NULL,*bbuf=NULL;
	int alen,blen,aout,bout,ret=0;
	EC_GROUP *group;

	BIGNUM *p, *pa, *pb, *px, *py, *pz;
	EC_POINT *G = NULL;

	p = BN_new();
	pa = BN_new();
	pb = BN_new();
	px = BN_new();
	py = BN_new();
	pz = BN_new();

	

	BN_hex2bn(&p, "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3");
	BN_hex2bn(&pa, "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498");
	BN_hex2bn(&pb, "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A");

	group = EC_GROUP_new(EC_GFp_mont_method());
	if (group == NULL) goto err;

	EC_GROUP_set_curve_GFp(group, p, pa, pb, ctx);
	
	G = EC_POINT_new(group);
	if (G== NULL) goto err;

	BN_hex2bn(&px, "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D");
	BN_hex2bn(&py, "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2");
	BN_hex2bn(&pz, "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7");
	EC_POINT_set_affine_coordinates_GFp(group, G, px, py, ctx);
	EC_GROUP_set_generator(group, G, pz, BN_value_one());

	ra = EC_KEY_new();
	rb = EC_KEY_new();
	a = EC_KEY_new();
	b = EC_KEY_new();

	EC_KEY_set_group(ra, group);
	EC_KEY_set_group(rb, group);
	EC_KEY_set_group(a, group);
	EC_KEY_set_group(b, group);


	set_key_str(a, ctx, group, AX, AY, APR);
	set_key_str(b, ctx, group, BX, BY, BPR);
	set_key_str(ra, ctx, group, ARX, ARY, ARPR);
	set_key_str(rb, ctx, group, BRX, BRY, BRPR);


	BIO_puts(out,"Testing key generation with ");
	BIO_puts(out,text);
	BIO_puts(out,"\n");

	if(!sm2_compute_z_digest(a_z, EVP_sm3(), (unsigned char *)a_id, a_id_len, a)
		|| !sm2_compute_z_digest(b_z, EVP_sm3(), (unsigned char *)b_id, b_id_len, b)) goto err;

	blen = 16;
	bbuf=(unsigned char *)OPENSSL_malloc(blen);
	bout = sm2_compute_key(bbuf, blen, EC_KEY_get0_public_key(ra), rb,
						b, EC_KEY_get0_public_key(a), b_z, 32, a_z, 32, EVP_sm3());


	alen = 16;
	abuf=(unsigned char *)OPENSSL_malloc(blen);
	aout = sm2_compute_key(abuf, alen, EC_KEY_get0_public_key(rb), ra,
						a, EC_KEY_get0_public_key(b), b_z, 32, a_z, 32, EVP_sm3());


	if ((aout < 4) || (bout != aout) || (memcmp(abuf,bbuf,aout) != 0))
		{
		BIO_printf(out, " failed\n\n");
		fprintf(stderr,"Error in SM2DH routines\n");
		ret=0;
		}
	else
		{
		BIO_printf(out, " stander ok\n");
		ret=1;
		}
		
err:
	ERR_print_errors_fp(stderr);
	if (abuf) OPENSSL_free(abuf);
	if (bbuf) OPENSSL_free(bbuf);
	if (b) EC_KEY_free(b);
	if (a) EC_KEY_free(a);
	if (rb) EC_KEY_free(rb);
	if (ra) EC_KEY_free(ra);
	if (p) BN_free(p);
	if (pa) BN_free(pa);
	if (pb) BN_free(pb);
	if (px) BN_free(px);
	if (py) BN_free(py);
	if (pz) BN_free(pz);
	EC_GROUP_free(group);
	EC_POINT_free(G);
	return(ret);
}


void sm2dhevptest()
{
	
	EVP_PKEY_CTX *akeyctx = NULL,*bkeyctx = NULL;
	EC_KEY *apk = NULL, *bpk = NULL;
	EVP_PKEY *akey = NULL, *bkey = NULL;
	EC_KEY *a = NULL,*b = NULL;

	unsigned char az[32]={0};
	unsigned char bz[32]={0};
	unsigned char aout[16]={0};
	unsigned char bout[16]={0};
	size_t alen = 16;
	size_t blen = 16;
	size_t azlen = 32;
	size_t bzlen = 32;

  
    a = EC_KEY_new_by_curve_name(OBJ_sn2nid("SM2"));
  	EC_KEY_generate_key(a);
  	b = EC_KEY_new_by_curve_name(EVP_PKEY_SM2);
  	EC_KEY_generate_key(b);

  	akey = EVP_PKEY_new();
  	bkey = EVP_PKEY_new();
  	EVP_PKEY_assign_SM2_KEY(akey,a);
  	EVP_PKEY_assign_SM2_KEY(bkey,b);
    
  	sm2_compute_z_digest(az, EVP_sm3(), (unsigned char *)a_id, a_id_len, a);
	sm2_compute_z_digest(bz, EVP_sm3(), (unsigned char *)b_id, b_id_len, b);
	
	akeyctx = EVP_PKEY_CTX_new(akey, NULL);
	bkeyctx = EVP_PKEY_CTX_new(bkey, NULL);

	EVP_PKEY_derive_init(akeyctx);
	EVP_PKEY_derive_init(bkeyctx);
	

	EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(akeyctx, NID_sm2);
	EVP_PKEY_CTX_set_sm2_paramgen_curve_nid(bkeyctx, NID_sm2);



	EVP_PKEY_CTX_set_sm2_md(akeyctx,EVP_sm3());
	EVP_PKEY_CTX_set_sm2_md(bkeyctx,EVP_sm3());


	EVP_PKEY_CTX_gen_sm2_dh_key(akeyctx);
	EVP_PKEY_CTX_gen_sm2_dh_key(bkeyctx);



	EVP_PKEY_CTX_set_sm2_az(akeyctx, az, azlen);
	EVP_PKEY_CTX_set_sm2_bz(akeyctx, bz, bzlen);

	EVP_PKEY_CTX_get_sm2_dh_key_pk(bkeyctx, &bpk);
	EVP_PKEY_CTX_set_sm2_peer_r(akeyctx, EC_KEY_get0_public_key(bpk));
	EVP_PKEY_derive_set_peer(akeyctx, bkey);
	EVP_PKEY_derive(akeyctx, aout, &alen);


	EVP_PKEY_CTX_set_sm2_az(bkeyctx, az, azlen);
	EVP_PKEY_CTX_set_sm2_bz(bkeyctx, bz, bzlen);
	EVP_PKEY_CTX_get_sm2_dh_key_pk(akeyctx, &apk);
	EVP_PKEY_CTX_set_sm2_peer_r(bkeyctx, EC_KEY_get0_public_key(apk));
	EVP_PKEY_derive_set_peer(bkeyctx, akey);
	EVP_PKEY_derive(bkeyctx, bout, &blen);

	int i = 0;
	for (; i < alen; ++i)
	{
		printf("%02x", aout[i] );
	}
	printf("\n");

	for ( i = 0; i < blen; ++i)
	{
		printf("%02x", bout[i]);
	}

	printf("\n");



	if ((alen < 4) || (alen != blen) || (memcmp(aout,bout,alen) != 0))
		{
		printf(" failed\n\n");
		fprintf(stderr,"Error EVP in SM2DH routines\n");
		}
	else
		{
		printf( " ok\n");
		}

	
	EVP_PKEY_CTX_free(akeyctx);
	EVP_PKEY_CTX_free(bkeyctx);
	EVP_PKEY_free(akey);
	EVP_PKEY_free(bkey);
	EC_KEY_free(apk);
	EC_KEY_free(bpk);
}

int main(int argc, char *argv[])
{
	int ret=1;
	

	BN_CTX *ctx=NULL;
	
	BIO *out;

	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

#ifdef OPENSSL_SYS_WIN32
	CRYPTO_malloc_init();
#endif



	RAND_seed(rnd_seed, sizeof rnd_seed);

	out=BIO_new(BIO_s_file());
	if (out == NULL) EXIT(1);
	BIO_set_fp(out,stdout,BIO_NOCLOSE);

	if ((ctx=BN_CTX_new()) == NULL) goto err;


	test_sm2_curve("SM2", ctx, out);
	ret = 0;

	sm2dhevptest();

err:
	ERR_print_errors_fp(stderr);
	if (ctx) BN_CTX_free(ctx);
	BIO_free(out);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	CRYPTO_mem_leaks_fp(stderr);
	EXIT(ret);


	return(ret);

}


#endif

