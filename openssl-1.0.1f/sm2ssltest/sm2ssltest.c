
#define _BSD_SOURCE 1 /* Or gethostname won't be declared properly \
			 on Linux and GNU platforms. */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define USE_SOCKETS
#include "e_os.h"

#ifdef OPENSSL_SYS_VMS
#define _XOPEN_SOURCE 500 /* Or isascii won't be declared properly on \
				 VMS (at least with DECompHP C).  */
#endif

#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_SM2
#include <openssl/sm2.h>
#endif

#include <openssl/bn.h>

#define _XOPEN_SOURCE_EXTENDED 1 /* Or gethostname won't be declared properly \
					on Compaq platforms (at least with DEC C).                \
					Do not try to put it earlier, or IPv6 includes            \
					get screwed...                                            \
				 */

#ifdef OPENSSL_SYS_WINDOWS
#include <winsock.h>
#else
#include OPENSSL_UNISTD
#endif

#define TEST_SERVER_CERT "server.pem"
#define TEST_CLIENT_CERT "client.pem"
#define TEST_CA_CERT "ca.pem"

/* There is really no standard for this, so let's assign some tentative
   numbers.  In any case, these numbers are only for this test */
#define COMP_RLE 255
#define COMP_ZLIB 1

static int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx);

static int MS_CALLBACK app_verify_callback(X509_STORE_CTX *ctx, void *arg);
#define APP_CALLBACK_STRING "Test Callback Argument"
struct app_verify_arg
{
	char *string;
	int app_verify;
	int allow_proxy_certs;
	char *proxy_auth;
	char *proxy_cond;
};


static BIO *bio_err = NULL;
static BIO *bio_stdout = NULL;

static int debug = 1;

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int doit_biopair(SSL *s_ssl, SSL *c_ssl, long bytes, clock_t *s_time, clock_t *c_time);
int doit(SSL *s_ssl, SSL *c_ssl, long bytes);

static void lock_dbg_cb(int mode, int type, const char *file, int line)
{
	static int modes[CRYPTO_NUM_LOCKS]; /* = {0, 0, ... } */
	const char *errstr = NULL;
	int rw;

	rw = mode & (CRYPTO_READ | CRYPTO_WRITE);
	if (!((rw == CRYPTO_READ) || (rw == CRYPTO_WRITE)))
	{
		errstr = "invalid mode";
		goto err;
	}

	if (type < 0 || type >= CRYPTO_NUM_LOCKS)
	{
		errstr = "type out of bounds";
		goto err;
	}

	if (mode & CRYPTO_LOCK)
	{
		if (modes[type])
		{
			errstr = "already locked";
			/* must not happen in a single-threaded program
			 * (would deadlock) */
			goto err;
		}

		modes[type] = rw;
	}
	else if (mode & CRYPTO_UNLOCK)
	{
		if (!modes[type])
		{
			errstr = "not locked";
			goto err;
		}

		if (modes[type] != rw)
		{
			errstr = (rw == CRYPTO_READ) ? "CRYPTO_r_unlock on write lock" : "CRYPTO_w_unlock on read lock";
		}

		modes[type] = 0;
	}
	else
	{
		errstr = "invalid mode";
		goto err;
	}

err:
	if (errstr)
	{
		/* we cannot use bio_err here */
		fprintf(stderr, "openssl (lock_dbg_cb): %s (mode=%d, type=%d) at %s:%d\n",
				errstr, mode, type, file, line);
	}
}

int main(int argc, char *argv[])
{
	char  *CAfile = TEST_CA_CERT;
	int  ret = 1;
	struct app_verify_arg app_verify_arg =
		{APP_CALLBACK_STRING, 0, 0, NULL, NULL};
	char *server_cert = TEST_SERVER_CERT;
	char *client_cert = TEST_CLIENT_CERT;

	SSL_CTX *s_ctx = NULL;
	SSL_CTX *c_ctx = NULL;
	const SSL_METHOD *meth = NULL;
	SSL *c_ssl, *s_ssl;
	long bytes = 256L;

#ifndef OPENSSL_NO_ECDH
	EC_KEY *ecdh = NULL;
#endif


	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

	CRYPTO_set_locking_callback(lock_dbg_cb);

	/* enable memory leak checking unless explicitly disabled */
	if (!((getenv("OPENSSL_DEBUG_MEMORY") != NULL) && (0 == strcmp(getenv("OPENSSL_DEBUG_MEMORY"), "off"))))
	{
		CRYPTO_malloc_debug_init();
		CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
	}
	else
	{
		/* OPENSSL_DEBUG_MEMORY=off */
		CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	}
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	RAND_seed(rnd_seed, sizeof rnd_seed);

	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);


	SSL_library_init();
	SSL_load_error_strings();

	meth = TLSv1_method();

	c_ctx = SSL_CTX_new(meth);
	s_ctx = SSL_CTX_new(meth);
	if ((c_ctx == NULL) || (s_ctx == NULL))
	{
		ERR_print_errors(bio_err);
		goto end;
	}

	ecdh = EC_KEY_new_by_curve_name(NID_sm2);
	if (ecdh == NULL)
	{
		BIO_printf(bio_err, "unable to create curve\n");
		goto end;
	}

	SSL_CTX_set_tmp_ecdh(s_ctx, ecdh);
	SSL_CTX_set_options(s_ctx, SSL_OP_SINGLE_ECDH_USE);
	EC_KEY_free(ecdh);

	if (!SSL_CTX_use_certificate_file(s_ctx, server_cert, SSL_FILETYPE_PEM))
	{
		ERR_print_errors(bio_err);
	}
	if (!SSL_CTX_use_PrivateKey_file(s_ctx, server_cert, SSL_FILETYPE_PEM))
	{
		ERR_print_errors(bio_err);
		goto end;
	}

	if (!SSL_CTX_use_certificate_file(c_ctx, client_cert, SSL_FILETYPE_PEM))
	{	
		ERR_print_errors(bio_err);
		goto end;
	}

	if(!SSL_CTX_use_PrivateKey_file(c_ctx, client_cert, SSL_FILETYPE_PEM))
	{
		ERR_print_errors(bio_err);
		goto end;
	}

	;
	if ((!SSL_CTX_load_verify_locations(s_ctx, CAfile, NULL)) ||
		(!SSL_CTX_set_default_verify_paths(s_ctx)) ||
		(!SSL_CTX_load_verify_locations(c_ctx, CAfile, NULL)) ||
		(!SSL_CTX_set_default_verify_paths(c_ctx)))
	{
		ERR_print_errors(bio_err);
		goto end;
	}

	
	SSL_CTX_set_verify(s_ctx,
						   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						   verify_callback);
	SSL_CTX_set_cert_verify_callback(s_ctx, app_verify_callback, &app_verify_arg);

	SSL_CTX_set_verify(c_ctx, SSL_VERIFY_PEER,
						   verify_callback);
	SSL_CTX_set_cert_verify_callback(c_ctx, app_verify_callback, &app_verify_arg);

	{
		int session_id_context = 0;
		SSL_CTX_set_session_id_context(s_ctx, (void *)&session_id_context, sizeof session_id_context);
	}

	c_ssl = SSL_new(c_ctx);
	s_ssl = SSL_new(s_ctx);

	SSL_set_session(c_ssl, NULL);
	ret = doit(s_ssl, c_ssl, bytes);

	SSL_free(s_ssl);
	SSL_free(c_ssl);

end:
	if (s_ctx != NULL)
		SSL_CTX_free(s_ctx);
	if (c_ctx != NULL)
		SSL_CTX_free(c_ctx);

	if (bio_stdout != NULL)
		BIO_free(bio_stdout);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_thread_state(NULL);
	EVP_cleanup();
	CRYPTO_mem_leaks(bio_err);
	if (bio_err != NULL)
		BIO_free(bio_err);
	EXIT(ret);
	return ret;
}

#define W_READ 1
#define W_WRITE 2
#define C_DONE 1
#define S_DONE 2

int doit(SSL *s_ssl, SSL *c_ssl, long count)
{
	MS_STATIC char cbuf[1024 * 8], sbuf[1024 * 8];
	long cw_num = count, cr_num = count;
	long sw_num = count, sr_num = count;
	int ret = 1;
	BIO *c_to_s = NULL;
	BIO *s_to_c = NULL;
	BIO *c_bio = NULL;
	BIO *s_bio = NULL;
	int c_r, c_w, s_r, s_w;
	int i, j;
	int done = 0;
	int c_write, s_write;
	int do_server = 0, do_client = 0;

	memset(cbuf, 0, sizeof(cbuf));
	memset(sbuf, 0, sizeof(sbuf));

	c_to_s = BIO_new(BIO_s_mem());
	s_to_c = BIO_new(BIO_s_mem());
	if ((s_to_c == NULL) || (c_to_s == NULL))
	{
		ERR_print_errors(bio_err);
		goto err;
	}

	c_bio = BIO_new(BIO_f_ssl());
	s_bio = BIO_new(BIO_f_ssl());
	if ((c_bio == NULL) || (s_bio == NULL))
	{
		ERR_print_errors(bio_err);
		goto err;
	}

	SSL_set_connect_state(c_ssl);
	SSL_set_bio(c_ssl, s_to_c, c_to_s);
	BIO_set_ssl(c_bio, c_ssl, BIO_NOCLOSE);

	SSL_set_accept_state(s_ssl);
	SSL_set_bio(s_ssl, c_to_s, s_to_c);
	BIO_set_ssl(s_bio, s_ssl, BIO_NOCLOSE);

	c_r = 0;
	s_r = 1;
	c_w = 1;
	s_w = 0;
	c_write = 1, s_write = 0;

	/* We can always do writes */
	for (;;)
	{
		do_server = 0;
		do_client = 0;

		i = (int)BIO_pending(s_bio);
		if ((i && s_r) || s_w)
			do_server = 1;

		i = (int)BIO_pending(c_bio);
		if ((i && c_r) || c_w)
			do_client = 1;

		if (do_server && debug)
		{
			if (SSL_in_init(s_ssl))
				printf("server waiting in SSL_accept - %s\n",
					   SSL_state_string_long(s_ssl));
			/*			else if (s_write)
				printf("server:SSL_write()\n");
			else
				printf("server:SSL_read()\n"); */
		}

		if (do_client && debug)
		{
			if (SSL_in_init(c_ssl))
				printf("client waiting in SSL_connect - %s\n",
					   SSL_state_string_long(c_ssl));
			/*			else if (c_write)
				printf("client:SSL_write()\n");
			else
				printf("client:SSL_read()\n"); */
		}

		if (!do_client && !do_server)
		{
			fprintf(stdout, "ERROR IN STARTUP\n");
			ERR_print_errors(bio_err);
			break;
		}
		if (do_client && !(done & C_DONE))
		{
			if (c_write)
			{
				j = (cw_num > (long)sizeof(cbuf)) ? (int)sizeof(cbuf) : (int)cw_num;
				i = BIO_write(c_bio, cbuf, j);
				if (i < 0)
				{
					c_r = 0;
					c_w = 0;
					if (BIO_should_retry(c_bio))
					{
						if (BIO_should_read(c_bio))
							c_r = 1;
						if (BIO_should_write(c_bio))
							c_w = 1;
					}
					else
					{
						fprintf(stderr, "ERROR in CLIENT\n");
						ERR_print_errors(bio_err);
						goto err;
					}
				}
				else if (i == 0)
				{
					fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
					goto err;
				}
				else
				{
					if (debug)
						printf("client wrote %d\n", i);
					/* ok */
					s_r = 1;
					c_write = 0;
					cw_num -= i;
				}
			}
			else
			{
				i = BIO_read(c_bio, cbuf, sizeof(cbuf));
				if (i < 0)
				{
					c_r = 0;
					c_w = 0;
					if (BIO_should_retry(c_bio))
					{
						if (BIO_should_read(c_bio))
							c_r = 1;
						if (BIO_should_write(c_bio))
							c_w = 1;
					}
					else
					{
						fprintf(stderr, "ERROR in CLIENT\n");
						ERR_print_errors(bio_err);
						goto err;
					}
				}
				else if (i == 0)
				{
					fprintf(stderr, "SSL CLIENT STARTUP FAILED\n");
					goto err;
				}
				else
				{
					if (debug)
						printf("client read %d\n", i);
					cr_num -= i;
					if (sw_num > 0)
					{
						s_write = 1;
						s_w = 1;
					}
					if (cr_num <= 0)
					{
						s_write = 1;
						s_w = 1;
						done = S_DONE | C_DONE;
					}
				}
			}
		}

		if (do_server && !(done & S_DONE))
		{
			if (!s_write)
			{
				i = BIO_read(s_bio, sbuf, sizeof(cbuf));
				if (i < 0)
				{
					s_r = 0;
					s_w = 0;
					if (BIO_should_retry(s_bio))
					{
						if (BIO_should_read(s_bio))
							s_r = 1;
						if (BIO_should_write(s_bio))
							s_w = 1;
					}
					else
					{
						fprintf(stderr, "ERROR in SERVER\n");
						ERR_print_errors(bio_err);
						goto err;
					}
				}
				else if (i == 0)
				{
					ERR_print_errors(bio_err);
					fprintf(stderr, "SSL SERVER STARTUP FAILED in SSL_read\n");
					goto err;
				}
				else
				{
					if (debug)
						printf("server read %d\n", i);
					sr_num -= i;
					if (cw_num > 0)
					{
						c_write = 1;
						c_w = 1;
					}
					if (sr_num <= 0)
					{
						s_write = 1;
						s_w = 1;
						c_write = 0;
					}
				}
			}
			else
			{
				j = (sw_num > (long)sizeof(sbuf)) ? (int)sizeof(sbuf) : (int)sw_num;
				i = BIO_write(s_bio, sbuf, j);
				if (i < 0)
				{
					s_r = 0;
					s_w = 0;
					if (BIO_should_retry(s_bio))
					{
						if (BIO_should_read(s_bio))
							s_r = 1;
						if (BIO_should_write(s_bio))
							s_w = 1;
					}
					else
					{
						fprintf(stderr, "ERROR in SERVER\n");
						ERR_print_errors(bio_err);
						goto err;
					}
				}
				else if (i == 0)
				{
					ERR_print_errors(bio_err);
					fprintf(stderr, "SSL SERVER STARTUP FAILED in SSL_write\n");
					goto err;
				}
				else
				{
					if (debug)
						printf("server wrote %d\n", i);
					sw_num -= i;
					s_write = 0;
					c_r = 1;
					if (sw_num <= 0)
						done |= S_DONE;
				}
			}
		}

		if ((done & S_DONE) && (done & C_DONE))
			break;
	}

err:
	/* We have to set the BIO's to NULL otherwise they will be
	 * OPENSSL_free()ed twice.  Once when th s_ssl is SSL_free()ed and
	 * again when c_ssl is SSL_free()ed.
	 * This is a hack required because s_ssl and c_ssl are sharing the same
	 * BIO structure and SSL_set_bio() and SSL_free() automatically
	 * BIO_free non NULL entries.
	 * You should not normally do this or be required to do this */
	if (s_ssl != NULL)
	{
		s_ssl->rbio = NULL;
		s_ssl->wbio = NULL;
	}
	if (c_ssl != NULL)
	{
		c_ssl->rbio = NULL;
		c_ssl->wbio = NULL;
	}

	if (c_to_s != NULL)
		BIO_free(c_to_s);
	if (s_to_c != NULL)
		BIO_free(s_to_c);
	if (c_bio != NULL)
		BIO_free_all(c_bio);
	if (s_bio != NULL)
		BIO_free_all(s_bio);
	return (ret);
}

static int get_proxy_auth_ex_data_idx(void)
{
	static volatile int idx = -1;
	if (idx < 0)
	{
		CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
		if (idx < 0)
		{
			idx = X509_STORE_CTX_get_ex_new_index(0,
												  "SSLtest for verify callback", NULL, NULL, NULL);
		}
		CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	}
	return idx;
}

static int MS_CALLBACK verify_callback(int ok, X509_STORE_CTX *ctx)
{
	char *s, buf[256];

	s = X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), buf,
						  sizeof buf);
	if (s != NULL)
	{
		if (ok)
			fprintf(stderr, "depth=%d %s\n",
					ctx->error_depth, buf);
		else
		{
			fprintf(stderr, "depth=%d error=%d %s\n",
					ctx->error_depth, ctx->error, buf);
		}
	}

	if (ok == 0)
	{
		fprintf(stderr, "Error string: %s\n",
				X509_verify_cert_error_string(ctx->error));
		switch (ctx->error)
		{
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			fprintf(stderr, "  ... ignored.\n");
			ok = 1;
		}
	}

	if (ok == 1)
	{
		X509 *xs = ctx->current_cert;
#if 0
		X509 *xi = ctx->current_issuer;
#endif

		if (xs->ex_flags & EXFLAG_PROXY)
		{
			unsigned int *letters =
				X509_STORE_CTX_get_ex_data(ctx,
										   get_proxy_auth_ex_data_idx());

			if (letters)
			{
				int found_any = 0;
				int i;
				PROXY_CERT_INFO_EXTENSION *pci =
					X509_get_ext_d2i(xs, NID_proxyCertInfo,
									 NULL, NULL);

				switch (OBJ_obj2nid(pci->proxyPolicy->policyLanguage))
				{
				case NID_Independent:
					/* Completely meaningless in this
					   program, as there's no way to
					   grant explicit rights to a
					   specific PrC.  Basically, using
					   id-ppl-Independent is the perfect
					   way to grant no rights at all. */
					fprintf(stderr, "  Independent proxy certificate");
					for (i = 0; i < 26; i++)
						letters[i] = 0;
					break;
				case NID_id_ppl_inheritAll:
					/* This is basically a NOP, we
					   simply let the current rights
					   stand as they are. */
					fprintf(stderr, "  Proxy certificate inherits all");
					break;
				default:
					s = (char *)
							pci->proxyPolicy->policy->data;
					i = pci->proxyPolicy->policy->length;

					/* The algorithm works as follows:
					   it is assumed that previous
					   iterations or the initial granted
					   rights has already set some elements
					   of `letters'.  What we need to do is
					   to clear those that weren't granted
					   by the current PrC as well.  The
					   easiest way to do this is to add 1
					   to all the elements whose letters
					   are given with the current policy.
					   That way, all elements that are set
					   by the current policy and were
					   already set by earlier policies and
					   through the original grant of rights
					   will get the value 2 or higher.
					   The last thing to do is to sweep
					   through `letters' and keep the
					   elements having the value 2 as set,
					   and clear all the others. */

					fprintf(stderr, "  Certificate proxy rights = %*.*s", i, i, s);
					while (i-- > 0)
					{
						int c = *s++;
						if (isascii(c) && isalpha(c))
						{
							if (islower(c))
								c = toupper(c);
							letters[c - 'A']++;
						}
					}
					for (i = 0; i < 26; i++)
						if (letters[i] < 2)
							letters[i] = 0;
						else
							letters[i] = 1;
				}

				found_any = 0;
				fprintf(stderr,
						", resulting proxy rights = ");
				for (i = 0; i < 26; i++)
					if (letters[i])
					{
						fprintf(stderr, "%c", i + 'A');
						found_any = 1;
					}
				if (!found_any)
					fprintf(stderr, "none");
				fprintf(stderr, "\n");

				PROXY_CERT_INFO_EXTENSION_free(pci);
			}
		}
	}

	return (ok);
}

static void process_proxy_debug(int indent, const char *format, ...)
{
	static const char indentation[] =
		">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
		">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"; /* That's 80 > */
	char my_format[256];
	va_list args;

	BIO_snprintf(my_format, sizeof(my_format), "%*.*s %s",
				 indent, indent, indentation, format);

	va_start(args, format);
	vfprintf(stderr, my_format, args);
	va_end(args);
}
/* Priority levels:
   0	[!]var, ()
   1	& ^
   2	|
*/
static int process_proxy_cond_adders(unsigned int letters[26],
									 const char *cond, const char **cond_end, int *pos, int indent);
static int process_proxy_cond_val(unsigned int letters[26],
								  const char *cond, const char **cond_end, int *pos, int indent)
{
	int c;
	int ok = 1;
	int negate = 0;

	while (isspace((int)*cond))
	{
		cond++;
		(*pos)++;
	}
	c = *cond;

	if (debug)
		process_proxy_debug(indent,
							"Start process_proxy_cond_val at position %d: %s\n",
							*pos, cond);

	while (c == '!')
	{
		negate = !negate;
		cond++;
		(*pos)++;
		while (isspace((int)*cond))
		{
			cond++;
			(*pos)++;
		}
		c = *cond;
	}

	if (c == '(')
	{
		cond++;
		(*pos)++;
		ok = process_proxy_cond_adders(letters, cond, cond_end, pos,
									   indent + 1);
		cond = *cond_end;
		if (ok < 0)
			goto end;
		while (isspace((int)*cond))
		{
			cond++;
			(*pos)++;
		}
		c = *cond;
		if (c != ')')
		{
			fprintf(stderr,
					"Weird condition character in position %d: "
					"%c\n",
					*pos, c);
			ok = -1;
			goto end;
		}
		cond++;
		(*pos)++;
	}
	else if (isascii(c) && isalpha(c))
	{
		if (islower(c))
			c = toupper(c);
		ok = letters[c - 'A'];
		cond++;
		(*pos)++;
	}
	else
	{
		fprintf(stderr,
				"Weird condition character in position %d: "
				"%c\n",
				*pos, c);
		ok = -1;
		goto end;
	}
end:
	*cond_end = cond;
	if (ok >= 0 && negate)
		ok = !ok;

	if (debug)
		process_proxy_debug(indent,
							"End process_proxy_cond_val at position %d: %s, returning %d\n",
							*pos, cond, ok);

	return ok;
}
static int process_proxy_cond_multipliers(unsigned int letters[26],
										  const char *cond, const char **cond_end, int *pos, int indent)
{
	int ok;
	char c;

	if (debug)
		process_proxy_debug(indent,
							"Start process_proxy_cond_multipliers at position %d: %s\n",
							*pos, cond);

	ok = process_proxy_cond_val(letters, cond, cond_end, pos, indent + 1);
	cond = *cond_end;
	if (ok < 0)
		goto end;

	while (ok >= 0)
	{
		while (isspace((int)*cond))
		{
			cond++;
			(*pos)++;
		}
		c = *cond;

		switch (c)
		{
		case '&':
		case '^':
		{
			int save_ok = ok;

			cond++;
			(*pos)++;
			ok = process_proxy_cond_val(letters,
										cond, cond_end, pos, indent + 1);
			cond = *cond_end;
			if (ok < 0)
				break;

			switch (c)
			{
			case '&':
				ok &= save_ok;
				break;
			case '^':
				ok ^= save_ok;
				break;
			default:
				fprintf(stderr, "SOMETHING IS SERIOUSLY WRONG!"
								" STOPPING\n");
				EXIT(1);
			}
		}
		break;
		default:
			goto end;
		}
	}
end:
	if (debug)
		process_proxy_debug(indent,
							"End process_proxy_cond_multipliers at position %d: %s, returning %d\n",
							*pos, cond, ok);

	*cond_end = cond;
	return ok;
}
static int process_proxy_cond_adders(unsigned int letters[26],
									 const char *cond, const char **cond_end, int *pos, int indent)
{
	int ok;
	char c;

	if (debug)
		process_proxy_debug(indent,
							"Start process_proxy_cond_adders at position %d: %s\n",
							*pos, cond);

	ok = process_proxy_cond_multipliers(letters, cond, cond_end, pos,
										indent + 1);
	cond = *cond_end;
	if (ok < 0)
		goto end;

	while (ok >= 0)
	{
		while (isspace((int)*cond))
		{
			cond++;
			(*pos)++;
		}
		c = *cond;

		switch (c)
		{
		case '|':
		{
			int save_ok = ok;

			cond++;
			(*pos)++;
			ok = process_proxy_cond_multipliers(letters,
												cond, cond_end, pos, indent + 1);
			cond = *cond_end;
			if (ok < 0)
				break;

			switch (c)
			{
			case '|':
				ok |= save_ok;
				break;
			default:
				fprintf(stderr, "SOMETHING IS SERIOUSLY WRONG!"
								" STOPPING\n");
				EXIT(1);
			}
		}
		break;
		default:
			goto end;
		}
	}
end:
	if (debug)
		process_proxy_debug(indent,
							"End process_proxy_cond_adders at position %d: %s, returning %d\n",
							*pos, cond, ok);

	*cond_end = cond;
	return ok;
}

static int process_proxy_cond(unsigned int letters[26],
							  const char *cond, const char **cond_end)
{
	int pos = 1;
	return process_proxy_cond_adders(letters, cond, cond_end, &pos, 1);
}

static int MS_CALLBACK app_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
	int ok = 1;
	struct app_verify_arg *cb_arg = arg;
	unsigned int letters[26]; /* only used with proxy_auth */

	if (cb_arg->app_verify)
	{
		char *s = NULL, buf[256];

		fprintf(stderr, "In app_verify_callback, allowing cert. ");
		fprintf(stderr, "Arg is: %s\n", cb_arg->string);
		fprintf(stderr, "Finished printing do we have a context? 0x%p a cert? 0x%p\n",
				(void *)ctx, (void *)ctx->cert);
		if (ctx->cert)
			s = X509_NAME_oneline(X509_get_subject_name(ctx->cert), buf, 256);
		if (s != NULL)
		{
			fprintf(stderr, "cert depth=%d %s\n", ctx->error_depth, buf);
		}
		return (1);
	}
	if (cb_arg->proxy_auth)
	{
		int found_any = 0, i;
		char *sp;

		for (i = 0; i < 26; i++)
			letters[i] = 0;
		for (sp = cb_arg->proxy_auth; *sp; sp++)
		{
			int c = *sp;
			if (isascii(c) && isalpha(c))
			{
				if (islower(c))
					c = toupper(c);
				letters[c - 'A'] = 1;
			}
		}

		fprintf(stderr,
				"  Initial proxy rights = ");
		for (i = 0; i < 26; i++)
			if (letters[i])
			{
				fprintf(stderr, "%c", i + 'A');
				found_any = 1;
			}
		if (!found_any)
			fprintf(stderr, "none");
		fprintf(stderr, "\n");

		X509_STORE_CTX_set_ex_data(ctx,
								   get_proxy_auth_ex_data_idx(), letters);
	}
	if (cb_arg->allow_proxy_certs)
	{
		X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
	}

#ifndef OPENSSL_NO_X509_VERIFY
	ok = X509_verify_cert(ctx);
#endif

	if (cb_arg->proxy_auth)
	{
		if (ok > 0)
		{
			const char *cond_end = NULL;

			ok = process_proxy_cond(letters,
									cb_arg->proxy_cond, &cond_end);

			if (ok < 0)
				EXIT(3);
			if (*cond_end)
			{
				fprintf(stderr, "Stopped processing condition before it's end.\n");
				ok = 0;
			}
			if (!ok)
				fprintf(stderr, "Proxy rights check with condition '%s' proved invalid\n",
						cb_arg->proxy_cond);
			else
				fprintf(stderr, "Proxy rights check with condition '%s' proved valid\n",
						cb_arg->proxy_cond);
		}
	}
	return (ok);
}
