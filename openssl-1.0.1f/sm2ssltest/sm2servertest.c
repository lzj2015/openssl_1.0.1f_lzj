#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>

#ifdef _WIN32
#include <Winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <openssl/ec.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SM2_SERVER_CERT     "SS.pem"
#define SM2_SERVER_KEY      "SS.pem"


#define SM2_SERVER_CA_CERT  "CA.pem"
#define SM2_SERVER_CA_PATH  "."

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define PORT 1111

int main(int argc, char **argv)
{

	int err;
	int listen_sd;
	int sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	size_t client_len;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    client_cert;
	char*    str;
	char     buf [4096];
	SSL_METHOD *meth;
	EC_KEY *ecdh = NULL;

	
#ifdef _WIN32
	//Winsows MINGW32  socket
	WSADATA wsadata;
	if(WSAStartup(MAKEWORD(1,1),&wsadata)==SOCKET_ERROR)
		{
		printf("WSAStartup() fail\n");
		exit(0);
		}
#endif
  

	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
	meth = TLSv1_server_method();

	/* Create a SSL_CTX structure */
	ctx = SSL_CTX_new(meth); 	CHK_NULL(ctx);

	ecdh = EC_KEY_new_by_curve_name(NID_sm2);
	SSL_CTX_set_tmp_ecdh(ctx, ecdh);

	/* Set to require peer (client) certificate verification */
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER |SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL); 

	/* Load the RSA CA certificate into the SSL_CTX structure */
	if (!SSL_CTX_load_verify_locations(ctx, SM2_SERVER_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			exit(1);
		}

	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, SM2_SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
		{
		ERR_print_errors_fp(stderr);
		exit(1);
		}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, SM2_SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
		{
		ERR_print_errors_fp(stderr);
		exit(1);
		}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx))
		{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(1);
		}

	SSL_CTX_set_cipher_list(ctx,"SM2DH-WITH-SM4-SM3");
	//SSL_CTX_set_cipher_list(ctx,"ECDHE-ECDSA-AES256-SHA");

	/* ----------------------------------------------- */
	/* Set up a TCP socket */
	printf("begin tcp socket... \n");

	listen_sd  = socket(AF_INET, SOCK_STREAM, 0);   

	CHK_ERR(listen_sd , "socket");
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons(PORT);          /* Server Port number */
	err = bind(listen_sd, (struct sockaddr*)&sa_serv, sizeof(sa_serv));

	CHK_ERR(err, "bind");

	/* Wait for an incoming TCP connection. */
	err = listen(listen_sd, 5);                    CHK_ERR(err, "listen");


	client_len = sizeof(sa_cli);

	/* Socket for a TCP/IP connection is created */
	sd = accept(listen_sd, (struct sockaddr *)&sa_cli, &client_len);

	CHK_ERR(sd, "accept");
	close(sd);

	printf("Connection from %lx, port %d\n",
		sa_cli.sin_addr.s_addr, 
		sa_cli.sin_port);

	/* TCP connection is ready. */
	/* A SSL structure is created */
	printf("begin server side ssl \n");
	ssl = SSL_new(ctx);

	CHK_NULL(ssl);

	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	SSL_set_fd(ssl, sd);

	/* Get client's certificate (note: beware of dynamic allocation) - opt */
	err = SSL_accept (ssl);                        CHK_SSL(err);
	printf("ssl_accept finished \n");

	printf ("ssl connection using %s \n", SSL_get_cipher (ssl));

	client_cert = SSL_get_peer_certificate (ssl);
	if (client_cert != NULL) {
		printf ("Client certificate:\n");
		
		str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
		CHK_NULL(str);
		printf ("\t subject: %s\n", str);
		OPENSSL_free (str);
		
		str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
		CHK_NULL(str);
		printf ("\t issuer: %s\n", str);
		OPENSSL_free (str);
		
		/* We could do all sorts of certificate verification stuff here before
		deallocating the certificate. */
		
		X509_free (client_cert);
	}
	else
    	printf ("Client does not have certificate.\n");


	/*------- DATA EXCHANGE - Receive message and send reply. -------*/
	/* Receive data from the SSL client */
	err = SSL_read(ssl, buf, sizeof(buf) - 1);

	CHK_SSL(err);

	buf[err] = '\0';

	printf("Received %d chars:'%s'\n", err, buf);

	/* Send data to the SSL client */
	err = SSL_write(ssl,
		"-----This message is from the SSL server-----\n", 
		strlen("-----This message is from the SSL server-----\n"));

	CHK_SSL(err);

	/*--------------- SSL closure ---------------*/
	/* Shutdown this side (server) of the connection. */

	err = SSL_shutdown(ssl);

	CHK_SSL(err);

	/* Terminate communication on a socket */
	close(sd);

	/* Free the SSL structure */
	SSL_free(ssl);

	/* Free the SSL_CTX structure */
	SSL_CTX_free(ctx);

	return 0;

}





