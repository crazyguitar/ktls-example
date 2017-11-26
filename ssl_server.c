#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/modes.h>
#include <openssl/aes.h>

#define PORT 4433

void main_server(int port);

int main(int argv, char* argc[])
{
	main_server(PORT);

	return 0;
}

int open_listener(int port)
{
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ( bind(sd, (const struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 ) {
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

void init_openssl()
{ 
	SSL_library_init();
	SSL_load_error_strings();	
	ERR_load_crypto_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX* init_server_ctx(void)
{
	const SSL_METHOD *method = NULL;
	SSL_CTX *ctx = NULL;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		abort();
 	}

	return ctx;
}

void load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
	    ERR_print_errors_fp(stderr);
	    abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) ) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

void serverlet(int client, SSL* ssl)/* Serve the connection -- threadable */
{
	int sd = -1;

	if ( SSL_accept(ssl) == -1 ) {
		ERR_print_errors_fp(stderr);
	} else {

		char buf[16384];
		int bytes = 0;

		/* recv request */
		bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes < 0) {
			perror("SSL_read failed");
			ERR_print_errors_fp(stderr);
		}

		/*send response */
		bytes = SSL_write(ssl, buf, bytes);
		if (bytes < 0) {
			perror("SSL_write failed");
			ERR_print_errors_fp(stderr);
		}
	}

	/* get socket connection */
	sd = SSL_get_fd(ssl);
	/* release SSL state */
	SSL_free(ssl);
	/* close connection */
	close(sd);
}

#define CRT_PEM "cert.pem"
#define KEY_PEM "key.pem"

void main_server(int port)
{
	SSL_CTX *ctx = NULL;

	/* init openssl */
	init_openssl();

	/* initialize SSL */
	ctx = init_server_ctx();

	/* load certs */
	load_certificates(ctx, CRT_PEM, KEY_PEM);

	/* set cipher list */
	SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");

	int server = open_listener(port);/* create server socket */
	while (1) {
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);
		SSL *ssl = NULL;

		int client = accept(server, (struct sockaddr*) &addr, &len);/* accept connection as usual */

		ssl = SSL_new(ctx);         /* get new SSL state with context */
		SSL_set_fd(ssl, client);/* set connection socket to SSL state */
 		serverlet(client, ssl);/* service connection */
	}
	/* close server socket */
	close(server);
	/* release context */
	SSL_CTX_free(ctx);
	cleanup_openssl();

	return;
}
