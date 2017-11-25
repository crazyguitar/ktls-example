#include "ktls_server.h"

#define PORT 4433

static void main_server(int port);

int main(int argv, char* argc[])
{
	main_server(PORT);

	return 0;
}

static int open_listener(int port)
{
	int sd = -1, reuse = 1, rc = -1;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
		perror("Unable to set SO_REUSEADDR");
		goto end;
	}

	if ( bind(sd, (const struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
		perror("can't bind port");
		goto end;
	}
	if ( listen(sd, 10) != 0 ) {
		perror("Can't configure listening port");
		goto end;
	}
	rc = 0;
end:
	if (rc < 0 && sd >=0) {
		close(sd);
		sd = -1;
	}
	return sd;
}

static void init_openssl()
{ 
	SSL_library_init();
	SSL_load_error_strings();	
	ERR_load_crypto_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_ssl_algorithms();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}

static SSL_CTX* init_server_ctx(void)
{
	const SSL_METHOD *method = NULL;
	SSL_CTX *ctx = NULL;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
 	}

	return ctx;
}

static int load_certificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	int rc = -1;
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) ) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		goto end;
	}
	rc = 0;
end:
	return rc;
}

static int configure_ktls(int client, SSL* ssl)
{
	int rc = -1;
	struct tls12_crypto_info_aes_gcm_128 crypto_info;

	memset(&crypto_info, 0, sizeof(crypto_info));

	crypto_info.info.version = TLS_1_2_VERSION;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

	EVP_CIPHER_CTX * write_ctx = ssl->enc_write_ctx;
	// ref: linux/include/uapi/linux/tls.h
	// XXX: TLS_RX not support yet
	// EVP_CIPHER_CTX * read_ctx = ssl->enc_read_ctx;

	EVP_AES_GCM_CTX* gcm_write = (EVP_AES_GCM_CTX*)(write_ctx->cipher_data);
	// XXX: TLS_RX not support yet
	// EVP_AES_GCM_CTX* gcm_read = (EVP_AES_GCM_CTX*)(read_ctx->cipher_data);

	unsigned char* key_write = (unsigned char*)(gcm_write->gcm.key);
	// XXX: TLS_RX not support yet
	// unsigned char* key_read = (unsigned char*)(gcm_read->gcm.key);

	unsigned char* iv_write = gcm_write->iv;
	// XXX: TLS_RX not support yet
	// unsigned char* iv_read = gcm_read->iv;

	unsigned char* seq_number_write = ssl->s3->write_sequence;
	// XXX: TLS_RX not support yet
	//unsigned char* seq_number_read = ssl->s3->read_sequence;

	memcpy(crypto_info.iv, seq_number_write, TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(crypto_info.rec_seq, seq_number_write, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
	memcpy(crypto_info.key, key_write, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(crypto_info.salt, iv_write, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	/* set ktls */
	if (setsockopt(client, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) <0) {
		perror("Unable set TCP_ULP");
		goto end;
	}
	if (setsockopt(client, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)) < 0) {
		perror("Unable set TLS_TX");
		goto end;
	}
	rc = 0;
end:
	return rc;
}

static void serverlet(int client, SSL* ssl)/* Serve the connection -- threadable */
{
	char buf[16384];
	int bytes = 0;

	if ( SSL_accept(ssl) == -1 ) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (configure_ktls(client, ssl) < 0) {
		perror("configure_ktls failed");
		goto end;
	}

	/* recv request */
	bytes = SSL_read(ssl, buf, sizeof(buf));
	if (bytes < 0) {
		perror("SSL_read failed");
		ERR_print_errors_fp(stderr);
		goto end;
	}

	/*send response */
	bytes = send(client, buf, sizeof(buf), 0);
	if (bytes < 0) {
		perror("KTLS send failed");
		ERR_print_errors_fp(stderr);
		goto end;
	}
end:
	return;
}

#define CRT_PEM "cert.pem"
#define KEY_PEM "key.pem"

static void main_server(int port)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	/* init openssl */
	init_openssl();

	/* initialize SSL */
	ctx = init_server_ctx();
	if (!ctx) goto end;

	/* load certs */
	if (load_certificates(ctx, CRT_PEM, KEY_PEM) < 0) goto end;

	/* set cipher list */
	if (SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256") == 0) goto end;

	/* create server socket */
	int server = open_listener(port);
	if (server < 0) goto end;

	while (1) {
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);

		/* accept connection as usual */
		int client = accept(server, (struct sockaddr*) &addr, &len);

		/* accept connection as usual */
		ssl = SSL_new(ctx);
		/* set connection socket to SSL state */
		SSL_set_fd(ssl, client);
		/* service connection */
 		serverlet(client, ssl);

		SSL_free(ssl);
		/* close connection */
		close(client);
	}
	/* close server socket */
	close(server);
	/* release context */
	SSL_CTX_free(ctx);
	cleanup_openssl();
end:
	return;
}
