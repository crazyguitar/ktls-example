#include <ktls_server.h>

#define PORT 4433

static void serverlet(int client, SSL* ssl)/* Serve the connection -- threadable */
{
	char buf[16384];
	int bytes = 0;

	if ( SSL_accept(ssl) == -1 ) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (setup_ktls(client, ssl) < 0) {
		perror("setup_ktls failed");
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

static void ssl_main_server(int port)
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
	int server = create_ktls_server(port);
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
	clean_openssl();
end:
	return;
}

int main(int argv, char* argc[])
{
	ssl_main_server(PORT);

	return 0;
}
