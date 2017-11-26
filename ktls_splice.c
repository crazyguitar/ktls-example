#include <sys/sendfile.h>
#include <openssl/md5.h>

#include <ktls_server.h>

#define PORT 4433
#define CRT_PEM "cert.pem"
#define KEY_PEM "key.pem"


static void main_server(int port, char *file)
{
	int rc = -1, server = -1;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	init_openssl();

	ctx = init_server_ctx();
	if (!ctx) goto end;

	rc = load_certificates(ctx, CRT_PEM, KEY_PEM);
	if (rc < 0) goto end;

	rc = SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");
	if (rc != 1) goto end;

	server = create_ktls_server(port);
	if (server < 0) goto end;

	for (;;) {
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);
		int client = accept(server, (struct sockaddr*)&addr, &len);
		if (client < 0) goto end;

		ssl = SSL_new(ctx);
		if (!ssl) goto loop_done;

		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) != 1) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

		if (setup_ktls(client, ssl) <0) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

		rc = do_splice(client, file, ssl);
		if (rc < 0) goto loop_done;

	loop_done:
		SSL_free(ssl);
		if (client >= 0) close(client);
	}
end:
	if (server >= 0) close(server);

	SSL_CTX_free(ctx);
	clean_openssl();
	return;
}

void main_client(char *host, int port, char *orig_file)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int rc = -1, server = -1;

	init_openssl();

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx) goto end;

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	rc = SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");
	if (rc != 1) goto end;

	ssl = SSL_new(ctx);
	if (!ssl) goto end;

	server = create_connection(host, port);
	if (server < 0) goto end;

	rc = do_recv(server, ssl, orig_file);
	if (rc < 0) goto end;

end:
	if (server >= 0) close(server);

	SSL_CTX_free(ctx);
	clean_openssl();
	return;
}


int main(int argc, char *argv[])
{
	char *host = NULL;
	char *file = NULL;
	pid_t pid;

	if (argc != 3) {
		perror("usage: ./ktls_sendfile host file");
		exit(EXIT_FAILURE);
	}

	host = argv[1];
	file = argv[2];

	pid = fork();

	if (pid == 0) {
		sleep(3);
		main_client(host, PORT, file);
	} else {
		main_server(PORT, file);
	}

	return 0;
}
