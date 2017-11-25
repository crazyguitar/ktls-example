#include <sys/sendfile.h>
#include <openssl/md5.h>

#include "ktls_server.h"

#define PORT 4433

static void init_openssl()
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_ssl_algorithms();
}

static void clean_openssl()
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
		perror("Unable to SSL_CTX_new");
		ERR_print_errors_fp(stderr);
	}
	return ctx;
}

static int load_certificates(SSL_CTX* ctx, char *cert_file, char *key_file)
{
	int rc = -1;

	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (SSL_CTX_check_private_key(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	rc = 0;
end:
	return rc;
}

static int setup_ktls(int client, SSL *ssl)
{
	int rc = -1;
	struct tls12_crypto_info_aes_gcm_128 crypto_info;

	bzero(&crypto_info, sizeof(crypto_info));

	EVP_CIPHER_CTX * write_ctx = ssl->enc_write_ctx;
	EVP_AES_GCM_CTX* gcm_write = (EVP_AES_GCM_CTX*)(write_ctx->cipher_data);

	unsigned char* key_write = (unsigned char*)(gcm_write->gcm.key);
	unsigned char* iv_write = gcm_write->iv;
	unsigned char* seq_number_write = ssl->s3->write_sequence;

	crypto_info.info.version = TLS_1_2_VERSION;
	crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;


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

static int create_ktls_server(int port)
{
	int fd = -1, rc = -1;
	struct sockaddr_in addr;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	rc = bind(fd, (const struct sockaddr*)&addr, sizeof(addr));
	if (rc < 0) {
		perror("Unable to bind");
		goto end;
	}

	rc = listen(fd, 10);
	if (rc < 0) {
		perror("Unable to listen");
		goto end;
	}
	rc = 0;
end:
	if (rc < 0 && fd >= 0) {
		close(fd);
		fd = -1;
	}
	return fd;
}

static int create_connection(char *host, int port)
{
	int fd = -1, rc = -1;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) goto end;

	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(host);

	rc = connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if (rc < 0) {
		perror("Connect: ");
		goto end;
	}
end:
	if (rc < 0 && fd >= 0) {
		close(fd);
		fd = -1;
	}
	return fd;

}


#define CRT_PEM "cert.pem"
#define KEY_PEM "key.pem"

static int do_sendfile(int client, char *file, SSL* ssl)
{
	int rc = -1, fd = -1;
	struct stat st;
	clock_t start = 0, end = 0;
	double cpu_time_used = 0.;

	printf("start do_sendfile(%s)\n", file);

	if (SSL_accept(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	if (setup_ktls(client, ssl) <0) {
		ERR_print_errors_fp(stderr);
		goto end;
	}

	fd = open(file, O_RDONLY);
	if (fd < 0) goto end;

	if (fstat(fd, &st) < 0)  goto end;

	off_t totalbyte = st.st_size;
	off_t offset = 0;
	ssize_t sent = 0;

	end = clock();
	sent = sendfile(client, fd, &offset, totalbyte);
	end = clock();
	if (sent != totalbyte) goto end;

	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("sendfile cost time: %.02f\n", cpu_time_used);

	rc = 0;
end:
	if (fd > 0) close(fd);

	printf("end do_sendfile(%s)\n", file);

	return rc;
}

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

		rc = do_sendfile(client, file, ssl);
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

int checksum(char *file1, char *file2)
{
	int i = 0, j = 0, rc = -1;
	unsigned char c1[MD5_DIGEST_LENGTH] = {};
	unsigned char c2[MD5_DIGEST_LENGTH] = {};

	FILE *f1 = NULL;
	FILE *f2 = NULL;

	f1 = fopen(file1, "rb");
	if (!f1) goto end;

	f2 = fopen(file2, "rb");
	if (!f2) goto end;

	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);

	size_t bytes = 0;
	unsigned char buf[BUFSIZ] = {};
	while ((bytes = fread (buf, 1, sizeof(buf), f1)) != 0) {
		MD5_Update(&md5_ctx, buf, bytes);
	}
	MD5_Final(c1, &md5_ctx);

	bzero(&buf, sizeof(buf));

	MD5_Init(&md5_ctx);
	while ((bytes = fread (buf, 1, sizeof(buf), f2)) != 0) {
		MD5_Update(&md5_ctx, buf, bytes);
	}
	MD5_Final(c2, &md5_ctx);

	printf("checksum(%s): ", file1);
	for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", c1[i]);
	printf("\n");

	printf("checksum(%s): ", file2);
	for(i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", c2[i]);
	printf("\n");

	for (i=0, j=0; i<MD5_DIGEST_LENGTH && j<MD5_DIGEST_LENGTH; i++, j++) {
		if (c1[i] != c2[j]) goto end;
	}

	rc = 0;
end:
	return  rc;
}

int do_recv(int server, SSL *ssl, char *orig_file)
{
	int fd = -1, rc = -1;
	char tmpfile[] = ".TMP_ktls";

	mode_t mode = S_IRWXU | S_IRUSR | S_IROTH;
	fd = open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC, mode);

	if (fd < 0) goto end;

	SSL_set_fd(ssl, server);

	if ( SSL_connect(ssl) != 1 ) {
		ERR_print_errors_fp(stderr);
		goto end;
	}


	char buf[BUFSIZ] = {};
	int recv = 0;


	do {
		recv = SSL_read(ssl, buf, sizeof(buf));
		if (recv < 0) {
			ERR_print_errors_fp(stderr);
			goto end;
		}

		rc  = write(fd, buf, recv);
		if (rc < 0) {
			fprintf(stderr, "write(%s) failed. %s\n", tmpfile, strerror(errno));
			goto end;
		}

	} while(recv > 0);

	if (checksum(tmpfile, orig_file) != 0) {
		fprintf(stderr, "checksum(%s, %s) failed.", tmpfile, orig_file);
		goto end;
	}

	rc = 0;
end:
	if (fd >= 0) close(fd);

	if (unlink(tmpfile) < 0) {
		fprintf(stderr, "unlink(%s) failed. %s\n", tmpfile, strerror(errno));
	}

	return 0;
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
