#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <sys/times.h>
#include <sys/sendfile.h>

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

int main_tls_client(void);

int main(int argv, char* argc[])
{

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* load all error messages */
	SSL_load_error_strings();

	main_tls_client();

	return 0;
}

int create_socket(char *host, int port) 
{
	int sockfd;
	struct sockaddr_in dest_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&(dest_addr), '\0', sizeof(dest_addr));
	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = inet_addr(host);


	if ( connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr_in)) == -1 ) {
  		perror("Connect: ");
 		exit(-1);
	}

	return sockfd;
}


int main_tls_client()
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int server = 0;

	if ( (ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
   		printf("Unable to create a new SSL context structure.\n");
		exit(-1);
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

	// Force gcm(aes) mode
	SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");

	ssl = SSL_new(ctx);

	server = create_socket("127.0.0.1", 4433);

	SSL_set_fd(ssl, server);

	if ( SSL_connect(ssl) != 1 ) {
 		printf("Error: Could not build a SSL session\n");
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	// Start tests
	char buf[BUFSIZ] = "Hello openssl client";
	int res = 0;

	printf("send(%s)\n", buf);
	res = SSL_write(ssl, buf, sizeof(buf));
	if (res < 0) {
		printf("SSL Read error: %i\n", res);
	}

	bzero(buf, sizeof(buf));
	res = SSL_read(ssl, buf, sizeof(buf));
	if (res < 0) {
		printf("SSL Read error: %i\n", res);
	}
	printf("recv(%s)\n", buf);

	SSL_free(ssl);
	close(server);
	SSL_CTX_free(ctx);
	return 0;
}
