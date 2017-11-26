#ifndef KTLS_EXAMPLE_H
#define KTLS_EXAMPLE_H

#define _GNU_SOURCE
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

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/modes.h>
#include <openssl/aes.h>

#define SOL_TLS		282
#define SOL_TCP		6

/* TLS socket options */
#define TLS_TX			1	/* Set transmit parameters */
#define TCP_ULP			31

/* Supported versions */
#define TLS_VERSION_MINOR(ver)	((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver)	(((ver) >> 8) & 0xFF)

#define TLS_VERSION_NUMBER(id)	((((id##_VERSION_MAJOR) & 0xFF) << 8) |	\
				 ((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_2_VERSION_MAJOR	0x3
#define TLS_1_2_VERSION_MINOR	0x3
#define TLS_1_2_VERSION		TLS_VERSION_NUMBER(TLS_1_2)

/* Supported ciphers */
#define TLS_CIPHER_AES_GCM_128				51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE			8
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE		16
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE		4
#define TLS_CIPHER_AES_GCM_128_TAG_SIZE		16
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE		8

#define TLS_SET_RECORD_TYPE	1

struct tls_crypto_info {
	unsigned short version;
	unsigned short cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

/* Opaque OpenSSL structures to fetch keys */
#define u64 uint64_t
#define u32 uint32_t
#define u8 uint8_t

typedef struct {
	u64 hi, lo;
} u128;

typedef struct {
	/* Following 6 names follow names in GCM specification */
	union {
		u64 u[2];
		u32 d[4];
		u8 c[16];
		size_t t[16 / sizeof(size_t)];
	} Yi, EKi, EK0, len, Xi, H;
	/*
	 * Relative position of Xi, H and pre-computed Htable is used in some
	 * assembler modules, i.e. don't change the order!
	 */
#if TABLE_BITS==8
	u128 Htable[256];
#else
	u128 Htable[16];
	void (*gmult) (u64 Xi[2], const u128 Htable[16]);
	void (*ghash) (u64 Xi[2], const u128 Htable[16], const u8 *inp, size_t len);
#endif
	unsigned int mres, ares;
	block128_f block;
	void *key;
} gcm128_context_alias;


/* ref: http://docs.huihoo.com/doxygen/openssl/1.0.1c/e__aes_8c_source.html */
typedef struct {
	union {
		double align;
		AES_KEY ks;
	} ks;                       /* AES key schedule to use */
	int key_set;                /* Set if key initialised */
	int iv_set;                 /* Set if an iv is set */
	gcm128_context_alias gcm;
	unsigned char *iv;          /* Temporary IV store */
	int ivlen;                  /* IV length */
	int taglen;
	int iv_gen;                 /* It is OK to generate IVs */
	int tls_aad_len;            /* TLS AAD length */
	ctr128_f ctr;
} EVP_AES_GCM_CTX;


extern void init_openssl(void);
extern void clean_openssl(void);
extern int load_certificates(SSL_CTX* ctx, char *cert_file, char *key_file);

extern int setup_ktls(int client, SSL *ssl);
extern int create_ktls_server(int port);
extern int create_connection(char *host, int port);

extern int do_sendfile(int client, char *file, SSL* ssl);
extern int do_splice(int client, char *file, SSL* ssl);
extern int do_recv(int server, SSL *ssl, char *orig_file);

extern int checksum(char *file1, char *file2);
extern SSL_CTX* init_server_ctx(void);

#endif
