#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define KEY_SIZE 16
#define IV_SIZE 16


int get_random_bytes(char *buf, size_t count)
{
	int rc = -1;
	int fd = -1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("Unable to open /dev/urandom");
		goto end;
	}
	rc = read(fd, buf, count);
	if (rc < 0) {
		perror("Unable to read from /dev/urandom");
		goto end;
	}
	rc = 0;
end:
	if (fd > 0)
		close(fd);

	return rc;
}

int create_af_alg(struct sockaddr_alg *sa, char *key_buf)
{
	int rc = -1, tfmfd = -1;

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);

	if (tfmfd < 0) {
		perror("Unable to create socket");
		goto end;
	}

	rc = bind(tfmfd, (struct sockaddr *)sa, sizeof(*sa));
	if (rc < 0) {
		perror("Unable to bind");
		goto end;
	}

	rc = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key_buf, KEY_SIZE);
	if (rc < 0) {
		perror("Unable to setsockopt");
		goto end;
	}
	rc = 0;
end:
	if (rc < 0 && tfmfd >= 0) {
		close(tfmfd);
		tfmfd = -1;
	}
	return tfmfd;
}

int sendmsg_af_alg(int opfd, char *data, int count, int op, char *iv_buf)
{
	int rc = -1;
	struct msghdr msg = {};
	struct cmsghdr *cmsg = NULL;
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {};
	struct af_alg_iv *iv = NULL;
	struct iovec iov = {};
	unsigned int *ptr = NULL;

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL) {
		perror("unexpected NULL result from CMSG_FIRSTHDR");
		goto end;
	}

	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	ptr = (unsigned int *) CMSG_DATA(cmsg);
	*ptr = (unsigned int) op;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	if (cmsg == NULL) {
		perror("unexpected NULL result from CMSG_NXTHDR");
		goto end;
	}

	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);
	iv = (void *)CMSG_DATA(cmsg);
	iv->ivlen = IV_SIZE;

	memcpy(iv->iv, iv_buf, IV_SIZE);

	iov.iov_base = data;
	iov.iov_len = count;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = sendmsg(opfd, &msg, 0);
	if (rc < 0) {
		perror("sendmsg failed");
		goto end;
	}

	rc = 0;
end:
	return rc;
}

int encrypt(char *plaintext, char *buf, size_t count, char *key_buf, char *iv_buf)
{
	int rc = -1, opfd = -1, tfmfd = -1;

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(aes)"
	};

	tfmfd = create_af_alg(&sa, key_buf);
	if (tfmfd < 0) {
		goto end;
	}


	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		perror("Unable to accept");
		goto end;
	}

	rc = sendmsg_af_alg(opfd, plaintext, count, ALG_OP_ENCRYPT, iv_buf);
	if (rc < 0) {
		perror("sendmsg failed");
		goto end;
	}

	rc = read(opfd, buf, 16);
	if (rc < 0) {
		perror("read encrypt data failed");
		goto end;
	}

end:
	if (opfd >= 0)
		close(opfd);

	if (tfmfd >= 0)
		close(tfmfd);

	return rc;
}

int decrypt(char *ciphertext, char *buf, size_t count, char *key_buf, char *iv_buf)
{
	int rc = -1, opfd = -1, tfmfd = -1;

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(aes)"
	};

	tfmfd = create_af_alg(&sa, key_buf);
	if (tfmfd < 0) {
		goto end;
	}

	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		perror("Unable to accept");
		goto end;
	}

	rc = sendmsg_af_alg(opfd, ciphertext, count, ALG_OP_DECRYPT, iv_buf);
	if (rc < 0) {
		perror("sendmsg failed");
		goto end;
	}

	rc = read(opfd, buf, 16);
	if (rc < 0) {
		perror("read encrypt data failed");
		goto end;
	}

end:
	if (opfd >= 0)
		close(opfd);

	if (tfmfd >= 0)
		close(tfmfd);

	return rc;
}


int main(int argc, char *argv[])
{
	int rc = -1;
	char buf[16] = {};
	char key_buf[KEY_SIZE] = {};
	char iv_buf[IV_SIZE] = {};

	rc = get_random_bytes(key_buf, sizeof(key_buf));
	if (rc < 0) {
		goto end;
	}

	rc = get_random_bytes(iv_buf, sizeof(iv_buf));
	if (rc < 0) {
		goto end;
	}

	rc = encrypt("Single block msg", buf, 16, key_buf, iv_buf);
	if (rc < 0) {
		goto end;
	}

	int i = 0;

	for (i = 0; i < 16; i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");

	char out[32] = {};

	rc = decrypt(buf, out, 16, key_buf, iv_buf);
	if (rc < 0) {
		goto end;
	}

	printf("%s\n", out);

	rc = 0;
end:
	return rc;
}
