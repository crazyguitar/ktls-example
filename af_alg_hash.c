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

int main(int argc, char *argv[])
{

	int rc = -1, tfmfd = -1, opfd = -1, len = 0;
	char buf[20] = {};
	char *msg = NULL;

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha1"
	};

	if (argc != 2) {
		perror("usage: cmd msg");
		goto end;
	}

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd < 0) {
		perror("Unable to create socket");
		goto end;
	}

	rc = bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc < 0) {
		perror("Unable to bind");
		goto end;
	}

	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		perror("Unable to accept");
		goto end;
	}

	msg = argv[1];
	len = strlen(msg);

	rc = write(opfd, msg, len);
	if (rc < 0) {
		perror("Unable to write");
		goto end;
	}

	rc = read(opfd, buf, sizeof(buf));
	if (rc < 0) {
		perror("Unable to read");
		goto end;
	}

	int i = 0;

	for (i = 0; i < sizeof(buf); i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");

	rc = 0;
end:
	if (tfmfd >= 0)
		close(tfmfd);

	if (opfd >= 0)
		close(opfd);

	return rc;
}
