#/bin/sh

BIN="ktls_splice ktls_sendfile ktls_send ssl_sslwrite"
HOST="127.0.0.1"
FILE=".dd.ktls.test"

echo "start to test..."

dd if=/dev/zero of=${FILE} bs=1M count=4096

for b in ${BIN}; do
	sync
	./${b} ${HOST} ${FILE}
done

rm -f ${FILE}

echo "end the tests"
