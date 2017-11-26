FROM alpine:3.6

ENV DIRPATH /ktls

RUN apk update && apk add --no-cache alpine-sdk openssl openssl-dev cppcheck
RUN mkdir ${DIRPATH}

COPY . ${DIRPATH}

WORKDIR ${DIRPATH}
RUN make
