FROM ubuntu:16.04

ENV DIRPATH /ktls

RUN apt-get update && apt-get install -y build-essential openssl libssl-dev pkg-config cppcheck
RUN mkdir ${DIRPATH}

COPY . ${DIRPATH}

WORKDIR ${DIRPATH}
RUN make
