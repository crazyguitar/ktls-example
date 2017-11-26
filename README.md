# KTLS example

[![Build Status](https://travis-ci.org/crazyguitar/ktls-example.svg?branch=master)](https://travis-ci.org/crazyguitar/ktls-example)

## Prerequisite

* linux 4.13 or above
* openssl 1.0.x

## Generate self-signed certificate

```bash
$ openssl ecparam -out key.pem -genkey -name prime256v1
$ openssl req -x509 -new -key key.pem -out cert.pem
```

## Run the binaries

```bash
$ make
$ dd if=/dev/zero of=.dd.test bs=1M count=512
$ ./ktls_sendfile 127.0.0.1 .dd.test 
start do_sendfile(.dd.test)
sendfile cost time: 2.27
end do_sendfile(.dd.test)
checksum(.TMP_ktls): aa559b4e3523a6c931f08f4df52d58f2
checksum(.dd.test): aa559b4e3523a6c931f08f4df52d58f2 
```

## Reference

* [djwatson/ktls](https://github.com/djwatson/ktls)
* [ktls/afi\_ktls-tool](https://github.com/ktls/af_ktls-tool)
* [include/uapi/linux/tls.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/tls.h)
* [linux/Documentation/networking/tls.txt](https://github.com/torvalds/linux/blob/master/Documentation/networking/tls.txt)
* [TLS: Linux Kernel Transport Layer Security - NetDev](https://netdevconf.org/1.2/papers/ktls.pdf)
* [Playing with kernel TLS in Linux 4.13 and Go - Filippo.io](https://blog.filippo.io/playing-with-kernel-tls-in-linux-4-13-and-go/)
