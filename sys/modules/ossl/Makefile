# $FreeBSD$

.PATH:	${SRCTOP}/sys/crypto/openssl
.PATH:	${SRCTOP}/sys/crypto/openssl/${MACHINE_CPUARCH}

KMOD=	ossl
SRCS=	ossl.c \
	ossl_sha1.c \
	ossl_sha256.c \
	ossl_sha512.c \
	sha1-x86_64.S \
	sha256-x86_64.S \
	sha512-x86_64.S

.include <bsd.kmod.mk>
