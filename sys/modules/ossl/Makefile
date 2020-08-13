# $FreeBSD$

.PATH:	${SRCTOP}/sys/crypto/openssl
.PATH:	${SRCTOP}/sys/crypto/openssl/${MACHINE_CPUARCH}

KMOD=	ossl
SRCS=	ossl.c \
	ossl_sha1.c \
	sha1-x86_64.S

.include <bsd.kmod.mk>
