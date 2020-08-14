# $FreeBSD$

.PATH:	${SRCTOP}/sys/crypto/ossl ${SRCTOP}/secure/lib/libcrypto/amd64

KMOD=	ossl
SRCS=	ossl.c \
	ossl_sha1.c \
	ossl_sha256.c \
	sha1-x86_64.S \
	sha256-x86_64.S

.include <bsd.kmod.mk>
