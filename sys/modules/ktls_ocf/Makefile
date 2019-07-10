# $FreeBSD$

.PATH:	${SRCTOP}/sys/opencrypto

KMOD=	ktls_ocf
SRCS=	ktls_ocf.c

CFLAGS+= -DKERN_TLS

.include <bsd.kmod.mk>
