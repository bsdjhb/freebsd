#
# $FreeBSD$
#

CXGBE=	${SRCTOP}/sys/dev/cxgbe
.PATH: ${CXGBE}/crypto

KMOD=	t4_kern_tls
SRCS=	opt_kern_tls.h
SRCS+=	t4_kern_tls.c

CFLAGS+= -I${CXGBE}

.include <bsd.kmod.mk>

