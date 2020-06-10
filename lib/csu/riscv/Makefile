# $FreeBSD$

.PATH: ${.CURDIR:H}/common

SRCS=		crt1.c crti.S crtn.S
OBJS=		${SRCS:N*.h:R:S/$/.o/g}
OBJS+=		Scrt1.o gcrt1.o
CFLAGS+=	-I${.CURDIR:H}/common \
		-I${SRCTOP}/lib/libc/include
CFLAGS+=	-DCRT_IRELOC_SUPPRESS

FILES=		${OBJS}
FILESMODE=	${LIBMODE}
FILESOWN=	${LIBOWN}
FILESGRP=	${LIBGRP}
FILESDIR=	${LIBDIR}
# These FILES qualify as libraries for the purpose of LIBRARIES_ONLY.
.undef LIBRARIES_ONLY

CLEANFILES=	${OBJS}

gcrt1.o: crt1.c
	${CC} ${CFLAGS} -DGCRT -c -o ${.TARGET} ${.CURDIR}/crt1.c

Scrt1.o: crt1.c
	${CC} ${CFLAGS} -fPIC -DPIC -c -o ${.TARGET} ${.CURDIR}/crt1.c

.include <bsd.lib.mk>
