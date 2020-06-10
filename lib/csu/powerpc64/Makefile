# $FreeBSD$

.PATH: ${.CURDIR:H}/common

SRCS=		crt1.c crti.S crtn.S
OBJS=		${SRCS:N*.h:R:S/$/.o/g}
OBJS+=		crtsavres.o Scrt1.o gcrt1.o
CFLAGS+=	-I${.CURDIR} -I${.CURDIR:H}/common \
		-I${SRCTOP}/lib/libc/include \
		-mlongcall -DCRT_IRELOC_RELA

FILES=		${OBJS}
FILESMODE=	${LIBMODE}
FILESOWN=	${LIBOWN}
FILESGRP=	${LIBGRP}
FILESDIR=	${LIBDIR}
# These FILES qualify as libraries for the purpose of LIBRARIES_ONLY.
.undef LIBRARIES_ONLY

CLEANFILES=	${OBJS}
CLEANFILES+=	crtsavres.S

crt1.o: crt1.c
	${CC} ${CFLAGS} -c -o ${.TARGET} ${.CURDIR}/crt1.c

# On powerpc64 crtsavres is an empty file
crtsavres.S:
	touch ${.TARGET}

gcrt1.o: crt1.c
	${CC} ${CFLAGS} -DGCRT -c -o ${.TARGET} ${.CURDIR}/crt1.c

Scrt1.o: crt1.c
	${CC} ${CFLAGS} -fPIC -DPIC -c -o ${.TARGET} ${.CURDIR}/crt1.c

.include <bsd.lib.mk>
