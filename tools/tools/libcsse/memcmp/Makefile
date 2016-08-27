.PATH: ${.CURDIR}/../../../../lib/libc/amd64/string

PROG=	memcmp
MAN=

SRCS=	main.c memcmp.S

CFLAGS+= -fno-builtin-memcmp

.include <bsd.prog.mk>
