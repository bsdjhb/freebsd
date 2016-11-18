.PATH: ${.CURDIR}/../../../../lib/libc/amd64/string

PROG=	memcpy
MAN=

SRCS=	main.c memcpy.S

CFLAGS+= -fno-builtin-memcpy -Dmemcpy_default=memcpy_plain

.include <bsd.prog.mk>
