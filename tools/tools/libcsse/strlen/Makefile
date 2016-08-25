.PATH: ${.CURDIR}/../../../../lib/libc/amd64/string
.PATH: ${.CURDIR}/../../../../lib/libc/string

PROG=	strlen
MAN=

SRCS=	main.c strlen.S strlen_mi.c

strlen_mi.c: strlen.c
	sed -e 's/strlen/strlen_mi/' ${.ALLSRC} > ${.TARGET}

CLEANFILES+= strlen_mi.c

.include <bsd.prog.mk>
