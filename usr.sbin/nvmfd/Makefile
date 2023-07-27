.include <src.opts.mk>

PACKAGE=nvme-tools
PROG=	nvmfd
SRCS=	nvmfd.c controller.c devices.c discovery.c io.c
CFLAGS+= -I${SRCTOP}/lib/libnvmf
MAN=
LIBADD+= nvmf pthread util

.include <bsd.prog.mk>
