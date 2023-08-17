.include <src.opts.mk>
.PATH:  ${SRCTOP}/sys/libkern

PACKAGE=nvme-tools
PROG=	nvmfd
SRCS=	nvmfd.c controller.c devices.c discovery.c gsb_crc32.c io.c
CFLAGS+= -I${SRCTOP}/lib/libnvmf
MAN=
LIBADD+= nvmf pthread util

.include <bsd.prog.mk>

CWARNFLAGS.gsb_crc32.c=	-Wno-cast-align
