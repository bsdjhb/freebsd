.PATH:  ${SRCTOP}/sys/libkern

LIB=		nvmf
INTERNALLIB=
PACKAGE=	nvmf

INCS=		libnvmf.h

SRCS=		gsb_crc32.c \
		nvmf.c \
		nvmf_host.c \
		nvmf_tcp.c

.include <bsd.lib.mk>

CWARNFLAGS.gsb_crc32.c=	-Wno-cast-align
