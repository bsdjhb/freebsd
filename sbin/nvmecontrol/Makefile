
.include <src.opts.mk>

PACKAGE=nvme-tools
PROG=	nvmecontrol
SRCS=	comnd.c nvmecontrol.c
SRCS+=	devlist.c discover.c firmware.c format.c
SRCS+=	identify.c logpage.c ns.c nsid.c
SRCS+=	perftest.c power.c reset.c resv.c sanitize.c
SRCS+=	passthru.c
SRCS+=	identify_ext.c nvme_util.c nc_util.c
SRCS+=  selftest.c
CFLAGS+= -I${SRCTOP}/lib/libnvmf
MAN=	nvmecontrol.8
LDFLAGS+= -rdynamic
LIBADD+= nvmf util
SUBDIR=	modules
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.PATH:	${SRCTOP}/sys/dev/nvme

.include <bsd.prog.mk>
.include <bsd.subdir.mk>
