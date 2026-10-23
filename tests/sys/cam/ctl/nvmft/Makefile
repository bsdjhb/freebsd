PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/cam/ctl/nvmft
BINDIR=${TESTSDIR}

${PACKAGE}FILES+=	README ctl.conf
${PACKAGE}FILESMODE_ctl.conf= 440

ATF_TESTS_C+=	nvmft
ATF_TESTS_C+=	nvmft_tcp
ATF_TESTS_SH+=	shutdown

SRCS.nvmft=	nvmft.c nvmft_subr.c
SRCS.nvmft_tcp=	nvmft_tcp.c nvmft_subr.c

PROGS+=		nvmf_shutdown
LIBADD+=	nvmf
CFLAGS+=	-I${SRCTOP}/lib/libnvmf

.include <bsd.test.mk>
