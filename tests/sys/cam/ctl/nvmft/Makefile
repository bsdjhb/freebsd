PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/cam/ctl/nvmft
BINDIR=${TESTSDIR}

${PACKAGE}FILES+=	README ctl.conf
${PACKAGE}FILESMODE_ctl.conf= 440

ATF_TESTS_SH+=	shutdown

PROGS+=		nvmf_shutdown
LIBADD+=	nvmf
CFLAGS+=	-I${SRCTOP}/lib/libnvmf

.include <bsd.test.mk>
