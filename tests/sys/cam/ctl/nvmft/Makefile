PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/cam/ctl/nvmft
BINDIR=${TESTSDIR}

${PACKAGE}FILES+=	ctl.conf
${PACKAGE}FILESMODE_ctl.conf= 440
${PACKAGE}FILES+=	ctld.subr

ATF_TESTS_SH+=	shutdown

PROGS+=		nvmf_shutdown
LIBADD+=	nvmf
CFLAGS+=	-I${SRCTOP}/lib/libnvmf

# Must be exclusive because it starts/stops a ctld daemon
TEST_METADATA+=	is_exclusive="true"

.include <bsd.test.mk>
