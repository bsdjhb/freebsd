PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/opencrypto
BINDIR=		${TESTSDIR}

CFLAGS+=	-I${SRCTOP}/tests
CFLAGS.blake2_test.c	+= -I${SRCTOP}/sys/opencrypto
CFLAGS.blake2_test.c	+= -I${SRCTOP}/sys/contrib/libb2
CFLAGS.poly1305_test.c	+= -I${SRCTOP}/sys/opencrypto

ATF_TESTS_C+=	blake2_test poly1305_test

TAP_TESTS_SH+=	runtests

TEST_METADATA.runtests+= required_programs="python3"
TEST_METADATA.runtests+= required_user="root"

PYMODULES=	cryptodev.py cryptodevh.py cryptotest.py

${PACKAGE}FILES+=	${PYMODULES}

.include <bsd.test.mk>
