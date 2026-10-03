PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/cam/ctl/nvmft
BINDIR=${TESTSDIR}

${PACKAGE}FILES+=	ctl.conf
${PACKAGE}FILESMODE_ctl.conf= 440

ATF_TESTS_C+=	nvmft
ATF_TESTS_SH+=	shutdown

PROGS+=		nvmf_shutdown
LIBADD+=	nvmf
CFLAGS+=	-I${SRCTOP}/lib/libnvmf

shutdown.sh: shutdown.head.sh shutdown.simple.sh shutdown.reenable.sh
	cp ${.CURDIR}/shutdown.head.sh ${.TARGET}.tmp
.for mode in normal abrupt close reset
	sed -e "s,%%MODE%%,${mode}," ${.CURDIR}/shutdown.simple.sh >> \
	    ${.TARGET}.tmp
.endfor
	# close doesn't support reenable
.for mode in normal abrupt reset
.for rmode in normal abrupt close reset
	sed -e "s,%%MODE%%,${mode}," -e "s,%%RMODE%%,${rmode}," \
	    ${.CURDIR}/shutdown.reenable.sh >> ${.TARGET}.tmp
.endfor
.endfor
	echo "" >> ${.TARGET}.tmp
	echo "atf_init_test_cases()" >> ${.TARGET}.tmp
	echo "{" >> ${.TARGET}.tmp
.for mode in normal abrupt close reset
	echo "	atf_add_test_case ${mode}" >> ${.TARGET}.tmp
	echo "	atf_add_test_case ${mode}_short_delay" >> ${.TARGET}.tmp
	echo "	atf_add_test_case ${mode}_long_delay" >> ${.TARGET}.tmp
.endfor
.for mode in normal abrupt reset
.for rmode in normal abrupt close reset
	echo "	atf_add_test_case ${mode}_${rmode}" >> ${.TARGET}.tmp
	echo "	atf_add_test_case ${mode}_${rmode}_short_delay" >> \
	    ${.TARGET}.tmp
	echo "	atf_add_test_case ${mode}_${rmode}_long_delay" >> ${.TARGET}.tmp
.endfor
.endfor
	echo "}" >> ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

.include <bsd.test.mk>
