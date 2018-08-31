#
# $FreeBSD$
#

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

SUBDIR=	if_cxgbe
SUBDIR+=	if_cxl
SUBDIR+=	if_cc
SUBDIR+=	if_cxgbev
SUBDIR+=	if_cxlv
SUBDIR+=	if_ccv
SUBDIR+=	t4_firmware
SUBDIR+=	t5_firmware
SUBDIR+=	t6_firmware
SUBDIR+=	${_tom}
SUBDIR+=	${_iw_cxgbe}
SUBDIR+=	${_cxgbei}
SUBDIR+=	ccr
SUBDIR+=	${_kern_tls}

.if ${MACHINE_CPUARCH} == "amd64"
_tom=	tom
_kern_tls=	kern_tls
_cxgbei=	cxgbei
.if ${MK_OFED} != "no" || defined(ALL_MODULES)
_iw_cxgbe=	iw_cxgbe
.endif
.endif

.if ${MACHINE_CPUARCH} == "i386"
_tom=	tom
_kern_tls=	kern_tls
.endif

.include <bsd.subdir.mk>
