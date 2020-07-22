# $FreeBSD$

.if ${COMPILER_TYPE} == "gcc"
# GCC 9 requires functions from libcompiler_rt.
LIBADD+=	compiler_rt
.endif
CFLAGS+=	${CFLAGS_NO_SIMD} -msoft-float -fvisibility=hidden
