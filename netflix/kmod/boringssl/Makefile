# BORINGDIR=${.CURDIR}/dist

CFLAGS+=-I${BORINGDIR} -DKERN_TLS
DEBUG_FLAGS=	-g
MK_KERNEL_SYMBOLS= yes


.PATH:	${BORINGDIR}
KMOD=	boring
SRCS=	aead.c			\
	aes-x86_64.S		\
	aes.c			\
	aesni-gcm-x86_64.S	\
	aesni-x86_64.S		\
	bcrypto.c		\
	bmem.c			\
	bsaes-x86_64.S		\
	bsha1.c			\
	bsha256.c		\
	cbc.c			\
	cfb.c			\
	chacha_generic.c	\
	chacha_vec.c		\
	cipher.c		\
	cpu-intel.c		\
	cpu-x86_64-asm.S	\
	ctr.c			\
	des.c			\
	digest.c		\
	digests.c		\
	e_aes.c			\
	e_des.c			\
	e_tls.c			\
	gcm.c			\
	ghash-x86_64.S		\
	hmac.c			\
	md5-x86_64.S		\
	md5.c			\
	mode_wrappers.c		\
	ofb.c			\
	rand.c			\
	sha1-x86_64.S		\
	sha512-x86_64.S		\
	sha512.c		\
	sha256-x86_64.S		\
	tls_cbc.c		\
	vpaes-x86_64.S		\
	boring_kern.c


# This requres special compiler flags (below), but is currently
# unused.
#	e_chacha20poly1305.c 	\
#	poly1305.c 		\
#	poly1305_vec.c
# COPTS.poly1305.c+= -O3 -nostdinc -mhard-float -Wno-cast-qual -mmmx -msse -msse2 -msse4 -maes -mpclmul

.include <bsd.kmod.mk>
