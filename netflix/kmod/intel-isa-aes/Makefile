#
# Copyright (c) 2016 Netflix, Inc
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer,
#    without modification.
# 2. Redistributions in binary form must reproduce at minimum a disclaimer
#    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
#    redistribution must be conditioned upon including a substantially
#    similar Disclaimer requirement for further binary redistribution.
#
# NO WARRANTY
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGES.
#
# $FreeBSD$
#

# ISASRC=${.CURDIR}/dist
ISAINC=${ISASRC}/include
ISAAES=${ISASRC}/aes
INCS=-I${ISAINC} -I${ISAAES}
CFLAGS+=${INCS} -DKERN_TLS
WITHOUT_FORMAT_EXTENSIONS=nope
DEBUG_FLAGS= -g
MK_KERNEL_SYMBOLS= yes
.if exists(${SRCTOP}/../.obj/nano.nflx/_.w/usr/local/bin/yasm)
YASM?=${SRCTOP}/../.obj/nano.nflx/_.w/usr/local/bin/yasm
.else
YASM?=/usr/local/bin/yasm
.endif

.PATH: ${ISASRC}/aes
.SUFFIXES: .asm
.asm.o:
	${YASM} -g dwarf2 -f elf64 ${INCS} -o ${.TARGET} ${ISAAES}/${.PREFIX}.asm

KMOD=	intel-isa-aes
SRCS=	XTS_AES_128_dec_avx.asm \
	XTS_AES_128_dec_expanded_key_avx.asm \
	XTS_AES_128_dec_expanded_key_sse.asm \
	XTS_AES_128_dec_sse.asm \
	XTS_AES_128_enc_avx.asm \
	XTS_AES_128_enc_expanded_key_avx.asm \
	XTS_AES_128_enc_expanded_key_sse.asm \
	XTS_AES_128_enc_sse.asm \
	XTS_AES_256_dec_avx.asm \
	XTS_AES_256_dec_expanded_key_avx.asm \
	XTS_AES_256_dec_expanded_key_sse.asm \
	XTS_AES_256_dec_sse.asm \
	XTS_AES_256_enc_avx.asm \
	XTS_AES_256_enc_expanded_key_avx.asm \
	XTS_AES_256_enc_expanded_key_sse.asm \
	XTS_AES_256_enc_sse.asm \
	cbc_dec_128_x4_sse.asm \
	cbc_dec_128_x8_avx.asm \
	cbc_dec_192_x4_sse.asm \
	cbc_dec_192_x8_avx.asm \
	cbc_dec_256_x4_sse.asm \
	cbc_dec_256_x8_avx.asm \
	cbc_enc_128_x4_sb.asm \
	cbc_enc_128_x8_sb.asm \
	cbc_enc_192_x4_sb.asm \
	cbc_enc_192_x8_sb.asm \
	cbc_enc_256_x4_sb.asm \
	cbc_enc_256_x8_sb.asm \
	cbc_multibinary.asm \
	gcm128_avx_gen2.asm \
	gcm128_avx_gen4.asm \
	gcm128_sse.asm \
	gcm256_avx_gen2.asm \
	gcm256_avx_gen4.asm \
	gcm256_sse.asm \
	gcm_multibinary.asm \
	gcm128_avx_gen2_nt.asm \
	gcm128_avx_gen4_nt.asm \
	gcm128_sse_nt.asm \
	gcm256_avx_gen2_nt.asm \
	gcm256_avx_gen4_nt.asm \
	gcm256_sse_nt.asm \
	gcm_multibinary_nt.asm \
	keyexp_128.asm \
	keyexp_192.asm \
	keyexp_256.asm \
	keyexp_multibinary.asm \
	xts_aes_128_multibinary.asm \
	xts_aes_256_multibinary.asm \
	cbc_pre.c \
	gcm_pre.c \
	intelisa_kern.c

.include <bsd.kmod.mk>
