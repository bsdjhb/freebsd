/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from locore.s.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#if 0
	RCSID("$NetBSD: bcopy.S,v 1.2 2003/08/07 16:42:36 agc Exp $")
#endif

	/*
	 * (ov)bcopy (src,dst,cnt)
	 *  ws@tools.de     (Wolfgang Solfrank, TooLs GmbH) +49-228-985800
	 */

#ifdef MEMCOPY
ENTRY(memcpy)
#else
#ifdef MEMMOVE
ENTRY(memmove)
#else
ENTRY(bcopy)
#endif
#endif
#if defined(MEMCOPY) || defined(MEMMOVE)
	movq	%rdi,%rax	/* return dst */
#else
	xchgq	%rdi,%rsi
#endif
	movq	%rdx,%rcx
	movq	%rdi,%r8
	subq	%rsi,%r8
	cmpq	%rcx,%r8	/* overlapping? */
	jb	1f
	cld			/* nope, copy forwards. */
	shrq	$3,%rcx		/* copy by words */
	rep
	movsq
	movq	%rdx,%rcx
	andq	$7,%rcx		/* any bytes left? */
	rep
	movsb
	ret
1:
	addq	%rcx,%rdi	/* copy backwards. */
	addq	%rcx,%rsi
	std
	andq	$7,%rcx		/* any fractional bytes? */
	decq	%rdi
	decq	%rsi
	rep
	movsb
	movq	%rdx,%rcx	/* copy remainder by words */
	shrq	$3,%rcx
	subq	$7,%rsi
	subq	$7,%rdi
	rep
	movsq
	cld
	ret
#ifdef MEMCOPY
END(memcpy)
#else
#ifdef MEMMOVE
END(memmove)
#else
END(bcopy)
#endif
#endif

/*
 * On CPUs with SSE 4.2, movups of an aligned block seems to be use the
 * same time as movaps of an aligned block.  On older CPUs, movups is
 * much slower.  The sse2_aligned variants use a separate block copy
 * using movaps for aligned copies.  The sse2_unaligned variants
 * always use movups instead.
 */
#ifdef MEMCOPY
ENTRY(memcpy_sse2_aligned)
#else
#ifdef MEMMOVE
ENTRY(memmove_sse2_aligned)
#else
ENTRY(bcopy_sse2_aligned)
#endif
#endif
#if defined(MEMCOPY) || defined(MEMMOVE)
	movq	%rdi,%rax	/* return dst */
#else
	xchgq	%rdi,%rsi
#endif
	movq	%rdx,%rcx
	movq	%rdi,%r8
	subq	%rsi,%r8
	cmpq	%rcx,%r8		/* overlapping? */
	jb	.Lbackwards_sse2_aligned

	/*
	 * If the string is too short, use a simple copy.
	 */
	cmpq	$0x10,%rcx
	jb	3f

	/*
	 * If the source is not aligned, do a short copy to align it.
	 */
	test	$0xf,%rsi
	jnz	11f

1:	shrq	$4,%rdx			/* dqwords to copy */
	andq	$0xf,%rcx

	/*
	 * The source is aligned and can use movaps.  See if the
	 * destination is aligned (movaps) or not (movups).
	 */
	test	$0xf,%rdi
	jnz	6f

	/* Both source and dest are aligned. */
	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	4f
2:	movaps	(%rsi),%xmm0		/* 64 bytes at a time */
	movaps	0x10(%rsi),%xmm1
	movaps	0x20(%rsi),%xmm2
	movaps	0x30(%rsi),%xmm3
	movaps	%xmm0,(%rdi)
	movaps	%xmm1,0x10(%rdi)
	movaps	%xmm2,0x20(%rdi)
	movaps	%xmm3,0x30(%rdi)
	addq	$0x40,%rsi
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	2b

3:	rep				/* copy remainder by bytes */
	movsb
	ret

4:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	5f
	movaps	(%rsi),%xmm0		/* 32 bytes at a time */
	movaps	0x10(%rsi),%xmm1
	movaps	%xmm0,(%rdi)
	movaps	%xmm1,0x10(%rdi)
	addq	$0x20,%rsi
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	3b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	2b
5:	movaps	(%rsi),%xmm0		/* 16 bytes at a time */
	movaps	%xmm0,(%rdi)
	addq	$0x10,%rsi
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	3b
	jmp	2b

6:	/* Source is aligned and destination is not. */
	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	9f
7:	movaps	(%rsi),%xmm0		/* 64 bytes at a time */
	movaps	0x10(%rsi),%xmm1
	movaps	0x20(%rsi),%xmm2
	movaps	0x30(%rsi),%xmm3
	movups	%xmm0,(%rdi)
	movups	%xmm1,0x10(%rdi)
	movups	%xmm2,0x20(%rdi)
	movups	%xmm3,0x30(%rdi)
	addq	$0x40,%rsi
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	7b

8:	rep				/* copy remainder by bytes */
	movsb
	ret

9:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	10f
	movaps	(%rsi),%xmm0		/* 32 bytes at a time */
	movaps	0x10(%rsi),%xmm1
	movups	%xmm0,(%rdi)
	movups	%xmm1,0x10(%rdi)
	addq	$0x20,%rsi
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	8b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	7b
10:	movaps	(%rsi),%xmm0		/* 16 bytes at a time */
	movups	%xmm0,(%rdi)
	addq	$0x10,%rsi
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	8b
	jmp	7b

11:	/* Use movsb to copy enough bytes to align the source address. */
	movq	%rsi,%r9
	neg	%r9
	addq	$0x10,%r9
	andq	$0xf,%r9
	movq	%r9,%rcx
	rep
	movsb
	sub	%r9,%rdx
	mov	%rdx,%rcx

	/*
	 * If the remaining length is long enough, use an SSE
	 * block-copy, otherwise use a simple movsb loop for the
	 * remainder.
	 */
	cmpq	$0x10,%rdx
	jae	1b
	rep
	movsb
	ret

.Lbackwards_sse2_aligned:
	addq	%rcx,%rdi		/* copy backwards. */
	addq	%rcx,%rsi

	/*
	 * If the string is too short, use a simple copy.
	 */
	cmpq	$0x10,%rcx
	jb	3f

	/*
	 * If the source is not aligned, do a short copy to align it.
	 */
	test	$0xf,%rsi
	jnz	11f

1:	shrq	$4,%rdx			/* dqwords to copy */
	andq	$0xf,%rcx

	/*
	 * The source is aligned and can use movaps.  See if the
	 * destination is aligned (movaps) or not (movups).
	 */
	test	$0xf,%rdi
	jnz	6f

	/* Both source and dest are aligned. */
	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	4f
2:	movaps	-0x10(%rsi),%xmm0	/* 64 bytes at a time */
	movaps	-0x20(%rsi),%xmm1
	movaps	-0x30(%rsi),%xmm2
	movaps	-0x40(%rsi),%xmm3
	movaps	%xmm0,-0x10(%rdi)
	movaps	%xmm1,-0x20(%rdi)
	movaps	%xmm2,-0x30(%rdi)
	movaps	%xmm3,-0x40(%rdi)
	subq	$0x40,%rsi
	subq	$0x40,%rdi
	subq	$4,%rdx
	jnz	2b

3:	decq	%rdi			/* copy remainder by bytes */
	decq	%rsi
	std
	rep
	movsb
	cld
	ret

4:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	5f
	movaps	-0x10(%rsi),%xmm0	/* 32 bytes at a time */
	movaps	-0x20(%rsi),%xmm1
	movaps	%xmm0,-0x10(%rdi)
	movaps	%xmm1,-0x20(%rdi)
	subq	$0x20,%rsi
	subq	$0x20,%rdi
	subq	$2,%rdx
	jz	3b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	2b
5:	movaps	-0x10(%rsi),%xmm0	/* 16 bytes at a time */
	movaps	%xmm0,-0x10(%rdi)
	subq	$0x10,%rsi
	subq	$0x10,%rdi
	subq	$1,%rdx
	jz	3b
	jmp	2b

6:	/* Source is aligned and destination is not. */
	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	9f
7:	movaps	-0x10(%rsi),%xmm0	/* 64 bytes at a time */
	movaps	-0x20(%rsi),%xmm1
	movaps	-0x30(%rsi),%xmm2
	movaps	-0x40(%rsi),%xmm3
	movups	%xmm0,-0x10(%rdi)
	movups	%xmm1,-0x20(%rdi)
	movups	%xmm2,-0x30(%rdi)
	movups	%xmm3,-0x40(%rdi)
	subq	$0x40,%rsi
	subq	$0x40,%rdi
	subq	$4,%rdx
	jnz	7b

8:	decq	%rdi			/* copy remainder by bytes */
	decq	%rsi
	std
	rep
	movsb
	cld
	ret

9:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	10f
	movaps	-0x10(%rsi),%xmm0	/* 32 bytes at a time */
	movaps	-0x20(%rsi),%xmm1
	movups	%xmm0,-0x10(%rdi)
	movups	%xmm1,-0x20(%rdi)
	subq	$0x20,%rsi
	subq	$0x20,%rdi
	subq	$2,%rdx
	jz	8b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	7b
10:	movaps	-0x10(%rsi),%xmm0	/* 16 bytes at a time */
	movups	%xmm0,-0x10(%rdi)
	subq	$0x10,%rsi
	subq	$0x10,%rdi
	subq	$1,%rdx
	jz	8b
	jmp	7b

11:	/* Use movsb to copy enough bytes to align the source address. */
	movq	%rsi,%r9
	decq	%rdi
	andq	$0xf,%r9
	decq	%rsi
	movq	%r9,%rcx
	std
	rep
	movsb
	cld
	incq	%rsi
	subq	%r9,%rdx
	incq	%rdi
	movq	%rdx,%rcx

	/*
	 * If the remaining length is long enough, use an SSE
	 * block-copy, otherwise use a simple movsb loop for the
	 * remainder.
	 */
	cmpq	$0x10,%rdx
	jae	1b
	jmp	8b
#ifdef MEMCOPY
END(memcpy_sse2_aligned)
#else
#ifdef MEMMOVE
END(memmove_sse2_aligned)
#else
END(bcopy_sse2_aligned)
#endif
#endif

#ifdef MEMCOPY
ENTRY(memcpy_sse2_unaligned)
#else
#ifdef MEMMOVE
ENTRY(memmove_sse2_unaligned)
#else
ENTRY(bcopy_sse2_unaligned)
#endif
#endif
#if defined(MEMCOPY) || defined(MEMMOVE)
	movq	%rdi,%rax	/* return dst */
#else
	xchgq	%rdi,%rsi
#endif
	movq	%rdx,%rcx
	movq	%rdi,%r8
	subq	%rsi,%r8
	cmpq	%rcx,%r8		/* overlapping? */
	jb	.Lbackwards_sse2_unaligned

	/*
	 * If the length is not an even multiple of an SSE reg, use a
	 * simple copy for the header.
	 */
	shrq	$4,%rdx
	andq	$0xf,%rcx
	jnz	5f

1:	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
2:	movups	(%rsi),%xmm0		/* 64 bytes at a time */
	movups	0x10(%rsi),%xmm1
	movups	0x20(%rsi),%xmm2
	movups	0x30(%rsi),%xmm3
	movups	%xmm0,(%rdi)
	movups	%xmm1,0x10(%rdi)
	movups	%xmm2,0x20(%rdi)
	movups	%xmm3,0x30(%rdi)
	addq	$0x40,%rsi
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	2b
	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	4f
	movups	(%rsi),%xmm0		/* 32 bytes at a time */
	movups	0x10(%rsi),%xmm1
	movups	%xmm0,(%rdi)
	movups	%xmm1,0x10(%rdi)
	addq	$0x20,%rsi
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	6f
	test	$1,%rdx			/* 16-byte chunk? */
	jz	2b
4:	movups	(%rsi),%xmm0		/* 16 bytes at a time */
	movups	%xmm0,(%rdi)
	addq	$0x10,%rsi
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	6f
	jmp	2b

5:	rep
	movsb
	test	%rdx,%rdx
	jnz	1b

6:	ret

.Lbackwards_sse2_unaligned:
	addq	%rcx,%rdi		/* copy backwards. */
	addq	%rcx,%rsi

	/*
	 * If the length is not an even multiple of an SSE reg, use a
	 * simple copy for the header.
	 */
	shrq	$4,%rdx
	andq	$0xf,%rcx
	jnz	5f
	
1:	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
2:	movups	-0x10(%rsi),%xmm0	/* 64 bytes at a time */
	movups	-0x20(%rsi),%xmm1
	movups	-0x30(%rsi),%xmm2
	movups	-0x40(%rsi),%xmm3
	movups	%xmm0,-0x10(%rdi)
	movups	%xmm1,-0x20(%rdi)
	movups	%xmm2,-0x30(%rdi)
	movups	%xmm3,-0x40(%rdi)
	subq	$0x40,%rsi
	subq	$0x40,%rdi
	subq	$4,%rdx
	jnz	2b
	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	4f
	movups	-0x10(%rsi),%xmm0	/* 32 bytes at a time */
	movups	-0x20(%rsi),%xmm1
	movups	%xmm0,-0x10(%rdi)
	movups	%xmm1,-0x20(%rdi)
	subq	$0x20,%rsi
	subq	$0x20,%rdi
	subq	$2,%rdx
	jz	6f
	test	$1,%rdx			/* 16-byte chunk? */
	jz	2b
4:	movups	-0x10(%rsi),%xmm0	/* 16 bytes at a time */
	movups	%xmm0,-0x10(%rdi)
	subq	$0x10,%rsi
	subq	$0x10,%rdi
	subq	$1,%rdx
	jz	6f
	jmp	2b

5:	decq	%rdi
	std
	decq	%rsi
	rep
	movsb
	incq	%rdi
	cld
	incq	%rsi
	test	%rdx,%rdx
	jnz	1b

6:	ret
#ifdef MEMCOPY
END(memcpy_sse2_unaligned)
#else
#ifdef MEMMOVE
END(memmove_sse2_unaligned)
#else
END(bcopy_sse2_unaligned)
#endif
#endif

/*
 * Uses AVX with 256-bit registers.  Requires AVX (but not AVX2).
 * We might want an avx_128 variant to avoid AVX <-> SSE transitions
 * in binaries that do not use AVX registers.
 */
#ifdef MEMCOPY
ENTRY(memcpy_avx_256)
#else
#ifdef MEMMOVE
ENTRY(memmove_avx_256)
#else
ENTRY(bcopy_avx_256)
#endif
#endif
#if defined(MEMCOPY) || defined(MEMMOVE)
	movq	%rdi,%rax	/* return dst */
#else
	xchgq	%rdi,%rsi
#endif
	movq	%rdx,%rcx
	movq	%rdi,%r8
	subq	%rsi,%r8
	cmpq	%rcx,%r8		/* overlapping? */
	jb	.Lbackwards_avx_256

	/*
	 * If the length is not an even multiple of an AVX reg, use a
	 * simple copy for the header.
	 */
	shrq	$4,%rdx
	andq	$0xf,%rcx
	jnz	6f

1:	test	$7,%rdx			/* Need non-128-byte chunk? */
	jnz	3f
2:	vmovups	(%rsi),%ymm0		/* 128 bytes at a time */
	vmovups	0x20(%rsi),%ymm1
	vmovups	0x40(%rsi),%ymm2
	vmovups	0x60(%rsi),%ymm3
	vmovups	%ymm0,(%rdi)
	vmovups	%ymm1,0x20(%rdi)
	vmovups	%ymm2,0x40(%rdi)
	vmovups	%ymm3,0x60(%rdi)
	addq	$0x80,%rsi
	addq	$0x80,%rdi
	subq	$8,%rdx
	jnz	2b
	ret

3:	test	$4,%rdx			/* 64-byte chunk? */
	jz 	4f
	vmovups	(%rsi),%ymm0		/* 64 bytes at a time */
	vmovups	0x20(%rsi),%ymm1
	vmovups	%ymm0,(%rdi)
	vmovups	%ymm1,0x20(%rdi)
	addq	$0x40,%rsi
	addq	$0x40,%rdi
	subq	$4,%rdx
	jz	7f
4:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	5f
	vmovups	(%rsi),%ymm0		/* 32 bytes at a time */
	vmovups	%ymm0,(%rdi)
	addq	$0x20,%rsi
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	7f
5:	test	$1,%rdx			/* 16-byte chunk? */
	jz	2b
	vmovups	(%rsi),%xmm0		/* 16 bytes at a time */
	vmovups	%xmm0,(%rdi)
	addq	$0x10,%rsi
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	7f
	jmp	2b

6:	rep
	movsb
	test	%rdx,%rdx
	jnz	1b

7:	ret

.Lbackwards_avx_256:
	addq	%rcx,%rdi		/* copy backwards. */
	addq	%rcx,%rsi

	/*
	 * If the length is not an even multiple of an AVX reg, use a
	 * simple copy for the header.
	 */
	shrq	$4,%rdx
	andq	$0xf,%rcx
	jnz	6f
	
1:	test	$7,%rdx			/* Need non-128-byte chunk? */
	jnz	3f
2:	vmovups	-0x20(%rsi),%ymm0	/* 128 bytes at a time */
	vmovups	-0x40(%rsi),%ymm1
	vmovups	-0x60(%rsi),%ymm2
	vmovups	-0x80(%rsi),%ymm3
	vmovups	%ymm0,-0x20(%rdi)
	vmovups	%ymm1,-0x40(%rdi)
	vmovups	%ymm2,-0x60(%rdi)
	vmovups	%ymm3,-0x80(%rdi)
	subq	$0x40,%rsi
	subq	$0x40,%rdi
	subq	$4,%rdx
	jnz	2b
	ret

3:	test	$4,%rdx			/* 64-byte chunk? */
	jz 	4f
	vmovups	-0x20(%rsi),%ymm0	/* 64 bytes at a time */
	vmovups	-0x40(%rsi),%ymm1
	vmovups	%ymm0,-0x20(%rdi)
	vmovups	%ymm1,-0x40(%rdi)
	subq	$0x40,%rsi
	subq	$0x40,%rdi
	subq	$4,%rdx
	jz	7f
4:	test	$2,%rdx			/* 32-byte chunk? */
	jz 	5f
	vmovups	-0x20(%rsi),%ymm0	/* 32 bytes at a time */
	vmovups	%ymm0,-0x20(%rdi)
	subq	$0x20,%rsi
	subq	$0x20,%rdi
	subq	$2,%rdx
	jz	7f
5:	test	$1,%rdx			/* 16-byte chunk? */
	jz	2b
	vmovups	-0x10(%rsi),%xmm0	/* 16 bytes at a time */
	vmovups	%xmm0,-0x10(%rdi)
	subq	$0x10,%rsi
	subq	$0x10,%rdi
	subq	$1,%rdx
	jz	7f
	jmp	2b

6:	decq	%rdi
	std
	decq	%rsi
	rep
	movsb
	incq	%rdi
	cld
	incq	%rsi
	test	%rdx,%rdx
	jnz	1b

7:	ret
#ifdef MEMCOPY
END(memcpy_avx_256)
#else
#ifdef MEMMOVE
END(memmove_avx_256)
#else
END(bcopy_avx_256)
#endif
#endif

/*
 * Variants for use with processors that support enhanced rep movs
 * (CPUID_STDEXT_ERMS).
 */
#ifdef MEMCOPY
ENTRY(memcpy_erms)
#else
#ifdef MEMMOVE
ENTRY(memmove_erms)
#else
ENTRY(bcopy_erms)
#endif
#endif
#if defined(MEMCOPY) || defined(MEMMOVE)
	movq	%rdi,%rax	/* return dst */
#else
	xchgq	%rdi,%rsi
#endif
	movq	%rdx,%rcx
	movq	%rdi,%r8
	subq	%rsi,%r8
	cmpq	%rcx,%r8		/* overlapping? */
	jb	1f

	rep
	movsb
	ret

1:
	leaq	-1(%rcx,%rsi),%rsi	/* copy backwards. */
	leaq	-1(%rcx,%rdi),%rdi
	std
	rep
	movsb
	cld
	ret
#ifdef MEMCOPY
END(memcpy_erms)
#else
#ifdef MEMMOVE
END(memmove_erms)
#else
END(bcopy_erms)
#endif
#endif
	.section .note.GNU-stack,"",%progbits
