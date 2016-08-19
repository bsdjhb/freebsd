/*
 * Written by J.T. Conklin <jtc@NetBSD.org>.
 * Public domain.
 * Adapted for NetBSD/x86_64 by Frank van der Linden <fvdl@wasabisystems.com>
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#if 0
	RCSID("$NetBSD: memset.S,v 1.3 2004/02/26 20:50:06 drochner Exp $")
#endif

ENTRY(memset)
	movq	%rsi,%rax
	andq	$0xff,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11

	cld				/* set fill direction forward */

	/*
	 * if the string is too short, it's really not worth the overhead
	 * of aligning to word boundries, etc.  So we jump to a plain
	 * unaligned set.
	 */
	cmpq	$0x0f,%rcx
	jle	L1

	movb	%al,%ah			/* copy char to all bytes in word */
	movl	%eax,%edx
	sall	$16,%eax
	orl	%edx,%eax

	movl	%eax,%edx
	salq	$32,%rax
	orq	%rdx,%rax

	movq	%rdi,%rdx		/* compute misalignment */
	negq	%rdx
	andq	$7,%rdx
	movq	%rcx,%r8
	subq	%rdx,%r8

	movq	%rdx,%rcx		/* set until word aligned */
	rep
	stosb

	movq	%r8,%rcx
	shrq	$3,%rcx			/* set by words */
	rep
	stosq

	movq	%r8,%rcx		/* set remainder by bytes */
	andq	$7,%rcx
L1:	rep
	stosb
	movq	%r11,%rax

	ret
END(memset)

/*
 * SSE2 variants.  Unaligned always uses movups.  Aligned uses movaps if
 * the buffer is aligned and movups otherwise.
 */
ENTRY(memset_sse2_aligned)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movb	%al,%ah			/* copy char to all bytes in word */
	movq	%rax,%xmm1
	pshuflw $0,%xmm1,%xmm1
	pshufd	$0,%xmm1,%xmm1

	/*
	 * If the starting address is aligned, use movaps for the block
	 * copy rather than movups.
	 */
	test	$0xf,%rdi
	jz	.Laligned_sse2

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	movups	%xmm1,(%rdi)		/* 64 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	movups	%xmm1,0x20(%rdi)
	movups	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	movups	%xmm1,(%rdi)		/* 32 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	movups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b

.Laligned_sse2:
	/* Use movaps for a known-aligned block. */
	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	movaps	%xmm1,(%rdi)		/* 64 bytes at a time */
	movaps	%xmm1,0x10(%rdi)
	movaps	%xmm1,0x20(%rdi)
	movaps	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	movaps	%xmm1,(%rdi)		/* 32 bytes at a time */
	movaps	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	movaps	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_sse2_aligned)

ENTRY(memset_sse2_unaligned)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movb	%al,%ah			/* copy char to all bytes in word */
	movq	%rax,%xmm1
	pshuflw $0,%xmm1,%xmm1
	pshufd	$0,%xmm1,%xmm1

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	movups	%xmm1,(%rdi)		/* 64 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	movups	%xmm1,0x20(%rdi)
	movups	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	movups	%xmm1,(%rdi)		/* 32 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	movups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_sse2_unaligned)

ENTRY(memset_ssse3_aligned)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movq	%rax,%xmm1		/* copy char to all bytes in word */
	pxor	%xmm0,%xmm0
	pshufb	%xmm0,%xmm1

	/*
	 * If the starting address is aligned, use movaps for the block
	 * copy rather than movups.
	 */
	test	$0xf,%rdi
	jz	.Laligned_ssse3

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	movups	%xmm1,(%rdi)		/* 64 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	movups	%xmm1,0x20(%rdi)
	movups	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	movups	%xmm1,(%rdi)		/* 32 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	movups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b

.Laligned_ssse3:
	/* Use movaps for a known-aligned block. */
	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	movaps	%xmm1,(%rdi)		/* 64 bytes at a time */
	movaps	%xmm1,0x10(%rdi)
	movaps	%xmm1,0x20(%rdi)
	movaps	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	movaps	%xmm1,(%rdi)		/* 32 bytes at a time */
	movaps	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	movaps	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_ssse3_aligned)

ENTRY(memset_ssse3_unaligned)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movq	%rax,%xmm1		/* copy char to all bytes in word */
	pxor	%xmm0,%xmm0
	pshufb	%xmm0,%xmm1

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	movups	%xmm1,(%rdi)		/* 64 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	movups	%xmm1,0x20(%rdi)
	movups	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	movups	%xmm1,(%rdi)		/* 32 bytes at a time */
	movups	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	movups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_ssse3_unaligned)

/*
 * Various AVX variants.
 */
ENTRY(memset_avx_128)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movq	%rax,%xmm1		/* copy char to all bytes in word */
	vpxor	%xmm0,%xmm0,%xmm0
	vpshufb	%xmm0,%xmm1,%xmm1

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	vmovups	%xmm1,(%rdi)		/* 64 bytes at a time */
	vmovups	%xmm1,0x10(%rdi)
	vmovups	%xmm1,0x20(%rdi)
	vmovups	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	vmovups	%xmm1,(%rdi)		/* 32 bytes at a time */
	vmovups	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	vmovups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_avx_128)

ENTRY(memset_avx2_128)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movq	%rax,%xmm1		/* copy char to all bytes in word */
	vbroadcastb %xmm1,%ymm1

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	vmovups	%xmm1,(%rdi)		/* 64 bytes at a time */
	vmovups	%xmm1,0x10(%rdi)
	vmovups	%xmm1,0x20(%rdi)
	vmovups	%xmm1,0x30(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	vmovups	%xmm1,(%rdi)		/* 32 bytes at a time */
	vmovups	%xmm1,0x10(%rdi)
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	vmovups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_avx2_128)

ENTRY(memset_avx_256)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movq	%rax,%xmm1		/* copy char to all bytes in word */
	vpxor	%xmm0,%xmm0,%xmm0
	vpshufb	%xmm0,%xmm1,%xmm1
	vinsertf128 $1,%xmm1,%ymm1,%ymm1

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	vmovups	%ymm1,(%rdi)		/* 64 bytes at a time */
	vmovups	%ymm1,0x20(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	vmovups	%ymm1,(%rdi)		/* 32 bytes at a time */
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	vmovups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_avx_256)

ENTRY(memset_avx2_256)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	/*
	 * If the string is too short for an SSE move use a simple set.
	 */
	shrq	$4,%rdx
	jz	2f
	andq	$0xf,%rcx

	movq	%rax,%xmm1		/* copy char to all bytes in word */
	vbroadcastb %xmm1,%ymm1

	test	$3,%rdx			/* Need non-64-byte chunk? */
	jnz	3f
1:	vmovups	%ymm1,(%rdi)		/* 64 bytes at a time */
	vmovups	%ymm1,0x20(%rdi)
	addq	$0x40,%rdi
	subq	$4,%rdx
	jnz	1b

2:	rep				/* set remainder by bytes */
	stosb
	movq	%r11,%rax

	ret

3:	test	$2,%rdx			/* 32-byte chunk? */
	jz	4f
	vmovups	%ymm1,(%rdi)		/* 32 bytes at a time */
	addq	$0x20,%rdi
	subq	$2,%rdx
	jz	2b
	test	$1,%rdx			/* 16-byte chunk? */
	jz	1b
4:	vmovups	%xmm1,(%rdi)		/* 16 bytes at a time */
	addq	$0x10,%rdi
	subq	$1,%rdx
	jz	2b
	jmp	1b
END(memset_avx2_256)

/*
 * Variant for use with processors that support enhanced rep movs
 * (CPUID_STDEXT_ERMS).
 */
ENTRY(memset_erms)
	movq	%rsi,%rax
	movq	%rdx,%rcx
	movq	%rdi,%r11
	cld				/* set fill direction forward */

	rep
	stosb
	movq	%r11,%rax

	ret
END(memset_erms)

	.section .note.GNU-stack,"",%progbits
