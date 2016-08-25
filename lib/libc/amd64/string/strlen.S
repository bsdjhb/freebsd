/*-
 * Copyright (c) 2016 John H. Baldwin <jhb@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD");

ENTRY(strlen_sse2)
	test	$0xf,%rdi		/* Is string aligned? */
	jnz	3f
	xor	%eax,%eax
	jmp	2f

1:	addq	$0x10,%rdi
	addq	$0x10,%rax
2:	pxor	%xmm1,%xmm1
	pcmpeqb	(%rdi),%xmm1
	pmovmskb %xmm1,%rcx
	jecxz	1b
	bsf	%ecx,%edx
	addq	%rdx,%rax
	ret

	/*
	 * If %rsi is not aligned, check for null characters in the
	 * 16-byte region containing %rsi, but ignore any null
	 * characters found before %rsi.
	 */
3:	mov	%rdi,%rcx		/* Compute bytes to ignore */
	mov	$0x10,%eax		
	andq	$0xf,%rcx
	pxor	%xmm1,%xmm1
	subq	%rcx,%rdi
	subq	%rcx,%rax
	pcmpeqb	(%rdi),%xmm1
	pmovmskb %xmm1,%rdx
	addq	$0x10,%rdi
	shr	%cl,%edx		/* Ignore bytes before original %rsi */
	jz	2b
	bsf	%edx,%eax
	ret
END(strlen_sse2)

ENTRY(strlen_sse42)
	/* XXX: On my laptop this is a lot slower than the SSE2 version */
	mov	$0x10,%eax
	pxor	%xmm1,%xmm1
	mov	%eax,%edx
	test	$0xf,%rdi		/* Is string aligned? */
	jnz	3f
	xor	%r9,%r9
	jmp	2f

1:	addq	$0x10,%rdi
	addq	$0x10,%r9
2:	pcmpestri $0,(%rdi),%xmm1
	jnc	1b
	or	%ecx,%ecx		/* Clear upper 32-bits */
	leaq	(%rcx,%r9),%rax
	ret

	/*
	 * If %rsi is not aligned, check for null characters in the
	 * 16-byte region containing %rsi, but ignore any null
	 * characters found before %rsi.
	 */
3:	mov	%rdi,%r8		/* Compute bytes to ignore */
	mov	%rax,%r9		/* %r9 is initial %eax if no null */
	andq	$0xf,%r8
	subq	%r8,%rdi
	subq	%r8,%r9
	pcmpestrm $0,(%rdi),%xmm1
	mov	%r8,%rcx
	movd	%xmm0,%r11
	addq	$0x10,%rdi
	shr	%cl,%r11d		/* Ignore bytes before original %rsi */
	jz	2b
	bsf	%r11d,%eax
	ret
END(strlen_sse42)

ENTRY(strlen_avx_128)
	vpxor	%xmm0,%xmm0,%xmm0
	test	$0xf,%rdi		/* Is string aligned? */
	jnz	3f
	xor	%eax,%eax
	jmp	2f

1:	addq	$0x10,%rdi
	addq	$0x10,%rax
2:	vpcmpeqb (%rdi),%xmm0,%xmm1
	vpmovmskb %xmm1,%rcx
	jecxz	1b
	bsf	%ecx,%edx
	addq	%rdx,%rax
	ret

	/*
	 * If %rsi is not aligned, check for null characters in the
	 * 16-byte region containing %rsi, but ignore any null
	 * characters found before %rsi.
	 */
3:	mov	%rdi,%rcx		/* Compute bytes to ignore */
	mov	$0x10,%eax		
	andq	$0xf,%rcx
	subq	%rcx,%rdi
	subq	%rcx,%rax
	vpcmpeqb (%rdi),%xmm0,%xmm1
	vpmovmskb %xmm1,%rdx
	addq	$0x10,%rdi
	shr	%cl,%edx		/* Ignore bytes before original %rsi */
	jz	2b
	bsf	%edx,%eax
	ret
END(strlen_avx_128)

ENTRY(strlen_avx_256)
	vpxor	%ymm0,%ymm0,%ymm0
	test	$0x1f,%rdi		/* Is string aligned? */
	jnz	3f
	xor	%eax,%eax
	jmp	2f

1:	addq	$0x20,%rdi
	addq	$0x20,%rax
2:	vpcmpeqb (%rdi),%ymm0,%ymm1
	vpmovmskb %xmm1,%rcx
	jecxz	1b
	bsf	%ecx,%edx
	addq	%rdx,%rax
	ret

	/*
	 * If %rsi is not aligned, check for null characters in the
	 * 16-byte region containing %rsi, but ignore any null
	 * characters found before %rsi.
	 */
3:	mov	%rdi,%rcx		/* Compute bytes to ignore */
	mov	$0x20,%eax		
	andq	$0x1f,%rcx
	subq	%rcx,%rdi
	subq	%rcx,%rax
	vpcmpeqb (%rdi),%ymm0,%ymm1
	vpmovmskb %xmm1,%rdx
	addq	$0x20,%rdi
	shr	%cl,%edx		/* Ignore bytes before original %rsi */
	jz	2b
	bsf	%edx,%eax
	ret
END(strlen_avx_256)

ENTRY(strlen_erms)
	xor	%ecx,%ecx
	mov	%rdi,%rsi
	decq	%rcx
	xor	%eax,%eax
	repne
	scasb
	not	%rcx
	leaq	-1(%rcx),%rax
	ret
END(strlen_erms)

	.section .note.GNU-stack,"",%progbits
