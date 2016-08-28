/*
 * Written by J.T. Conklin <jtc@NetBSD.org>.
 * Public domain.
 * Adapted for NetBSD/x86_64 by Frank van der Linden <fvdl@wasabisystems.com>
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#if 0
	RCSID("$NetBSD: memcmp.S,v 1.2 2003/07/26 19:24:39 salo Exp $")
#endif

ENTRY(memcmp)
	cld				/* set compare direction forward */
	movq	%rdx,%rcx		/* compare by longs */
	shrq	$3,%rcx
	repe
	cmpsq
	jne	L5			/* do we match so far? */

	movq	%rdx,%rcx		/* compare remainder by bytes */
	andq	$7,%rcx
	repe
	cmpsb
	jne	L6			/* do we match? */

	xorl	%eax,%eax		/* we match, return zero	*/
	ret

L5:	movl	$8,%ecx			/* We know that one of the next	*/
	subq	%rcx,%rdi		/* eight pairs of bytes do not	*/
	subq	%rcx,%rsi		/* match.			*/
	repe
	cmpsb
L6:	xorl	%eax,%eax		/* Perform unsigned comparison	*/
	movb	-1(%rdi),%al
	xorl	%edx,%edx
	movb	-1(%rsi),%dl
	subl    %edx,%eax
	ret
END(memcmp)

	.set memcmp_stock, memcmp
	.global memcmp_stock
	
ENTRY(memcmp_sse2_unaligned)
	cld
1:	cmpq	$0x10,%rdx
	jb	3f
	subq	$0x10,%rdx
	movups	(%rsi),%xmm0
	addq	$0x10,%rsi
	pcmpeqb	(%rdi),%xmm0
	addq	$0x10,%rdi
	pmovmskb %xmm0,%rax
	xor	$0xffff,%eax
	jz	1b
	bsf	%eax,%edx
	leaq	-0xf(%rsi,%rdx),%rsi
	leaq	-0xf(%rdi,%rdx),%rdi

2:	movzbl	-1(%rdi),%eax
	movzbl	-1(%rsi),%edx
	subl	%edx,%eax
	ret

3:	mov	%edx,%ecx
	repe
	cmpsb
	jne	2b

	xorl	%eax,%eax
	ret

END(memcmp_sse2_unaligned)

ENTRY(memcmp_erms)
	cld
	movq	%rdx,%rcx
	repe
	cmpsb
	jne	1f

	xorl	%eax,%eax
	ret

1:	movzbl	-1(%rdi),%eax
	movzbl	-1(%rsi),%edx
	subl	%edx,%eax
	ret
END(memcmp_erms)

	.section .note.GNU-stack,"",%progbits
