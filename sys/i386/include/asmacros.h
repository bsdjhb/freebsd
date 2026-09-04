/* -*- mode: asm -*- */
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1993 The Regents of the University of California.
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

#ifndef _MACHINE_ASMACROS_H_
#define _MACHINE_ASMACROS_H_

#include <sys/cdefs.h>

/* XXX too much duplication in various asm*.h's. */

/*
 * CNAME is used to manage the relationship between symbol names in C
 * and the equivalent assembly language names.  CNAME is given a name as
 * it would be used in a C program.  It expands to the equivalent assembly
 * language name.
 */
#define CNAME(csym)		csym

#define ALIGN_DATA	.p2align 2	/* 4 byte alignment, zero filled */
#define ALIGN_TEXT	.p2align 2,0x90	/* 4-byte alignment, nop filled */
#define SUPERALIGN_TEXT	.p2align 4,0x90	/* 16-byte alignment, nop filled */

#define GEN_ENTRY(name)		ALIGN_TEXT; .globl CNAME(name); \
				.type CNAME(name),@function; CNAME(name):
#define ENTRY(name)		GEN_ENTRY(name)
#define ALTENTRY(name)		GEN_ENTRY(name)
#define	END(name)		.size name, . - name

#ifdef __STDC__
#define ELFNOTE(name, type, desctype, descdata...) \
.pushsection .note.name, "a", @note     ;       \
  .align 4                              ;       \
  .long 2f - 1f         /* namesz */    ;       \
  .long 4f - 3f         /* descsz */    ;       \
  .long type                            ;       \
1:.asciz #name                          ;       \
2:.align 4                              ;       \
3:desctype descdata                     ;       \
4:.align 4                              ;       \
.popsection
#else /* !__STDC__, i.e. -traditional */
#define ELFNOTE(name, type, desctype, descdata) \
.pushsection .note.name, "a", @note     ;       \
  .align 4                              ;       \
  .long 2f - 1f         /* namesz */    ;       \
  .long 4f - 3f         /* descsz */    ;       \
  .long type                            ;       \
1:.asciz "name"                         ;       \
2:.align 4                              ;       \
3:desctype descdata                     ;       \
4:.align 4                              ;       \
.popsection
#endif /* __STDC__ */

#endif /* !_MACHINE_ASMACROS_H_ */
