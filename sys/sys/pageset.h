/*-
 * Copyright (c) 2017 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>
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
 *
 * $FreeBSD$
 */

#ifndef __SYS_PAGESET_H__
#define	__SYS_PAGESET_H__

#include <vm/vm.h>

struct proc;

/*
 * A pageset handles a set of VM pages backing a wired or held user
 * buffer.  It provides functions to hold (and optionally wire) the
 * pages backing a user buffer as well as releasing the pages once
 * wiring is no longer needed.
 *
 * The caller of the APIs is responsible for allocating storage for
 * the pageset structure.  The pageset_create function will malloc()
 * the 'pages' array, so it must be called from a sleepable context.
 * Callers are also responsible for providing any needed
 * sychronization.
 */
struct pageset {
	vm_page_t *pages;
	int npages;
	bool wired;
	int offset;		/* offset in first page */
	vm_size_t len;
};

int	pageset_create(struct pageset *ps, struct proc *p, void *buf,
	    size_t len, vm_prot_t prot);
void	pageset_wire(struct pageset *ps);
void	pageset_release(struct pageset *ps);

#endif /* !__SYS_PAGESET_H__ */
