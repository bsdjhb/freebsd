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
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/pageset.h>
#include <sys/proc.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

static MALLOC_DEFINE(M_PAGESET, "pageset", "pageset page arrays");

int
pageset_create(struct pageset *ps, struct proc *p, void *buf, size_t len,
    vm_prot_t prot)
{
	struct vmspace *vm;
	vm_map_t map;
	vm_offset_t start, end, pgoff;
	int n;

	vm = p->p_vmspace;
	map = &vm->vm_map;
	start = (uintptr_t)buf;
	pgoff = start & PAGE_MASK;
	end = round_page(start + len);
	start = trunc_page(start);

	n = atop(end - start);

	ps->pages = malloc(n * sizeof(vm_page_t), M_PAGESET, M_WAITOK | M_ZERO);
	ps->npages = vm_fault_quick_hold_pages(map, start, end - start, prot,
	    ps->pages, n);
	if (ps->npages < 0) {
		free(ps->pages, M_PAGESET);
		ps->pages = NULL;
		return (EFAULT);
	}
	ps->offset = pgoff;
	ps->len = len;
	ps->wired = false;
	return (0);
}

void
pageset_wire(struct pageset *ps)
{
	vm_page_t p;
	int i;

	if (ps->wired)
		return;

	for (i = 0; i < ps->npages; i++) {
		p = ps->pages[i];
		vm_page_lock(p);
		vm_page_wire(p);
		vm_page_unhold(p);
		vm_page_unlock(p);
	}
	ps->wired = true;
}

void
pageset_release(struct pageset *ps)
{
	vm_page_t p;
	int i;

	if (ps->wired) {
		for (i = 0; i < ps->npages; i++) {
			p = ps->pages[i];
			vm_page_lock(p);
			vm_page_unwire(p, PQ_INACTIVE);
			vm_page_unlock(p);
		}
	} else
		vm_page_unhold_pages(ps->pages, ps->npages);
	free(ps->pages, M_PAGESET);
}
