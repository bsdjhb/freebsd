/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
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
 *
 * Derived from hp300 version by Mike Hibler, this version by William
 * Jolitz uses a recursive map [a pde points to the page directory] to
 * map the page tables using the pagetables themselves. This is done to
 * reduce the impact on kernel virtual memory for lots of sparse address
 * space, and to reduce the cost of memory to each process.
 */

#ifndef _MACHINE_PMAP_H_
#define	_MACHINE_PMAP_H_

/*
 * Page-directory and page-table entries follow this format, with a few
 * of the fields not present here and there, depending on a lot of things.
 */
				/* ---- Intel Nomenclature ---- */
#define	PG_V		0x001	/* P	Valid			*/
#define PG_RW		0x002	/* R/W	Read/Write		*/
#define PG_U		0x004	/* U/S  User/Supervisor		*/
#define	PG_NC_PWT	0x008	/* PWT	Write through		*/
#define	PG_NC_PCD	0x010	/* PCD	Cache disable		*/
#define PG_A		0x020	/* A	Accessed		*/
#define	PG_M		0x040	/* D	Dirty			*/
#define	PG_PS		0x080	/* PS	Page size (0=4k,1=4M)	*/
#define	PG_PTE_PAT	0x080	/* PAT	PAT index		*/
#define	PG_G		0x100	/* G	Global			*/
#define	PG_AVAIL1	0x200	/*    /	Available for system	*/
#define	PG_AVAIL2	0x400	/*   <	programmers use		*/
#define	PG_AVAIL3	0x800	/*    \				*/
#define	PG_PDE_PAT	0x1000	/* PAT	PAT index		*/
#define	PG_NX		(1ull<<63) /* No-execute */

/* Our various interpretations of the above */
#define PG_W		PG_AVAIL1	/* "Wired" pseudoflag */
#define	PG_MANAGED	PG_AVAIL2
#define	PG_PROMOTED	PG_AVAIL3	/* PDE only */

#define	PG_PROT		(PG_RW|PG_U)	/* all protection bits . */
#define PG_N		(PG_NC_PWT|PG_NC_PCD)	/* Non-cacheable */

/* Page level cache control fields used to determine the PAT type */
#define PG_PDE_CACHE	(PG_PDE_PAT | PG_NC_PWT | PG_NC_PCD)
#define PG_PTE_CACHE	(PG_PTE_PAT | PG_NC_PWT | PG_NC_PCD)

/*
 * Promotion to a 2 or 4MB (PDE) page mapping requires that the corresponding
 * 4KB (PTE) page mappings have identical settings for the following fields:
 */
#define PG_PTE_PROMOTE	(PG_MANAGED | PG_W | PG_G | PG_PTE_PAT | \
	    PG_M | PG_NC_PCD | PG_NC_PWT | PG_U | PG_RW | PG_V)

/*
 * Page Protection Exception bits
 */

#define PGEX_P		0x01	/* Protection violation vs. not present */
#define PGEX_W		0x02	/* during a Write cycle */
#define PGEX_U		0x04	/* access from User mode (UPL) */
#define PGEX_RSV	0x08	/* reserved PTE field is non-zero */
#define PGEX_I		0x10	/* during an instruction fetch */

/*
 * Pte related macros
 */
#define VADDR(pdi, pti) ((vm_offset_t)(((pdi)<<PDRSHIFT)|((pti)<<PAGE_SHIFT)))

#ifndef NKPDE
#define NKPDE	(KVA_PAGES)	/* number of page tables/pde's */
#endif

#define PDRSHIFT_PAE		21		/* LOG2(NBPDR) */
#define	PG_FRAME_PAE		(0x000ffffffffff000ull)
#define	PG_PS_FRAME_PAE		(0x000fffffffe00000ull)

#define	PDRSHIFT_NOPAE		22
#define	PG_FRAME_NOPAE		(~PAGE_MASK)
#define	PG_PS_FRAME_NOPAE	(0xffc00000)

/*
 * The *PTDI values control the layout of virtual memory
 */
#define	KPTDI		0		/* start of kernel virtual pde's */
/* ptd entry that points to ptd */
#define	PTDPTDI		(NPDEPTD - NTRPPTD - NPGPTD)
#define	TRPTDI		(NPDEPTD - NTRPPTD)	/* u/k trampoline ptd */

/*
 * XXX doesn't really belong here I guess...
 */
#define ISA_HOLE_START    0xa0000
#define ISA_HOLE_LENGTH (0x100000-ISA_HOLE_START)

#ifndef LOCORE

#include <sys/queue.h>
#include <sys/_cpuset.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>
#include <sys/_pv_entry.h>

#include <vm/_vm_radix.h>

/*
 * Address of current address space page table maps and directories.
 */

/*
 * Pmap stuff
 */
struct md_page {
	TAILQ_HEAD(,pv_entry)	pv_list;
	int			pat_mode;
};

struct pmap {
	cpuset_t		pm_active;	/* active on cpus */
	struct mtx		pm_mtx;
	struct pmap_statistics	pm_stats;	/* pmap statistics */
	uint32_t		*pm_pdir_nopae;	/* KVA of page directory */
	uint64_t		*pm_pdir_pae;
	TAILQ_HEAD(,pv_chunk)	pm_pvchunk;	/* list of mappings in pmap */
	LIST_ENTRY(pmap) 	pm_list;	/* List of all pmaps */
	uint64_t		*pm_pdpt_pae;
	struct vm_radix		pm_root;	/* spare page table pages */
	vm_page_t		pm_ptdpg[4];	/* PAE NPGPTD */
};

typedef struct pmap	*pmap_t;

#endif /* !LOCORE */

#endif /* !_MACHINE_PMAP_H_ */
