/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/libkern.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/reg.h>
#include <machine/ptrace.h>

static struct ptrace_cpuid *nt_x86_cpuid;

static bool
get_x86_cpuid(struct regset *rs, struct thread *td, void *buf,
    size_t *sizep);

static struct regset regset_cpuid = {
	.note = NT_X86_CPUID,
	.size = 0,
	.get = get_x86_cpuid,
};

static void
populate_cpuid_leaf(struct ptrace_cpuid *pc, uint32_t eax, uint32_t ecx)
{
	uint32_t regs[4];

	cpuid_count(eax, ecx, regs);
	pc->leaf = eax;
	pc->count = ecx;
	pc->eax = regs[0];
	pc->ebx = regs[1];
	pc->ecx = regs[2];
	pc->edx = regs[3];
}

/*
 * Allocate and initialize CPUID leaves saved in NT_X86_CPUID.  For
 * now this just contains leaves describing the layout of the XSAVE
 * area.
 */
static void
init_nt_x86_cpuid(void *arg __unused)
{
	struct ptrace_cpuid *pc;
	uint64_t mask;
	u_int count, i;

	count = 0;
	if (use_xsave) {
		/* Leaves 0 and 1. */
		count += 2;

		/* Include the leaf for each bit >= 2 set in XCR0. */
		count += bitcount64(xsave_mask & ~(uint64_t)3);
	}

	if (count == 0)
		return;

	regset_cpuid.size = count * sizeof(*nt_x86_cpuid);
	nt_x86_cpuid = mallocarray(count, sizeof(*nt_x86_cpuid), M_DEVBUF,
	    M_WAITOK);

	pc = nt_x86_cpuid;
	if (use_xsave) {
		/* Leaves 0 and 1. */
		populate_cpuid_leaf(pc, 0xd, 0x0);
		pc++;
		populate_cpuid_leaf(pc, 0xd, 0x1);
		pc++;

		/* Leaves for bits >= 2. */
		mask = xsave_mask >> 2;
		i = 2;
		while (mask != 0) {
			if (mask & 1 == 1) {
				populate_cpuid_leaf(pc, 0xd, i);
				pc++;
			}
			mask >>= 1;
			i++;
		}
	}

	KASSERT(pc - nt_x86_cpuid == count, ("%s: mismatch", __func__));
}
SYSINIT(init_nt_x86_cpuid, SI_SUB_EXEC, SI_ORDER_FIRST, init_nt_x86_cpuid,
    NULL);

static bool
get_x86_cpuid(struct regset *rs, struct thread *td, void *buf,
    size_t *sizep)
{
	if (buf != NULL) {
		KASSERT(*sizep == regset_cpuid.save,
		    ("%s: invalid size", __func__));

		memcpy(buf, nt_x86_cpuid, *sizep);
	}
	*sizep = regset_cpuid.size;
	return (true);
}

ELF_REGSET(regset_cpuid);
#ifdef COMPAT_FREEBSD32
ELF32_REGSET(regset_cpuid);
#endif
