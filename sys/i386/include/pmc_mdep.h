/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003-2005,2008 Joseph Koshy
 * Copyright (c) 2007 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by A. Joseph Koshy under
 * sponsorship from the FreeBSD Foundation and Google, Inc.
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

#ifndef _MACHINE_PMC_MDEP_H
#define	_MACHINE_PMC_MDEP_H 1

/*
 * On the i386 platform we support the following PMCs.
 *
 * TSC		The timestamp counter
 * K8		AMD Athlon64 and Opteron PMCs in 32 bit mode.
 * IBS		AMD IBS
 * IAP		Intel Core/Core2/Atom programmable PMCs.
 * IAF		Intel fixed-function PMCs.
 * UCP		Intel Uncore programmable PMCs.
 * UCF		Intel Uncore fixed-function PMCs.
 */

#include <dev/hwpmc/hwpmc_amd.h>
#include <dev/hwpmc/hwpmc_ibs.h>
#include <dev/hwpmc/hwpmc_core.h>
#include <dev/hwpmc/hwpmc_rapl.h>
#include <dev/hwpmc/hwpmc_tsc.h>
#include <dev/hwpmc/hwpmc_uncore.h>

/*
 * Intel processors implementing V2 and later of the Intel performance
 * measurement architecture have PMCs of the following classes: TSC,
 * IAF, IAP, UCF and UCP.
 */
#define	PMC_MDEP_CLASS_INDEX_TSC	1
#define	PMC_MDEP_CLASS_INDEX_K8		2
#define	PMC_MDEP_CLASS_INDEX_IBS	3
#define	PMC_MDEP_CLASS_INDEX_IAP	2
#define	PMC_MDEP_CLASS_INDEX_IAF	3
#define	PMC_MDEP_CLASS_INDEX_UCP	4
#define	PMC_MDEP_CLASS_INDEX_UCF	5

/*
 * Architecture specific extensions to <sys/pmc.h> structures.
 */

union pmc_md_op_pmcallocate  {
	struct pmc_md_amd_op_pmcallocate	pm_amd;
	struct pmc_md_ibs_op_pmcallocate	pm_ibs;
	struct pmc_md_iap_op_pmcallocate	pm_iap;
	struct pmc_md_ucf_op_pmcallocate	pm_ucf;
	struct pmc_md_ucp_op_pmcallocate	pm_ucp;
	uint64_t				__pad[4];
};

/* Logging */
#define	PMCLOG_READADDR		PMCLOG_READ32
#define	PMCLOG_EMITADDR		PMCLOG_EMIT32

#endif /* _MACHINE_PMC_MDEP_H */
