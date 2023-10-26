/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Chelsio Communications, Inc.
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

#include <sys/types.h>
#include <sys/libkern.h>

#include <dev/nvmf/nvmf_proto.h>
#include <dev/nvmf/controller/nvmft_var.h>

bool
nvmf_nqn_valid(const char *nqn)
{
	size_t len;

	len = strnlen(nqn, NVME_NQN_FIELD_SIZE);
	if (len == 0 || len > NVMF_NQN_MAX_LEN)
		return (false);

#if 0
	/*
	 * Stricter checks from the spec.  Linux does not seem to
	 * require these.  NVMF_NQN_MIN_LEN does not include '.',
	 * and require at least one character of a domain name.
	 */
	if (len < NVMF_NQN_MIN_LEN + 2)
		return (false);
	if (memcmp("nqn.", nqn, strlen("nqn.")) != 0)
		return (false);
	nqn += strlen("nqn.");

	/* Next 4 digits must be a year. */
	for (u_int i = 0; i < 4; i++) {
		if (!isdigit(nqn[i]))
			return (false);
	}
	nqn += 4;

	/* '-' between year and month. */
	if (nqn[0] != '-')
		return (false);
	nqn++;

	/* 2 digit month. */
	for (u_int i = 0; i < 2; i++) {
		if (!isdigit(nqn[i]))
			return (false);
	}
	nqn += 2;

	/* '.' between month and reverse domain name. */
	if (nqn[0] != '.')
		return (false);
#endif
	return (true);
}

uint64_t
nvmf_controller_cap(uint32_t max_io_qsize, uint8_t enable_timeout)
{
	uint32_t caphi, caplo;
	u_int mps;

	caphi = 0 << NVME_CAP_HI_REG_CMBS_SHIFT |
	    0 << NVME_CAP_HI_REG_PMRS_SHIFT;
	if (max_io_qsize != 0) {
		mps = ffs(PAGE_SIZE) - 1;
		if (mps < NVME_MPS_SHIFT)
			mps = 0;
		else
			mps -= NVME_MPS_SHIFT;
		caphi |= mps << NVME_CAP_HI_REG_MPSMAX_SHIFT |
		    mps << NVME_CAP_HI_REG_MPSMIN_SHIFT;
	}
	caphi |= 0 << NVME_CAP_HI_REG_BPS_SHIFT |
	    NVME_CAP_HI_REG_CSS_NVM_MASK << NVME_CAP_HI_REG_CSS_SHIFT |
	    0 << NVME_CAP_HI_REG_NSSRS_SHIFT |
	    0 << NVME_CAP_HI_REG_DSTRD_SHIFT;

	caplo = (uint32_t)enable_timeout << NVME_CAP_LO_REG_TO_SHIFT |
	    0 << NVME_CAP_LO_REG_AMS_SHIFT |
	    1 << NVME_CAP_LO_REG_CQR_SHIFT;

	if (max_io_qsize != 0)
		caplo |= (max_io_qsize - 1) << NVME_CAP_LO_REG_MQES_SHIFT;

	return ((uint64_t)caphi << 32 | caplo);
}

bool
nvmf_validate_cc(uint32_t max_io_qsize, uint64_t cap, uint32_t old_cc,
    uint32_t new_cc)
{
	uint32_t caphi, changes, field;

	changes = old_cc ^ new_cc;
	field = NVMEV(NVME_CC_REG_IOCQES, new_cc);
	if (field != 0) {
		if (max_io_qsize == 0)
			return (false);
		if (field != 4)
			return (false);
	}
	field = NVMEV(NVME_CC_REG_IOSQES, new_cc);
	if (field != 0) {
		if (max_io_qsize == 0)
			return (false);
		if (field != 6)
			return (false);
	}
	field = NVMEV(NVME_CC_REG_SHN, new_cc);
	if (field == 3)
		return (false);

	field = NVMEV(NVME_CC_REG_AMS, new_cc);
	if (field != 0)
		return (false);

	caphi = cap >> 32;
	field = NVMEV(NVME_CC_REG_MPS, new_cc);
	if (field < NVMEV(NVME_CAP_HI_REG_MPSMAX, caphi) ||
	    field > NVMEV(NVME_CAP_HI_REG_MPSMIN, caphi))
		return (false);

	field = NVMEV(NVME_CC_REG_CSS, new_cc);
	if (field != 0 && field != 0x7)
		return (false);

	/* AMS, MPS, and CSS can only be changed while CC.EN is 0. */
	if (NVMEV(NVME_CC_REG_EN, old_cc) != 0 &&
	    (NVMEV(NVME_CC_REG_AMS, changes) != 0 ||
	    NVMEV(NVME_CC_REG_MPS, changes) != 0 ||
	    NVMEV(NVME_CC_REG_CSS, changes) != 0))
		return (false);

	return (true);
}

void
nvmf_controller_serial(char *buf, size_t len, u_long hostid)
{
	snprintf(buf, len, "HI:%lu", hostid);
}

/*
 * Copy an ASCII string in the destination buffer but pad the end of
 * the buffer with spaces and no terminating nul.
 */
static void
strpad(char *dst, const char *src, size_t len)
{
	while (len > 0 && *src != '\0')
		*dst++ = *src++;
	memset(dst, ' ', len);
}

void
nvmf_init_io_controller_data(uint16_t cntlid, uint32_t max_io_qsize,
    const char *serial, const char *model, const char *firmware_version,
    const char *subnqn, int nn, uint32_t ioccsz, uint32_t iorcsz,
    struct nvme_controller_data *cdata)
{
	char *cp;

	strpad(cdata->sn, serial, sizeof(cdata->sn));
	strpad(cdata->mn, model, sizeof(cdata->mn));
	strpad(cdata->fr, firmware_version, sizeof(cdata->fr));
	cp = memchr(cdata->fr, '-', sizeof(cdata->fr));
	if (cp != NULL)
		memset(cp, ' ', sizeof(cdata->fr) - (cp - (char *)cdata->fr));

	/* FreeBSD OUI */
	cdata->ieee[0] = 0xfc;
	cdata->ieee[1] = 0x9c;
	cdata->ieee[2] = 0x58;

	cdata->ctrlr_id = htole16(cntlid);
	cdata->ver = htole32(NVME_REV(1, 4));
	cdata->ctratt = htole32(
	    1 << NVME_CTRLR_DATA_CTRATT_128BIT_HOSTID_SHIFT |
	    1 << NVME_CTRLR_DATA_CTRATT_TBKAS_SHIFT);
	cdata->cntrltype = 1;
	cdata->acl = 4;
	cdata->aerl = 4;

	/* 1 read-only firmware slot */
	cdata->frmw = 1 << NVME_CTRLR_DATA_FRMW_SLOT1_RO_SHIFT |
	    1 << NVME_CTRLR_DATA_FRMW_NUM_SLOTS_SHIFT;

	cdata->lpa = 1 << NVME_CTRLR_DATA_LPA_EXT_DATA_SHIFT;

	/* Single power state */
	cdata->npss = 0;

	/*
	 * 1.2+ require a non-zero value for these even though it makes
	 * no sense for Fabrics.
	 */
	cdata->wctemp = htole16(0x0157);
	cdata->cctemp = cdata->wctemp;

	/* 1 second granularity for KeepAlive */
	cdata->kas = htole16(10);

	cdata->sqes = 6 << NVME_CTRLR_DATA_SQES_MAX_SHIFT |
	    6 << NVME_CTRLR_DATA_SQES_MIN_SHIFT;
	cdata->cqes = 4 << NVME_CTRLR_DATA_CQES_MAX_SHIFT |
	    4 << NVME_CTRLR_DATA_CQES_MIN_SHIFT;

	cdata->maxcmd = htole16(max_io_qsize);
	cdata->nn = htole32(nn);

	/* XXX: ONCS_DSM for TRIM */

	cdata->vwc = NVME_CTRLR_DATA_VWC_ALL_NO <<
	    NVME_CTRLR_DATA_VWC_ALL_SHIFT;

	/* Transport-specific? */
	cdata->sgls = htole32(
	    1 << NVME_CTRLR_DATA_SGLS_TRANSPORT_DATA_BLOCK_SHIFT |
	    1 << NVME_CTRLR_DATA_SGLS_ADDRESS_AS_OFFSET_SHIFT |
	    1 << NVME_CTRLR_DATA_SGLS_NVM_COMMAND_SET_SHIFT);

	strlcpy(cdata->subnqn, subnqn, sizeof(cdata->subnqn));

	cdata->ioccsz = htole32(ioccsz / 16);
	cdata->iorcsz = htole32(iorcsz / 16);

	/* Transport-specific? */
	cdata->icdoff = 0;

	cdata->fcatt = 0;

	/* Transport-specific? */
	cdata->msdbd = 1;
}
