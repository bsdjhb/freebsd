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

#include <sys/utsname.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "libnvmf.h"
#include "internal.h"

void
nvmf_init_cqe(void *cqe, const struct nvmf_capsule *nc, uint16_t status)
{
	struct nvme_completion *cpl = cqe;
	const struct nvme_command *cmd = nvmf_capsule_sqe(nc);

	memset(cpl, 0, sizeof(*cpl));
	cpl->cid = cmd->cid;
	cpl->status = htole16(status);
}

static struct nvmf_capsule *
nvmf_simple_response(const struct nvmf_capsule *nc, uint8_t sc_type,
    uint8_t sc_status)
{
	struct nvme_completion cpl;
	uint16_t status;

	status = sc_type << NVME_STATUS_SCT_SHIFT |
	    sc_status << NVME_STATUS_SC_SHIFT;
	nvmf_init_cqe(&cpl, nc, status);
	return (nvmf_allocate_response(nc->nc_qpair, &cpl));
}

int
nvmf_controller_receive_capsule(struct nvmf_qpair *qp,
    struct nvmf_capsule **ncp)
{
	struct nvmf_capsule *nc;
	int error;
	uint8_t sc_status;

	*ncp = NULL;
	error = nvmf_receive_capsule(qp, &nc);
	if (error != 0)
		return (error);

	sc_status = nvmf_validate_command_capsule(nc);
	if (sc_status != 0) {
		nvmf_send_generic_error(nc, sc_status);
		nvmf_free_capsule(nc);
		return (EPROTO);
	}

	*ncp = nc;
	return (0);
}

int
nvmf_controller_transmit_response(struct nvmf_capsule *nc)
{
	struct nvmf_qpair *qp = nc->nc_qpair;

	/* Set SQHD. */
	if (qp->nq_flow_control) {
		qp->nq_sqhd = (qp->nq_sqhd + 1) % qp->nq_qsize;
		nc->nc_cqe.sqhd = htole16(qp->nq_sqhd);
	} else
		nc->nc_cqe.sqhd = 0;

	return (nvmf_transmit_capsule(nc));
}

int
nvmf_send_response(const struct nvmf_capsule *cc, const void *cqe)
{
	struct nvmf_capsule *rc;
	int error;

	rc = nvmf_allocate_response(cc->nc_qpair, cqe);
	if (rc == NULL)
		return (ENOMEM);
	error = nvmf_controller_transmit_response(rc);
	nvmf_free_capsule(rc);
	return (error);
}

int
nvmf_send_error(const struct nvmf_capsule *cc, uint8_t sc_type,
    uint8_t sc_status)
{
	struct nvmf_capsule *rc;
	int error;

	rc = nvmf_simple_response(cc, sc_type, sc_status);
	error = nvmf_controller_transmit_response(rc);
	nvmf_free_capsule(rc);
	return (error);
}

int
nvmf_send_generic_error(const struct nvmf_capsule *nc, uint8_t sc_status)
{
	return (nvmf_send_error(nc, NVME_SCT_GENERIC, sc_status));
}

int
nvmf_send_success(const struct nvmf_capsule *nc)
{
	return (nvmf_send_generic_error(nc, NVME_SC_SUCCESS));
}

void
nvmf_connect_invalid_parameters(const struct nvmf_capsule *cc, bool data,
    uint16_t offset)
{
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_capsule *rc;

	nvmf_init_cqe(&rsp, cc,
	    NVME_SCT_COMMAND_SPECIFIC << NVME_STATUS_SCT_SHIFT |
	    NVMF_FABRIC_SC_INVALID_PARAM << NVME_STATUS_SC_SHIFT);
	rsp.status_code_specific.invalid.ipo = htole16(offset);
	rsp.status_code_specific.invalid.iattr = data ? 1 : 0;
	rc = nvmf_allocate_response(cc->nc_qpair, &rsp);
	nvmf_transmit_capsule(rc);
	nvmf_free_capsule(rc);
}

static bool
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

struct nvmf_qpair *
nvmf_accept(struct nvmf_association *na, const struct nvmf_qpair_params *params,
    struct nvmf_capsule **ccp, struct nvmf_fabric_connect_data *data)
{
	static const char hostid_zero[sizeof(data->hostid)];
	const struct nvmf_fabric_connect_cmd *cmd;
	struct nvmf_qpair *qp;
	struct nvmf_capsule *cc, *rc;
	struct iovec iov[1];
	u_int qsize;
	int error;
	uint16_t cntlid;
	uint8_t sc_status;

	qp = NULL;
	cc = NULL;
	rc = NULL;
	*ccp = NULL;
	na_clear_error(na);
	if (!na->na_controller) {
		na_error(na, "Cannot accept on a host");
		goto error;
	}

	qp = nvmf_allocate_qpair(na, params);
	if (qp == NULL)
		goto error;

	/* Read the CONNECT capsule. */
	error = nvmf_receive_capsule(qp, &cc);
	if (error != 0) {
		na_error(na, "Failed to receive CONNECT: %s", strerror(error));
		goto error;
	}

	sc_status = nvmf_validate_command_capsule(cc);
	if (sc_status != 0) {
		na_error(na, "CONNECT command failed to validate: %u",
		    sc_status);
		rc = nvmf_simple_response(cc, NVME_SCT_GENERIC, sc_status);
		goto error;
	}

	cmd = nvmf_capsule_sqe(cc);
	if (cmd->opcode != NVME_OPC_FABRIC ||
	    cmd->fctype != NVMF_FABRIC_COMMAND_CONNECT) {
		na_error(na, "Invalid opcode in CONNECT (%u,%u)", cmd->opcode,
		    cmd->fctype);
		rc = nvmf_simple_response(cc, NVME_SCT_GENERIC,
		    NVME_SC_INVALID_OPCODE);
		goto error;
	}

	if (cmd->recfmt != htole16(0)) {
		na_error(na, "Unsupported CONNECT record format %u",
		    le16toh(cmd->recfmt));
		rc = nvmf_simple_response(cc, NVME_SCT_COMMAND_SPECIFIC,
		    NVMF_FABRIC_SC_INCOMPATIBLE_FORMAT);
		goto error;
	}

	qsize = le16toh(cmd->sqsize) + 1;
	if (cmd->qid == 0) {
		/* Admin queue limits. */
		if (qsize < NVME_MIN_ADMIN_ENTRIES ||
		    qsize > NVME_MAX_ADMIN_ENTRIES ||
		    qsize > na->na_params.max_admin_qsize) {
			na_error(na, "Invalid queue size %u", qsize);
			nvmf_connect_invalid_parameters(cc, false,
			    offsetof(struct nvmf_fabric_connect_cmd, sqsize));
			goto error;
		}
		qp->nq_admin = true;
	} else {
		/* I/O queues not allowed for discovery. */
		if (na->na_params.max_io_qsize == 0) {
			na_error(na, "I/O queue on discovery controller");
			nvmf_connect_invalid_parameters(cc, false,
			    offsetof(struct nvmf_fabric_connect_cmd, qid));
			goto error;
		}

		/* I/O queue limits. */
		if (qsize < NVME_MIN_IO_ENTRIES ||
		    qsize > NVME_MAX_IO_ENTRIES ||
		    qsize > na->na_params.max_io_qsize) {
			na_error(na, "Invalid queue size %u", qsize);
			nvmf_connect_invalid_parameters(cc, false,
			    offsetof(struct nvmf_fabric_connect_cmd, sqsize));
			goto error;
		}

		/* KATO is reserved for I/O queues. */
		if (cmd->kato != 0) {
			na_error(na,
			    "KeepAlive timeout specified for I/O queue");
			nvmf_connect_invalid_parameters(cc, false,
			    offsetof(struct nvmf_fabric_connect_cmd, kato));
			goto error;
		}
		qp->nq_admin = false;
	}
	qp->nq_qsize = qsize;

	/* Fetch CONNECT data. */
	if (nvmf_capsule_data_len(cc) != sizeof(*data)) {
		na_error(na, "Invalid data payload length for CONNECT: %zu",
		    nvmf_capsule_data_len(cc));
		nvmf_connect_invalid_parameters(cc, false,
		    offsetof(struct nvmf_fabric_connect_cmd, sgl1));
		goto error;
	}

	iov[0].iov_base = data;
	iov[0].iov_len = sizeof(*data);
	error = nvmf_receive_controller_data(cc, 0, iov, nitems(iov));
	if (error != 0) {
		na_error(na, "Failed to read data for CONNECT: %s",
		    strerror(error));
		rc = nvmf_simple_response(cc, NVME_SCT_GENERIC,
		    NVME_SC_DATA_TRANSFER_ERROR);
		goto error;
	}

	/* The hostid must be non-zero. */
	if (memcmp(data->hostid, hostid_zero, sizeof(hostid_zero)) == 0) {
		na_error(na, "HostID in CONNECT data is zero");
		nvmf_connect_invalid_parameters(cc, true,
		    offsetof(struct nvmf_fabric_connect_data, hostid));
		goto error;
	}

	cntlid = le16toh(data->cntlid);
	if (cmd->qid == 0) {
		if (na->na_params.dynamic_controller_model) {
			if (cntlid != NVMF_CNTLID_DYNAMIC) {
				na_error(na, "Invalid controller ID %#x",
				    cntlid);
				nvmf_connect_invalid_parameters(cc, true,
				    offsetof(struct nvmf_fabric_connect_data,
					cntlid));
				goto error;
			}
		} else {
			if (cntlid > NVMF_CNTLID_STATIC_MAX &&
			    cntlid != NVMF_CNTLID_STATIC_ANY) {
				na_error(na, "Invalid controller ID %#x",
				    cntlid);
				nvmf_connect_invalid_parameters(cc, true,
				    offsetof(struct nvmf_fabric_connect_data,
					cntlid));
				goto error;
			}
		}
	} else {
		/* Wildcard Controller IDs are only valid on an Admin queue. */
		if (cntlid > NVMF_CNTLID_STATIC_MAX) {
			na_error(na, "Invalid controller ID %#x", cntlid);
			nvmf_connect_invalid_parameters(cc, true,
			    offsetof(struct nvmf_fabric_connect_data, cntlid));
			goto error;
		}
	}

	/* Simple validation of each NQN. */
	if (!nvmf_nqn_valid(data->subnqn)) {
		na_error(na, "Invalid SubNQN %.*s", (int)sizeof(data->subnqn),
		    data->subnqn);
		nvmf_connect_invalid_parameters(cc, true,
		    offsetof(struct nvmf_fabric_connect_data, subnqn));
		goto error;
	}
	if (!nvmf_nqn_valid(data->hostnqn)) {
		na_error(na, "Invalid HostNQN %.*s", (int)sizeof(data->hostnqn),
		    data->hostnqn);
		nvmf_connect_invalid_parameters(cc, true,
		    offsetof(struct nvmf_fabric_connect_data, hostnqn));
		goto error;
	}

	if (na->na_params.sq_flow_control ||
	    (cmd->cattr & NVMF_CONNECT_ATTR_DISABLE_SQ_FC) == 0)
		qp->nq_flow_control = true;
	else
		qp->nq_flow_control = false;
	qp->nq_sqhd = 0;
	qp->nq_kato = le32toh(cmd->kato);
	*ccp = cc;
	return (qp);
error:
	if (rc != NULL) {
		nvmf_transmit_capsule(rc);
		nvmf_free_capsule(rc);
	}
	if (cc != NULL)
		nvmf_free_capsule(cc);
	if (qp != NULL)
		nvmf_free_qpair(qp);
	return (NULL);
}

int
nvmf_finish_accept(const struct nvmf_capsule *cc, uint16_t cntlid)
{
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair *qp = cc->nc_qpair;
	struct nvmf_capsule *rc;
	int error;

	nvmf_init_cqe(&rsp, cc, 0);
	if (qp->nq_flow_control)
		rsp.sqhd = htole16(qp->nq_sqhd);
	else
		rsp.sqhd = htole16(0xffff);
	rsp.status_code_specific.success.cntlid = htole16(cntlid);
	rc = nvmf_allocate_response(qp, &rsp);
	if (rc == NULL)
		return (ENOMEM);
	error = nvmf_transmit_capsule(rc);
	nvmf_free_capsule(rc);
	if (error == 0)
		qp->nq_cntlid = cntlid;
	return (error);
}

uint64_t
nvmf_controller_cap(struct nvmf_qpair *qp)
{
	const struct nvmf_association *na = qp->nq_association;
	uint32_t caphi, caplo;
	u_int mps;

	caphi = 0 << NVME_CAP_HI_REG_CMBS_SHIFT |
	    0 << NVME_CAP_HI_REG_PMRS_SHIFT;
	if (na->na_params.max_io_qsize != 0) {
		mps = ffs(getpagesize()) - 1;
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

	caplo = NVMET_CC_EN_TIMEOUT << NVME_CAP_LO_REG_TO_SHIFT |
	    0 << NVME_CAP_LO_REG_AMS_SHIFT |
	    1 << NVME_CAP_LO_REG_CQR_SHIFT;

	if (na->na_params.max_io_qsize != 0)
		caplo |= (na->na_params.max_io_qsize - 1) <<
		    NVME_CAP_LO_REG_MQES_SHIFT;

	return ((uint64_t)caphi << 32 | caplo);
}

bool
nvmf_validate_cc(struct nvmf_qpair *qp, uint64_t cap, uint32_t old_cc,
    uint32_t new_cc)
{
	const struct nvmf_association *na = qp->nq_association;
	uint32_t caphi, changes, field;

	changes = old_cc ^ new_cc;
	field = NVMEV(NVME_CC_REG_IOCQES, new_cc);
	if (field != 0) {
		if (na->na_params.max_io_qsize == 0)
			return (false);
		if (field != 4)
			return (false);
	}
	field = NVMEV(NVME_CC_REG_IOSQES, new_cc);
	if (field != 0) {
		if (na->na_params.max_io_qsize == 0)
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
nvmf_init_discovery_controller_data(struct nvmf_qpair *qp,
    struct nvme_controller_data *cdata)
{
	const struct nvmf_association *na = qp->nq_association;
	struct utsname utsname;
	char *cp;

	memset(cdata, 0, sizeof(*cdata));

	/*
	 * 5.2 Figure 37 states model name and serial are reserved,
	 * but Linux includes them.  Don't bother with serial, but
	 * do set model name.
	 */
	uname(&utsname);
	strlcpy(cdata->mn, utsname.sysname, sizeof(cdata->mn));
	strlcpy(cdata->fr, utsname.release, sizeof(cdata->fr));
	cp = memchr(cdata->fr, '-', sizeof(cdata->fr));
	if (cp != NULL)
		memset(cp, 0, sizeof(cdata->fr) - (cp - (char *)cdata->fr));

	cdata->ctrlr_id = qp->nq_cntlid;
	cdata->ver = NVME_REV(1, 4);
	cdata->cntrltype = 2;

	cdata->lpa = 1 << NVME_CTRLR_DATA_LPA_EXT_DATA_SHIFT;
	cdata->elpe = 0;

	cdata->maxcmd = na->na_params.max_admin_qsize;

	/* Transport-specific? */
	cdata->sgls = 1 << NVME_CTRLR_DATA_SGLS_TRANSPORT_DATA_BLOCK_SHIFT |
	    1 << NVME_CTRLR_DATA_SGLS_ADDRESS_AS_OFFSET_SHIFT |
	    1 << NVME_CTRLR_DATA_SGLS_NVM_COMMAND_SET_SHIFT;

	strlcpy(cdata->subnqn, NVMF_DISCOVERY_NQN, sizeof(cdata->subnqn));
}

void
nvmf_init_io_controller_data(struct nvmf_qpair *qp, const char *serial,
    const char *subnqn, int nn, uint32_t ioccsz,
    struct nvme_controller_data *cdata)
{
	const struct nvmf_association *na = qp->nq_association;
	struct utsname utsname;
	char *cp;

	uname(&utsname);

	strlcpy(cdata->sn, serial, sizeof(cdata->sn));
	strlcpy(cdata->mn, utsname.sysname, sizeof(cdata->mn));
	strlcpy(cdata->fr, utsname.release, sizeof(cdata->fr));
	cp = memchr(cdata->fr, '-', sizeof(cdata->fr));
	if (cp != NULL)
		memset(cp, 0, sizeof(cdata->fr) - (cp - (char *)cdata->fr));

	/* FreeBSD OUI */
	cdata->ieee[0] = 0x58;
	cdata->ieee[1] = 0x9c;
	cdata->ieee[2] = 0xfc;

	cdata->ctrlr_id = qp->nq_cntlid;
	cdata->ver = NVME_REV(1, 4);
	cdata->ctratt = 1 << NVME_CTRLR_DATA_CTRATT_128BIT_HOSTID_SHIFT |
	    1 << NVME_CTRLR_DATA_CTRATT_TBKAS_SHIFT;
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
	cdata->wctemp = 0x0157;
	cdata->cctemp = cdata->wctemp;

	/* 1 second granularity for KeepAlive */
	cdata->kas = 10;

	cdata->sqes = 6 << NVME_CTRLR_DATA_SQES_MAX_SHIFT |
	    6 << NVME_CTRLR_DATA_SQES_MIN_SHIFT;
	cdata->cqes = 4 << NVME_CTRLR_DATA_CQES_MAX_SHIFT |
	    4 << NVME_CTRLR_DATA_CQES_MIN_SHIFT;

	cdata->maxcmd = na->na_params.max_io_qsize;
	cdata->nn = nn;

	/* XXX: ONCS_DSM for TRIM */

	cdata->vwc = NVME_CTRLR_DATA_VWC_ALL_NO <<
	    NVME_CTRLR_DATA_VWC_ALL_SHIFT;

	/* Transport-specific? */
	cdata->sgls = 1 << NVME_CTRLR_DATA_SGLS_TRANSPORT_DATA_BLOCK_SHIFT |
	    1 << NVME_CTRLR_DATA_SGLS_ADDRESS_AS_OFFSET_SHIFT |
	    1 << NVME_CTRLR_DATA_SGLS_NVM_COMMAND_SET_SHIFT;

	strlcpy(cdata->subnqn, subnqn, sizeof(cdata->subnqn));

	cdata->ioccsz = ioccsz / 16;
	cdata->iorcsz = sizeof(struct nvme_completion) / 16;

	/* Transport-specific? */
	cdata->icdoff = 0;

	cdata->fcatt = 0;

	/* Transport-specific? */
	cdata->msdbd = 1;
}

uint8_t
nvmf_get_log_page_id(const struct nvme_command *cmd)
{
	assert(cmd->opc == NVME_OPC_GET_LOG_PAGE);
	return (le32toh(cmd->cdw10) & 0xff);
}

uint64_t
nvmf_get_log_page_length(const struct nvme_command *cmd)
{
	uint32_t numd;

	assert(cmd->opc == NVME_OPC_GET_LOG_PAGE);
	numd = le32toh(cmd->cdw10) >> 16 | (le32toh(cmd->cdw11) & 0xffff) << 16;
	return ((numd + 1) * 4);
}

uint64_t
nvmf_get_log_page_offset(const struct nvme_command *cmd)
{
	assert(cmd->opc == NVME_OPC_GET_LOG_PAGE);
	return (le32toh(cmd->cdw12) | (uint64_t)le32toh(cmd->cdw13) << 32);
}
