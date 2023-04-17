/*-
 * Copyright (c) 2023 Chelsio Communications, Inc.
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

#include <sys/sysctl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <uuid.h>

#include "libnvmf.h"
#include "internal.h"

static void
nvmf_init_sqe(struct nvmf_qpair *qp, void *sqe, uint8_t opcode)
{
	struct nvme_command *cmd = sqe;

	memset(cmd, 0, sizeof(*cmd));
	cmd->opc = opcode;
	cmd->cid = htole16(qp->nq_cid++);
}

static void
nvmf_init_fabrics_sqe(struct nvmf_qpair *qp, void *sqe, uint8_t fctype)
{
	struct nvmf_capsule_cmd *cmd = sqe;

	nvmf_init_sqe(qp, sqe, NVME_OPC_FABRIC);
	cmd->fctype = fctype;
}

struct nvmf_qpair *
nvmf_connect(struct nvmf_connection *nc, uint16_t qid, u_int queue_size,
    const uint8_t hostid[16], uint16_t cntlid, const char *subnqn,
    const char *hostnqn, uint32_t kato)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	const struct nvmf_fabric_connect_rsp *rsp;
	struct nvmf_qpair *qp;
	struct nvmf_capsule *ncap, *rcap;
	int error;
	uint16_t sqhd, status;

	qp = NULL;
	ncap = NULL;
	rcap = NULL;
	if (nc->nc_controller)
		goto error;

	if (qid == 0) {
		if (queue_size < NVME_MIN_ADMIN_ENTRIES ||
		    queue_size > NVME_MAX_ADMIN_ENTRIES)
			goto error;
	} else {
		if (queue_size < NVME_MIN_IO_ENTRIES ||
		    queue_size > NVME_MAX_IO_ENTRIES)
			goto error;

		/* KATO is only for Admin queues. */
		if (kato != 0)
			goto error;
	}

	qp = nvmf_allocate_qpair(nc, qid == 0);
	if (qp == NULL)
		goto error;

	nvmf_init_fabrics_sqe(qp, &cmd, NVMF_FABRIC_COMMAND_CONNECT);
	cmd.recfmt = 0;
	cmd.qid = htole16(qid);

	/* N.B. sqsize is 0's based. */
	cmd.sqsize = htole16(queue_size - 1);
	if (!nc->nc_sq_flow_control)
		cmd.cattr |= NVMF_CONNECT_ATTR_DISABLE_SQ_FC;
	cmd.kato = htole32(kato);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL)
		goto error;

	memset(&data, 0, sizeof(data));
	memcpy(data.hostid, hostid, sizeof(data.hostid));
	data.cntlid = htole16(cntlid);
	strlcpy(data.subnqn, subnqn, sizeof(data.subnqn));
	strlcpy(data.hostnqn, hostnqn, sizeof(data.hostnqn));

	error = nvmf_capsule_append_data(ncap, &data, sizeof(data));
	if (error != 0)
		goto error;

	error = nvmf_transmit_capsule(ncap, true);
	if (error != 0) {
		printf("NVMF: Failed to transmit CONNECT capsule: %d\n",
		    error);
		goto error;
	}

	error = nvmf_receive_capsule(qp, &rcap);
	if (error != 0) {
		printf("NVMF: Failed to receive CONNECT response: %d\n",
		    error);
		goto error;
	}

	rsp = (const struct nvmf_fabric_connect_rsp *)&rcap->nc_cqe;
	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: CONNECT failed, status %#x\n", status);
		if (NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM)
			printf("NVMF: IATTR: %#x IPO: %#x\n",
			    rsp->status_code_specific.invalid.iattr,
			    rsp->status_code_specific.invalid.ipo);
		goto error;
	}

	if (rcap->nc_cqe.cid != cmd.cid) {
		printf("NVMF: Mismatched CID in CONNECT response\n");
		goto error;
	}

	if (!rcap->nc_sqhd_valid) {
		printf("NVMF: CONNECT response without valid SQHD\n");
		goto error;
	}

	sqhd = le16toh(rsp->sqhd);
	if (sqhd == 0xffff) {
		if (nc->nc_sq_flow_control) {
			printf("NVMF: Controller disabled SQ flow control\n");
			goto error;
		}
		qp->nq_flow_control = false;
	} else {
		qp->nq_flow_control = true;
		qp->nq_sqhd = sqhd;
		qp->nq_sqtail = sqhd;
	}

	if (rsp->status_code_specific.success.authreq) {
		printf("NVMF: CONNECT response requests authentication\n");
		goto error;
	}

	qp->nq_qsize = queue_size;
	qp->nq_cntlid = le16toh(rsp->status_code_specific.success.cntlid);
	/* XXX: Save qid in qp? */
	return (qp);

error:
	if (rcap != NULL)
		nvmf_free_capsule(rcap);
	if (ncap != NULL)
		nvmf_free_capsule(ncap);
	if (qp != NULL)
		nvmf_free_qpair(qp);
	return (NULL);
}

uint16_t
nvmf_cntlid(struct nvmf_qpair *qp)
{
	return (qp->nq_cntlid);
}

int
nvmf_host_transmit_command(struct nvmf_capsule *ncap, bool send_data)
{
	struct nvmf_qpair *qp = ncap->nc_qpair;
	uint16_t new_sqtail;
	int error;

	/* Fail if the queue is full. */
	new_sqtail = (qp->nq_sqtail + 1) % qp->nq_qsize;
	if (new_sqtail == qp->nq_sqhd)
		return (EBUSY);

	error = nvmf_transmit_capsule(ncap, send_data);
	if (error != 0)
		return (error);

	qp->nq_sqtail = new_sqtail;
	return (0);
}

/* Receive a single capsule and update SQ FC accounting. */
static int
nvmf_host_receive_capsule(struct nvmf_qpair *qp, struct nvmf_capsule **rcapp)
{
	struct nvmf_capsule *rcap;
	int error;

	/* If the SQ is empty, there is no response to wait for. */
	if (qp->nq_sqhd == qp->nq_sqtail)
		return (EWOULDBLOCK);

	error = nvmf_receive_capsule(qp, &rcap);
	if (error != 0)
		return (error);

	if (qp->nq_flow_control) {
		if (rcap->nc_sqhd_valid)
			qp->nq_sqhd = le16toh(rcap->nc_cqe.sqhd);
	} else {
		/*
		 * If SQ FC is disabled, just advance the head for
		 * each response capsule received so that we track the
		 * number of outstanding commands.
		 */
		qp->nq_sqhd = (qp->nq_sqhd + 1) % qp->nq_qsize;
	}
	*rcapp = rcap;
	return (0);
}

int
nvmf_host_receive_response(struct nvmf_qpair *qp, struct nvmf_capsule **rcapp)
{
	struct nvmf_capsule *rcap;

	/* Return the oldest previously received response. */
	if (!TAILQ_EMPTY(&qp->nq_rx_capsules)) {
		rcap = TAILQ_FIRST(&qp->nq_rx_capsules);
		TAILQ_REMOVE(&qp->nq_rx_capsules, rcap, nc_link);
		*rcapp = rcap;
		return (0);
	}

	return (nvmf_host_receive_capsule(qp, rcapp));
}

int
nvmf_host_wait_for_response(struct nvmf_capsule *ncap,
    struct nvmf_capsule **rcapp)
{
	struct nvmf_qpair *qp = ncap->nc_qpair;
	struct nvmf_capsule *rcap;
	int error;

	/* Check if a response was already received. */
	TAILQ_FOREACH(rcap, &qp->nq_rx_capsules, nc_link) {
		if (rcap->nc_cqe.cid == ncap->nc_sqe.cid) {
			TAILQ_REMOVE(&qp->nq_rx_capsules, rcap, nc_link);
			*rcapp = rcap;
			return (0);
		}
	}

	/* Wait for a response. */
	for (;;) {
		error = nvmf_host_receive_capsule(qp, &rcap);
		if (error != 0)
			return (error);

		if (rcap->nc_cqe.cid != ncap->nc_sqe.cid) {
			TAILQ_INSERT_TAIL(&qp->nq_rx_capsules, rcap, nc_link);
			continue;
		}

		*rcapp = rcap;
		return (0);
	}
}

struct nvmf_capsule *
nvmf_keepalive(struct nvmf_qpair *qp)
{
	struct nvme_command cmd;

	nvmf_init_sqe(qp, &cmd, NVME_OPC_KEEP_ALIVE);

	return (nvmf_allocate_command(qp, &cmd));
}

static struct nvmf_capsule *
nvmf_get_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size)
{
	struct nvmf_fabric_prop_get_cmd cmd;

	nvmf_init_fabrics_sqe(qp, &cmd, NVMF_FABRIC_COMMAND_PROPERTY_GET);
	switch (size) {
	case 4:
		cmd.attrib.size = NVMF_PROP_SIZE_4;
		break;
	case 8:
		cmd.attrib.size = NVMF_PROP_SIZE_8;
		break;
	default:
		errno = EINVAL;
		return (NULL);
	}
	cmd.ofst = htole32(offset);

	return (nvmf_allocate_command(qp, &cmd));
}

int
nvmf_read_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size,
    uint64_t *value)
{
	struct nvmf_capsule *ncap, *rcap;
	const struct nvmf_fabric_prop_get_rsp *rsp;
	uint16_t status;
	int error;

	ncap = nvmf_get_property(qp, offset, size);
	if (ncap == NULL)
		return (errno);

	error = nvmf_host_transmit_command(ncap, false);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	rsp = (const struct nvmf_fabric_prop_get_rsp *)&rcap->nc_cqe;
	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: PROPERTY_GET failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	if (size == 8)
		*value = le64toh(rsp->value.u64);
	else
		*value = le32toh(rsp->value.u32.low);
	nvmf_free_capsule(rcap);
	return (0);
}

static struct nvmf_capsule *
nvmf_set_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size,
    uint64_t value)
{
	struct nvmf_fabric_prop_set_cmd cmd;

	nvmf_init_fabrics_sqe(qp, &cmd, NVMF_FABRIC_COMMAND_PROPERTY_SET);
	switch (size) {
	case 4:
		cmd.attrib.size = NVMF_PROP_SIZE_4;
		cmd.value.u32.low = htole32(value);
		break;
	case 8:
		cmd.attrib.size = NVMF_PROP_SIZE_8;
		cmd.value.u64 = htole64(value);
		break;
	default:
		errno = EINVAL;
		return (NULL);
	}
	cmd.ofst = htole32(offset);

	return (nvmf_allocate_command(qp, &cmd));
}

int
nvmf_write_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size,
    uint64_t value)
{
	struct nvmf_capsule *ncap, *rcap;
	uint16_t status;
	int error;

	ncap = nvmf_set_property(qp, offset, size, value);
	if (ncap == NULL)
		return (errno);

	error = nvmf_host_transmit_command(ncap, false);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: PROPERTY_SET failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	nvmf_free_capsule(rcap);
	return (0);
}

int
nvmf_hostid_from_hostuuid(uint8_t hostid[16])
{
	char hostuuid_str[64];
	uuid_t hostuuid;
	size_t len;
	uint32_t status;

	len = sizeof(hostuuid_str);
	if (sysctlbyname("kern.hostuuid", hostuuid_str, &len, NULL, 0) != 0)
		return (errno);

	uuid_from_string(hostuuid_str, &hostuuid, &status);
	switch (status) {
	case uuid_s_ok:
		break;
	case uuid_s_no_memory:
		return (ENOMEM);
	default:
		return (EINVAL);
	}

	uuid_enc_le(hostid, &hostuuid);
	return (0);
}

int
nvmf_nqn_from_hostuuid(char nqn[NVMF_NQN_MAX_LEN])
{
	char hostuuid_str[64];
	size_t len;

	len = sizeof(hostuuid_str);
	if (sysctlbyname("kern.hostuuid", hostuuid_str, &len, NULL, 0) != 0)
		return (errno);

	strlcpy(nqn, NVMF_NQN_UUID_PRE, NVMF_NQN_MAX_LEN);
	strlcat(nqn, hostuuid_str, NVMF_NQN_MAX_LEN);
	return (0);
}

int
nvmf_host_identify_controller(struct nvmf_qpair *qp,
    struct nvme_controller_data *cdata)
{
	struct nvme_command cmd;
	struct nvmf_capsule *ncap, *rcap;
	int error;
	uint16_t status;

	nvmf_init_sqe(qp, &cmd, NVME_OPC_IDENTIFY);

	/* 5.15.1 Use CNS of 0x01 for controller data. */
	cmd.cdw10 = htole32(1);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL)
		return (errno);

	error = nvmf_capsule_append_data(ncap, cdata, sizeof(*cdata));
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_transmit_command(ncap, false);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: IDENTIFY failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	nvmf_free_capsule(rcap);
	return (0);
}
