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

#include "libnvmf.h"

static void
nvmf_init_fabrics_sqe(struct nvmf_qpair *qp, void *sqe, uint8_t fctype)
{
	struct nvmf_capsule_cmd *cmd = sqe;

	memset(cmd, 0, sizeof(*cmd));
	cmd.opcode = NVME_OPC_FABRIC;
	cmd.cid = htole16(qp->nq_cid++);
	cmd.fctype = fctype;
}

struct nvmf_qpair *
nvmf_connect(struct nvmf_connection *nc, uint16_t qid, u_int queue_size,
    const uint8_t hostid[16], uint16_t cntlid, const char *subnqn,
    const char *hostnqn, uint32_t kato);
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
	cmd.sqsize = htole16(queue_size);
	if (!nc->nc_sq_flow_control)
		cmd.cattr |= NVMF_CONNECT_ATTR_DISABLE_SQ_FC;
	cmd.kato = htole32(kato);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL)
		goto error;

	memset(&data, 0, sizeof(data));
	memcpy(data.hostid, hostid, sizeof(data.hostid));
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

	rsp = (const struct nvmf_fabric_connect_rsp *)rcap->nc_qe;
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
		qp->nq_sqtail = 0;
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

struct nvmf_capsule *
nvmf_keepalive(struct nvmf_qpair *qp)
{
	struct nvmf_capsule *ncap;
	struct nvme_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = NVME_OPC_KEEP_ALIVE;
	cmd.cid = htole16(qp->nq_cid++);

	return (nvmf_allocate_command(qp, &cmd));
}
