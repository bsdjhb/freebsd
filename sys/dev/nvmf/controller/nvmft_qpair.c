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
#include <sys/lock.h>
#include <sys/mutex.h>

#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/controller/nvmft_var.h>

struct nvmft_qpair {
	struct nvmft_controller *ctrlr;
	struct nvmf_qpair *qp;

	bool	admin;
	bool	sq_flow_control;
	u_int	qsize;
	uint16_t sqhd;
	uint16_t sqtail;

	struct mtx lock;

	char	name[16];
};

static void
nvmft_qpair_error(void *arg)
{
	struct nvmft_qpair *qp = arg;

	printf("NVMFT: TODO: error on %s\n", qp->name);
}

static void
nvmft_receive_capsule(void *arg, struct nvmf_capsule *nc)
{
	struct nvmft_qpair *qp = arg;
	struct nvmft_controller *ctrlr = qp->ctrlr;
	const struct nvme_command *cmd;
	uint8_t sc_status;

	if (ctrlr == NULL) {
		cmd = nvmf_capsule_sqe(nc);
		printf("NVMFT: %s received CID %u opcode %u on newborn queue\n",
		    qp->name, le16toh(cmd->cid), cmd->opc);
		nvmf_free_capsule(nc);
		return;
	}

	/* TODO: KeepAlive accounting */

	sc_status = nvmf_validate_command_capsule(nc);
	if (sc_status != NVME_SC_SUCCESS) {
		nvmft_send_generic_error(qp, nc, sc_status);
		nvmf_free_capsule(nc);
		return;
	}

	if (qp->admin)
		nvmft_handle_admin_command(ctrlr, nc);
	else
		nvmft_handle_io_command(qp, nc);
}

struct nvmft_qpair *
nvmft_qpair_init(enum nvmf_trtype trtype,
    const struct nvmf_handoff_qpair_params *handoff, const char *name)
{
	struct nvmft_qpair *qp;

	qp = malloc(sizeof(*qp), M_NVMFT, M_WAITOK | M_ZERO);
	qp->admin = handoff->admin;
	qp->sq_flow_control = handoff->sq_flow_control;
	qp->qsize = handoff->qsize;
	qp->sqhd = handoff->sqhd;
	qp->sqtail = handoff->sqtail;
	strlcpy(qp->name, name, sizeof(qp->name));
	mtx_init(&qp->lock, "nvmft qp", NULL, MTX_DEF);

	qp->qp = nvmf_allocate_qpair(trtype, true, handoff, nvmft_qpair_error,
	    qp, nvmft_receive_capsule, qp);
	if (qp->qp == NULL) {
		mtx_destroy(&qp->lock);
		free(qp, M_NVMFT);
		return (NULL);
	}

	return (qp);
}

void
nvmft_qpair_destroy(struct nvmft_qpair *qp)
{
	/* TODO: Abort any outstanding requests? */
	nvmf_free_qpair(qp->qp);
	mtx_destroy(&qp->lock);
	free(qp, M_NVMFT);
}

struct nvmft_controller *
nvmft_qpair_ctrlr(struct nvmft_qpair *qp)
{
	return (qp->ctrlr);
}

const char *
nvmft_qpair_name(struct nvmft_qpair *qp)
{
	return (qp->name);
}

int
nvmft_transmit_response(struct nvmft_qpair *qp, struct nvmf_capsule *nc)
{
	struct nvme_completion *cpl = nvmf_capsule_cqe(nc);

	/* Set SQHD. */
	if (qp->sq_flow_control) {
		mtx_lock(&qp->lock);
		qp->sqhd = (qp->sqhd + 1) % qp->qsize;
		cpl->sqhd = htole16(qp->sqhd);
		mtx_unlock(&qp->lock);
	} else
		cpl->sqhd = 0;

	return (nvmf_transmit_capsule(nc));
}

int
nvmft_send_response(struct nvmft_qpair *qp, const void *cqe)
{
	struct nvmf_capsule *rc;
	int error;

	rc = nvmf_allocate_response(qp->qp, cqe, M_WAITOK);
	error = nvmft_transmit_response(qp, rc);
	nvmf_free_capsule(rc);
	return (error);
}

int
nvmft_send_error(struct nvmft_qpair *qp, struct nvmf_capsule *nc,
    uint8_t sc_type, uint8_t sc_status)
{
	struct nvme_completion cpl;
	uint16_t status;

	status = sc_type << NVME_STATUS_SCT_SHIFT |
	    sc_status << NVME_STATUS_SC_SHIFT;
	nvmf_init_cqe(&cpl, nc, status);
	return (nvmft_send_response(qp, &cpl));
}

int
nvmft_send_generic_error(struct nvmft_qpair *qp, struct nvmf_capsule *nc,
    uint8_t sc_status)
{
	return (nvmft_send_error(qp, nc, NVME_SCT_GENERIC, sc_status));
}

int
nvmft_send_success(struct nvmft_qpair *qp, struct nvmf_capsule *nc)
{
	return (nvmft_send_generic_error(qp, nc, NVME_SC_SUCCESS));
}

static void
nvmft_init_connect_rsp(struct nvmf_fabric_connect_rsp *rsp,
    const struct nvmf_fabric_connect_cmd *cmd, uint16_t status)
{	
	memset(rsp, 0, sizeof(*rsp));
	rsp->cid = cmd->cid;
	rsp->status = htole16(status);
}

static int
nvmft_send_connect_response(struct nvmft_qpair *qp,
    const struct nvmf_fabric_connect_rsp *rsp)
{
	struct nvmf_capsule *nc;
	int error;

	nc = nvmf_allocate_response(qp->qp, rsp, M_WAITOK);
	error = nvmf_transmit_capsule(nc);
	nvmf_free_capsule(nc);
	return (error);
}

void
nvmft_connect_error(struct nvmft_qpair *qp,
    const struct nvmf_fabric_connect_cmd *cmd, uint8_t sc_type,
    uint8_t sc_status)
{
	struct nvmf_fabric_connect_rsp rsp;
	uint16_t status;

	status = sc_type << NVME_STATUS_SCT_SHIFT |
	    sc_status << NVME_STATUS_SC_SHIFT;
	nvmft_init_connect_rsp(&rsp, cmd, status);
	nvmft_send_connect_response(qp, &rsp);
}

void
nvmft_connect_invalid_parameters(struct nvmft_qpair *qp,
    const struct nvmf_fabric_connect_cmd *cmd, bool data, uint16_t offset)
{
	struct nvmf_fabric_connect_rsp rsp;

	nvmft_init_connect_rsp(&rsp, cmd,
	    NVME_SCT_COMMAND_SPECIFIC << NVME_STATUS_SCT_SHIFT |
	    NVMF_FABRIC_SC_INVALID_PARAM << NVME_STATUS_SC_SHIFT);
	rsp.status_code_specific.invalid.ipo = htole16(offset);
	rsp.status_code_specific.invalid.iattr = data ? 1 : 0;
	nvmft_send_connect_response(qp, &rsp);
}

int
nvmft_finish_accept(struct nvmft_qpair *qp,
    const struct nvmf_fabric_connect_cmd *cmd, struct nvmft_controller *ctrlr)
{
	struct nvmf_fabric_connect_rsp rsp;

	qp->ctrlr = ctrlr;
	nvmft_init_connect_rsp(&rsp, cmd, 0);
	if (qp->sq_flow_control)
		rsp.sqhd = htole16(qp->sqhd);
	else
		rsp.sqhd = htole16(0xffff);
	rsp.status_code_specific.success.cntlid = htole16(ctrlr->cntlid);
	return (nvmft_send_connect_response(qp, &rsp));
}
