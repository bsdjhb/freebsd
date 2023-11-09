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
#include <sys/malloc.h>
#include <sys/memdesc.h>
#include <sys/sbuf.h>
#include <sys/sx.h>

#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/controller/nvmft_var.h>

static int __printflike(2, 3)
nvmft_printf(struct nvmft_controller *ctrlr, const char *fmt, ...)	
{
	char buf[128];
	struct sbuf sb;
	va_list ap;
	size_t retval;

	sbuf_new(&sb, buf, sizeof(buf), SBUF_FIXEDLEN);
	sbuf_set_drain(&sb, sbuf_printf_drain, &retval);

	sbuf_printf(&sb, "nvmft%u: ", ctrlr->cntlid);

	va_start(ap, fmt);
	sbuf_vprintf(&sb, fmt, ap);
	va_end(ap);

	sbuf_finish(&sb);
	sbuf_delete(&sb);

	return (retval);
}

static struct nvmft_controller *
nvmft_controller_alloc(struct nvmft_port *np, uint16_t cntlid,
    const struct nvmf_fabric_connect_data *data)
{
	struct nvmft_controller *ctrlr;

	ctrlr = malloc(sizeof(*ctrlr), M_NVMFT, M_WAITOK | M_ZERO);
	ctrlr->cntlid = cntlid;
	nvmft_port_ref(np);
	TAILQ_INSERT_TAIL(&np->controllers, ctrlr, link);
	ctrlr->np = np;
	sx_init(&ctrlr->lock, "nvmft controller");
	refcount_init(&ctrlr->refs, 1);

	ctrlr->cdata = np->cdata;
	ctrlr->cdata.ctrlr_id = htole16(cntlid);
	memcpy(ctrlr->hostid, data->hostid, sizeof(ctrlr->hostid));
	memcpy(ctrlr->hostnqn, data->hostnqn, sizeof(ctrlr->hostnqn));

	return (ctrlr);
}

static void
nvmft_controller_ref(struct nvmft_controller *ctrlr)
{
	refcount_acquire(&ctrlr->refs);
}

static void
nvmft_controller_free(struct nvmft_controller *ctrlr)
{
	struct nvmft_port *np;

	np = ctrlr->np;
	/* TODO: Maybe take controller out of list once it is shutting down? */
	sx_xlock(&np->lock);
	TAILQ_REMOVE(&np->controllers, ctrlr, link);
	free_unr(np->ids, ctrlr->cntlid);
	sx_xunlock(&np->lock);
	sx_destroy(&ctrlr->lock);
	free(ctrlr->io_qpairs, M_NVMFT);
	free(ctrlr, M_NVMFT);
	nvmft_port_rele(np);
}

static void
nvmft_controller_rele(struct nvmft_controller *ctrlr)
{
	if (refcount_release(&ctrlr->refs))
		nvmft_controller_free(ctrlr);
}

int
nvmft_handoff_admin_queue(struct nvmft_port *np,
    const struct nvmf_handoff_controller_qpair *handoff,
    const struct nvmf_fabric_connect_cmd *cmd,
    const struct nvmf_fabric_connect_data *data)
{
	struct nvmft_controller *ctrlr;
	struct nvmft_qpair *qp;
	int cntlid;

	if (cmd->qid != htole16(0))
		return (EINVAL);

	qp = nvmft_init_qp(handoff->trtype, &handoff->params, "admin queue");

	sx_xlock(&np->lock);
	cntlid = alloc_unr(np->ids);
	if (cntlid == -1) {
		sx_xunlock(&np->lock);
		printf("NVMFT: Unable to allocate controller for %.*s\n",
		    (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_COMMAND_SPECIFIC,
		    NVMF_FABRIC_SC_INVALID_HOST);
		nvmft_destroy_qp(qp);
		return (ENOMEM);
	}

#ifdef INVARIANTS
	TAILQ_FOREACH(ctrlr, &np->controllers, link) {
		KASSERT(ctrlr->cntlid != cntlid,
		    ("%s: duplicate controllers with id %d", __func__, cntlid));
	}
#endif
	
	ctrlr = nvmft_controller_alloc(np, cntlid, data);
	nvmft_printf(ctrlr, "associated with %.*s\n",
	    (int)sizeof(data->hostnqn), data->hostnqn);
	ctrlr->admin = qp;

	/* TODO: Start KeepAlive timer. */

	nvmft_finish_accept(qp, cmd, ctrlr);
	sx_xunlock(&np->lock);

	return (0);
}

int
nvmft_handoff_io_queue(struct nvmft_port *np,
    const struct nvmf_handoff_controller_qpair *handoff,
    const struct nvmf_fabric_connect_cmd *cmd,
    const struct nvmf_fabric_connect_data *data)
{
	struct nvmft_controller *ctrlr;
	struct nvmft_qpair *qp;
	char name[16];
	uint16_t cntlid, qid;

	qid = le16toh(cmd->qid);
	if (qid == 0)
		return (EINVAL);
	cntlid = le16toh(data->cntlid);

	snprintf(name, sizeof(name), "I/O queue %u", qid);
	qp = nvmft_init_qp(handoff->trtype, &handoff->params, name);

	sx_slock(&np->lock);
	TAILQ_FOREACH(ctrlr, &np->controllers, link) {
		if (ctrlr->cntlid == cntlid)
			break;
	}
	if (ctrlr == NULL) {
		sx_sunlock(&np->lock);
		printf("NVMFT: Nonexistent controller %u for I/O queue %u from %.*s\n",
		    ctrlr->cntlid, qid, (int)sizeof(data->hostnqn),
		    data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, true,
		    offsetof(struct nvmf_fabric_connect_data, cntlid));
		nvmft_destroy_qp(qp);
		return (ENOENT);
	}

	if (memcmp(ctrlr->hostid, data->hostid, sizeof(ctrlr->hostid)) != 0) {
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "hostid mismatch for I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, true,
		    offsetof(struct nvmf_fabric_connect_data, hostid));
		nvmft_destroy_qp(qp);
		return (EINVAL);
		
	}
	if (memcmp(ctrlr->hostnqn, data->hostnqn, sizeof(ctrlr->hostnqn)) != 0) {
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "hostnqn mismatch for I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, true,
		    offsetof(struct nvmf_fabric_connect_data, hostnqn));
		nvmft_destroy_qp(qp);
		return (EINVAL);
		
	}

	sx_xlock(&ctrlr->lock);
	if (ctrlr->num_io_queues == 0) {
		sx_xunlock(&ctrlr->lock);
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to create I/O queue %u without enabled queues from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_GENERIC,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		nvmft_destroy_qp(qp);
		return (EINVAL);
	}
	if (cmd->qid > ctrlr->num_io_queues) {
		sx_xunlock(&ctrlr->lock);
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to create invalid I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, false,
		    offsetof(struct nvmf_fabric_connect_cmd, qid));
		nvmft_destroy_qp(qp);
		return (EINVAL);
	}
	if (ctrlr->io_qpairs[qid - 1] != NULL) {
		sx_xunlock(&ctrlr->lock);
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to re-create I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_GENERIC,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		nvmft_destroy_qp(qp);
		return (EINVAL);
	}

	ctrlr->io_qpairs[qid - 1] = qp;
	sx_xunlock(&ctrlr->lock);
	nvmft_finish_accept(qp, cmd, ctrlr);
	sx_sunlock(&np->lock);

	return (0);
}

static bool
update_cc(struct nvmft_controller *ctrlr, uint32_t new_cc)
{
	struct nvmft_port *np = ctrlr->np;
	uint32_t changes;
	bool shutdown;

	if (!nvmf_validate_cc(np->max_io_qsize, np->cap, ctrlr->cc, new_cc))
		return (false);

	shutdown = false;
	changes = ctrlr->cc ^ new_cc;
	ctrlr->cc = new_cc;

	/* Handle shutdown requests. */
	if (NVMEV(NVME_CC_REG_SHN, changes) != 0 &&
	    NVMEV(NVME_CC_REG_SHN, new_cc) != 0) {
		ctrlr->csts &= ~NVMEB(NVME_CSTS_REG_SHST);
		ctrlr->csts |= NVME_SHST_COMPLETE << NVME_CSTS_REG_SHST_SHIFT;
		shutdown = true;
	}

	if (NVMEV(NVME_CC_REG_EN, changes) != 0) {
		if (NVMEV(NVME_CC_REG_EN, new_cc) == 0) {
			/* Controller reset. */
			ctrlr->csts = 0;
			shutdown = true;
		} else
			ctrlr->csts |= 1 << NVME_CSTS_REG_RDY_SHIFT;
	}

	if (shutdown) {
		/* TODO: Shutdown handling */
	}
	return (true);
}

static void
handle_property_get(struct nvmft_controller *ctrlr, struct nvmf_capsule *nc,
    const struct nvmf_fabric_prop_get_cmd *pget)
{
	struct nvmf_fabric_prop_get_rsp rsp;

	nvmf_init_cqe(&rsp, nc, 0);

	switch (le32toh(pget->ofst)) {
	case NVMF_PROP_CAP:
		if (pget->attrib.size != NVMF_PROP_SIZE_8)
			goto error;
		rsp.value.u64 = htole64(ctrlr->np->cap);
		break;
	case NVMF_PROP_VS:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = ctrlr->cdata.ver;
		break;
	case NVMF_PROP_CC:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(ctrlr->cc);
		break;
	case NVMF_PROP_CSTS:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(ctrlr->csts);
		break;
	default:
		goto error;
	}

	nvmft_send_response(ctrlr->admin, &rsp);
	return;
error:
	nvmft_send_generic_error(ctrlr->admin, nc, NVME_SC_INVALID_FIELD);
}

static void
handle_property_set(struct nvmft_controller *ctrlr, struct nvmf_capsule *nc,
    const struct nvmf_fabric_prop_set_cmd *pset)
{
	switch (le32toh(pset->ofst)) {
	case NVMF_PROP_CC:
		if (pset->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		if (!update_cc(ctrlr, le32toh(pset->value.u32.low)))
			goto error;
		break;
	default:
		goto error;
	}

	nvmft_send_success(ctrlr->admin, nc);
	return;
error:
	nvmft_send_generic_error(ctrlr->admin, nc, NVME_SC_INVALID_FIELD);
}

static void
handle_admin_fabrics_command(struct nvmft_controller *ctrlr,
    struct nvmf_capsule *nc, const struct nvmf_fabric_cmd *fc)
{
	switch (fc->fctype) {
	case NVMF_FABRIC_COMMAND_PROPERTY_GET:
		handle_property_get(ctrlr, nc,
		    (const struct nvmf_fabric_prop_get_cmd *)fc);
		break;
	case NVMF_FABRIC_COMMAND_PROPERTY_SET:
		handle_property_set(ctrlr, nc,
		    (const struct nvmf_fabric_prop_set_cmd *)fc);
		break;
	case NVMF_FABRIC_COMMAND_CONNECT:
		nvmft_printf(ctrlr, "CONNECT command on connected admin queue\n");
		nvmft_send_generic_error(ctrlr->admin, nc,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		break;
	case NVMF_FABRIC_COMMAND_DISCONNECT:
		nvmft_printf(ctrlr, "DISCONNECT command on admin queue\n");
		nvmft_send_error(ctrlr->admin, nc, NVME_SCT_COMMAND_SPECIFIC,
		    NVMF_FABRIC_SC_INVALID_QUEUE_TYPE);
		break;
	default:
		nvmft_printf(ctrlr, "Unsupported fabrics command %#x\n",
		    fc->fctype);
		nvmft_send_generic_error(ctrlr->admin, nc,
		    NVME_SC_INVALID_OPCODE);
		break;
	}
}

static void
identify_cdata_complete(void *arg, size_t len __unused, int error __unused)
{
	struct nvmft_controller *ctrlr = arg;

	nvmft_controller_rele(ctrlr);
}

static void
handle_identify_command(struct nvmft_controller *ctrlr,
    struct nvmf_capsule *nc, const struct nvme_command *cmd)
{
	struct memdesc mem;
	u_int status;
	uint8_t cns;

	cns = le32toh(cmd->cdw10) & 0xFF;
	switch (cns) {
	case 1:
		nvmft_controller_ref(ctrlr);
		mem = memdesc_vaddr(&ctrlr->cdata, sizeof(ctrlr->cdata));
		status = nvmf_send_controller_data(nc, &mem, 0,
		    sizeof(ctrlr->cdata), identify_cdata_complete, ctrlr);
		break;
	case 0:
		/* TODO: Will need to construct ctl_io and sent it down to the LUN. */
	default:
		nvmft_printf(ctrlr, "Unsupported CNS %#x for IDENTIFY\n", cns);
		goto error;
	}

	if (status != NVMF_SUCCESS_SENT)
		nvmft_send_generic_error(ctrlr->admin, nc, status);
	return;
error:
	nvmft_send_generic_error(ctrlr->admin, nc, NVME_SC_INVALID_FIELD);
}

static void
handle_set_features(struct nvmft_controller *ctrlr,
    struct nvmf_capsule *nc, const struct nvme_command *cmd)
{
	struct nvme_completion cqe;
	uint8_t fid;

	fid = NVMEV(NVME_FEAT_SET_FID, le32toh(cmd->cdw10));
	switch (fid) {
	case NVME_FEAT_NUMBER_OF_QUEUES:
	{
		uint32_t num_queues;

		sx_xlock(&ctrlr->lock);
		if (ctrlr->num_io_queues != 0) {
			sx_xunlock(&ctrlr->lock);
			nvmft_send_generic_error(ctrlr->admin, nc,
			    NVME_SC_COMMAND_SEQUENCE_ERROR);
			return;
		}

		num_queues = le32toh(cmd->cdw11) & 0xffff;

		/* 5.12.1.7: 65535 is invalid. */
		if (num_queues == 65535) {
			sx_xunlock(&ctrlr->lock);
			goto error;
		}

		/* Fabrics requires the same number of SQs and CQs. */
		if (le32toh(cmd->cdw11) >> 16 != num_queues) {
			sx_xunlock(&ctrlr->lock);
			goto error;
		}

		/* Convert to 1's based */
		num_queues++;

		ctrlr->num_io_queues = num_queues;
		ctrlr->io_qpairs = mallocarray(num_queues,
		    sizeof(*ctrlr->io_qpairs), M_NVMFT, M_WAITOK | M_ZERO);
		sx_xunlock(&ctrlr->lock);

		nvmf_init_cqe(&cqe, nc, 0);
		cqe.cdw0 = cmd->cdw11;
		nvmft_send_response(ctrlr->admin, &cqe);
		return;
	}
	default:
		nvmft_printf(ctrlr, "Unsupported feature ID %u for SET_FEATURES\n",
		    fid);
		goto error;
	}

error:
	nvmft_send_generic_error(ctrlr->admin, nc, NVME_SC_INVALID_FIELD);
}

void
nvmft_handle_admin_command(struct nvmft_controller *ctrlr,
    struct nvmf_capsule *nc)
{
	const struct nvme_command *cmd = nvmf_capsule_sqe(nc);

	switch (cmd->opc) {
	case NVME_OPC_FABRICS_COMMANDS:
		handle_admin_fabrics_command(ctrlr, nc,
		    (const struct nvmf_fabric_cmd *)cmd);
		break;
	case NVME_OPC_IDENTIFY:
		handle_identify_command(ctrlr, nc, cmd);
		break;
	case NVME_OPC_SET_FEATURES:
		handle_set_features(ctrlr, nc, cmd);
		break;
	case NVME_OPC_KEEP_ALIVE:
		/* TODO: Keep Alive timer reset */
		nvmft_send_success(ctrlr->admin, nc);
		break;
	default:
		nvmft_printf(ctrlr, "Unsupported admin opcode %#x\n", cmd->opc);
		nvmft_send_generic_error(ctrlr->admin, nc,
		    NVME_SC_INVALID_OPCODE);
		break;
	}
	nvmf_free_capsule(nc);
}

void
nvmft_handle_io_command(struct nvmft_controller *ctrlr, struct nvmft_qpair *qp,
    struct nvmf_capsule *nc)
{
	const struct nvme_command *cmd = nvmf_capsule_sqe(nc);

	switch (cmd->opc) {
	default:
		nvmft_printf(ctrlr, "Unsupported I/O opcode %#x\n", cmd->opc);
		nvmft_send_generic_error(qp, nc,
		    NVME_SC_INVALID_OPCODE);
		break;
	}
	nvmf_free_capsule(nc);
}
