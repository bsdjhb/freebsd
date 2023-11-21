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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/memdesc.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>

#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/controller/nvmft_var.h>

static void	nvmft_controller_shutdown(void *arg, int pending);
static void	nvmft_controller_terminate(void *arg, int pending);

int
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
	mtx_init(&ctrlr->lock, "nvmft controller", NULL, MTX_DEF);
	refcount_init(&ctrlr->refs, 1);
	TASK_INIT(&ctrlr->shutdown_task, 0, nvmft_controller_shutdown, ctrlr);
	TIMEOUT_TASK_INIT(taskqueue_thread, &ctrlr->terminate_task, 0,
	    nvmft_controller_terminate, ctrlr);

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
	mtx_destroy(&ctrlr->lock);
	MPASS(ctrlr->io_qpairs == NULL);
	free(ctrlr, M_NVMFT);
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

	qp = nvmft_qpair_init(handoff->trtype, &handoff->params, 0,
	    "admin queue");

	sx_xlock(&np->lock);
	cntlid = alloc_unr(np->ids);
	if (cntlid == -1) {
		sx_xunlock(&np->lock);
		printf("NVMFT: Unable to allocate controller for %.*s\n",
		    (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_COMMAND_SPECIFIC,
		    NVMF_FABRIC_SC_INVALID_HOST);
		nvmft_qpair_destroy(qp);
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
	qp = nvmft_qpair_init(handoff->trtype, &handoff->params, qid, name);

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
		nvmft_qpair_destroy(qp);
		return (ENOENT);
	}

	if (memcmp(ctrlr->hostid, data->hostid, sizeof(ctrlr->hostid)) != 0) {
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "hostid mismatch for I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, true,
		    offsetof(struct nvmf_fabric_connect_data, hostid));
		nvmft_qpair_destroy(qp);
		return (EINVAL);
	}
	if (memcmp(ctrlr->hostnqn, data->hostnqn, sizeof(ctrlr->hostnqn)) != 0) {
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "hostnqn mismatch for I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, true,
		    offsetof(struct nvmf_fabric_connect_data, hostnqn));
		nvmft_qpair_destroy(qp);
		return (EINVAL);
	}

	mtx_lock(&ctrlr->lock);
	if (ctrlr->shutdown) {
		mtx_unlock(&ctrlr->lock);
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to create I/O queue %u on disabled controller from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, true,
		    offsetof(struct nvmf_fabric_connect_data, cntlid));
		nvmft_qpair_destroy(qp);
		return (EINVAL);
	}
	if (ctrlr->num_io_queues == 0) {
		mtx_unlock(&ctrlr->lock);
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to create I/O queue %u without enabled queues from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_GENERIC,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		nvmft_qpair_destroy(qp);
		return (EINVAL);
	}
	if (cmd->qid > ctrlr->num_io_queues) {
		mtx_unlock(&ctrlr->lock);
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to create invalid I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, false,
		    offsetof(struct nvmf_fabric_connect_cmd, qid));
		nvmft_qpair_destroy(qp);
		return (EINVAL);
	}
	if (ctrlr->io_qpairs[qid - 1].qp != NULL) {
		mtx_unlock(&ctrlr->lock);
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to re-create I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_GENERIC,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		nvmft_qpair_destroy(qp);
		return (EINVAL);
	}

	ctrlr->io_qpairs[qid - 1].qp = qp;
	mtx_unlock(&ctrlr->lock);
	nvmft_finish_accept(qp, cmd, ctrlr);
	sx_sunlock(&np->lock);

	return (0);
}

static void
nvmft_controller_shutdown(void *arg, int pending)
{
	struct nvmft_controller *ctrlr = arg;

	MPASS(pending == 1);

	/*
	 * Shutdown all I/O queues to terminate pending datamoves and
	 * stop receiving new commands.
	 */
	mtx_lock(&ctrlr->lock);	
	for (u_int i = 0; i < ctrlr->num_io_queues; i++) {
		if (ctrlr->io_qpairs[i].qp != NULL) {
			ctrlr->io_qpairs[i].shutdown = true;
			mtx_unlock(&ctrlr->lock);
			nvmft_qpair_shutdown(ctrlr->io_qpairs[i].qp);
			mtx_lock(&ctrlr->lock);
		}
	}
	mtx_unlock(&ctrlr->lock);

	/* Terminate active CTL commands. */
	nvmft_terminate_commands(ctrlr);

	/* Wait for all pending CTL commands to complete. */
	while (!atomic_cmpset_32(&ctrlr->pending_commands, 0, 0))
		tsleep(&ctrlr->pending_commands, 0, "nvmftsh", hz / 100);

	/* Delete all of the I/O queues. */
	for (u_int i = 0; i < ctrlr->num_io_queues; i++) {
		if (ctrlr->io_qpairs[i].qp != NULL)
			nvmft_qpair_destroy(ctrlr->io_qpairs[i].qp);
	}
	free(ctrlr->io_qpairs, M_NVMFT);
	ctrlr->io_qpairs = NULL;

	mtx_lock(&ctrlr->lock);
	ctrlr->num_io_queues = 0;

	/* Mark shutdown complete. */
	if (NVMEV(NVME_CSTS_REG_SHST, ctrlr->csts) == NVME_SHST_OCCURRING) {
		ctrlr->csts &= ~NVMEB(NVME_CSTS_REG_SHST);
		ctrlr->csts |= NVME_SHST_COMPLETE << NVME_CSTS_REG_SHST_SHIFT;
	}

	ctrlr->csts &= ~NVMEB(NVME_CSTS_REG_RDY);
	ctrlr->shutdown = false;
	mtx_unlock(&ctrlr->lock);

	taskqueue_enqueue_timeout(taskqueue_thread, &ctrlr->terminate_task,
	    hz * 60 * 2);
}

static void
nvmft_controller_terminate(void *arg, int pending)
{
	struct nvmft_controller *ctrlr = arg;
	struct nvmft_port *np;

	/* If the controller has been re-enabled, nothing to do. */
	mtx_lock(&ctrlr->lock);
	if (NVMEV(NVME_CC_REG_EN, ctrlr->cc) != 0) {
		/* TODO: Restart KA timer */
		mtx_unlock(&ctrlr->lock);
		return;
	}

	/* Disable updates to CC while destroying admin qpair. */
	ctrlr->shutdown = true;
	mtx_unlock(&ctrlr->lock);

	nvmft_qpair_destroy(ctrlr->admin);

	/* Remove association (CNTLID). */
	np = ctrlr->np;
	sx_xlock(&np->lock);
	TAILQ_REMOVE(&np->controllers, ctrlr, link);
	free_unr(np->ids, ctrlr->cntlid);
	sx_xunlock(&np->lock);

	nvmft_printf(ctrlr, "association terminated\n");
	nvmft_controller_rele(ctrlr);
	nvmft_port_rele(np);
}

/*
 * XXX: Probably want a separate notification from the transport layer
 * when a queue is closed to avoid spurious TCP timeout errors once
 * the other side has closed a queue pair during shutdown.  Also can
 * tear down the association sooner in that case.
 */
void
nvmft_controller_error(struct nvmft_controller *ctrlr)
{
	/* Ignore transport errors if we are already shutting down. */
	mtx_lock(&ctrlr->lock);
	if (ctrlr->shutdown) {
		mtx_unlock(&ctrlr->lock);
		return;
	}

	ctrlr->csts |= 1 << NVME_CSTS_REG_CFS_SHIFT;
	ctrlr->cc &= ~NVMEB(NVME_CC_REG_EN);
	ctrlr->shutdown = true;

	/* TODO: Stop KA timer. */
	mtx_unlock(&ctrlr->lock);

	taskqueue_enqueue(taskqueue_thread, &ctrlr->shutdown_task);
}

static bool
update_cc(struct nvmft_controller *ctrlr, uint32_t new_cc)
{
	struct nvmft_port *np = ctrlr->np;
	uint32_t changes;
	bool need_shutdown;

	mtx_lock(&ctrlr->lock);

	/* Don't allow any changes while shutting down. */
	if (ctrlr->shutdown) {
		mtx_unlock(&ctrlr->lock);
		return (false);
	}

	if (!nvmf_validate_cc(np->max_io_qsize, np->cap, ctrlr->cc, new_cc)) {
		mtx_unlock(&ctrlr->lock);
		return (false);
	}

	changes = ctrlr->cc ^ new_cc;
	ctrlr->cc = new_cc;
	need_shutdown = false;

	/* Handle shutdown requests. */
	if (NVMEV(NVME_CC_REG_SHN, changes) != 0 &&
	    NVMEV(NVME_CC_REG_SHN, new_cc) != 0) {
		ctrlr->csts &= ~NVMEB(NVME_CSTS_REG_SHST);
		ctrlr->csts |= NVME_SHST_OCCURRING << NVME_CSTS_REG_SHST_SHIFT;
		ctrlr->cc &= ~NVMEB(NVME_CC_REG_EN);
		ctrlr->shutdown = true;
		need_shutdown = true;
		nvmft_printf(ctrlr, "shutdown requested\n");
	}

	if (NVMEV(NVME_CC_REG_EN, changes) != 0) {
		if (NVMEV(NVME_CC_REG_EN, new_cc) == 0) {
			/* Controller reset. */
			nvmft_printf(ctrlr, "reset requested\n");
			ctrlr->shutdown = true;
			need_shutdown = true;
		} else
			ctrlr->csts |= 1 << NVME_CSTS_REG_RDY_SHIFT;
	}

	if (need_shutdown) {
		/* TODO: Stop KA timer. */
	}

	mtx_unlock(&ctrlr->lock);

	if (need_shutdown)
		taskqueue_enqueue(taskqueue_thread, &ctrlr->shutdown_task);

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
	nvmf_free_capsule(nc);
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
		status = nvmf_send_controller_data(nc, 0, &mem,
		    sizeof(ctrlr->cdata), 0, identify_cdata_complete, ctrlr);
		MPASS(status != NVMF_MORE);
		break;
	case 0:
		nvmft_dispatch_command(ctrlr->admin, nc, true);
		return;
	default:
		nvmft_printf(ctrlr, "Unsupported CNS %#x for IDENTIFY\n", cns);
		status = NVME_SC_INVALID_FIELD;
		break;
	}

	if (status != NVMF_SUCCESS_SENT)
		nvmft_send_generic_error(ctrlr->admin, nc, status);
	nvmf_free_capsule(nc);
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
		struct nvmft_io_qpair *io_qpairs;

		num_queues = le32toh(cmd->cdw11) & 0xffff;

		/* 5.12.1.7: 65535 is invalid. */
		if (num_queues == 65535)
			goto error;

		/* Fabrics requires the same number of SQs and CQs. */
		if (le32toh(cmd->cdw11) >> 16 != num_queues)
			goto error;

		/* Convert to 1's based */
		num_queues++;

		io_qpairs = mallocarray(num_queues, sizeof(*io_qpairs),
		    M_NVMFT, M_WAITOK | M_ZERO);

		mtx_lock(&ctrlr->lock);
		if (ctrlr->num_io_queues != 0) {
			mtx_unlock(&ctrlr->lock);
			free(io_qpairs, M_NVMFT);
			nvmft_send_generic_error(ctrlr->admin, nc,
			    NVME_SC_COMMAND_SEQUENCE_ERROR);
			nvmf_free_capsule(nc);
			return;
		}

		ctrlr->num_io_queues = num_queues;
		ctrlr->io_qpairs = io_qpairs;
		mtx_unlock(&ctrlr->lock);

		nvmf_init_cqe(&cqe, nc, 0);
		cqe.cdw0 = cmd->cdw11;
		nvmft_send_response(ctrlr->admin, &cqe);
		nvmf_free_capsule(nc);
		return;
	}
	default:
		nvmft_printf(ctrlr, "Unsupported feature ID %u for SET_FEATURES\n",
		    fid);
		goto error;
	}

error:
	nvmft_send_generic_error(ctrlr->admin, nc, NVME_SC_INVALID_FIELD);
	nvmf_free_capsule(nc);
}

void
nvmft_handle_admin_command(struct nvmft_controller *ctrlr,
    struct nvmf_capsule *nc)
{
	const struct nvme_command *cmd = nvmf_capsule_sqe(nc);

	/* Only permit Fabrics commands while a controller is disabled. */
	if (NVMEV(NVME_CC_REG_EN, ctrlr->cc) == 0 &&
	    cmd->opc != NVME_OPC_FABRICS_COMMANDS) {
		nvmft_printf(ctrlr,
		    "Unsupported admin opcode %#x whiled disabled\n", cmd->opc);
		nvmft_send_generic_error(ctrlr->admin, nc,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		nvmf_free_capsule(nc);
		return;
	}

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
		nvmf_free_capsule(nc);
		break;
	default:
		nvmft_printf(ctrlr, "Unsupported admin opcode %#x\n", cmd->opc);
		nvmft_send_generic_error(ctrlr->admin, nc,
		    NVME_SC_INVALID_OPCODE);
		nvmf_free_capsule(nc);
		break;
	}
}

void
nvmft_handle_io_command(struct nvmft_qpair *qp, uint16_t qid,
    struct nvmf_capsule *nc)
{
	struct nvmft_controller *ctrlr = nvmft_qpair_ctrlr(qp);
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
