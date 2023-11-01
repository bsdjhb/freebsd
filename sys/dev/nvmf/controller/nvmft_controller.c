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
#include <sys/sbuf.h>
#include <sys/sx.h>

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
	sx_xlock(&np->lock);
	TAILQ_REMOVE(&np->controllers, ctrlr, link);
	free_unr(np->ids, ctrlr->cntlid);
	sx_xunlock(&np->lock);
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

	if (ctrlr->num_io_queues == 0) {
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to create I/O queue %u without enabled queues from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_GENERIC,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		nvmft_destroy_qp(qp);
		return (EINVAL);
	}
	if (cmd->qid > ctrlr->num_io_queues) {
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to create invalid I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_invalid_parameters(qp, cmd, false,
		    offsetof(struct nvmf_fabric_connect_cmd, qid));
		nvmft_destroy_qp(qp);
		return (EINVAL);
	}
	if (ctrlr->io_qpairs[qid - 1] != NULL) {
		sx_sunlock(&np->lock);
		nvmft_printf(ctrlr, "attempt to re-create I/O queue %u from %.*s\n",
		    qid, (int)sizeof(data->hostnqn), data->hostnqn);
		nvmft_connect_error(qp, cmd, NVME_SCT_GENERIC,
		    NVME_SC_COMMAND_SEQUENCE_ERROR);
		nvmft_destroy_qp(qp);
		return (EINVAL);
	}

	ctrlr->io_qpairs[qid - 1] = qp;
	nvmft_finish_accept(qp, cmd, ctrlr);
	sx_sunlock(&np->lock);

	return (0);
}
