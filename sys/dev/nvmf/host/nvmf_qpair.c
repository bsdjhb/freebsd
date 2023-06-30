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

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/host/nvmf_var.h>

struct nvmf_host_command {
	struct nvmf_request *req;
	TAILQ_ENTRY(nvmf_host_command) link;
	uint16_t cid;
};

struct nvmf_host_qpair {
	struct nvmf_softc *sc;
	struct nvmf_qpair *qp;

	bool	sq_flow_control;
	uint16_t qsize;
	uint16_t sqhd;
	uint16_t sqtail;

	struct mtx lock;

	TAILQ_HEAD(, nvmf_host_command) free_commands;
	STAILQ_HEAD(, nvmf_request) pending_requests;

	/* Indexed by cid. */
	struct nvmf_host_command **active_commands;

	char name[16];
};

struct nvmf_request *
nvmf_allocate_request(struct nvmf_host_qpair *qp, void *sqe,
    nvmf_request_complete_t *cb, void *cb_arg, int how)
{
	struct nvmf_request *req;

	KASSERT(how == M_WAITOK || how == M_NOWAIT,
	    ("%s: invalid how", __func__));

	req = malloc(sizeof(*req), M_NVMF, how | M_ZERO);
	if (req == NULL)
		return (NULL);

	req->qp = qp;
	req->cb = cb;
	req->cb_arg = cb_arg;
	req->nc = nvmf_allocate_command(qp->qp, sqe, how);
	if (req->nc == NULL) {
		free(req, M_NVMF);
		return (NULL);
	}

	return (req);
}

static void
nvmf_abort_request(struct nvmf_request *req, uint16_t cid)
{
	struct nvme_completion cqe;

	memset(&cqe, 0, sizeof(cqe));
	cqe.cid = cid;
	cqe.status = htole16(NVME_SCT_PATH_RELATED << NVME_STATUS_SCT_SHIFT |
	    NVME_SC_COMMAND_ABORTED_BY_HOST << NVME_STATUS_SC_SHIFT);
	req->cb(req->cb_arg, &cqe);
}

void
nvmf_free_request(struct nvmf_request *req)
{
	if (req->nc != NULL)
		nvmf_free_capsule(req->nc);
	free(req, M_NVMF);
}

static void
nvmf_dispatch_command(struct nvmf_host_qpair *qp, struct nvmf_host_command *cmd)
{
	struct nvmf_softc *sc = qp->sc;
	struct nvme_command *sqe;
	struct nvmf_capsule *nc;
	int error;

	nc = cmd->req->nc;
	sqe = nvmf_capsule_sqe(nc);

	/*
	 * NB: Don't bother byte-swapping the cid so that receive
	 * doesn't have to swap.
	 */
	sqe->cid = cmd->cid;

	error = nvmf_transmit_capsule(nc);
	if (error != 0) {
		device_printf(sc->dev,
		    "failed to transmit capsule: %d, disconnecting\n", error);
		nvmf_disconnect(sc);
		return;
	}

	if (sc->ka_traffic)
		atomic_store_int(&sc->ka_active_tx_traffic, 1);
}

static void
nvmf_qp_error(void *arg)
{
	struct nvmf_host_qpair *qp = arg;
	struct nvmf_softc *sc = qp->sc;

	device_printf(sc->dev, "error on %s, disconnecting\n", qp->name);
	nvmf_disconnect(sc);
}

static void
nvmf_receive_capsule(void *arg, struct nvmf_capsule *nc)
{
	struct nvmf_host_qpair *qp = arg;
	struct nvmf_softc *sc = qp->sc;
	struct nvmf_host_command *cmd;
	struct nvmf_request *req;
	const struct nvme_completion *cqe;
	uint16_t cid;

	cqe = nvmf_capsule_cqe(nc);

	if (sc->ka_traffic)
		atomic_store_int(&sc->ka_active_rx_traffic, 1);

	/*
	 * NB: Don't bother byte-swapping the cid as transmit doesn't
	 * swap either.
	 */
	cid = cqe->cid;

	if (cid > qp->qsize - 1) {
		device_printf(sc->dev,
		    "received invalid CID %u, disconnecting\n", cid);
		nvmf_disconnect(sc);
		nvmf_free_capsule(nc);
		return;
	}

	mtx_lock(&qp->lock);
	cmd = qp->active_commands[cid];
	if (cmd == NULL) {
		mtx_unlock(&qp->lock);
		device_printf(sc->dev,
		    "received completion for inactive CID %u, disconnecting\n",
		    cid);
		nvmf_disconnect(sc);
		nvmf_free_capsule(nc);
		return;
	}

	KASSERT(cmd->cid == cid, ("%s: CID mismatch", __func__));
	req = cmd->req;
	cmd->req = NULL;
	if (STAILQ_EMPTY(&qp->pending_requests)) {
		qp->active_commands[cid] = NULL;
		TAILQ_INSERT_TAIL(&qp->free_commands, cmd, link);
		mtx_unlock(&qp->lock);
	} else {
		cmd->req = STAILQ_FIRST(&qp->pending_requests);
		STAILQ_REMOVE_HEAD(&qp->pending_requests, link);
		mtx_unlock(&qp->lock);
		nvmf_dispatch_command(qp, cmd);
	}

	req->cb(req->cb_arg, cqe);
	nvmf_free_capsule(nc);
	nvmf_free_request(req);
}

struct nvmf_host_qpair *
nvmf_init_qp(struct nvmf_softc *sc, enum nvmf_trtype trtype,
    struct nvmf_handoff_qpair_params *handoff, const char *name)
{
	struct nvmf_host_command *cmd, *ncmd;
	struct nvmf_host_qpair *qp;
	u_int i, num_commands;

	qp = malloc(sizeof(*qp), M_NVMF, M_WAITOK | M_ZERO);
	qp->sc = sc;
	qp->sq_flow_control = handoff->sq_flow_control;
	qp->qsize = handoff->qsize;
	qp->sqhd = handoff->sqhd;
	qp->sqtail = handoff->sqtail;
	strlcpy(qp->name, name, sizeof(qp->name));
	mtx_init(&qp->lock, "nvmf qp", NULL, MTX_DEF);

	num_commands = qp->qsize - 1;
	qp->active_commands = malloc(sizeof(*qp->active_commands) *
	    num_commands, M_NVMF, M_WAITOK | M_ZERO);
	TAILQ_INIT(&qp->free_commands);
	for (i = 0; i < num_commands; i++) {
		cmd = malloc(sizeof(*cmd), M_NVMF, M_WAITOK | M_ZERO);
		cmd->cid = i;
		TAILQ_INSERT_TAIL(&qp->free_commands, cmd, link);
	}
	STAILQ_INIT(&qp->pending_requests);

	qp->qp = nvmf_allocate_qpair(trtype, false, handoff, nvmf_qp_error,
	    qp, nvmf_receive_capsule, qp);
	if (qp->qp == NULL) {
		TAILQ_FOREACH_SAFE(cmd, &qp->free_commands, link, ncmd) {
			TAILQ_REMOVE(&qp->free_commands, cmd, link);
			free(cmd, M_NVMF);
		}
		free(qp->active_commands, M_NVMF);
		mtx_destroy(&qp->lock);
		free(qp, M_NVMF);
		return (NULL);
	}

	return (qp);
}

void
nvmf_destroy_qp(struct nvmf_host_qpair *qp)
{
	struct nvmf_host_command *cmd, *ncmd;
	struct nvmf_request *req;

	nvmf_free_qpair(qp->qp);

	/*
	 * Abort outstanding requests.  Active requests will have
	 * their I/O completions invoked and associated capsules freed
	 * by the transport layer via nvmf_free_qpair.  Pending
	 * requests must have their I/O completion invoked via
	 * nvmf_abort_capsule_data.
	 */
	for (u_int i = 0; i < qp->qsize - 1; i++) {
		cmd = qp->active_commands[i];
		if (cmd != NULL) {
			printf("%s: aborted active command %p (CID %u)\n",
			    __func__, cmd->req, cmd->cid);

			/* This was freed by nvmf_free_qpair. */
			cmd->req->nc = NULL;
			nvmf_abort_request(cmd->req, cmd->cid);
			nvmf_free_request(cmd->req);
			free(cmd, M_NVMF);
		}
	}
	while (!STAILQ_EMPTY(&qp->pending_requests)) {
		req = STAILQ_FIRST(&qp->pending_requests);
		STAILQ_REMOVE_HEAD(&qp->pending_requests, link);
		printf("%s: aborted pending command %p\n", __func__, req);
		nvmf_abort_capsule_data(req->nc, ECONNABORTED);
		nvmf_abort_request(req, 0);
		nvmf_free_request(req);
	}

	TAILQ_FOREACH_SAFE(cmd, &qp->free_commands, link, ncmd) {
		TAILQ_REMOVE(&qp->free_commands, cmd, link);
		free(cmd, M_NVMF);
	}
	free(qp->active_commands, M_NVMF);
	mtx_destroy(&qp->lock);
	free(qp, M_NVMF);
}

void
nvmf_submit_request(struct nvmf_request *req)
{
	struct nvmf_host_qpair *qp;
	struct nvmf_host_command *cmd;

	qp = req->qp;
	mtx_lock(&qp->lock);
	cmd = TAILQ_FIRST(&qp->free_commands);
	if (cmd == NULL) {
		/*
		 * Queue this request.  Will be sent after enough
		 * in-flight requests have completed.
		 */
		STAILQ_INSERT_TAIL(&qp->pending_requests, req, link);
		mtx_unlock(&qp->lock);
		return;
	}

	TAILQ_REMOVE(&qp->free_commands, cmd, link);
	KASSERT(qp->active_commands[cmd->cid] == NULL,
	    ("%s: CID already busy", __func__));
	qp->active_commands[cmd->cid] = cmd;
	cmd->req = req;
	mtx_unlock(&qp->lock);
	nvmf_dispatch_command(qp, cmd);
}
