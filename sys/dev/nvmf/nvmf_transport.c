/*-
 * Copyright (c) 2022-2023 Chelsio Communications, Inc.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/refcount.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/nvmf_transport_internal.h>

/* Transport-independent support for fabrics queue pairs and commands. */

struct nvmf_transport {
	struct nvmf_transport_ops *nt_ops;

	volatile u_int nt_active_connections;
	SLIST_ENTRY(nvmf_transport) nt_link;
};

/* nvmf_transports[nvmf_trtype] is sorted by priority */
static SLIST_HEAD(, nvmf_transport) nvmf_transports[NVMF_TRTYPE_TCP + 1];
static struct sx nvmf_transports_lock;

static MALLOC_DEFINE(M_NVMF_TRANSPORT, "nvmf_xport",
    "NVMe over Fabrics transport");

SYSCTL_NODE(_kern, OID_AUTO, nvmf, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "NVMe over Fabrics");

static bool
nvmf_supported_trtype(enum nvmf_trtype trtype)
{
	return (trtype < nitems(nvmf_transports));
}

struct nvmf_connection *
nvmf_allocate_connection(enum nvmf_trtype trtype, bool controller,
    const struct nvmf_connection_params *params,
    nvmf_connection_error_t *error_cb, void *cb_arg)
{
	struct nvmf_connection *nc;
	struct nvmf_transport *nt;

	if (!nvmf_supported_trtype(trtype))
		return (NULL);

	sx_slock(&nvmf_transports_lock);
	SLIST_FOREACH(nt, &nvmf_transports[trtype], nt_link) {
		nc = nt->nt_ops->allocate_connection(controller, params);
		if (nc != NULL)
			break;
	}
	if (nc != NULL) {
		refcount_acquire(&nt->nt_active_connections);
		nc->nc_transport = nt;
		nc->nc_ops = nt->nt_ops;
		nc->nc_controller = controller;
		refcount_init(&nc->nc_refs, 1);
		nc->nc_error = error_cb;
		nc->nc_error_arg = cb_arg;
	}
	sx_sunlock(&nvmf_transports_lock);
	return (nc);
}

void
nvmf_free_connection(struct nvmf_connection *nc)
{
	struct nvmf_transport *nt;

	if (!refcount_release(&nc->nc_refs))
		return;

	nt = nc->nc_transport;
	nt->nt_ops->free_connection(nc);
	if (refcount_release(&nt->nt_active_connections))
		wakeup(nt);
}

struct nvmf_qpair *
nvmf_allocate_qpair(struct nvmf_connection *nc, bool admin,
    nvmf_capsule_receive_t *receive_cb, void *cb_arg)
{
	struct nvmf_qpair *qp;

	qp = nc->nc_ops->allocate_qpair(nc, admin);
	if (qp == NULL)
		return (NULL);

	refcount_acquire(&nc->nc_refs);
	qp->nq_connection = nc;
	qp->nq_receive = receive_cb;
	qp->nq_receive_arg = cb_arg;
	qp->nq_admin = admin;
	return (qp);
}

void
nvmf_free_qpair(struct nvmf_qpair *qp)
{
	struct nvmf_connection *nc;

	nc = qp->nq_connection;
	nc->nc_ops->free_qpair(qp);
	nvmf_free_connection(nc);
}

struct nvmf_capsule *
nvmf_allocate_command(struct nvmf_qpair *qp, const void *sqe)
{
	struct nvmf_capsule *nc;

	nc = qp->nq_connection->nc_ops->allocate_capsule(qp);
	if (nc == NULL)
		return (NULL);

	nc->nc_qpair = qp;
	nc->nc_qe_len = sizeof(struct nvme_command);
	memcpy(&nc->nc_sqe, sqe, nc->nc_qe_len);

	/* 4.2 of NVMe base spec: Fabrics always uses SGL. */
	nc->nc_sqe.fuse &= ~NVMEB(NVME_CMD_PSDT);
	nc->nc_sqe.fuse |= NVME_PSDT_SGL << NVME_CMD_PSDT_SHIFT;
	return (nc);
}

struct nvmf_capsule *
nvmf_allocate_response(struct nvmf_qpair *qp, const void *cqe)
{
	struct nvmf_capsule *nc;

	nc = qp->nq_connection->nc_ops->allocate_capsule(qp);
	if (nc == NULL)
		return (NULL);

	nc->nc_qpair = qp;
	nc->nc_qe_len = sizeof(struct nvme_completion);
	memcpy(&nc->nc_cqe, cqe, nc->nc_qe_len);
	return (nc);
}

int
nvmf_capsule_append_data(struct nvmf_capsule *nc, struct memdesc *mem,
    size_t len, u_int offset, bool send, nvmf_io_complete_t *complete_cb,
    void *cb_arg)
{
	if (nc->nc_data.io_len != 0)
		return (EBUSY);

	nc->nc_send_data = send;
	nc->nc_data.io_mem = *mem;
	nc->nc_data.io_len = len;
	nc->nc_data.io_offset = offset;
	nc->nc_data.io_complete = complete_cb;
	nc->nc_data.io_complete_arg = cb_arg;
	return (0);
}

void
nvmf_free_capsule(struct nvmf_capsule *nc)
{
	nc->nc_qpair->nq_connection->nc_ops->free_capsule(nc);
}

int
nvmf_transmit_capsule(struct nvmf_capsule *nc)
{
	return (nc->nc_qpair->nq_connection->nc_ops->transmit_capsule(nc));
}

void *
nvmf_capsule_sqe(struct nvmf_capsule *nc)
{
	KASSERT(nc->nc_qe_len == sizeof(struct nvme_command),
	    ("%s: capsule %p is not a command capsule", __func__, nc));
	return (&nc->nc_sqe);
}

void *
nvmf_capsule_cqe(struct nvmf_capsule *nc)
{
	KASSERT(nc->nc_qe_len == sizeof(struct nvme_completion),
	    ("%s: capsule %p is not a response capsule", __func__, nc));
	return (&nc->nc_cqe);
}

uint8_t
nvmf_validate_command_capsule(struct nvmf_capsule *nc)
{
	KASSERT(nc->nc_qe_len == sizeof(struct nvme_command),
	    ("%s: capsule %p is not a command capsule", __func__, nc));

	if (NVMEV(NVME_CMD_PSDT, nc->nc_sqe.fuse) != NVME_PSDT_SGL)
		return (NVME_SC_INVALID_FIELD);

	return (nc->nc_qpair->nq_connection->nc_ops->validate_command_capsule(nc));
}

int
nvmf_receive_controller_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct memdesc *mem, size_t len, u_int offset,
    nvmf_io_complete_t *complete_cb, void *cb_arg)
{
	struct nvmf_io_request io;

	io.io_mem = *mem;
	io.io_len = len;
	io.io_offset = offset;
	io.io_complete = complete_cb;
	io.io_complete_arg = cb_arg;
	return (nc->nc_qpair->nq_connection->nc_ops->receive_controller_data(nc,
	    data_offset, &io));
}

int
nvmf_send_controller_data(struct nvmf_capsule *nc, struct memdesc *mem,
    size_t len, u_int offset, nvmf_io_complete_t *complete_cb, void *cb_arg)
{
	struct nvmf_io_request io;

	io.io_mem = *mem;
	io.io_len = len;
	io.io_offset = offset;
	io.io_complete = complete_cb;
	io.io_complete_arg = cb_arg;
	return (nc->nc_qpair->nq_connection->nc_ops->send_controller_data(nc,
	    &io));
}

int
nvmf_transport_module_handler(struct module *mod, int what, void *arg)
{
	struct nvmf_transport_ops *ops = arg;
	struct nvmf_transport *nt, *nt2, *prev;
	int error;

	switch (what) {
	case MOD_LOAD:
		if (!nvmf_supported_trtype(ops->trtype)) {
			printf("NVMF: Unsupported transport %u", ops->trtype);
			return (EINVAL);
		}

		nt = malloc(sizeof(*nt), M_NVMF_TRANSPORT, M_WAITOK | M_ZERO);
		nt->nt_ops = arg;

		sx_xlock(&nvmf_transports_lock);
		if (SLIST_EMPTY(&nvmf_transports[ops->trtype])) {
			SLIST_INSERT_HEAD(&nvmf_transports[ops->trtype], nt,
			    nt_link);
		} else {
			prev = NULL;
			SLIST_FOREACH(nt2, &nvmf_transports[ops->trtype],
			    nt_link) {
				if (ops->priority > nt2->nt_ops->priority)
					break;
				prev = nt2;
			}
			if (prev == NULL)
				SLIST_INSERT_HEAD(&nvmf_transports[ops->trtype],
				    nt, nt_link);
			else
				SLIST_INSERT_AFTER(prev, nt, nt_link);
		}
		sx_xunlock(&nvmf_transports_lock);
		return (0);

	case MOD_QUIESCE:
		if (!nvmf_supported_trtype(ops->trtype))
			return (0);

		sx_slock(&nvmf_transports_lock);
		SLIST_FOREACH(nt, &nvmf_transports[ops->trtype], nt_link) {
			if (nt->nt_ops == ops)
				break;
		}
		if (nt == NULL) {
			sx_sunlock(&nvmf_transports_lock);
			return (0);
		}
		if (nt->nt_active_connections != 0) {
			sx_sunlock(&nvmf_transports_lock);
			return (EBUSY);
		}
		sx_sunlock(&nvmf_transports_lock);
		return (0);

	case MOD_UNLOAD:
		if (!nvmf_supported_trtype(ops->trtype))
			return (0);

		sx_xlock(&nvmf_transports_lock);
		prev = NULL;
		SLIST_FOREACH(nt, &nvmf_transports[ops->trtype], nt_link) {
			if (nt->nt_ops == ops)
				break;
			prev = nt;
		}
		if (nt == NULL) {
			KASSERT(nt->nt_active_connections == 0,
			    ("unregistered transport has connections"));
			sx_xunlock(&nvmf_transports_lock);
			return (0);
		}

		if (prev == NULL)
			SLIST_REMOVE_HEAD(&nvmf_transports[ops->trtype],
			    nt_link);
		else
			SLIST_REMOVE_AFTER(prev, nt_link);

		error = 0;
		while (nt->nt_active_connections != 0 && error == 0)
			error = sx_sleep(nt, &nvmf_transports_lock, PCATCH,
			    "nftunld", 0);
		sx_xunlock(&nvmf_transports_lock);
		if (error != 0)
			return (error);
		free(nt, M_NVMF_TRANSPORT);
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static int
nvmf_transport_modevent(module_t mod __unused, int what, void *arg __unused)
{
	switch (what) {
	case MOD_LOAD:
		for (u_int i = 0; i < nitems(nvmf_transports); i++)
			SLIST_INIT(&nvmf_transports[i]);
		sx_init(&nvmf_transports_lock, "nvmf transports");
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t nvmf_transport_mod = {
	"nvmf_transport",
	nvmf_transport_modevent,
	0
};

DECLARE_MODULE(nvmf_transport, nvmf_transport_mod, SI_SUB_DRIVERS,
    SI_ORDER_FIRST);
MODULE_VERSION(nvmf_transport, 1);
