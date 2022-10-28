/*-
 * Copyright (c) 2022 Chelsio Communications, Inc.
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
#include <sys/sx.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>

/* Transport-independent support for fabrics queue pairs and commands. */

struct nvmf_transport {
	struct nvmf_transport_ops *nt_ops;

	volatile u_int nt_active_connections;
	bool nt_detaching;
	TAILQ_ENTRY(nvmf_transport) nt_link;
};

static TAILQ_HEAD(, nvmf_transport) nvmf_transports;
static struct sx nvmf_transports_lock;

static MALLOC_DEFINE(M_NVMF, "nvmf", "NVMe over Fabrics");

static bool
transport_ops_matches(struct nvmf_transport_ops *ops, enum nvmf_trtype trtype,
    const char *offload)
{
	return (ops->trtype == trtype &&
	    (ops->offload == offload || strcmp(ops->offload, offload) == 0));
}

static struct nvmf_connection *
nvmf_allocate_connection(enum nvmf_trtype trtype, const char *offload,
    bool controller, union nvmf_connection_params *params)
{
	struct nvmf_connection *nc;
	struct nvmf_transport *nt;

	sx_slock(&nvmf_transports_lock);
	TAILQ_FOREACH(nt, &nvmf_transports, nt_link) {
		if (transport_ops_matches(nt->nt_ops, trtype, offload))
			break;
	}

	if (nt == NULL || nt->nt_detaching ||
	    !refcount_acquire_checked(&nt->nt_active_connections)) {
		sx_sunlock(&nvmf_transports_lock);
		return (NULL);
	}
	sx_sunlock(&nvmf_transports_lock);

	nc = nt->nt_ops->allocate_connection(controller, params);
	if (nc == NULL) {
		if (refcount_release(&nt->nt_active_connections))
			wakeup(nt);
	}
	return (nc);
}

static void
nvmf_free_connection(struct nvmf_connection *nc)
{
	struct nvmf_transport *nt;

	nt = nc->nc_transport;
	nt->nt_ops->free_connection(nc);
	if (refcount_release(&nt->nt_active_connections))
		wakeup(nt);
}

struct nvmf_qpair *
nvmf_allocate_qpair(struct nvmf_connection *nc, bool admin,
    nvmf_capsule_receive_t *receive_cb)
{
	struct nvmf_qpair *qp;

	KASSERT(!nc->nc_disconnecting, ("%s: connection is shutting down",
	    __func__));

	qp = nc->nc_ops->allocate_qpair(nc);
	if (qp == NULL)
		return (NULL);

	qp->nq_connection = nc;
	qp->nq_receive = receive_cb;
	qp->nq_admin = admin;
	return (qp);
}

void
nvmf_free_qpair(struct nvmf_qpair *qp)
{
	qp->nq_connection->nc_ops->free_qpair(qp);
}

struct nvmf_capsule *
nvmf_allocate_command(struct nvmf_qpair *qp)
{
	struct nvmf_capsule *nc;

	nc = qp->nq_connection->nc_ops->allocate_command(qp);
	if (nc == NULL)
		return (NULL);

	KASSERT(nc->nc_qe != NULL &&
	    nc->nc_qe_len == sizeof(struct nvmf_fabric_connect_cmd),
	    ("%s: invalid command capsule %p", __func__, nc));
	nc->nc_qpair = qp;
	return (nc);
}

struct nvmf_capsule *
nvmf_allocate_response(struct nvmf_capsule *cmd)
{
	struct nvmf_capsule *nc;
	struct nvmf_qpair *qp;

	qp = cmd->nc_qpair;
	nc = qp->nq_connection->nc_ops->allocate_response(qp);
	if (nc == NULL)
		return (NULL);

	KASSERT(nc->nc_qe != NULL &&
	    nc->nc_qe_len == sizeof(struct nvmf_fabric_connect_rsp),
	    ("%s: invalid command capsule %p", __func__, nc));
	nc->nc_qpair = qp;
	return (nc);
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

void
nvmf_receive_capsule(struct nvmf_capsule *nc)
{
	nc->nc_qpair->nq_receive(nc);
}

static const char *
nvmf_transport_type_name(enum nvmf_trtype trtype)
{
	switch (trtype) {
	case NVMF_TRTYPE_RDMA:
		return ("RDMA");
	case NVMF_TRTYPE_FC:
		return ("FC");
	case NVMF_TRTYPE_TCP:
		return ("TCP");
	case NVMF_TRTYPE_INTRA_HOST:
		return ("loopback");
	}
}

int
nvmf_transport_module_handler(struct module *mod, int what, void *arg)
{
	struct nvmf_transport_ops *ops = arg;
	struct nvmf_transport *nt;
	int error;

	switch (what) {
	case MOD_LOAD:
		sx_xlock(&nvmf_transports_lock);
		TAILQ_FOREACH(nt, &nvmf_transports, nt_link) {
			if (transport_ops_matches(nt->nt_ops, ops->trtype,
			    ops->offload)) {
				sx_xunlock(&nvmf_transports_lock);
				printf("NVMF: Attempt to register duplicate transport %s",
				    nvmf_transport_type_name(ops->trtype));
				if (ops->offload != NULL)
					printf(" (%s)", ops->offload);
				printf("\n");
				return (EBUSY);
			}
		}
		nt = malloc(sizeof(*nt), M_NVMF, M_WAITOK | M_ZERO);
		nt->nt_ops = arg;
		TAILQ_INSERT_TAIL(&nvmf_transports, nt, nt_link);
		sx_xunlock(&nvmf_transports_lock);
		return (0);

	case MOD_QUIESCE:
		sx_slock(&nvmf_transports_lock);
		TAILQ_FOREACH(nt, &nvmf_transports, nt_link)
			if (nt->nt_ops == ops)
				break;
		if (nt == NULL) {
			sx_sunlock(&nvmf_transports_lock);
			return (ENXIO);
		}
		if (nt->nt_active_connections != 0) {
			sx_sunlock(&nvmf_transports_lock);
			return (EBUSY);
		}
		sx_sunlock(&nvmf_transports_lock);
		return (0);

	case MOD_UNLOAD:
		sx_xlock(&nvmf_transports_lock);
		TAILQ_FOREACH(nt, &nvmf_transports, nt_link)
			if (nt->nt_ops == ops)
				break;
		if (nt == NULL) {
			sx_xunlock(&nvmf_transports_lock);
			return (ENXIO);
		}
		nt->nt_detaching = true;
		error = 0;
		while (nt->nt_active_qpairs != 0 && error = 0)
			error = sx_sleep(nt, &nvmf_transports_lock, PCATCH,
			    "nftunld", 0);
		if (error != 0) {
			nt->nt_detaching = false;
			sx_xunlock(&nvmf_transports_lock);
			return (error);
		}
		TAILQ_REMOVE(&nvmf_transports, nt, nt_link);
		sx_xunlock(&nvmf_transports_lock);
		free(nt, M_NVMF);
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static void
nvmf_transport_init(void * __unused dummy)
{
	TAILQ_INIT(&nvmf_transports);
	sx_init(&nvmf_transports_lock, "nvmf transports");
}
SYSINIT(nvmf_transport_init, SI_SUB_DRIVERS, SI_ORDER_FIRST,
    nvmf_transport_init, NULL);
