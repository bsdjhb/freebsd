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

#include <assert.h>

#include "libnvmf.h"
#include "internal.h"

struct nvmf_connection *
nvmf_allocate_connection(enum nvmf_trtype trtype, bool controller,
    const union nvmf_connection_params *params)
{
	struct nvmf_transport_ops *ops;
	struct nvmf_connection *nc;
	int error;

	switch (trtype) {
	case NVMF_TRTYPE_TCP:
		ops = &tcp_ops;
		break;
	default:
		ops = NULL;
		break;
	}

	if (ops == NULL)
		return (NULL);

	nc = ops->allocate_connection(controller, params);
	if (nc == NULL)
		return (NULL);

	nc->nc_ops = ops;
	nc->nc_controller = controller;
	if (controller)
		error = ops->accept(nc, params);
	else
		error = ops->connect(nc, params);
	if (error != 0) {
		nvmf_free_connection(nc);
		return (NULL);
	}
	return (nc);
}

void
nvmf_free_connection(struct nvmf_connection *nc)
{
	nc->nc_ops->free_connection(nc);
}

struct nvmf_qpair *
nvmf_allocate_qpair(struct nvmf_connection *nc, bool admin)
{
	struct nvmf_qpair *qp;

	qp = nc->nc_ops->allocate_qpair(nc);
	if (qp == NULL)
		return (NULL);

	qp->nq_connection = nc;
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

	assert(nc->nc_qe != NULL);
	assert(nc->nc_qe_len == sizeof(struct nvmf_fabric_connect_cmd));
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

	assert(nc->nc_qe != NULL);
	assert(nc->nc_qe_len == sizeof(struct nvmf_fabric_connect_rsp));
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

#if 0
int
nvmf_receive_capsule(struct nvmf_capsule **nc)
{
	return (nc->nc_qpair->nq_receive_capsule(nc));
}
#endif
