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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libnvmf.h"
#include "internal.h"

struct nvmf_connection *
nvmf_allocate_connection(enum nvmf_trtype trtype, bool controller,
    const struct nvmf_connection_params *params)
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
	nc->nc_sq_flow_control = params->sq_flow_control;
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

	qp = nc->nc_ops->allocate_qpair(nc, admin);
	if (qp == NULL)
		return (NULL);

	qp->nq_connection = nc;
	qp->nq_admin = admin;
	TAILQ_INIT(&qp->nq_rx_capsules);
	return (qp);
}

void
nvmf_free_qpair(struct nvmf_qpair *qp)
{
	struct nvmf_capsule *ncap, *tcap;

	TAILQ_FOREACH_SAFE(ncap, &qp->nq_rx_capsules, nc_link, tcap) {
		TAILQ_REMOVE(&qp->nq_rx_capsules, ncap, nc_link);
		nvmf_free_capsule(ncap);
	}
	qp->nq_connection->nc_ops->free_qpair(qp);
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
nvmf_capsule_append_data(struct nvmf_capsule *nc, const void *buf, size_t len)
{
	struct iovec *new_iov;

	if (nc->nc_qe_len == sizeof(struct nvme_completion))
		return (EINVAL);
	if (nc->nc_data_iovcnt >= INT_MAX)
		return (EFBIG);
	if (nc->nc_data_len + len < nc->nc_data_len)
		return (EFBIG);

	new_iov = realloc(nc->nc_data_iov, (nc->nc_data_iovcnt + 1) *
	    sizeof(*new_iov));
	if (new_iov == NULL)
		return (ENOMEM);
	new_iov[nc->nc_data_iovcnt].iov_base = __DECONST(void *, buf);
	new_iov[nc->nc_data_iovcnt].iov_len = len;
	nc->nc_data_iov = new_iov;
	nc->nc_data_iovcnt++;
	nc->nc_data_len += len;
	return (0);
}

void
nvmf_free_capsule(struct nvmf_capsule *nc)
{
	nc->nc_qpair->nq_connection->nc_ops->free_capsule(nc);
}

int
nvmf_transmit_capsule(struct nvmf_capsule *nc, bool send_data)
{
	return (nc->nc_qpair->nq_connection->nc_ops->transmit_capsule(nc,
	    send_data));
}

int
nvmf_receive_capsule(struct nvmf_qpair *qp, struct nvmf_capsule **nc)
{
	return (qp->nq_connection->nc_ops->receive_capsule(qp, nc));
}

const void *
nvmf_capsule_sqe(struct nvmf_capsule *nc)
{
	assert(nc->nc_qe_len == sizeof(struct nvme_command));
	return (&nc->nc_sqe);
}

const void *
nvmf_capsule_cqe(struct nvmf_capsule *nc)
{
	assert(nc->nc_qe_len == sizeof(struct nvme_completion));
	return (&nc->nc_cqe);
}

int
nvmf_receive_controller_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct iovec *iov, u_int iovcnt)
{
	return (nc->nc_qpair->nq_connection->nc_ops->receive_controller_data(nc,
	    data_offset, iov, iovcnt));
}

int
nvmf_send_controller_data(struct nvmf_capsule *nc, struct iovec *iov,
    u_int iovcnt)
{
	return (nc->nc_qpair->nq_connection->nc_ops->send_controller_data(nc,
	    iov, iovcnt));
}
