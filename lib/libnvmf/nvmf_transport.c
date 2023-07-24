/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022-2023 Chelsio Communications, Inc.
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

#include <sys/refcount.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnvmf.h"
#include "internal.h"

struct nvmf_association *
nvmf_allocate_association(enum nvmf_trtype trtype, bool controller,
    const struct nvmf_association_params *params)
{
	struct nvmf_transport_ops *ops;
	struct nvmf_association *na;

	switch (trtype) {
	case NVMF_TRTYPE_TCP:
		ops = &tcp_ops;
		break;
	default:
		errno = EINVAL;
		return (NULL);
	}

	na = ops->allocate_association(controller, params);
	if (na == NULL)
		return (NULL);

	na->na_ops = ops;
	na->na_trtype = trtype;
	na->na_controller = controller;
	na->na_params = *params;
	na->na_last_error = NULL;
	refcount_init(&na->na_refs, 1);
	return (na);
}

void
nvmf_update_assocation(struct nvmf_association *na,
    const struct nvme_controller_data *cdata)
{
	na->na_ops->update_association(na, cdata);
}

void
nvmf_free_association(struct nvmf_association *na)
{
	if (refcount_release(&na->na_refs)) {
		free(na->na_last_error);
		na->na_ops->free_association(na);
	}
}

const char *
nvmf_association_error(const struct nvmf_association *na)
{
	return (na->na_last_error);
}

void
na_clear_error(struct nvmf_association *na)
{
	free(na->na_last_error);
	na->na_last_error = NULL;
}

void
na_error(struct nvmf_association *na, const char *fmt, ...)
{
	va_list ap;
	char *str;

	if (na->na_last_error != NULL)
		return;
	va_start(ap, fmt);
	vasprintf(&str, fmt, ap);
	va_end(ap);
	na->na_last_error = str;
}

struct nvmf_qpair *
nvmf_allocate_qpair(struct nvmf_association *na,
    const struct nvmf_qpair_params *params)
{
	struct nvmf_qpair *qp;

	na_clear_error(na);
	qp = na->na_ops->allocate_qpair(na, params);
	if (qp == NULL)
		return (NULL);

	refcount_acquire(&na->na_refs);
	qp->nq_association = na;
	qp->nq_admin = params->admin;
	TAILQ_INIT(&qp->nq_rx_capsules);
	return (qp);
}

void
nvmf_free_qpair(struct nvmf_qpair *qp)
{
	struct nvmf_association *na;
	struct nvmf_capsule *nc, *tc;

	TAILQ_FOREACH_SAFE(nc, &qp->nq_rx_capsules, nc_link, tc) {
		TAILQ_REMOVE(&qp->nq_rx_capsules, nc, nc_link);
		nvmf_free_capsule(nc);
	}
	na = qp->nq_association;
	na->na_ops->free_qpair(qp);
	nvmf_free_association(na);
}

struct nvmf_capsule *
nvmf_allocate_command(struct nvmf_qpair *qp, const void *sqe)
{
	struct nvmf_capsule *nc;

	nc = qp->nq_association->na_ops->allocate_capsule(qp);
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

	nc = qp->nq_association->na_ops->allocate_capsule(qp);
	if (nc == NULL)
		return (NULL);

	nc->nc_qpair = qp;
	nc->nc_qe_len = sizeof(struct nvme_completion);
	memcpy(&nc->nc_cqe, cqe, nc->nc_qe_len);
	return (nc);
}

int
nvmf_capsule_append_data(struct nvmf_capsule *nc, const void *buf, size_t len, bool send)
{
	struct iovec *new_iov;

	if (nc->nc_qe_len == sizeof(struct nvme_completion))
		return (EINVAL);
	if (nc->nc_data_iovcnt >= INT_MAX)
		return (EFBIG);
	if (nc->nc_data_len + len < nc->nc_data_len)
		return (EFBIG);
	if (nc->nc_data_len != 0 && nc->nc_send_data != send)
		return (EINVAL);

	new_iov = realloc(nc->nc_data_iov, (nc->nc_data_iovcnt + 1) *
	    sizeof(*new_iov));
	if (new_iov == NULL)
		return (ENOMEM);
	new_iov[nc->nc_data_iovcnt].iov_base = __DECONST(void *, buf);
	new_iov[nc->nc_data_iovcnt].iov_len = len;
	nc->nc_data_iov = new_iov;
	nc->nc_data_iovcnt++;
	nc->nc_data_len += len;
	nc->nc_send_data = send;
	return (0);
}

void
nvmf_free_capsule(struct nvmf_capsule *nc)
{
	nc->nc_qpair->nq_association->na_ops->free_capsule(nc);
}

int
nvmf_transmit_capsule(struct nvmf_capsule *nc)
{
	return (nc->nc_qpair->nq_association->na_ops->transmit_capsule(nc));
}

int
nvmf_receive_capsule(struct nvmf_qpair *qp, struct nvmf_capsule **ncp)
{
	return (qp->nq_association->na_ops->receive_capsule(qp, ncp));
}

const void *
nvmf_capsule_sqe(const struct nvmf_capsule *nc)
{
	assert(nc->nc_qe_len == sizeof(struct nvme_command));
	return (&nc->nc_sqe);
}

const void *
nvmf_capsule_cqe(const struct nvmf_capsule *nc)
{
	assert(nc->nc_qe_len == sizeof(struct nvme_completion));
	return (&nc->nc_cqe);
}

uint8_t
nvmf_validate_command_capsule(struct nvmf_capsule *nc)
{
	assert(nc->nc_qe_len == sizeof(struct nvme_command));

	if (NVMEV(NVME_CMD_PSDT, nc->nc_sqe.fuse) != NVME_PSDT_SGL)
		return (NVME_SC_INVALID_FIELD);

	return (nc->nc_qpair->nq_association->na_ops->validate_command_capsule(nc));
}

size_t
nvmf_capsule_data_len(struct nvmf_capsule *nc)
{
	return (nc->nc_qpair->nq_association->na_ops->capsule_data_len(nc));
}

int
nvmf_receive_controller_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct iovec *iov, u_int iovcnt)
{
	return (nc->nc_qpair->nq_association->na_ops->receive_controller_data(nc,
	    data_offset, iov, iovcnt));
}

int
nvmf_send_controller_data(struct nvmf_capsule *nc, struct iovec *iov,
    u_int iovcnt)
{
	return (nc->nc_qpair->nq_association->na_ops->send_controller_data(nc,
	    iov, iovcnt));
}

int
nvmf_kernel_handoff_params(struct nvmf_qpair *qp,
    struct nvmf_handoff_qpair_params *qparams)
{
	memset(qparams, 0, sizeof(*qparams));
	qparams->admin = qp->nq_admin;
	qparams->sq_flow_control = qp->nq_flow_control;
	qparams->qsize = qp->nq_qsize;
	qparams->sqhd = qp->nq_sqhd;
	qparams->sqtail = qp->nq_sqtail;
	return (qp->nq_association->na_ops->kernel_handoff_params(qp, qparams));
}
