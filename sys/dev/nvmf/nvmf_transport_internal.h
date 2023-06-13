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

#ifndef __NVMF_TRANSPORT_INTERNAL_H__
#define	__NVMF_TRANSPORT_INTERNAL_H__

#include <sys/memdesc.h>

/*
 * Interface between the transport-independent APIs in
 * nvmf_transport.c and individual transports.
 */

struct module;
struct nvmf_io_request;

struct nvmf_transport_ops {
	/* Queue pair management. */
	struct nvmf_qpair *(*allocate_qpair)(bool controller,
	    const struct nvmf_handoff_qpair_params *params);
	void (*free_qpair)(struct nvmf_qpair *qp);

	/* Capsule operations. */
	struct nvmf_capsule *(*allocate_capsule)(struct nvmf_qpair *qp,
	    int how);
	void (*free_capsule)(struct nvmf_capsule *nc);
	int (*transmit_capsule)(struct nvmf_capsule *nc);
	uint8_t (*validate_command_capsule)(struct nvmf_capsule *nc);

	/* Transferring controller data. */
	int (*receive_controller_data)(struct nvmf_capsule *nc,
	    uint32_t data_offset, struct nvmf_io_request *io);
	int (*send_controller_data)(struct nvmf_capsule *nc,
	    struct nvmf_io_request *io);

	enum nvmf_trtype trtype;
	int priority;
};

/* Either an Admin or I/O Submission/Completion Queue pair. */
struct nvmf_qpair {
	struct nvmf_transport *nq_transport;
	struct nvmf_transport_ops *nq_ops;
	bool nq_controller;

	/* Callback to invoke for a received capsule. */
	nvmf_capsule_receive_t *nq_receive;
	void *nq_receive_arg;

	/* Callback to invoke for an error. */
	nvmf_qpair_error_t *nq_error;
	void *nq_error_arg;

	bool nq_admin;

#ifdef host_only
	/* Move these fields to a host-only structure for a queue pair */
	uint16_t nq_cid;

	/*
	 * Queue sizes.  This assumes the same size for both the
	 * completion and submission queues within a pair.
	 */
	uint16_t nq_qsize;

	/* Flow control management for submission queues. */
	bool nq_flow_control;
	uint16_t nq_sqhd;
	uint16_t nq_sqtail;	/* host only */

#ifdef notsure
	/* Value in response from CONNECT. */
	uint16_t nq_cntlid;	/* host only */
#endif
#endif

	/* XXX: TAILQ_ENTRY probably?  refcount? */
};

struct nvmf_io_request {
	/*
	 * Data buffer contains len bytes starting at offset offset of
	 * the backing store described by mem.
	 */
	struct memdesc io_mem;
	size_t	io_len;
	u_int	io_offset;
	nvmf_io_complete_t *io_complete;
	void	*io_complete_arg;
};

/*
 * Fabrics Command and Response Capsules.  The Fabrics host
 * (initiator) and controller (target) drivers work with capsules that
 * are transmitted and received by a specific transport.
 */
struct nvmf_capsule {
	struct nvmf_qpair *nc_qpair;

	/* Either a SQE or CQE. */
	union {
		struct nvme_command nc_sqe;
		struct nvme_completion nc_cqe;
	};
	int	nc_qe_len;

	/*
	 * Is SQHD in received capsule valid?  False for locally-
	 * synthesized responses.
	 */
	bool	nc_sqhd_valid;

	bool	nc_send_data;
	struct nvmf_io_request nc_data;

	/* XXX: TAILQ_ENTRY probably?  refcount? */
};

static void __inline
nvmf_qpair_error(struct nvmf_qpair *nq)
{
	nq->nq_error(nq->nq_error_arg);
}

static void __inline
nvmf_capsule_received(struct nvmf_qpair *nq, struct nvmf_capsule *nc)
{
	nq->nq_receive(nq->nq_receive_arg, nc);
}

static void __inline
nvmf_complete_io_request(struct nvmf_io_request *io, size_t xfered, int error)
{
	io->io_complete(io->io_complete_arg, xfered, error);
}

int	nvmf_transport_module_handler(struct module *, int, void *);

#define	NVMF_TRANSPORT(name, ops)					\
static moduledata_t nvmf_transport_##name##_mod = {			\
	"nvmf/" #name,							\
	nvmf_transport_module_handler,					\
	&(ops)								\
};									\
DECLARE_MODULE(nvmf_transport_##name, nvmf_transport_##name##_mod,	\
    SI_SUB_DRIVERS, SI_ORDER_ANY);					\
MODULE_DEPEND(nvmf_transport_##name, nvmf_transport, 1, 1, 1)

#endif /* !__NVMF_TRANSPORT_INTERNAL_H__ */
