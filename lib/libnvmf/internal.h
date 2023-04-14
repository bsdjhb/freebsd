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

#ifndef __LIBNVMF_INTERNAL_H__
#define __LIBNVMF_INTERNAL_H__

#include <sys/queue.h>

struct nvmf_transport_ops {
	/* Connection management. */
	struct nvmf_connection *(*allocate_connection)(bool controller,
	    const struct nvmf_connection_params *params);
	int (*connect)(struct nvmf_connection *nc,
	    const struct nvmf_connection_params *params);
	int (*accept)(struct nvmf_connection *nc,
	    const struct nvmf_connection_params *params);
	void (*free_connection)(struct nvmf_connection *nc);

	/* Queue pair management. */
	struct nvmf_qpair *(*allocate_qpair)(struct nvmf_connection *nt,
	    bool admin);
	void (*free_qpair)(struct nvmf_qpair *qp);

	/* Capsule operations. */
	struct nvmf_capsule *(*allocate_capsule)(struct nvmf_qpair *qp);
	void (*free_capsule)(struct nvmf_capsule *nc);
	int (*transmit_capsule)(struct nvmf_capsule *nc, bool send_data);
	int (*receive_capsule)(struct nvmf_qpair *qp, struct nvmf_capsule **nc);

	/* Transferring controller data. */
	int (*receive_controller_data)(struct nvmf_capsule *nc,
	    uint32_t data_offset, struct iovec *iov, u_int iovcnt);
	int (*send_controller_data)(struct nvmf_capsule *nc, struct iovec *iov,
	    u_int iovcnt);
};

struct nvmf_connection {
	struct nvmf_transport_ops *nc_ops;
	bool nc_controller;
	bool nc_sq_flow_control;
};

struct nvmf_qpair {
	struct nvmf_connection *nq_connection;
	bool nq_admin;

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

	/* Value in response from CONNECT. */
	uint16_t nq_cntlid;	/* host only */

	TAILQ_HEAD(, nvmf_capsule) nq_rx_capsules;
};

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

	/* Data buffer. */
	u_int	nc_data_iovcnt;
	size_t	nc_data_len;
	struct iovec *nc_data_iov;

	TAILQ_ENTRY(nvmf_capsule) nc_link;
};

extern struct nvmf_transport_ops tcp_ops;

#endif /* !__LIBNVMF_INTERNAL_H__ */
