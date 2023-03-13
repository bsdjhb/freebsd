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

struct nvmf_transport_ops {
	/* Connection management. */
	struct nvmf_connection *(*allocate_connection)(bool controller,
	    const union nvmf_connection_params *params);
	int (*connect)(struct nvmf_connection *nc,
	    const union nvmf_connection_params *params);
	int (*accept)(struct nvmf_connection *nc,
	    const union nvmf_connection_params *params);
	void (*free_connection)(struct nvmf_connection *nc);

	/* Queue pair management. */
	struct nvmf_qpair *(*allocate_qpair)(struct nvmf_connection *nt);
	void (*free_qpair)(struct nvmf_qpair *qp);

	/* Capsule operations. */
	struct nvmf_capsule *(*allocate_command)(struct nvmf_qpair *qp);
	struct nvmf_capsule *(*allocate_response)(struct nvmf_qpair *qp);
	void (*free_capsule)(struct nvmf_capsule *nc);
	int (*transmit_capsule)(struct nvmf_capsule *nc);
#if 0
	int (*receive_capsule)(struct nvmf_capsule **nc);
#endif
};

struct nvmf_connection {
	struct nvmf_transport_ops *nc_ops;
	bool nc_controller;
};

struct nvmf_qpair {
	struct nvmf_connection *nq_connection;
	bool nq_admin;
};

struct nvmf_capsule {
	struct nvmf_qpair *nc_qpair;

	/* Either a SQE or CQE. */
	void 	*nc_qe;

	void	*nc_data;
	size_t	nc_data_len;

	int	nc_qe_len;
};

extern struct nvmf_transport_ops tcp_ops;

#endif /* !__LIBNVMF_INTERNAL_H__ */
