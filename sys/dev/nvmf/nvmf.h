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

#ifndef __NVMF_H__
#define	__NVMF_H__

#ifdef _KERNEL
#include <sys/memdesc.h>
#include <dev/nvmf/nvmf_proto.h>

struct module;

/*
 * Fabrics Command and Response Capsules.  The Fabrics layer works with
 * capsules that are transmitted and received by a specific transport.
 */
struct nvmf_capsule {
	struct nvmf_qpair *nc_qpair;

	/* Either a SQE or CQE. */
	void 	*nc_qe;

	/*
	 * Data buffer contains ncb_data_len bytes starting at offset
	 * ncb_data_offset of the backing store described by
	 * ncb_data_mem.
	 */
	struct memdesc nc_data_mem;
	size_t	nc_data_len;
	int	nc_data_offset;

	/* Size of the QE. */
	int	nc_qe_len;

	/* XXX: TAILQ_ENTRY probably?  refcount? */
};

/* Callback to invoke when a capsule is received. */
typedef void nvmf_capsule_receive_t(struct nvmf_capsule *);

/* Either an Admin or I/O Submission/Completion Queue pair. */
struct nvmf_qpair {
	struct nvmf_transport *nq_transport;

	nvmf_capsule_receive_t *nq_receive;
	bool nq_admin;

	/* XXX: TAILQ_ENTRY probably?  refcount? */
};

struct nvmf_transport_ops {
	/* Queue pair management. */
	struct nvmf_qpair *(*allocate_qpair)(void);
	void (*free_qpair)(struct nvmf_qpair *qp);

	/* Capsule operations. */
	struct nvmf_capsule *(*allocate_command)(struct nvmf_qpair *qp);
	struct nvmf_capsule *(*allocate_response)(struct nvmf_qpair *qp);
	void (*free_capsule)(struct nvmf_capsule *nc);
	int (*transmit_capsule)(struct nvmf_capsule *nc);

	enum nvmf_trtype trtype;
	const char *offload;
};

struct nvmf_transport {
	struct nvmf_transport_ops *nt_ops;

	/*
	 * XXX: Some other refcount?  Probably more like open sessions
	 * than open qpairs.
	 */
	u_int nt_active_qpairs;
	bool nt_detaching;
	TAILQ_ENTRY(nvmf_transport) nt_link;
};

struct nvmf_qpair *nvmf_allocate_qpair(struct nvmf_transport *nt, bool admin,
    nvmf_capsule_receive_t *receive_cb);
void	nvmf_free_qpair(struct nvmf_qpair *qp);

struct nvmf_capsule *nvmf_allocate_command(struct nvmf_qpair *qp);
struct nvmf_capsule *nvmf_allocate_response(struct nvmf_capsule *nc);
void	nvmf_free_capsule(struct nvmf_capsule *nc);
int	nvmf_transmit_capsule(struct nvmf_capsule *nc);
void	nvmf_receive_capsule(struct nvmf_capsule *nc);

struct nvmf_transport *nvmf_find_transport(enum nvmf_trtype trtype,
    const char *offload);
int	nvmf_transport_module_handler(struct module *, int, void *);

#define	NVMF_TRANSPORT(name, ops)					\
static module_data_t nvmf_transport_##name##_mod = {			\
	"nvmf/" #name,							\
	nvmf_transport_module_handler,					\
	&(ops)								\
};									\
DECLARE_MODULE(nvmf_transport_##name, nvmf_transport_##name##_mod,	\
    SI_SUB_DRIVERS, SI_ORDER_ANY)

#endif /* !_KERNEL */

#endif /* !__NVMF_H__ */
