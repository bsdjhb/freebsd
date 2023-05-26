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

#ifndef __NVMF_VAR_H__
#define	__NVMF_VAR_H__

#include <sys/queue.h>

struct nvmf_capsule;
struct nvmf_host_qpair;

typedef void nvmf_request_complete_t(void *, struct nvmf_capsule *);

struct nvmf_ivars {
	struct nvmf_handoff_host *hh;
	struct nvmf_handoff_qpair *io_params;
};

struct nvmf_softc {
	device_t dev;

	struct nvmf_host_qpair *admin;
	struct nvmf_host_qpair **io;
	u_int	num_io_queues;

	struct cdev *cdev;
};

struct nvmf_request {
	struct nvme_command cmd;
	struct nvmf_capsule *nc;
	nvmf_request_complete_t *cb;
	void	*cb_arg;

	STAILQ_ENTRY(nvmf_request) link;
};

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_NVMF);
#endif

/* nvmf_cmd.c */
void	nvmf_cmd_get_property(struct nvmf_softc *sc, uint32_t offset,
    uint8_t size, nvmf_request_complete_t *cb, void *cb_arg, int how);
void	nvmf_cmd_set_property(struct nvmf_softc *sc, uint32_t offset,
    uint8_t size, uint64_t value, nvmf_request_complete_t *cb, void *cb_arg,
    int how);

/* nvmf_ctldev.c */
int	nvmf_ctl_load(void);
void	nvmf_ctl_unload(void);

/* nvmf_qpair.c */
struct nvmf_host_qpair *nvmf_init_qp(struct nvmf_softc *sc,
    enum nvmf_trtype trtype, struct nvmf_handoff_qpair *handoff);
void	nvmf_destroy_qp(struct nvmf_host_qpair *qp);

struct nvmf_request *nvmf_allocate_request(nvmf_request_complete_t *cb,
    void *cb_arg, int how);
void	nvmf_submit_request(struct nvmf_host_qpair *qp,
    struct nvmf_request *req, int how);
void	nvmf_free_request(struct nvmf_request *req);

#endif /* !__NVMF_VAR_H__ */
