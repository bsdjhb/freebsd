/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Chelsio Communications, Inc.
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

#ifndef __NVMFT_VAR_H__
#define	__NVMFT_VAR_H__

#include <sys/_callout.h>
#include <sys/refcount.h>
#include <sys/taskqueue.h>

#include <dev/nvmf/nvmf_proto.h>

#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_frontend.h>

struct nvmf_capsule;
struct nvmft_controller;
struct nvmft_qpair;

struct nvmft_port {
	TAILQ_ENTRY(nvmft_port) link;
	u_int	refs;
	struct ctl_port port;
	struct nvme_controller_data cdata;
	uint64_t cap;
	uint32_t max_io_qsize;
	bool	online;

	struct sx lock;

	struct unrhdr *ids;
	TAILQ_HEAD(, nvmft_controller) controllers;

	int	*luns;
	u_int	num_luns;
};

struct nvmft_io_qpair {
	struct nvmft_qpair *qp;

	bool shutdown;
};

struct nvmft_controller {
	struct nvmft_qpair *admin;
	struct nvmft_io_qpair *io_qpairs;
	u_int	num_io_queues;
	bool	shutdown;
	bool	admin_closed;
	uint16_t cntlid;
	uint32_t cc;
	uint32_t csts;

	struct nvmft_port *np;
	struct mtx lock;

	struct nvme_controller_data cdata;

	uint8_t	hostid[16];
	uint8_t	hostnqn[NVME_NQN_FIELD_SIZE];

	TAILQ_ENTRY(nvmft_controller) link;

	/*
	 * Each queue can have at most UINT16_MAX commands, so the total
	 * across all queues will fit in a uint32_t.
	 */
	uint32_t pending_commands;

	volatile int ka_active_traffic;
	struct callout ka_timer;
	sbintime_t ka_sbt;

	struct task shutdown_task;
	struct timeout_task terminate_task;
};

MALLOC_DECLARE(M_NVMFT);

/* ctl_frontend_nvmf.c */
void	nvmft_port_free(struct nvmft_port *np);
void	nvmft_dispatch_command(struct nvmft_qpair *qp,
    struct nvmf_capsule *nc, bool admin);
void	nvmft_terminate_commands(struct nvmft_controller *ctrlr);

/* nvmft_controller.c */
void	nvmft_controller_error(struct nvmft_controller *ctrlr,
    struct nvmft_qpair *qp, int error);
void	nvmft_handle_admin_command(struct nvmft_controller *ctrlr,
    struct nvmf_capsule *nc);
void	nvmft_handle_io_command(struct nvmft_qpair *qp, uint16_t qid,
    struct nvmf_capsule *nc);
int	nvmft_handoff_admin_queue(struct nvmft_port *np,
    const struct nvmf_handoff_controller_qpair *handoff,
    const struct nvmf_fabric_connect_cmd *cmd,
    const struct nvmf_fabric_connect_data *data);
int	nvmft_handoff_io_queue(struct nvmft_port *np,
    const struct nvmf_handoff_controller_qpair *handoff,
    const struct nvmf_fabric_connect_cmd *cmd,
    const struct nvmf_fabric_connect_data *data);
int	nvmft_printf(struct nvmft_controller *ctrlr, const char *fmt, ...)
    __printflike(2, 3);

/* nvmft_subr.c */

/*
 * Construct a CQE for a reply to a command capsule in 'nc' with the
 * completion status 'status'.  This is useful when additional CQE
 * info is required beyond the completion status.
 */

/* Validate a NVMe Qualified Name. */
bool	nvmf_nqn_valid(const char *nqn);

/* Compute the initial state of CAP for a controller. */
uint64_t nvmf_controller_cap(uint32_t max_io_qsize, uint8_t enable_timeout);

/* Generate a serial string from a host ID. */
void	nvmf_controller_serial(char *buf, size_t len, u_long hostid);

/*
 * Populate an Identify Controller data structure for an I/O
 * controller.
 */
void	nvmf_init_io_controller_data(uint16_t cntlid, uint32_t max_io_qsize,
    const char *serial, const char *model, const char *firmware_version,
    const char *subnqn, int nn, uint32_t ioccsz, uint32_t iorcsz,
    struct nvme_controller_data *cdata);

/*
 * Validate if a new value for CC is legal given the existing values of
 * CAP and CC.
 */
bool	nvmf_validate_cc(uint32_t max_io_qsize, uint64_t cap, uint32_t old_cc,
    uint32_t new_cc);

/* nvmft_qpair.c */
struct nvmft_qpair *nvmft_qpair_init(enum nvmf_trtype trtype,
    const struct nvmf_handoff_qpair_params *handoff, uint16_t qid,
    const char *name);
void	nvmft_qpair_shutdown(struct nvmft_qpair *qp);
void	nvmft_qpair_destroy(struct nvmft_qpair *qp);
struct nvmft_controller *nvmft_qpair_ctrlr(struct nvmft_qpair *qp);
uint16_t nvmft_qpair_id(struct nvmft_qpair *qp);
const char *nvmft_qpair_name(struct nvmft_qpair *qp);
void	nvmft_command_completed(struct nvmft_qpair *qp,
    struct nvmf_capsule *nc);
int	nvmft_send_response(struct nvmft_qpair *qp, const void *cqe);
void	nvmft_init_cqe(void *cqe, struct nvmf_capsule *nc, uint16_t status);
int	nvmft_send_error(struct nvmft_qpair *qp, struct nvmf_capsule *nc,
    uint8_t sc_type, uint8_t sc_status);
int	nvmft_send_generic_error(struct nvmft_qpair *qp,
    struct nvmf_capsule *nc, uint8_t sc_status);
int	nvmft_send_success(struct nvmft_qpair *qp,
    struct nvmf_capsule *nc);
void	nvmft_connect_error(struct nvmft_qpair *qp,
    const struct nvmf_fabric_connect_cmd *cmd, uint8_t sc_type,
    uint8_t sc_status);
void	nvmft_connect_invalid_parameters(struct nvmft_qpair *qp,
    const struct nvmf_fabric_connect_cmd *cmd, bool data, uint16_t offset);
int	nvmft_finish_accept(struct nvmft_qpair *qp,
    const struct nvmf_fabric_connect_cmd *cmd, struct nvmft_controller *ctrlr);

static __inline void
nvmft_port_ref(struct nvmft_port *np)
{
	refcount_acquire(&np->refs);
}

static __inline void
nvmft_port_rele(struct nvmft_port *np)
{
	if (refcount_release(&np->refs))
		nvmft_port_free(np);
}

#endif	/* !__NVMFT_VAR_H__ */
