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

#ifndef __NVMF_TRANSPORT_H__
#define	__NVMF_TRANSPORT_H__

/*
 * Interface used by the Fabrics host (initiator) and controller
 * (target) to send and receive capsules and associated data.
 */

#include <dev/nvmf/nvmf_proto.h>

struct memdesc;
struct nvmf_capsule;
struct nvmf_connection;
struct nvmf_qpair;

/* Callback to invoke when an error occurs for a connection. */
typedef void nvmf_connection_error_t(void *);

/* Callback to invoke when a capsule is received. */
typedef void nvmf_capsule_receive_t(void *, struct nvmf_capsule *);

/* params contains negotiated values passed in from userland. */
struct nvmf_connection *nvmf_allocate_connection(enum nvmf_trtype trtype,
    bool controller, const struct nvmf_connection_params *params,
    nvmf_connection_error_t *error_cb, void *cb_arg);
void	nvmf_free_connection(struct nvmf_connection *nc);

/*
 * A queue pair represents either an Admin or I/O
 * submission/completion queue pair.  TCP requires a separate
 * connection for each queue pair.
 */
struct nvmf_qpair *nvmf_allocate_qpair(struct nvmf_connection *nc,
    bool admin, nvmf_capsule_receive_t *receive_cb, void *cb_arg);
void	nvmf_free_qpair(struct nvmf_qpair *qp);

/*
 * Capsules are either commands (host -> controller) or responses
 * (controller -> host).  A data buffer may be associated with a
 * command capsule.  Transmitted data is not copied by this API but
 * instead must be preserved until the capsule is transmitted and
 * freed.
 */
struct nvmf_capsule *nvmf_allocate_command(struct nvmf_qpair *qp,
    const void *sqe);
struct nvmf_capsule *nvmf_allocate_response(struct nvmf_qpair *qp,
    const void *cqe);
void	nvmf_free_capsule(struct nvmf_capsule *nc);
int	nvmf_capsule_append_data(struct nvmf_capsule *nc,
    struct memdesc *mem, size_t len, u_int offset);
int	nvmf_transmit_capsule(struct nvmf_capsule *nc, bool send_data);
const void *nvmf_capsule_sqe(struct nvmf_capsule *nc);
const void *nvmf_capsule_cqe(struct nvmf_capsule *nc);

/* Controller-specific APIs. */

/*
 * A controller calls this function to check for any
 * transport-specific errors (invalid fields) in a received command
 * capsule.  The callback returns a generic command status value:
 * NVME_SC_SUCCESS if no error is found.
 */
uint8_t	nvmf_validate_command_capsule(struct nvmf_capsule *nc);

/*
 * A controller calls this function to receive data associated with a
 * command capsule (e.g. the data for a WRITE command).  This can
 * either return in-capsule data or fetch data from the host
 * (e.g. using a R2T PDU over TCP).  The received command capsule
 * should be passed in 'nc'.  The received data is stored in the
 * passed in I/O vector.
 */
int	nvmf_receive_controller_data(struct nvmf_capsule *nc,
    uint32_t data_offset, struct memdesc *mem, size_t len, int offset);

/*
 * A controller calls this function to send data in response to a
 * command prior to sending a response capsule.
 *
 * TODO: Support for SUCCESS flag for final TCP C2H_DATA PDU?
 */
int	nvmf_send_controller_data(struct nvmf_capsule *nc,
    struct memdesc *mem, size_t len, u_int offset);

int	nvmf_transport_module_handler(struct module *, int, void *);

#define	NVMF_TRANSPORT(name, ops)					\
static moduledata_t nvmf_transport_##name##_mod = {			\
	"nvmf/" #name,							\
	nvmf_transport_module_handler,					\
	&(ops)								\
};									\
DECLARE_MODULE(nvmf_transport_##name, nvmf_transport_##name##_mod,	\
    SI_SUB_DRIVERS, SI_ORDER_ANY)

#endif /* !__NVMF_TRANSPORT_H__ */
