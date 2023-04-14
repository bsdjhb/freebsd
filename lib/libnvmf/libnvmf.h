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

#ifndef __LIBNVMF_H__
#define	__LIBNVMF_H__

#include <sys/uio.h>
#include <stdbool.h>
#include <stddef.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_proto.h>

/* XXX: Should be in nvme.h */
#define NVME_MIN_ADMIN_ENTRIES	(2)
#define NVME_MAX_ADMIN_ENTRIES	(4096)

#define NVME_MIN_IO_ENTRIES	(2)
#define NVME_MAX_IO_ENTRIES	(65536)

/* XXX: Should be in nvmf_proto.h */
#define	NVMF_CNTLID_DYNAMIC	0xFFFF
#define	NVMF_CNTLID_STATIC_ANY	0xFFFE

/* 5.21.1.15 in NVMe */
#define	NVMF_KATO_DEFAULT	(120000)

struct nvmf_capsule;
struct nvmf_connection;
struct nvmf_qpair;

/* Transport-independent APIs. */

/* params contains requested values for this side of the negotiation. */
struct nvmf_connection *nvmf_allocate_connection(enum nvmf_trtype trtype,
    bool controller, const struct nvmf_connection_params *params);
void	nvmf_free_connection(struct nvmf_connection *nc);

/*
 * A queue pair represents either an Admin or I/O
 * submission/completion queue pair.  TCP requires a separate
 * connection for each queue pair.
 */
struct nvmf_qpair *nvmf_allocate_qpair(struct nvmf_connection *nc, bool admin);
void	nvmf_free_qpair(struct nvmf_qpair *qp);

/*
 * Capsules are either commands (host -> controller) or responses
 * (controller -> host).  One or more data buffer segments may be
 * associated with a command capsule.  Transmitted data is not copied
 * by this API but instead must be preserved until the capsule is
 * transmitted and freed.
 */
struct nvmf_capsule *nvmf_allocate_command(struct nvmf_qpair *qp,
    const void *sqe);
struct nvmf_capsule *nvmf_allocate_response(struct nvmf_qpair *qp,
    const void *cqe);
void	nvmf_free_capsule(struct nvmf_capsule *nc);
int	nvmf_capsule_append_data(struct nvmf_capsule *nc,
    const void *buf, size_t len);
int	nvmf_transmit_capsule(struct nvmf_capsule *nc, bool send_data);
int	nvmf_receive_capsule(struct nvmf_qpair *qp, struct nvmf_capsule **nc);

/*
 * A controller calls this function to receive data associated with a
 * command capsule (e.g. the data for a WRITE command).  This can
 * either return in-capsule data or fetch data from the host
 * (e.g. using a R2T PDU over TCP).  The received command capsule
 * should be passed in 'nc'.  The received data is stored in the
 * passed in I/O vector.
 */
int	nvmf_receive_controller_data(struct nvmf_capsule *nc,
    uint32_t data_offset, struct iovec *iov, u_int iovcnt);

/*
 * A controller calls this function to send data in response to a
 * command prior to sending a response capsule.
 *
 * TODO: Support for SUCCESS flag for final TCP C2H_DATA PDU?
 */
int	nvmf_send_controller_data(struct nvmf_capsule *nc,
    struct iovec *iov, u_int iovcnt);

/* Host-specific APIs. */

/* Connect to an admin or I/O queue. */
struct nvmf_qpair *nvmf_connect(struct nvmf_connection *nc, uint16_t qid,
    u_int queue_size, const uint8_t hostid[16], uint16_t cntlid,
    const char *subnqn, const char *hostnqn, uint32_t kato);

/* Return the CNTLID for a queue returned from CONNECT. */
uint16_t nvmf_cntlid(struct nvmf_qpair *qp);

/*
 * Send a command to the controller.  This can fail with EBUSY if the
 * submission queue is full.
 */
int	nvmf_host_transmit_command(struct nvmf_capsule *ncap, bool send_data);

/*
 * Wait for a response to a command.  If there are no outstanding
 * commands in the SQ, fails with EWOULDBLOCK.
 */
int	nvmf_host_receive_response(struct nvmf_qpair *qp,
    struct nvmf_capsule **rcapp);

/*
 * Wait for a response to a specific command.  The command must have been
 * succesfully sent previously.
 */
int	nvmf_host_wait_for_response(struct nvmf_capsule *ncap,
    struct nvmf_capsule **rcap);

/* Build a KeepAlive command. */
struct nvmf_capsule *nvmf_keepalive(struct nvmf_qpair *qp);

/* Read a controller property. */
int	nvmf_read_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size,
    uint64_t *value);

/* Write a controller property. */
int	nvmf_write_property(struct nvmf_qpair *qp, uint32_t offset,
    uint8_t size, uint64_t value);

/* Construct a 16-byte HostId from kern.hostuuid. */
int	nvmf_hostid_from_hostuuid(uint8_t hostid[16]);

/* Construct a NQN from kern.hostuuid. */
int	nvmf_nqn_from_hostuuid(char nqn[NVMF_NQN_MAX_LEN]);

#endif /* !__LIBNVMF_H__ */
