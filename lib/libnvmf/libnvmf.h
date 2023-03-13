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

#include <stdbool.h>
#include <stddef.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_proto.h>

struct nvmf_capsule;
struct nvmf_connection;
struct nvmf_qpair;

/* Transport-independent APIs. */

/* params contains requested values for this side of the negotiation. */
struct nvmf_connection *nvmf_allocate_connection(enum nvmf_trtype trtype,
    bool controller, const union nvmf_connection_params *params);
void	nvmf_free_connection(struct nvmf_connection *nc);

struct nvmf_qpair *nvmf_allocate_qpair(struct nvmf_connection *nc, bool admin);
void	nvmf_free_qpair(struct nvmf_qpair *qp);

struct nvmf_capsule *nvmf_allocate_command(struct nvmf_qpair *qp);
struct nvmf_capsule *nvmf_allocate_response(struct nvmf_capsule *nc);
void	nvmf_free_capsule(struct nvmf_capsule *nc);
int	nvmf_transmit_capsule(struct nvmf_capsule *nc);
int	nvmf_receive_capsule(struct nvmf_capsule **nc);

/* TCP transport-specific APIs. */
int	nvmf_tcp_read_pdu(struct nvmf_connection *nc,
    struct nvme_tcp_common_pdu_hdr **pdu);

#endif /* !__LIBNVMF_H__ */
