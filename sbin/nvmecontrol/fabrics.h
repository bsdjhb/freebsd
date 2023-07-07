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

#ifndef __FABRICS_H__
#define	__FABRICS_H__

const char *nvmf_transport_type(uint8_t trtype);

/*
 * Splits 'in_address' into separate 'address' and 'port' strings.  If
 * a separate buffer for the address was allocated, 'tofree' is set to
 * the allocated buffer, otherwise 'tofree' is set to NULL.
 */
void	nvmf_parse_address(const char *in_address, const char **address,
    const char **port, char **tofree);

uint16_t nvmf_parse_cntlid(const char *cntlid);

/* Returns true if able to open a connection. */
bool	tcp_qpair_params(struct nvmf_qpair_params *params, int adrfam,
    const char *address, const char *port);

/* Connect to a discovery controller and return the Admin qpair. */
struct nvmf_qpair *connect_discovery_adminq(enum nvmf_trtype trtype,
    const char *address, const char *port);

/*
 * Connect to an NVM controller establishing an Admin qpair and one or
 * more I/O qpairs.  The controller's controller data is returned in
 * *cdata on success.  Returns a non-zero value from <sysexits.h> on
 * failure.
 */
int	connect_nvm_queues(const struct nvmf_association_params *aparams,
    enum nvmf_trtype trtype, int adrfam, const char *address,
    const char *port, uint16_t cntlid, const char *subnqn,
    struct nvmf_qpair **admin, struct nvmf_qpair **io, u_int num_io_queues,
    struct nvme_controller_data *cdata);

#endif /* !__FABRICS_H__ */
