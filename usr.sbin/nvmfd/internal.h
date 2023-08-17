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

#ifndef __INTERNAL_H__
#define	__INTERNAL_H__

#include <stdbool.h>

struct controller;
struct nvme_command;
struct nvme_controller_data;
struct nvmf_capsule;
struct nvmf_qpair;

typedef bool handle_command(const struct nvmf_capsule *,
    const struct nvme_command *, void *);

extern bool data_digests;
extern bool header_digests;
extern bool flow_control_disable;

/* controller.c */
void	controller_handle_admin_commands(struct controller *c,
    handle_command *cb, void *cb_arg);
struct controller *init_controller(struct nvmf_qpair *qp,
    const struct nvme_controller_data *cdata);
void	free_controller(struct controller *c);

/* discovery.c */
void	init_discovery(void);
void	handle_discovery_socket(int s);
void	discovery_add_io_controller(int s, const char *subnqn);

/* io.c */
void	init_io(const char *subnqn);
void	handle_io_socket(int s);

/* devices.c */
void	register_devices(int ac, char **av);
u_int	device_count(void);
bool	device_namespace_data(u_int nsid, struct nvme_namespace_data *nsdata);

#endif /* !__INTERNAL_H__ */
