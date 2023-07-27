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

#include <err.h>
#include <libnvmf.h>
#include <stdlib.h>

#include "internal.h"

struct controller {
	struct nvmf_qpair *qp;

	uint64_t cap;
	uint32_t vs;
	uint32_t cc;
	uint32_t csts;

	struct nvme_controller_data cdata;
};

void
controller_handle_admin_commands(struct controller *c, handle_command *cb,
    void *cb_arg)
{
	struct nvmf_qpair *qp = c->qp;
	const struct nvme_command *cmd;
	struct nvmf_capsule *nc;
	int error;

	for (;;) {
		error = nvmf_controller_receive_capsule(qp, &nc);
		if (error != 0) {
			warnc(error, "Failed to read command capsule");
			break;
		}

		cmd = nvmf_capsule_sqe(nc);
		switch (cmd->opc) {
		default:
			if (cb(nc, cmd, cb_arg))
				break;
			warnx("Unsupported opcode %#x", cmd->opc);
			nvmf_send_generic_error(nc, NVME_SC_INVALID_OPCODE);
			break;
		}
		nvmf_free_capsule(nc);
	}
}

struct controller *
init_controller(struct nvmf_qpair *qp,
    const struct nvme_controller_data *cdata)
{
	struct controller *c;

	c = calloc(1, sizeof(*c));
	c->qp = qp;
	c->cap = nvmf_controller_cap(c->qp);
	c->vs = cdata->ver;
	c->cdata = *cdata;

	return (c);
}

void
free_controller(struct controller *c)
{
	free(c);
}
