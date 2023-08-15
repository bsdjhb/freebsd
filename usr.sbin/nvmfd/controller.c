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
#include <errno.h>
#include <libnvmf.h>
#include <stdlib.h>

#include "internal.h"

struct controller {
	struct nvmf_qpair *qp;

	uint64_t cap;
	uint32_t vs;
	uint32_t cc;
	uint32_t csts;

	bool shutdown;

	struct nvme_controller_data cdata;
};

static bool
update_cc(struct controller *c, uint32_t new_cc)
{
	uint32_t changes;

	if (!nvmf_validate_cc(c->qp, c->cap, c->cc, new_cc))
		return (false);

	changes = c->cc ^ new_cc;
	c->cc = new_cc;

	/* Handle shutdown requests. */
	if (NVMEV(NVME_CC_REG_SHN, changes) != 0 &&
	    NVMEV(NVME_CC_REG_SHN, new_cc) != 0) {
		c->csts &= ~NVMEB(NVME_CSTS_REG_SHST);
		c->csts |= NVME_SHST_COMPLETE << NVME_CSTS_REG_SHST_SHIFT;
		c->shutdown = true;
	}

	if (NVMEV(NVME_CC_REG_EN, changes) != 0) {
		if (NVMEV(NVME_CC_REG_EN, new_cc) == 0) {
			/* Controller reset. */
			c->csts = 0;
			c->shutdown = true;
		} else
			c->csts |= 1 << NVME_CSTS_REG_RDY_SHIFT;
	}
	return (true);
}

static void
handle_property_get(const struct controller *c, const struct nvmf_capsule *nc,
    const struct nvmf_fabric_prop_get_cmd *pget)
{
	struct nvmf_fabric_prop_get_rsp rsp;

	nvmf_init_cqe(&rsp, nc, 0);

	switch (le32toh(pget->ofst)) {
	case NVMF_PROP_CAP:
		if (pget->attrib.size != NVMF_PROP_SIZE_8)
			goto error;
		rsp.value.u64 = htole64(c->cap);
		break;
	case NVMF_PROP_VS:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(c->vs);
		break;
	case NVMF_PROP_CC:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(c->cc);
		break;
	case NVMF_PROP_CSTS:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(c->csts);
		break;
	default:
		goto error;
	}

	nvmf_send_response(nc, &rsp);
	return;
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

static void
handle_property_set(struct controller *c, const struct nvmf_capsule *nc,
    const struct nvmf_fabric_prop_set_cmd *pset)
{
	switch (le32toh(pset->ofst)) {
	case NVMF_PROP_CC:
		if (pset->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		if (!update_cc(c, le32toh(pset->value.u32.low)))
			goto error;
		break;
	default:
		goto error;
	}

	nvmf_send_success(nc);
	return;
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

static void
handle_fabrics_command(struct controller *c,
    const struct nvmf_capsule *nc, const struct nvmf_fabric_cmd *fc)
{
	switch (fc->fctype) {
	case NVMF_FABRIC_COMMAND_PROPERTY_GET:
		handle_property_get(c, nc,
		    (const struct nvmf_fabric_prop_get_cmd *)fc);
		break;
	case NVMF_FABRIC_COMMAND_PROPERTY_SET:
		handle_property_set(c, nc,
		    (const struct nvmf_fabric_prop_set_cmd *)fc);
		break;
	case NVMF_FABRIC_COMMAND_DISCONNECT:
		warnx("Disconnect command on admin queue");
		nvmf_send_error(nc, NVME_SCT_COMMAND_SPECIFIC,
		    NVMF_FABRIC_SC_INVALID_QUEUE_TYPE);
		break;
	default:
		warnx("Unsupported fabrics command %#x", fc->fctype);
		nvmf_send_generic_error(nc, NVME_SC_INVALID_OPCODE);
		break;
	}
}

static void
handle_identify_command(const struct controller *c,
    const struct nvmf_capsule *nc, const struct nvme_command *cmd)
{
	struct iovec iov[1];
	int error;
	uint8_t cns;

	cns = le32toh(cmd->cdw10) & 0xFF;
	switch (cns) {
	case 1:
		break;
	default:
		goto error;
	}

	if (nvmf_capsule_data_len(nc) != sizeof(c->cdata))
		goto error;
	iov[0].iov_base = __DECONST(void *, &c->cdata);
	iov[0].iov_len = sizeof(c->cdata);
	error = nvmf_send_controller_data(nc, iov, nitems(iov));
	if (error != 0)
		nvmf_send_generic_error(nc, NVME_SC_DATA_TRANSFER_ERROR);
	else
		nvmf_send_success(nc);
	return;
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

void
controller_handle_admin_commands(struct controller *c, handle_command *cb,
    void *cb_arg)
{
	struct nvmf_qpair *qp = c->qp;
	const struct nvme_command *cmd;
	struct nvmf_capsule *nc;
	int error;

	while (!c->shutdown) {
		error = nvmf_controller_receive_capsule(qp, &nc);
		if (error != 0) {
			if (error != ECONNRESET)
				warnc(error, "Failed to read command capsule");
			break;
		}

		cmd = nvmf_capsule_sqe(nc);
		if (cb(nc, cmd, cb_arg)) {
			nvmf_free_capsule(nc);
			continue;
		}

		switch (cmd->opc) {
		case NVME_OPC_FABRICS_COMMANDS:
			handle_fabrics_command(c, nc,
			    (const struct nvmf_fabric_cmd *)cmd);
			break;
		case NVME_OPC_IDENTIFY:
			handle_identify_command(c, nc, cmd);
			break;
		default:
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
