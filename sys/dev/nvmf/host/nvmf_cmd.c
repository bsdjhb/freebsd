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

#include <sys/types.h>
#include <sys/systm.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_proto.h>
#include <dev/nvmf/host/nvmf_var.h>

void
nvmf_cmd_get_property(struct nvmf_softc *sc, uint32_t offset, uint8_t size,
    nvmf_request_complete_t *cb, void *cb_arg, int how)
{
	struct nvmf_fabric_prop_get_cmd cmd;
	struct nvmf_request *req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = NVME_OPC_FABRIC;
	cmd.fctype = NVMF_FABRIC_COMMAND_PROPERTY_GET;
	switch (size) {
	case 4:
		cmd.attrib.size = NVMF_PROP_SIZE_4;
		break;
	case 8:
		cmd.attrib.size = NVMF_PROP_SIZE_8;
		break;
	default:
		panic("Invalid property size");
	}
	cmd.ofst = htole32(offset);

	req = nvmf_allocate_request(sc->admin, &cmd, cb, cb_arg, how);
	nvmf_submit_request(req);
}

void
nvmf_cmd_set_property(struct nvmf_softc *sc, uint32_t offset, uint8_t size,
    uint64_t value, nvmf_request_complete_t *cb, void *cb_arg, int how)
{
	struct nvmf_fabric_prop_set_cmd cmd;
	struct nvmf_request *req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = NVME_OPC_FABRIC;
	cmd.fctype = NVMF_FABRIC_COMMAND_PROPERTY_SET;
	switch (size) {
	case 4:
		cmd.attrib.size = NVMF_PROP_SIZE_4;
		cmd.value.u32.low = htole32(value);
		break;
	case 8:
		cmd.attrib.size = NVMF_PROP_SIZE_8;
		cmd.value.u64 = htole64(value);
		break;
	default:
		panic("Invalid property size");
	}
	cmd.ofst = htole32(offset);

	req = nvmf_allocate_request(sc->admin, &cmd, cb, cb_arg, how);
	nvmf_submit_request(req);
}
