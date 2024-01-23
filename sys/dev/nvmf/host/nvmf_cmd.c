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

#include <sys/types.h>
#include <sys/memdesc.h>
#include <sys/systm.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_proto.h>
#include <dev/nvmf/host/nvmf_var.h>

bool
nvmf_cmd_get_property(struct nvmf_softc *sc, uint32_t offset, uint8_t size,
    nvmf_request_complete_t *cb, void *cb_arg, int how)
{
	struct nvmf_fabric_prop_get_cmd cmd;
	struct nvmf_request *req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = NVME_OPC_FABRICS_COMMANDS;
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
	if (req != NULL)
		nvmf_submit_request(req);
	return (req != NULL);
}

bool
nvmf_cmd_set_property(struct nvmf_softc *sc, uint32_t offset, uint8_t size,
    uint64_t value, nvmf_request_complete_t *cb, void *cb_arg, int how)
{
	struct nvmf_fabric_prop_set_cmd cmd;
	struct nvmf_request *req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = NVME_OPC_FABRICS_COMMANDS;
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
	if (req != NULL)
		nvmf_submit_request(req);
	return (req != NULL);
}

bool
nvmf_cmd_keep_alive(struct nvmf_softc *sc, nvmf_request_complete_t *cb,
    void *cb_arg, int how)
{
	struct nvme_command cmd;
	struct nvmf_request *req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opc = NVME_OPC_KEEP_ALIVE;

	req = nvmf_allocate_request(sc->admin, &cmd, cb, cb_arg, how);
	if (req != NULL)
		nvmf_submit_request(req);
	return (req != NULL);
}

bool
nvmf_cmd_identify_active_namespaces(struct nvmf_softc *sc, uint32_t id,
    struct nvme_ns_list *nslist, nvmf_request_complete_t *req_cb,
    void *req_cb_arg, nvmf_io_complete_t *io_cb, void *io_cb_arg, int how)
{
	struct nvme_command cmd;
	struct memdesc mem;
	struct nvmf_request *req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opc = NVME_OPC_IDENTIFY;

	/* 5.15.1 Use CNS of 0x02 for namespace data. */
	cmd.cdw10 = htole32(2);
	cmd.nsid = htole32(id);

	req = nvmf_allocate_request(sc->admin, &cmd, req_cb, req_cb_arg, how);
	if (req == NULL)
		return (false);
	mem = memdesc_vaddr(nslist, sizeof(*nslist));
	nvmf_capsule_append_data(req->nc, &mem, sizeof(*nslist), false,
	    io_cb, io_cb_arg);
	nvmf_submit_request(req);
	return (true);
}

bool
nvmf_cmd_identify_namespace(struct nvmf_softc *sc, uint32_t id,
    struct nvme_namespace_data *nsdata, nvmf_request_complete_t *req_cb,
    void *req_cb_arg, nvmf_io_complete_t *io_cb, void *io_cb_arg, int how)
{
	struct nvme_command cmd;
	struct memdesc mem;
	struct nvmf_request *req;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opc = NVME_OPC_IDENTIFY;

	/* 5.15.1 Use CNS of 0x00 for namespace data. */
	cmd.cdw10 = htole32(0);
	cmd.nsid = htole32(id);

	req = nvmf_allocate_request(sc->admin, &cmd, req_cb, req_cb_arg, how);
	if (req == NULL)
		return (false);
	mem = memdesc_vaddr(nsdata, sizeof(*nsdata));
	nvmf_capsule_append_data(req->nc, &mem, sizeof(*nsdata), false,
	    io_cb, io_cb_arg);
	nvmf_submit_request(req);
	return (true);
}

bool
nvmf_cmd_get_log_page(struct nvmf_softc *sc, uint32_t nsid, uint8_t lid,
    uint64_t offset, void *buf, size_t len, nvmf_request_complete_t *req_cb,
    void *req_cb_arg, nvmf_io_complete_t *io_cb, void *io_cb_arg, int how)
{
	struct nvme_command cmd;
	struct memdesc mem;
	struct nvmf_request *req;
	size_t numd;

	MPASS(len != 0 && len % 4 == 0);
	MPASS(offset % 4 == 0);

	numd = (len / 4) - 1;
	memset(&cmd, 0, sizeof(cmd));
	cmd.opc = NVME_OPC_GET_LOG_PAGE;
	cmd.nsid = htole32(nsid);
	cmd.cdw10 = htole32(numd << 16 | lid);
	cmd.cdw11 = htole32(numd >> 16);
	cmd.cdw12 = htole32(offset);
	cmd.cdw13 = htole32(offset >> 32);

	req = nvmf_allocate_request(sc->admin, &cmd, req_cb, req_cb_arg, how);
	if (req == NULL)
		return (false);
	mem = memdesc_vaddr(buf, len);
	nvmf_capsule_append_data(req->nc, &mem, len, false, io_cb, io_cb_arg);
	nvmf_submit_request(req);
	return (true);
}
