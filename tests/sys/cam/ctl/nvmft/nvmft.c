/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023,2026 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <errno.h>
#include <inttypes.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdlib.h>
#include <atf-c.h>

#include "nvmft_subr.h"

static void
nvmf_init_sqe(void *sqe, uint8_t opcode)
{
	struct nvme_command *cmd = sqe;

	memset(cmd, 0, sizeof(*cmd));
	cmd->opc = opcode;
}

static void
nvmf_init_fabrics_sqe(void *sqe, uint8_t fctype)
{
	struct nvmf_capsule_cmd *cmd = sqe;

	nvmf_init_sqe(sqe, NVME_OPC_FABRICS_COMMANDS);
	cmd->fctype = fctype;
}

static void
init_connect_cmd(const atf_tc_t *tc, uint16_t qid, uint32_t sqsize,
    struct nvmf_fabric_connect_cmd *cmd)
{
	nvmf_init_fabrics_sqe(cmd, NVMF_FABRIC_COMMAND_CONNECT);
	cmd->recfmt = htole16(0);
	cmd->qid = htole16(qid);

	cmd->sqsize = htole16(sqsize - 1);
	if (!atf_tc_get_config_var_as_bool_wd(tc, "nvmft.flow_control", false))
		cmd->cattr |= NVMF_CONNECT_ATTR_DISABLE_SQ_FC;
}

static void
init_connect_data(const atf_tc_t *tc, uint16_t cntlid, const uint8_t hostid[16],
    const char *hostnqn, struct nvmf_fabric_connect_data *data)
{
	memset(data, 0, sizeof(*data));
	memcpy(data->hostid, hostid, sizeof(data->hostid));
	data->cntlid = htole16(cntlid);
	strlcpy(data->subnqn, atf_tc_get_config_var(tc, "nvmft.nqn"),
	    sizeof(data->subnqn));
	strlcpy(data->hostnqn, hostnqn, sizeof(data->hostnqn));
}

static void
manual_connect(struct nvmf_qpair *qp, const struct nvmf_fabric_connect_cmd *cmd,
    const struct nvmf_fabric_connect_data *data,
    struct nvmf_fabric_connect_rsp *rsp)
{
	struct nvmf_capsule *cc, *rc;
	int error;

	cc = nvmf_allocate_command(qp, cmd);
	if (cc == NULL)
		atf_tc_fail("Failed to allocate command capsule: %s",
		    strerror(errno));

	error = nvmf_capsule_append_data(cc, __DECONST(void *, data),
	    sizeof(*data), true);
	if (error != 0)
		atf_tc_fail("Failed to append data to CONNECT capsule: %s",
		    strerror(error));

	error = nvmf_transmit_capsule(cc);
	if (error != 0)
		atf_tc_fail("Failed to transmit CONNECT capsule: %s",
		    strerror(errno));

	error = nvmf_receive_capsule(qp, &rc);
	if (error != 0)
		atf_tc_fail("Failed to receive CONNECT response: %s",
		    strerror(error));

	memcpy(rsp, nvmf_capsule_cqe(rc), sizeof(*rsp));
	nvmf_free_capsule(rc);
}

/*
 * Test that an I/O queue with a byte-swapped queue ID that is
 * out-of-bounds is correctly rejected.
 */
ATF_TC(invalid_qid);
ATF_TC_HEAD(invalid_qid, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(invalid_qid, tc)
{
	struct nvme_controller_data cdata;
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin, *io;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	struct addrinfo *ai, *list;
	int error, queues;
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, &ai, &list);

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));

	error = nvmf_host_identify_controller(admin, &cdata);
	if (error != 0)
		atf_tc_fail("Failed to fetch controller data: %s",
		    strerror(error));
	nvmf_update_assocation(na, &cdata);

	error = nvmf_host_request_queues(admin, 1, &queues);
	if (error != 0)
		atf_tc_fail("Failed to request I/O queues: %s",
		    strerror(error));

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = false;
	qparams.tcp.fd = open_socket_ai(ai);
	freeaddrinfo(list);

	/*
	 * Manually construct queue pair and send CONNECT command to
	 * verify error from controller.
	 */
	io = nvmf_allocate_qpair(na, &qparams);
	if (io == NULL)
		atf_tc_fail("Failed to create I/O queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 0x100, NVME_MIN_IO_ENTRIES, &cmd);
	init_connect_data(tc, nvmf_cntlid(admin), hostid, hostnqn, &data);
	manual_connect(io, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 0);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_cmd, qid));

	nvmf_free_qpair(io);

	shutdown_controller(admin);
	nvmf_free_qpair(admin);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, invalid_qid);

	return (atf_no_error());
}
