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

ATF_TC(invalid_connect_recfmt);
ATF_TC_HEAD(invalid_connect_recfmt, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(invalid_connect_recfmt, tc)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, NULL, NULL);

	admin = nvmf_allocate_qpair(na, &qparams);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 0, NVMF_MIN_ADMIN_MAX_SQ_SIZE, &cmd);
	cmd.recfmt = htole16(1);

	init_connect_data(tc, parse_cntlid(tc), hostid, hostnqn, &data);
	manual_connect(admin, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) ==
	    NVMF_FABRIC_SC_INCOMPATIBLE_FORMAT);

	nvmf_free_qpair(admin);
}

static void
invalid_admin_sqsize(const atf_tc_t *tc, uint32_t sqsize)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, NULL, NULL);

	admin = nvmf_allocate_qpair(na, &qparams);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 0, sqsize, &cmd);
	init_connect_data(tc, parse_cntlid(tc), hostid, hostnqn, &data);
	manual_connect(admin, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 0);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_cmd, sqsize));

	nvmf_free_qpair(admin);
}

ATF_TC(admin_sqsize_small);
ATF_TC_HEAD(admin_sqsize_small, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(admin_sqsize_small, tc)
{
	invalid_admin_sqsize(tc, NVME_MIN_ADMIN_ENTRIES - 1);
}

ATF_TC(admin_sqsize_large);
ATF_TC_HEAD(admin_sqsize_large, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(admin_sqsize_large, tc)
{
	invalid_admin_sqsize(tc, NVME_MAX_ADMIN_ENTRIES + 1);
}

ATF_TC(io_sqsize_small);
ATF_TC_HEAD(io_sqsize_small, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(io_sqsize_small, tc)
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

	io = nvmf_allocate_qpair(na, &qparams);
	if (io == NULL)
		atf_tc_fail("Failed to create I/O queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 1, NVME_MIN_IO_ENTRIES - 1, &cmd);
	init_connect_data(tc, nvmf_cntlid(admin), hostid, hostnqn, &data);
	manual_connect(io, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 0);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_cmd, sqsize));

	nvmf_free_qpair(io);

	shutdown_controller(admin);
	nvmf_free_qpair(admin);
}

ATF_TC(invalid_connect_attr_admin);
ATF_TC_HEAD(invalid_connect_attr_admin, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(invalid_connect_attr_admin, tc)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, NULL, NULL);

	admin = nvmf_allocate_qpair(na, &qparams);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 0, NVMF_MIN_ADMIN_MAX_SQ_SIZE, &cmd);

	/* Admin queues require a priority class of 0. */
	cmd.cattr |= 0x1;

	init_connect_data(tc, parse_cntlid(tc), hostid, hostnqn, &data);
	manual_connect(admin, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 0);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_cmd, cattr));

	nvmf_free_qpair(admin);
}

ATF_TC(invalid_connect_attr_io);
ATF_TC_HEAD(invalid_connect_attr_io, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(invalid_connect_attr_io, tc)
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

	init_connect_cmd(tc, 1, NVME_MIN_IO_ENTRIES, &cmd);

	/* Set a reserved bit in CATTR. */
	cmd.cattr |= 0x10;

	init_connect_data(tc, nvmf_cntlid(admin), hostid, hostnqn, &data);
	manual_connect(io, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 0);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_cmd, cattr));

	nvmf_free_qpair(io);

	shutdown_controller(admin);
	nvmf_free_qpair(admin);
}

ATF_TC(io_kato_nonzero);
ATF_TC_HEAD(io_kato_nonzero, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(io_kato_nonzero, tc)
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

	io = nvmf_allocate_qpair(na, &qparams);
	if (io == NULL)
		atf_tc_fail("Failed to create I/O queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 1, NVME_MIN_IO_ENTRIES, &cmd);
	init_connect_data(tc, nvmf_cntlid(admin), hostid, hostnqn, &data);

	cmd.kato = htole32(NVMF_KATO_DEFAULT);

	manual_connect(io, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 0);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_cmd, kato));

	nvmf_free_qpair(io);

	shutdown_controller(admin);
	nvmf_free_qpair(admin);
}

ATF_TC(invalid_connect_hostid);
ATF_TC_HEAD(invalid_connect_hostid, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(invalid_connect_hostid, tc)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, NULL, NULL);

	admin = nvmf_allocate_qpair(na, &qparams);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 0, NVMF_MIN_ADMIN_MAX_SQ_SIZE, &cmd);
	init_connect_data(tc, parse_cntlid(tc), hostid, hostnqn, &data);

	/* Zero the hostid. */
	memset(data.hostid, 0, sizeof(data.hostid));

	manual_connect(admin, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 1);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_data, hostid));

	nvmf_free_qpair(admin);
}

ATF_TC(invalid_connect_subnqn);
ATF_TC_HEAD(invalid_connect_subnqn, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(invalid_connect_subnqn, tc)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, NULL, NULL);

	admin = nvmf_allocate_qpair(na, &qparams);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 0, NVMF_MIN_ADMIN_MAX_SQ_SIZE, &cmd);
	init_connect_data(tc, parse_cntlid(tc), hostid, hostnqn, &data);

	/* Replace the SubNQN with one that is not null terminated. */
	memset(data.subnqn, 'a', sizeof(data.subnqn));

	manual_connect(admin, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 1);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_data, subnqn));

	nvmf_free_qpair(admin);
}

ATF_TC(invalid_connect_hostnqn);
ATF_TC_HEAD(invalid_connect_hostnqn, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(invalid_connect_hostnqn, tc)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_fabric_connect_rsp rsp;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, NULL, NULL);

	admin = nvmf_allocate_qpair(na, &qparams);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	init_connect_cmd(tc, 0, NVMF_MIN_ADMIN_MAX_SQ_SIZE, &cmd);
	init_connect_data(tc, parse_cntlid(tc), hostid, hostnqn, &data);

	/* Replace the HostNQN with one that is not null terminated. */
	memset(data.hostnqn, 'a', sizeof(data.hostnqn));

	manual_connect(admin, &cmd, &data, &rsp);

	status = le16toh(rsp.status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp.status_code_specific.invalid.iattr == 1);
	ATF_REQUIRE(rsp.status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_data, hostnqn));

	nvmf_free_qpair(admin);
}

static struct nvmf_qpair *
connect_admin_only(const atf_tc_t *tc)
{
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, NULL, NULL);

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	return (admin);
}

/* Fetch the HIP log page with a given offset and length. */
static uint16_t
fetch_log_page(struct nvmf_qpair *qp, uint8_t page, uint64_t offset,
    uint32_t numd, void *buf, size_t len)
{
	struct nvme_command cmd;
	const struct nvme_completion *cpl;
	struct nvmf_capsule *cc, *rc;
	int error;
	uint16_t status;

	nvmf_init_sqe(&cmd, NVME_OPC_GET_LOG_PAGE);
	cmd.cdw10 = htole32(numd << 16 | page);
	cmd.cdw11 = htole32(numd >> 16);
	cmd.cdw12 = htole32(offset);
	cmd.cdw13 = htole32(offset >> 32);

	cc = nvmf_allocate_command(qp, &cmd);
	if (cc == NULL)
		atf_tc_fail("failed to allocate command: %s",
		    strerror(errno));

	error = nvmf_capsule_append_data(cc, buf, len, false);
	if (error != 0) {
		nvmf_free_capsule(cc);
		atf_tc_fail("failed to append data buffer to command: %s",
		    strerror(error));
	}

	error = nvmf_host_transmit_command(cc);
	if (error != 0) {
		nvmf_free_capsule(cc);
		atf_tc_fail("failed to transmit command: %s", strerror(error));
	}

	error = nvmf_host_wait_for_response(cc, &rc);
	nvmf_free_capsule(cc);
	if (error != 0)
		atf_tc_fail("failed to receive response: %s", strerror(error));

	cpl = nvmf_capsule_cqe(rc);
	status = le16toh(cpl->status);
	nvmf_free_capsule(rc);
	return (status);
}

static void
fetch_hip_log_page_test(const atf_tc_t *tc, uint64_t offset, uint32_t numd,
    bool should_fail)
{
	struct nvmf_qpair *admin;
	char *buf;
	size_t len;
	uint16_t status;

	admin = connect_admin_only(tc);

	len = (numd + 1) * 4;
	buf = malloc(len);

	status = fetch_log_page(admin, NVME_LOG_HEALTH_INFORMATION, offset,
	    numd, buf, len);
	if (should_fail) {
		ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_GENERIC);
		ATF_REQUIRE(NVME_STATUS_GET_SC(status) ==
		    NVME_SC_INVALID_FIELD);
	} else {
		ATF_REQUIRE(status == 0);
	}

	free(buf);
	shutdown_controller(admin);
	nvmf_free_qpair(admin);
}

#define	LEN_TO_NUMD(len)	((len) / 4 - 1)

/*
 * Test various offsets and lengths for fetching a log page.
 */
ATF_TC(fetch_hip);
ATF_TC_HEAD(fetch_hip, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip, tc)
{
	fetch_hip_log_page_test(tc, 0,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), false);
}

ATF_TC(fetch_hip_short);
ATF_TC_HEAD(fetch_hip_short, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip_short, tc)
{
	fetch_hip_log_page_test(tc, 0,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page) / 2),
	    false);
}

ATF_TC(fetch_hip_middle);
ATF_TC_HEAD(fetch_hip_middle, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip_middle, tc)
{
	fetch_hip_log_page_test(tc,
	    sizeof(struct nvme_health_information_page) / 4,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page) / 2),
	    false);
}

ATF_TC(fetch_hip_long);
ATF_TC_HEAD(fetch_hip_long, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip_long, tc)
{
	fetch_hip_log_page_test(tc, 0,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page) + 64),
	    false);
}

ATF_TC(fetch_hip_offset_1);
ATF_TC_HEAD(fetch_hip_offset_1, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip_offset_1, tc)
{
	fetch_hip_log_page_test(tc, 1,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), true);
}

ATF_TC(fetch_hip_offset_2);
ATF_TC_HEAD(fetch_hip_offset_2, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip_offset_2, tc)
{
	fetch_hip_log_page_test(tc, 2,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), true);
}

ATF_TC(fetch_hip_offset_3);
ATF_TC_HEAD(fetch_hip_offset_3, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip_offset_3, tc)
{
	fetch_hip_log_page_test(tc, 3,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), true);
}

ATF_TC(fetch_hip_offset_beyond_end);
ATF_TC_HEAD(fetch_hip_offset_beyond_end, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_hip_offset_beyond_end, tc)
{
	fetch_hip_log_page_test(tc,
	    sizeof(struct nvme_health_information_page),
	    LEN_TO_NUMD(16), true);
}

ATF_TC(fetch_reserved_log_page);
ATF_TC_HEAD(fetch_reserved_log_page, tc)
{
	require_nvmft(tc);
}
ATF_TC_BODY(fetch_reserved_log_page, tc)
{
	struct nvmf_qpair *admin;
	char buf[4];
	uint16_t status;

	admin = connect_admin_only(tc);

	status = fetch_log_page(admin, 0x00, 0, 0, buf, sizeof(buf));
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVME_SC_INVALID_LOG_PAGE);

	shutdown_controller(admin);
	nvmf_free_qpair(admin);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, invalid_qid);
	ATF_TP_ADD_TC(tp, invalid_connect_recfmt);
	ATF_TP_ADD_TC(tp, admin_sqsize_small);
	ATF_TP_ADD_TC(tp, admin_sqsize_large);
	ATF_TP_ADD_TC(tp, io_sqsize_small);
	ATF_TP_ADD_TC(tp, invalid_connect_attr_admin);
	ATF_TP_ADD_TC(tp, invalid_connect_attr_io);
	ATF_TP_ADD_TC(tp, io_kato_nonzero);
	ATF_TP_ADD_TC(tp, invalid_connect_hostid);
	ATF_TP_ADD_TC(tp, invalid_connect_subnqn);
	ATF_TP_ADD_TC(tp, invalid_connect_hostnqn);
	ATF_TP_ADD_TC(tp, fetch_hip);
	ATF_TP_ADD_TC(tp, fetch_hip_short);
	ATF_TP_ADD_TC(tp, fetch_hip_middle);
	ATF_TP_ADD_TC(tp, fetch_hip_long);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_1);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_2);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_3);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_beyond_end);
	ATF_TP_ADD_TC(tp, fetch_reserved_log_page);

	return (atf_no_error());
}
