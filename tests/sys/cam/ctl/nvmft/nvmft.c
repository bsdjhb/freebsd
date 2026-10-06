/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023,2026 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <atf-c.h>

static void
require(atf_tc_t *tc)
{
	atf_tc_set_md_var(tc, "require.config", "address port nqn");
}

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
init_hostid(uint8_t hostid[16], char hostnqn[NVMF_NQN_MAX_LEN])
{
	int error;

	error = nvmf_hostid_from_hostuuid(hostid);
	if (error != 0)
		atf_tc_fail("Failed to generate hostid: %s", strerror(error));
	error = nvmf_nqn_from_hostuuid(hostnqn);
	if (error != 0)
		atf_tc_fail("Failed to generate host NQN: %s", strerror(error));
}

static void
tcp_association_params(const atf_tc_t *tc,
    struct nvmf_association_params *params)
{
	params->tcp.pda = 0;
	params->tcp.header_digests =
	    atf_tc_get_config_var_as_bool_wd(tc, "header_digests", false);
	params->tcp.data_digests =
	    atf_tc_get_config_var_as_bool_wd(tc, "data_digests", false);
	params->tcp.maxr2t = 1;
}

static struct nvmf_association *
create_association(const atf_tc_t *tc)
{
	struct nvmf_association_params aparams;
	struct nvmf_association *na;
	const char *transport;
	enum nvmf_trtype trtype;

	transport = atf_tc_get_config_var_wd(tc, "transport", "tcp");

	memset(&aparams, 0, sizeof(aparams));
	aparams.sq_flow_control =
	    atf_tc_get_config_var_as_bool_wd(tc, "flow_control", false);
	if (strcasecmp(transport, "tcp") == 0) {
		trtype = NVMF_TRTYPE_TCP;
		tcp_association_params(tc, &aparams);
	} else
		atf_tc_fail("Invalid transport %s", transport);

	na = nvmf_allocate_association(trtype, false, &aparams);
	if (na == NULL)
		atf_tc_fail("Failed to create association: %s",
		    strerror(errno));
	return (na);
}

static int
open_socket(const atf_tc_t *tc, struct addrinfo **aip, struct addrinfo **listp)
{
	struct addrinfo hints, *ai, *list;
	int error, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(atf_tc_get_config_var(tc, "address"),
	    atf_tc_get_config_var(tc, "port"), &hints, &list);
	if (error != 0)
		atf_tc_fail("%s", gai_strerror(error));

	for (ai = list; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			continue;

		if (connect(s, ai->ai_addr, ai->ai_addrlen) != 0) {
			close(s);
			continue;
		}

		if (listp != NULL) {
			*aip = ai;
			*listp = list;
		} else
			freeaddrinfo(list);
		return (s);
	}
	atf_tc_fail("Failed to connect to controller: %s", strerror(errno));
}

static int
open_socket_ai(struct addrinfo *ai)
{
	int s;

	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s == -1)
		atf_tc_fail("socket: %s", strerror(errno));

	if (connect(s, ai->ai_addr, ai->ai_addrlen) != 0)
		atf_tc_fail("connect: %s", strerror(errno));

	return (s);
}

static uint16_t
parse_cntlid(const atf_tc_t *tc)
{
	const char *cntlid;
	char *cp;
	u_long val;

	cntlid = atf_tc_get_config_var_wd(tc, "cntlid", "dynamic");
	if (strcasecmp(cntlid, "dynamic") == 0)
		return (NVMF_CNTLID_DYNAMIC);
	else if (strcasecmp(cntlid, "static") == 0)
		return (NVMF_CNTLID_STATIC_ANY);

	val = strtoul(cntlid, &cp, 0);
	if (*cp != '\0' || cp == cntlid || val > NVMF_CNTLID_STATIC_MAX)
		atf_tc_fail("Invalid controller ID");
	return (val);
}

static struct nvmf_qpair *
connect_admin_queue(const atf_tc_t *tc, struct nvmf_association *na,
    const struct nvmf_qpair_params *params, const uint8_t hostid[16],
    const char *hostnqn)
{
	struct nvmf_qpair *qp;
	const char *subnqn;
	uint64_t cap, cc, csts;
	u_int mps, mpsmin, mpsmax;
	int error, timo;
	uint16_t cntlid;

	cntlid = parse_cntlid(tc);
	subnqn = atf_tc_get_config_var(tc, "nqn");
	qp = nvmf_connect(na, params, 0, NVMF_MIN_ADMIN_MAX_SQ_SIZE, hostid,
	    cntlid, subnqn, hostnqn, 0);
	if (qp == NULL)
		return (NULL);

	/* Fetch Controller Capabilities Property */
	error = nvmf_read_property(qp, NVMF_PROP_CAP, 8, &cap);
	if (error != 0)
		atf_tc_fail("Failed to fetch CAP: %s", strerror(error));
	timo = NVME_CAP_LO_TO(cap);

	/* Require the NVM command set. */
	if (NVME_CAP_HI_CSS_NVM(cap >> 32) == 0)
		atf_tc_fail("Controller does not support the NVM command set");

	/* Prefer native host page size if it fits. */
	mpsmin = NVMEV(NVME_CAP_HI_REG_MPSMIN, cap >> 32);
	mpsmax = NVMEV(NVME_CAP_HI_REG_MPSMAX, cap >> 32);
	mps = ffs(getpagesize()) - 1;
	if (mps < mpsmin + 12)
		mps = mpsmin;
	else if (mps > mpsmax + 12)
		mps = mpsmax;
	else
		mps -= 12;

	/* Configure controller. */
	error = nvmf_read_property(qp, NVMF_PROP_CC, 4, &cc);
	if (error != 0)
		atf_tc_fail("Failed to fetch CC: %s", strerror(error));

	/* Clear known fields preserving any reserved fields. */
	cc &= ~(NVMEM(NVME_CC_REG_IOCQES) | NVMEM(NVME_CC_REG_IOSQES) |
	    NVMEM(NVME_CC_REG_SHN) | NVMEM(NVME_CC_REG_AMS) |
	    NVMEM(NVME_CC_REG_MPS) | NVMEM(NVME_CC_REG_CSS));

	cc |= NVMEF(NVME_CC_REG_IOCQES, 4);	/* CQE entry size == 16 */
	cc |= NVMEF(NVME_CC_REG_IOSQES, 6);	/* SQE entry size == 64 */
	cc |= NVMEF(NVME_CC_REG_AMS, 0);	/* AMS 0 (Round-robin) */
	cc |= NVMEF(NVME_CC_REG_MPS, mps);
	cc |= NVMEF(NVME_CC_REG_CSS, 0);	/* NVM command set */
	cc |= NVMEF(NVME_CC_REG_EN, 1);		/* EN = 1 */

	error = nvmf_write_property(qp, NVMF_PROP_CC, 4, cc);
	if (error != 0)
		atf_tc_fail("Failed to fetch CC: %s", strerror(error));

	/* Wait for CSTS.RDY in Controller Status */
	timo = NVME_CAP_LO_TO(cap);
	for (;;) {
		error = nvmf_read_property(qp, NVMF_PROP_CSTS, 4, &csts);
		if (error != 0)
			atf_tc_fail("Failed to fetch CSTS: %s",
			    strerror(error));

		if (NVMEV(NVME_CSTS_REG_RDY, csts) != 0)
			break;

		if (timo == 0)
			atf_tc_fail("Controller failed to become ready");
		timo--;
		usleep(500 * 1000);
	}

	return (qp);
}

static void
shutdown_controller(struct nvmf_qpair *qp)
{
	uint64_t cc;
	int error;

	error = nvmf_read_property(qp, NVMF_PROP_CC, 4, &cc);
	if (error != 0)
		atf_tc_fail("Failed to fetch CC: %s", strerror(error));

	cc |= NVMEF(NVME_CC_REG_SHN, NVME_SHN_NORMAL);

	error = nvmf_write_property(qp, NVMF_PROP_CC, 4, cc);
	if (error != 0)
		atf_tc_fail("Failed to set CC to trigger shutdown: %s",
		    strerror(error));
}

/*
 * Test that an I/O queue with a byte-swapped queue ID that is
 * out-of-bounds is correctly rejected.
 */
ATF_TC(invalid_qid);
ATF_TC_HEAD(invalid_qid, tc)
{
	require(tc);
}
ATF_TC_BODY(invalid_qid, tc)
{
	struct nvme_controller_data cdata;
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	struct nvmf_qpair_params qparams;
	const struct nvmf_fabric_connect_rsp *rsp;
	struct nvmf_association *na;
	struct nvmf_qpair *admin, *io;
	struct nvmf_capsule *cc, *rc;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	struct addrinfo *ai, *list;
	int as, error, is, queues;
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	as = open_socket(tc, &ai, &list);
	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = as;

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	error = nvmf_host_identify_controller(admin, &cdata);
	if (error != 0)
		atf_tc_fail("Failed to fetch controller data: %s",
		    strerror(error));
	nvmf_update_assocation(na, &cdata);

	error = nvmf_host_request_queues(admin, 1, &queues);
	if (error != 0)
		atf_tc_fail("Failed to request I/O queues: %s",
		    strerror(error));

	is = open_socket_ai(ai);
	freeaddrinfo(list);
	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = false;
	qparams.tcp.fd = is;

	/*
	 * Manually construct queue pair and send CONNECT command to
	 * verify error from controller.
	 */
	io = nvmf_allocate_qpair(na, &qparams);
	if (io == NULL)
		atf_tc_fail("Failed to create I/O queue: %s",
		    nvmf_association_error(na));

	memset(&cmd, 0, sizeof(cmd));
	nvmf_init_fabrics_sqe(&cmd, NVMF_FABRIC_COMMAND_CONNECT);
	cmd.recfmt = 0;
	cmd.qid = htole16(0x100);

	cmd.sqsize = htole16(NVME_MIN_IO_ENTRIES - 1);
	if (!atf_tc_get_config_var_as_bool_wd(tc, "flow_control", false))
		cmd.cattr |= NVMF_CONNECT_ATTR_DISABLE_SQ_FC;

	cc = nvmf_allocate_command(io, &cmd);
	if (cc == NULL)
		atf_tc_fail("Failed to allocate command capsule: %s",
		    strerror(errno));

	memset(&data, 0, sizeof(data));
	memcpy(data.hostid, hostid, sizeof(data.hostid));
	data.cntlid = htole16(nvmf_cntlid(admin));
	strlcpy(data.subnqn, atf_tc_get_config_var(tc, "nqn"),
	    sizeof(data.subnqn));
	strlcpy(data.hostnqn, hostnqn, sizeof(data.hostnqn));

	error = nvmf_capsule_append_data(cc, &data, sizeof(data), true);
	if (error != 0)
		atf_tc_fail("Failed to append data to CONNECT capsule: %s",
		    strerror(error));

	error = nvmf_transmit_capsule(cc);
	if (error != 0)
		atf_tc_fail("Failed to transmit CONNECT capsule: %s",
		    strerror(errno));

	error = nvmf_receive_capsule(io, &rc);
	if (error != 0)
		atf_tc_fail("Failed to receive CONNECT response: %s",
		    strerror(error));

	rsp = nvmf_capsule_cqe(rc);
	status = le16toh(rsp->status);
	ATF_REQUIRE(status != 0);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_COMMAND_SPECIFIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM);
	ATF_REQUIRE(rsp->status_code_specific.invalid.iattr == 0);
	ATF_REQUIRE(rsp->status_code_specific.invalid.ipo ==
	    offsetof(struct nvmf_fabric_connect_cmd, qid));

	nvmf_free_qpair(io);
	close(is);

	shutdown_controller(admin);
	nvmf_free_qpair(admin);
	close(as);
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
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char *buf;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	size_t len;
	int s;
	uint16_t status;

	init_hostid(hostid, hostnqn);

	na = create_association(tc);

	s = open_socket(tc, NULL, NULL);
	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = s;

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

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
	close(s);
}

#define	LEN_TO_NUMD(len)	((len) / 4 - 1)

/*
 * Test various offsets and lengths for fetching a log page.
 */
ATF_TC(fetch_hip);
ATF_TC_HEAD(fetch_hip, tc)
{
	require(tc);
}
ATF_TC_BODY(fetch_hip, tc)
{
	fetch_hip_log_page_test(tc, 0,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), false);
}

ATF_TC(fetch_hip_short);
ATF_TC_HEAD(fetch_hip_short, tc)
{
	require(tc);
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
	require(tc);
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
	require(tc);
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
	require(tc);
}
ATF_TC_BODY(fetch_hip_offset_1, tc)
{
	fetch_hip_log_page_test(tc, 1,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), true);
}

ATF_TC(fetch_hip_offset_2);
ATF_TC_HEAD(fetch_hip_offset_2, tc)
{
	require(tc);
}
ATF_TC_BODY(fetch_hip_offset_2, tc)
{
	fetch_hip_log_page_test(tc, 2,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), true);
}

ATF_TC(fetch_hip_offset_3);
ATF_TC_HEAD(fetch_hip_offset_3, tc)
{
	require(tc);
}
ATF_TC_BODY(fetch_hip_offset_3, tc)
{
	fetch_hip_log_page_test(tc, 3,
	    LEN_TO_NUMD(sizeof(struct nvme_health_information_page)), true);
}

ATF_TC(fetch_hip_offset_beyond_end);
ATF_TC_HEAD(fetch_hip_offset_beyond_end, tc)
{
	require(tc);
}
ATF_TC_BODY(fetch_hip_offset_beyond_end, tc)
{
	fetch_hip_log_page_test(tc,
	    sizeof(struct nvme_health_information_page),
	    LEN_TO_NUMD(16), true);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, invalid_qid);
	ATF_TP_ADD_TC(tp, fetch_hip);
	ATF_TP_ADD_TC(tp, fetch_hip_short);
	ATF_TP_ADD_TC(tp, fetch_hip_middle);
	ATF_TP_ADD_TC(tp, fetch_hip_long);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_1);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_2);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_3);
	ATF_TP_ADD_TC(tp, fetch_hip_offset_beyond_end);

	return (atf_no_error());
}
