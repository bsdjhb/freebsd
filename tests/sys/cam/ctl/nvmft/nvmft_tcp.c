/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023,2026 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <errno.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdlib.h>
#include <atf-c.h>

#include "nvmft_subr.h"

static void
require_nvmft_tcp(atf_tc_t *tc)
{
	const char *transport;

	require_nvmft(tc);
	transport = atf_tc_get_config_var_wd(tc, "nvmft.transport", "tcp");
	if (strcasecmp(transport, "tcp") != 0)
		atf_tc_skip("requires TCP transport");
}

static void
nvmf_init_sqe(void *sqe, uint8_t opcode)
{
	struct nvme_command *cmd = sqe;

	memset(cmd, 0, sizeof(*cmd));
	cmd->opc = opcode;
}

static void
write_data(int s, const void *pdu, size_t len)
{
	const char *buf;
	ssize_t nwritten;

	buf = pdu;
	while (len > 0) {
		nwritten = write(s, buf, len);
		ATF_REQUIRE(nwritten >= 0);
		ATF_REQUIRE((size_t)nwritten <= len);

		buf += nwritten;
		len -= nwritten;
	}
}

static void
write_pdu(int s, const void *pdu)
{
	const struct nvme_tcp_common_pdu_hdr *hdr = pdu;

	write_data(s, pdu, MAX(sizeof(*hdr), le32toh(hdr->plen)));
}

static void
read_data(int s, void *data, size_t len)
{
	char *buf;
	ssize_t nread;

	buf = data;
	while (len > 0) {
		nread = read(s, buf, len);
		ATF_REQUIRE(nread >= 0);
		ATF_REQUIRE((size_t)nread <= len);

		buf += nread;
		len -= nread;
	}
}

static void *
read_pdu(int s)
{
	struct nvme_tcp_common_pdu_hdr hdr;
	uint32_t plen;
	char *pdu;

	read_data(s, &hdr, sizeof(hdr));
	plen = le32toh(hdr.plen);

	pdu = malloc(plen);
	memcpy(pdu, &hdr, sizeof(hdr));
	read_data(s, pdu + sizeof(hdr), plen - sizeof(hdr));
	return (pdu);
}

static void
expect_c2hterm(int s, uint16_t fes, uint32_t fei, const void *badpdu)
{
	const struct nvme_tcp_common_pdu_hdr *badhdr = badpdu;
	struct nvme_tcp_term_req_hdr *pdu;
	uint32_t badlen, plen, hdrlen;

	pdu = read_pdu(s);
	ATF_REQUIRE_EQ(NVME_TCP_PDU_TYPE_C2H_TERM_REQ, pdu->common.pdu_type);
	ATF_REQUIRE_EQ(sizeof(*pdu), pdu->common.hlen);

	plen = le32toh(pdu->common.plen);
	ATF_REQUIRE(plen >= sizeof(*pdu));
	ATF_REQUIRE(plen <= NVME_TCP_TERM_REQ_PDU_MAX_SIZE);

	ATF_REQUIRE_EQ(fes, le16toh(pdu->fes));
	ATF_REQUIRE_EQ(fei, le32dec(pdu->fei));

	badlen = MIN(badhdr->hlen, le32toh(badhdr->plen));
	badlen = MAX(badlen, sizeof(*badhdr));
	hdrlen = plen - sizeof(*pdu);
	ATF_REQUIRE_EQ(MIN(badlen, NVME_TCP_TERM_REQ_ERROR_DATA_MAX_SIZE),
	    hdrlen);
	ATF_REQUIRE_EQ(0, memcmp(pdu + 1, badpdu, hdrlen));
	free(pdu);
}

ATF_TC(initial_reserved_opcode);
ATF_TC_HEAD(initial_reserved_opcode, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(initial_reserved_opcode, tc)
{
	struct nvme_tcp_ic_req pdu;
	int s;

	s = open_socket(tc, NULL, NULL);

	/* Reserved, host to controller opcode. */
	memset(&pdu, 0, sizeof(pdu));
	pdu.common.pdu_type = 0x8;
	pdu.common.hlen = sizeof(pdu);
	pdu.common.plen = htole32(sizeof(pdu));
	pdu.pfv = htole16(0);
	pdu.hpda = 0;
	pdu.maxr2t = htole32(0);
	write_pdu(s, &pdu);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, pdu_type), &pdu);

	close(s);
}

ATF_TC(initial_ic_resp);
ATF_TC_HEAD(initial_ic_resp, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(initial_ic_resp, tc)
{
	struct nvme_tcp_ic_resp pdu;
	int s;

	s = open_socket(tc, NULL, NULL);

	memset(&pdu, 0, sizeof(pdu));
	pdu.common.pdu_type = NVME_TCP_PDU_TYPE_IC_RESP;
	pdu.common.hlen = sizeof(pdu);
	pdu.common.plen = htole32(sizeof(pdu));
	pdu.pfv = htole16(0);
	pdu.cpda = 0;
	pdu.maxh2cdata = htole32(4096);
	write_pdu(s, &pdu);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, pdu_type), &pdu);

	close(s);
}

ATF_TC(send_h2cterm);
ATF_TC_HEAD(send_h2cterm, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(send_h2cterm, tc)
{
	struct nvme_tcp_term_req_hdr pdu;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	int s;

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

	/* Fake up an error. */
	memset(&pdu, 0, sizeof(pdu));
	pdu.common.pdu_type = NVME_TCP_PDU_TYPE_H2C_TERM_REQ;
	pdu.common.hlen = sizeof(pdu);
	pdu.common.plen = htole32(sizeof(pdu));
	pdu.fes = htole16(NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR);
	write_pdu(s, &pdu);

	nvmf_free_qpair(admin);
}

static struct nvmf_association *
create_association_forced_header_digests(const atf_tc_t *tc)
{
	struct nvmf_association_params aparams;
	struct nvmf_association *na;
	enum nvmf_trtype trtype;

	trtype = init_association_params(tc, &aparams);

	aparams.tcp.header_digests = true;

	na = nvmf_allocate_association(trtype, false, &aparams);
	if (na == NULL)
		atf_tc_fail("Failed to create association: %s",
		    strerror(errno));
	return (na);
}

static struct nvmf_association *
create_association_no_header_digests(const atf_tc_t *tc)
{
	struct nvmf_association_params aparams;
	struct nvmf_association *na;
	enum nvmf_trtype trtype;

	trtype = init_association_params(tc, &aparams);

	aparams.tcp.header_digests = false;

	na = nvmf_allocate_association(trtype, false, &aparams);
	if (na == NULL)
		atf_tc_fail("Failed to create association: %s",
		    strerror(errno));
	return (na);
}

static struct nvmf_qpair *
connect_tcp_admin_queue(const atf_tc_t *tc, struct nvmf_association *na, int s)
{
	struct nvmf_qpair_params qparams;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];

	init_hostid(hostid, hostnqn);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = s;

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	return (admin);
}

static void
send_bad_pdu_on_admin_queue(const atf_tc_t *tc, struct nvmf_association *na,
    uint16_t fes, uint32_t fei, const void *pdu)
{
	struct nvmf_qpair *admin;
	int s;

	s = open_socket(tc, NULL, NULL);

	admin = connect_tcp_admin_queue(tc, na, s);

	write_pdu(s, pdu);
	expect_c2hterm(s, fes, fei, pdu);

	nvmf_free_qpair(admin);
}

ATF_TC(reserved_opcode);
ATF_TC_HEAD(reserved_opcode, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(reserved_opcode, tc)
{
	struct nvme_tcp_common_pdu_hdr pdu;

	/* Reserved, host to controller opcode. */
	pdu.pdu_type = 0x8;
	pdu.hlen = sizeof(pdu);
	pdu.plen = htole32(sizeof(pdu));

	send_bad_pdu_on_admin_queue(tc,
	    create_association_no_header_digests(tc),
	    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, pdu_type), &pdu);
}

/*
 * Populate a command capsule PDU with a keep alive command.
 */
static void
keepalive_command_pdu(struct nvme_tcp_cmd *pdu, bool header_digest)
{
	uint32_t plen;

	memset(pdu, 0, sizeof(*pdu));
	pdu->common.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_CMD;
	pdu->common.hlen = sizeof(*pdu);
	plen = sizeof(*pdu);
	if (header_digest) {
		pdu->common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(uint32_t);
	}
	pdu->common.plen = htole32(plen);

	nvmf_init_sqe(&pdu->ccsqe, NVME_OPC_KEEP_ALIVE);

	/* 4.2 of NVMe base spec: Fabrics always uses SGL. */
	pdu->ccsqe.fuse &= ~NVMEM(NVME_CMD_PSDT);
	pdu->ccsqe.fuse |= NVMEF(NVME_CMD_PSDT, NVME_PSDT_SGL);

	/* Arbitrary CID, but should be far enough into the future. */
	pdu->ccsqe.cid = htole16(0x1000);

	if (header_digest) {
		uint32_t *dgst;

		dgst = (void *)(pdu + 1);
		*dgst = nvmf_tcp_compute_digest(pdu, sizeof(*pdu));
	}
}

ATF_TC(reserved_pdu_flags);
ATF_TC_HEAD(reserved_pdu_flags, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(reserved_pdu_flags, tc)
{
	struct nvme_tcp_cmd pdu;

	keepalive_command_pdu(&pdu, false);

	/* Set reserved flags. */
	pdu.common.flags |= 0x80;

	send_bad_pdu_on_admin_queue(tc,
	    create_association_no_header_digests(tc),
	    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, flags), &pdu);
}

ATF_TC(spurious_header_digest);
ATF_TC_HEAD(spurious_header_digest, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(spurious_header_digest, tc)
{
	struct {
		struct nvme_tcp_cmd cmd;
		uint32_t dgst;
	} pdu;

	keepalive_command_pdu(&pdu.cmd, true);

	send_bad_pdu_on_admin_queue(tc,
	    create_association_no_header_digests(tc),
	    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, flags), &pdu);
}

ATF_TC(missing_header_digest);
ATF_TC_HEAD(missing_header_digest, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(missing_header_digest, tc)
{
	struct nvme_tcp_cmd pdu;
	struct nvmf_qpair *admin;
	int s;

	s = open_socket(tc, NULL, NULL);

	admin = connect_tcp_admin_queue(tc,
	    create_association_forced_header_digests(tc), s);

	if (!nvmf_tcp_using_header_digests(admin))
		atf_tc_skip("Controller does not support header digests");

	keepalive_command_pdu(&pdu, false);

	write_pdu(s, &pdu);
	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, flags), &pdu);

	nvmf_free_qpair(admin);
}

ATF_TC(invalid_header_digest);
ATF_TC_HEAD(invalid_header_digest, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(invalid_header_digest, tc)
{
	struct {
		struct nvme_tcp_cmd cmd;
		uint32_t dgst;
	} pdu;
	struct nvmf_qpair *admin;
	int s;

	s = open_socket(tc, NULL, NULL);

	admin = connect_tcp_admin_queue(tc,
	    create_association_forced_header_digests(tc), s);

	if (!nvmf_tcp_using_header_digests(admin))
		atf_tc_skip("Controller does not support header digests");

	keepalive_command_pdu(&pdu.cmd, true);

	/* Corrupt the header digest. */
	pdu.dgst ^= 0x1;

	write_pdu(s, &pdu);
	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_HDGST_ERROR, pdu.dgst, &pdu);

	nvmf_free_qpair(admin);
}

ATF_TC(short_header_digest);
ATF_TC_HEAD(short_header_digest, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(short_header_digest, tc)
{
	struct {
		struct nvme_tcp_cmd cmd;
		uint32_t dgst;
	} pdu;
	struct nvmf_qpair *admin;
	int s;

	s = open_socket(tc, NULL, NULL);

	admin = connect_tcp_admin_queue(tc,
	    create_association_forced_header_digests(tc), s);

	if (!nvmf_tcp_using_header_digests(admin))
		atf_tc_skip("Controller does not support header digests");

	keepalive_command_pdu(&pdu.cmd, true);

	/* Exclude the digest from the PDU length. */
	pdu.cmd.common.plen = htole32(sizeof(pdu.cmd));

	write_pdu(s, &pdu);
	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, plen), &pdu);

	nvmf_free_qpair(admin);
}

ATF_TC(tiny_header);
ATF_TC_HEAD(tiny_header, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(tiny_header, tc)
{
	struct nvme_tcp_common_pdu_hdr pdu;

	memset(&pdu, 0, sizeof(pdu));
	pdu.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_CMD;
	pdu.plen = htole32(4);

	send_bad_pdu_on_admin_queue(tc,
	    create_association_no_header_digests(tc),
	    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, hlen), &pdu);
}

ATF_TC(invalid_header_len);
ATF_TC_HEAD(invalid_header_len, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(invalid_header_len, tc)
{
	struct nvme_tcp_cmd pdu;

	keepalive_command_pdu(&pdu, false);

	pdu.common.hlen -= 4;

	send_bad_pdu_on_admin_queue(tc,
	    create_association_no_header_digests(tc),
	    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, hlen), &pdu);
}

ATF_TC(invalid_header_pdo);
ATF_TC_HEAD(invalid_header_pdo, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(invalid_header_pdo, tc)
{
	struct nvme_tcp_cmd pdu;

	keepalive_command_pdu(&pdu, false);

	pdu.common.pdo = 4;

	send_bad_pdu_on_admin_queue(tc,
	    create_association_no_header_digests(tc),
	    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, pdo), &pdu);
}

ATF_TC(short_plen);
ATF_TC_HEAD(short_plen, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(short_plen, tc)
{
	struct nvme_tcp_cmd pdu;

	keepalive_command_pdu(&pdu, false);

	pdu.common.plen = htole32(pdu.common.hlen - 4);

	send_bad_pdu_on_admin_queue(tc,
	    create_association_no_header_digests(tc),
	    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, plen), &pdu);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, initial_reserved_opcode);
	ATF_TP_ADD_TC(tp, initial_ic_resp);
	ATF_TP_ADD_TC(tp, send_h2cterm);
	ATF_TP_ADD_TC(tp, reserved_opcode);
	ATF_TP_ADD_TC(tp, reserved_pdu_flags);
	ATF_TP_ADD_TC(tp, spurious_header_digest);
	ATF_TP_ADD_TC(tp, missing_header_digest);
	ATF_TP_ADD_TC(tp, invalid_header_digest);
	ATF_TP_ADD_TC(tp, short_header_digest);
	ATF_TP_ADD_TC(tp, tiny_header);
	ATF_TP_ADD_TC(tp, invalid_header_len);
	ATF_TP_ADD_TC(tp, invalid_header_pdo);
	ATF_TP_ADD_TC(tp, short_plen);

	return (atf_no_error());
}
