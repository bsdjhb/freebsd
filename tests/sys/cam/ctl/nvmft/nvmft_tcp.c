/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023,2026 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <errno.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <atf-c.h>

#include "nvmft_subr.h"

#include <assert.h>
#include <stdio.h>
#include "nvmf_tcp.h"

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

static size_t
pdu_len(size_t hlen, size_t data_len, bool header_digest, bool data_digest,
    u_int txpda)
{
	size_t pdo, plen;

	plen = hlen;
	if (header_digest)
		plen += sizeof(uint32_t);
	if (data_len != 0) {
		pdo = roundup(plen, txpda);
		plen = pdo + data_len;
		if (data_digest)
			plen += sizeof(uint32_t);
	}
	return (plen);
}

static void
construct_pdu(void *buf, const void *hdr, size_t hlen, void *data,
    size_t data_len, bool header_digest, bool data_digest, u_int txpda)
{
	struct nvme_tcp_common_pdu_hdr *ch = buf;
	size_t pdo, plen;

	plen = hlen;
	if (header_digest)
		plen += sizeof(uint32_t);
	if (data_len != 0) {
		pdo = roundup(plen, txpda);
		plen = pdo + data_len;
		if (data_digest)
			plen += sizeof(uint32_t);
	} else {
		pdo = 0;
	}

	memset(buf, 0, plen);
	memcpy(buf, hdr, hlen);
	ch->hlen = hlen;
	if (header_digest)
		ch->flags |= NVME_TCP_CH_FLAGS_HDGSTF;
	if (data_digest && data_len != 0)
		ch->flags |= NVME_TCP_CH_FLAGS_DDGSTF;
	ch->pdo = pdo;
	ch->plen = htole32(plen);

	if (header_digest) {
		uint32_t *dgst;

		dgst = (void *)((char *)buf + hlen);
		*dgst = nvmf_tcp_compute_digest(buf, hlen);
	}

	if (data_len != 0) {
		void *pdu_data;

		pdu_data = (char *)buf + pdo;
		memcpy(pdu_data, data, data_len);
		if (data_digest) {
			uint32_t *dgst;

			dgst = (void *)((char *)pdu_data + data_len);
			*dgst = nvmf_tcp_compute_digest(pdu_data, data_len);
		}
	}
}

static size_t
command_pdu_len(size_t data_len, bool header_digest, bool data_digest,
    u_int txpda)
{
	return (pdu_len(sizeof(struct nvme_tcp_cmd), data_len, header_digest,
	    data_digest, txpda));
}

static void
construct_command_pdu(void *buf, const struct nvme_command *cmd, void *data,
    size_t data_len, bool header_digest, bool data_digest, u_int txpda,
    bool icd)
{
	struct nvme_tcp_cmd pdu;
	struct nvme_sgl_descriptor *sgl;

	memset(&pdu, 0, sizeof(pdu));
	pdu.common.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_CMD;
	pdu.ccsqe = *cmd;

	/* 4.2 of NVMe base spec: Fabrics always uses SGL. */
	pdu.ccsqe.fuse &= ~NVMEM(NVME_CMD_PSDT);
	pdu.ccsqe.fuse |= NVMEF(NVME_CMD_PSDT, NVME_PSDT_SGL);

	/* Populate SGL in SQE. */
	if (data_len != 0) {
		sgl = &pdu.ccsqe.sgl;
		memset(sgl, 0, sizeof(*sgl));
		sgl->address = 0;
		sgl->length = htole32(data_len);
		sgl->type = icd ? NVME_SGL_TYPE_ICD :
		    NVME_SGL_TYPE_COMMAND_BUFFER;
	}

	construct_pdu(buf, &pdu, sizeof(pdu), data, icd ? data_len : 0,
	    header_digest, data_digest, txpda);
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
		ATF_REQUIRE(nread > 0);
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
	ATF_REQUIRE(plen > sizeof(hdr));

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

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn, 0);
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

static struct nvmf_association *
create_association_forced_data_digests(const atf_tc_t *tc)
{
	struct nvmf_association_params aparams;
	struct nvmf_association *na;
	enum nvmf_trtype trtype;

	trtype = init_association_params(tc, &aparams);

	aparams.tcp.data_digests = true;

	na = nvmf_allocate_association(trtype, false, &aparams);
	if (na == NULL)
		atf_tc_fail("Failed to create association: %s",
		    strerror(errno));
	return (na);
}

static struct nvmf_association *
create_association_no_data_digests(const atf_tc_t *tc)
{
	struct nvmf_association_params aparams;
	struct nvmf_association *na;
	enum nvmf_trtype trtype;

	trtype = init_association_params(tc, &aparams);

	aparams.tcp.data_digests = false;

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

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn, 0);
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
keepalive_command_pdu(void *pdu, bool header_digest)
{
	struct nvme_command cmd;

	nvmf_init_sqe(&cmd, NVME_OPC_KEEP_ALIVE);

	/* Arbitrary CID, but should be far enough into the future. */
	cmd.cid = htole16(0x1000);
	construct_command_pdu(pdu, &cmd, NULL, 0, header_digest, false, 0,
	    false);
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

	keepalive_command_pdu(&pdu, true);

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

	keepalive_command_pdu(&pdu, true);

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

	keepalive_command_pdu(&pdu, true);

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

/*
 * Build a command capsule PDU with a COMPARE command using ICD.
 */
static void
nvmf_init_compare_sqe(void *sqe, uint32_t nsid, uint64_t lba, u_int nlb)
{
	struct nvme_command *cmd = sqe;

	nvmf_init_sqe(cmd, NVME_OPC_COMPARE);
	cmd->nsid = htole32(nsid);
	cmd->cdw10 = htole32(lba);
	cmd->cdw11 = htole32(lba >> 32);
	cmd->cdw12 = htole16(nlb - 1);
}

static void *
compare_command_pdu(struct nvmf_qpair *qp, uint32_t nsid, uint64_t lba,
    u_int nlb, void *data, uint32_t data_len, bool header_digest,
    bool data_digest, u_int txpda, bool icd)
{
	struct nvme_command cmd;
	void *pdu;

	pdu = malloc(command_pdu_len(data_len, header_digest, data_digest,
	    txpda));
	nvmf_init_compare_sqe(&cmd, nsid, lba, nlb);
	cmd.cid = nvmf_host_next_cid(qp);
	construct_command_pdu(pdu, &cmd, data, data_len, header_digest,
	    data_digest, txpda, icd);
	return (pdu);
}

static void
open_queues_for_compare(const atf_tc_t *tc, struct nvmf_association *na,
    struct nvmf_qpair **adminp, struct nvmf_qpair **iop, int *sp)
{
	struct nvmf_qpair_params qparams;
	struct nvmf_qpair *admin, *io;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	struct addrinfo *ai, *list;
	int s;

	init_hostid(hostid, hostnqn);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = open_socket(tc, &ai, &list);

	admin = connect_admin_queue(tc, na, &qparams, hostid, hostnqn, 0);
	if (admin == NULL)
		atf_tc_fail("Failed to create admin queue: %s",
		    nvmf_association_error(na));

	require_compare(admin);

	s = open_socket_ai(ai);
	freeaddrinfo(list);

	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = false;
	qparams.tcp.fd = s;

	io = connect_io_queue(tc, admin, na, &qparams, hostid, hostnqn);
	nvmf_free_association(na);

	*adminp = admin;
	*iop = io;
	*sp = s;
}

ATF_TC(spurious_data_digest);
ATF_TC_HEAD(spurious_data_digest, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(spurious_data_digest, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *pdu;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association_no_data_digests(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	ATF_REQUIRE(block_size <= nvmf_tcp_max_icd(io));

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	/* Force data digest. */
	pdu = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), true, nvmf_tcp_txpda(io), true);
	free(buf);

	write_pdu(s, pdu);
	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, flags), pdu);
	free(pdu);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(missing_data_digest);
ATF_TC_HEAD(missing_data_digest, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(missing_data_digest, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *pdu;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association_forced_data_digests(tc),
	    &admin, &io, &s);

	if (!nvmf_tcp_using_data_digests(io))
		atf_tc_skip("Controller does not support data digests");

	nsid = validate_namespace(tc, admin, &block_size);

	ATF_REQUIRE(block_size <= nvmf_tcp_max_icd(io));

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	/* Force no data digest. */
	pdu = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), false, nvmf_tcp_txpda(io), true);
	free(buf);

	write_pdu(s, pdu);
	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_common_pdu_hdr, flags), pdu);
	free(pdu);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(invalid_data_digest_icd);
ATF_TC_HEAD(invalid_data_digest_icd, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(invalid_data_digest_icd, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_rsp *rsp;
	uint32_t *dgst;
	void *buf;
	u_int block_size, nsid;
	uint16_t status;
	int s;

	open_queues_for_compare(tc, create_association_forced_data_digests(tc),
	    &admin, &io, &s);

	if (!nvmf_tcp_using_data_digests(io))
		atf_tc_skip("Controller does not support data digests");

	nsid = validate_namespace(tc, admin, &block_size);

	ATF_REQUIRE(block_size <= nvmf_tcp_max_icd(io));

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), true, nvmf_tcp_txpda(io), true);
	free(buf);

	/* Corrupt the data digest. */
	dgst = (void *)((char *)cmd + le32toh(cmd->common.plen) -
	    sizeof(*dgst));
	*dgst ^= 0x1;

	write_pdu(s, cmd);

	/*
	 * A data digest mismatch is not a fatal error, but the
	 * command should fail with a data transfer error.
	 */
	rsp = read_pdu(s);
	ATF_REQUIRE(rsp->common.pdu_type == NVME_TCP_PDU_TYPE_CAPSULE_RESP);
	ATF_REQUIRE(rsp->common.hlen == sizeof(*rsp));
	ATF_REQUIRE(le32toh(rsp->common.plen) >= sizeof(*rsp));
	ATF_REQUIRE(rsp->rccqe.cid == cmd->ccsqe.cid);
	status = le16toh(rsp->rccqe.status);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_GENERIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVME_SC_DATA_TRANSFER_ERROR);

	free(cmd);
	free(rsp);

	shutdown_controller(admin);
	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

static void *
h2cdata_pdu(struct nvmf_qpair *qp, uint16_t cid, uint16_t ttag, uint32_t datao,
    uint32_t datal, uint8_t flags, void *data, uint32_t data_len)
{
	struct nvme_tcp_h2c_data_hdr h2c;
	void *pdu;
	u_int txpda;
	bool data_digest, header_digest;

	memset(&h2c, 0, sizeof(h2c));
	h2c.common.pdu_type = NVME_TCP_PDU_TYPE_H2C_DATA;
	h2c.common.flags = flags;
	h2c.cccid = htole16(cid);
	h2c.ttag = htole16(ttag);
	h2c.datao = htole32(datao);
	h2c.datal = htole32(datal);

	header_digest = nvmf_tcp_using_header_digests(qp);
	data_digest = nvmf_tcp_using_data_digests(qp);
	txpda = nvmf_tcp_txpda(qp);

	pdu = malloc(pdu_len(sizeof(h2c), data_len, header_digest, data_digest,
	    txpda));

	construct_pdu(pdu, &h2c, sizeof(h2c), data, data_len, header_digest,
	    data_digest, txpda);
	return (pdu);
}

ATF_TC(invalid_data_digest_r2t);
ATF_TC_HEAD(invalid_data_digest_r2t, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(invalid_data_digest_r2t, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	struct nvme_tcp_rsp *rsp;
	uint32_t *dgst;
	void *buf;
	u_int block_size, nsid;
	uint16_t status;
	int s;

	open_queues_for_compare(tc, create_association_forced_data_digests(tc),
	    &admin, &io, &s);

	if (!nvmf_tcp_using_data_digests(io))
		atf_tc_skip("Controller does not support data digests");

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);

	/* Send H2C data with corrupted data digest. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    block_size, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf, block_size);
	free(buf);
	free(r2t);

	/* Corrupt the data digest. */
	dgst = (void *)((char *)h2c + le32toh(h2c->common.plen) -
	    sizeof(*dgst));
	*dgst ^= 0x1;
	write_pdu(s, h2c);
	free(h2c);

	/*
	 * A data digest mismatch is not a fatal error, but the
	 * command should fail with a data transfer error.
	 */
	rsp = read_pdu(s);
	ATF_REQUIRE(rsp->common.pdu_type == NVME_TCP_PDU_TYPE_CAPSULE_RESP);
	ATF_REQUIRE(rsp->common.hlen == sizeof(*rsp));
	ATF_REQUIRE(le32toh(rsp->common.plen) >= sizeof(*rsp));
	ATF_REQUIRE(rsp->rccqe.cid == cmd->ccsqe.cid);
	status = le16toh(rsp->rccqe.status);
	ATF_REQUIRE(NVME_STATUS_GET_SCT(status) == NVME_SCT_GENERIC);
	ATF_REQUIRE(NVME_STATUS_GET_SC(status) == NVME_SC_DATA_TRANSFER_ERROR);

	free(cmd);
	free(rsp);

	shutdown_controller(admin);
	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(excessive_h2cdata);
ATF_TC_HEAD(excessive_h2cdata, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(excessive_h2cdata, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	struct nvme_tcp_term_req_hdr *term;
	void *buf;
	size_t len;
	uint32_t plen, hdrlen;
	u_int block_size, maxh2cdata, nsid, nlb;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/*
	 * Need a request with enough blocks to exceed MAXH2CDATA.
	 *
	 * XXX: This doesn't check the nsdata to ensure the namespace
	 * has this many LBAs available.
	 */
	maxh2cdata = nvmf_tcp_maxh2cdata(io);
	nlb = howmany(maxh2cdata, block_size) + 1;
	len = (size_t)nlb * block_size;
	if (len > UINT32_MAX)
		atf_tc_skip("Minimum nlb to overflow MAXH2CDATA is too large");

	/* Allocate blocks of zeroes for the compare data. */
	buf = calloc(nlb, block_size);

	cmd = compare_command_pdu(io, nsid, 0, nlb, buf, len,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/*
	 * Next PDU should be a R2T to request the transfer.
	 *
	 * NB: The R2T might not request all of the data.  If it doesn't
	 * try to overshoot anyway.
	 */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	free(cmd);

	/* Send one (giant) H2C data. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    len, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf, len);
	free(buf);
	write_pdu(s, h2c);

	/*
	 * This should trigger some sort of termination request.  If
	 * the R2T did not request all of the data, it might instead
	 * report that the data is out of range rather than that the
	 * transfer limit was exceeded however.
	 */
	term = read_pdu(s);
	ATF_REQUIRE_EQ(NVME_TCP_PDU_TYPE_C2H_TERM_REQ, term->common.pdu_type);
	ATF_REQUIRE_EQ(sizeof(*term), term->common.hlen);

	plen = le32toh(term->common.plen);
	ATF_REQUIRE(plen >= sizeof(*term));
	ATF_REQUIRE(plen <= NVME_TCP_TERM_REQ_PDU_MAX_SIZE);

	if (le32toh(r2t->r2tl) == len)
		ATF_REQUIRE_EQ(
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED,
		    le16toh(term->fes));
	else
		ATF_REQUIRE(le16toh(term->fes) ==
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED ||
		    le16toh(term->fes) ==
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE);
	ATF_REQUIRE_EQ(0, le32dec(term->fei));

	hdrlen = plen - sizeof(*term);
	ATF_REQUIRE_EQ(MIN(sizeof(*h2c), NVME_TCP_TERM_REQ_ERROR_DATA_MAX_SIZE),
	    hdrlen);
	ATF_REQUIRE_EQ(0, memcmp(term + 1, h2c, hdrlen));
	free(r2t);
	free(term);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(invalid_h2cdata_ttag);
ATF_TC_HEAD(invalid_h2cdata_ttag, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(invalid_h2cdata_ttag, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* Send H2C data with different ttag. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag) ^ 1, 0,
	    block_size, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf, block_size);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_h2c_data_hdr, ttag), h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(mismatched_h2cdata_data_len);
ATF_TC_HEAD(mismatched_h2cdata_data_len, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(mismatched_h2cdata_data_len, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* Send H2C data with a truncated payload. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    block_size, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf, block_size / 2);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
	    offsetof(struct nvme_tcp_h2c_data_hdr, datal), h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(too_large_h2cdata_data_offset);
ATF_TC_HEAD(too_large_h2cdata_data_offset, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(too_large_h2cdata_data_offset, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* Send H2C data with out of bounds offset. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag),
	    block_size, block_size, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf,
	    block_size);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0,
	    h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(too_much_h2cdata_data);
ATF_TC_HEAD(too_much_h2cdata_data, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(too_much_h2cdata_data, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(block_size + 16, 1);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* Send H2C data with extra data. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    block_size + 16, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf,
	    block_size + 16);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0,
	    h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(missing_start_h2cdata_data);
ATF_TC_HEAD(missing_start_h2cdata_data, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(missing_start_h2cdata_data, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* Send H2C data missing first 16 bytes. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 16,
	    block_size - 16, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf,
	    block_size - 16);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(overlapping_h2cdata);
ATF_TC_HEAD(overlapping_h2cdata, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(overlapping_h2cdata, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* First H2C data sends half of the data. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    block_size / 2, 0, buf, block_size / 2);
	write_pdu(s, h2c);
	free(h2c);

	/* Second H2C data sends all of the data. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    block_size, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf, block_size);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(missing_h2cdata_last_pdu);
ATF_TC_HEAD(missing_h2cdata_last_pdu, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(missing_h2cdata_last_pdu, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* Send H2C data without LAST_PDU flag. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    block_size, 0, buf, block_size);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
}

ATF_TC(early_h2cdata_last_pdu);
ATF_TC_HEAD(early_h2cdata_last_pdu, tc)
{
	require_nvmft_tcp(tc);
}
ATF_TC_BODY(early_h2cdata_last_pdu, tc)
{
	struct nvmf_qpair *admin, *io;
	struct nvme_tcp_cmd *cmd;
	struct nvme_tcp_r2t_hdr *r2t;
	struct nvme_tcp_h2c_data_hdr *h2c;
	void *buf;
	u_int block_size, nsid;
	int s;

	open_queues_for_compare(tc, create_association(tc),
	    &admin, &io, &s);

	nsid = validate_namespace(tc, admin, &block_size);

	/* Allocate block of zeroes for the compare data. */
	buf = calloc(1, block_size);

	cmd = compare_command_pdu(io, nsid, 0, 1, buf, block_size,
	    nvmf_tcp_using_header_digests(io), nvmf_tcp_using_data_digests(io),
	    nvmf_tcp_txpda(io), false);

	write_pdu(s, cmd);

	/* Next PDU should be a R2T to request the transfer. */
	r2t = read_pdu(s);
	ATF_REQUIRE(r2t->common.pdu_type == NVME_TCP_PDU_TYPE_R2T);
	ATF_REQUIRE(r2t->common.hlen == sizeof(*r2t));
	ATF_REQUIRE(le32toh(r2t->common.plen) >= sizeof(*r2t));
	ATF_REQUIRE(r2t->cccid == cmd->ccsqe.cid);
	ATF_REQUIRE(le32toh(r2t->r2to) == 0);
	ATF_REQUIRE(le32toh(r2t->r2tl) == block_size);
	free(cmd);

	/* Send short H2C data with LAST_PDU flag. */
	h2c = h2cdata_pdu(io, le16toh(r2t->cccid), le16toh(r2t->ttag), 0,
	    block_size - 16, NVME_TCP_H2C_DATA_FLAGS_LAST_PDU, buf,
	    block_size - 16);
	free(buf);
	free(r2t);
	write_pdu(s, h2c);

	expect_c2hterm(s, NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, h2c);
	free(h2c);

	nvmf_free_qpair(io);
	nvmf_free_qpair(admin);
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
	ATF_TP_ADD_TC(tp, spurious_data_digest);
	ATF_TP_ADD_TC(tp, missing_data_digest);
	ATF_TP_ADD_TC(tp, invalid_data_digest_icd);
	ATF_TP_ADD_TC(tp, invalid_data_digest_r2t);
	ATF_TP_ADD_TC(tp, excessive_h2cdata);
	ATF_TP_ADD_TC(tp, invalid_h2cdata_ttag);
	ATF_TP_ADD_TC(tp, mismatched_h2cdata_data_len);
	ATF_TP_ADD_TC(tp, too_large_h2cdata_data_offset);
	ATF_TP_ADD_TC(tp, too_much_h2cdata_data);
	ATF_TP_ADD_TC(tp, missing_start_h2cdata_data);
	ATF_TP_ADD_TC(tp, overlapping_h2cdata);
	ATF_TP_ADD_TC(tp, missing_h2cdata_last_pdu);
	ATF_TP_ADD_TC(tp, early_h2cdata_last_pdu);

	return (atf_no_error());
}
