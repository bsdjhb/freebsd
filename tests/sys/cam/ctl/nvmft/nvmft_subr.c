/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023,2026 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdlib.h>
#include <atf-c.h>

#include "nvmft_subr.h"

void
require_nvmft(atf_tc_t *tc)
{
	atf_tc_set_md_var(tc, "require.config",
	    "nvmft.address nvmft.port nvmft.nqn");
}

void
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
	    atf_tc_get_config_var_as_bool_wd(tc, "nvmft.header_digests", false);
	params->tcp.data_digests =
	    atf_tc_get_config_var_as_bool_wd(tc, "nvmft.data_digests", false);
	params->tcp.maxr2t = 1;
}

struct nvmf_association *
create_association(const atf_tc_t *tc)
{
	struct nvmf_association_params aparams;
	struct nvmf_association *na;
	const char *transport;
	enum nvmf_trtype trtype;

	transport = atf_tc_get_config_var_wd(tc, "nvmft.transport", "tcp");

	memset(&aparams, 0, sizeof(aparams));
	aparams.sq_flow_control =
	    atf_tc_get_config_var_as_bool_wd(tc, "nvmft.flow_control", false);
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

int
open_socket(const atf_tc_t *tc, struct addrinfo **aip, struct addrinfo **listp)
{
	struct addrinfo hints, *ai, *list;
	int error, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(atf_tc_get_config_var(tc, "nvmft.address"),
	    atf_tc_get_config_var(tc, "nvmft.port"), &hints, &list);
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

int
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

uint16_t
parse_cntlid(const atf_tc_t *tc)
{
	const char *cntlid;
	char *cp;
	u_long val;

	cntlid = atf_tc_get_config_var_wd(tc, "nvmft.cntlid", "dynamic");
	if (strcasecmp(cntlid, "dynamic") == 0)
		return (NVMF_CNTLID_DYNAMIC);
	else if (strcasecmp(cntlid, "static") == 0)
		return (NVMF_CNTLID_STATIC_ANY);

	val = strtoul(cntlid, &cp, 0);
	if (*cp != '\0' || cp == cntlid || val > NVMF_CNTLID_STATIC_MAX)
		atf_tc_fail("Invalid controller ID");
	return (val);
}

struct nvmf_qpair *
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
	subnqn = atf_tc_get_config_var(tc, "nvmft.nqn");
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
	if (mps < mpsmin + NVME_MPS_SHIFT)
		mps = mpsmin;
	else if (mps > mpsmax + NVME_MPS_SHIFT)
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

void
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
