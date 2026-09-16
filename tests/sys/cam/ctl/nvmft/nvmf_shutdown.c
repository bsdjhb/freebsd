/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023,2026 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <inttypes.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool header_digests, data_digests;
static uint64_t cap;
static u_int mps;

enum shutdown_mode { NONE, NORMAL, ABRUPT, CLOSE, RESET };

static void
usage(void)
{
	fprintf(stderr,
"nvmf_connect [-FGg] [-D reenable delay] [-R mode] [-c cntlid] [-d delay]\n"
"             [-t transport] <mode> <address:port> <nqn>\n"
"\n"
"  Where mode is one of:\n"
"\tclose - just close the socket\n"
"\tnormal - normal shutdown\n"
"\tabrupt - abrupt shutdown\n"
"\treset - controller reset\n");
	exit(1);
}

static enum shutdown_mode
parse_mode(const char *s)
{
	if (strcasecmp(s, "normal") == 0)
		return (NORMAL);
	else if (strcasecmp(s, "abrupt") == 0)
		return (ABRUPT);
	else if (strcasecmp(s, "close") == 0)
		return (CLOSE);
	else if (strcasecmp(s, "reset") == 0)
		return (RESET);
	else
		errx(1, "Invalid mode: %s", s);
}

static void
tcp_association_params(struct nvmf_association_params *params)
{
	params->tcp.pda = 0;
	params->tcp.header_digests = header_digests;
	params->tcp.data_digests = data_digests;
	params->tcp.maxr2t = 1;
}

static int
open_socket(const char *address, const char *port)
{
	struct addrinfo hints, *ai, *list;
	int error, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(address, port, &hints, &list);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));

	for (ai = list; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			continue;

		if (connect(s, ai->ai_addr, ai->ai_addrlen) != 0) {
			close(s);
			continue;
		}

		freeaddrinfo(list);
		return (s);
	}
	err(1, "Failed to connect to controller");
}

/* Wait for shutdown to complete by polling CSTS. */
static void
wait_for_shutdown(struct nvmf_qpair *qp)
{
	uint64_t csts;
	int error, timo;

	timo = NVME_CAP_LO_TO(cap);
	for (;;) {
		error = nvmf_read_property(qp, NVMF_PROP_CSTS, 4, &csts);
		if (error != 0)
			errc(1, error, "Failed to fetch CSTS");

		switch (NVME_CSTS_GET_SHST(csts)) {
		case NVME_SHST_COMPLETE:
			return;
		case NVME_SHST_OCCURRING:
			break;
		default:
			errx(1, "Invalid shutdown status: %u",
			    (u_int)NVME_CSTS_GET_SHST(csts));
		}

		if (timo == 0)
			errx(1, "Controller failed to complete shutdown");
		timo--;
		usleep(500 * 1000);
	}
}

/* Wait for CSTS.RDY in Controller Status */
static void
wait_for_ready(struct nvmf_qpair *qp, bool ready)
{
	uint64_t csts, rdy;
	int error, timo;

	timo = NVME_CAP_LO_TO(cap);
	for (;;) {
		error = nvmf_read_property(qp, NVMF_PROP_CSTS, 4, &csts);
		if (error != 0)
			errc(1, error, "Failed to fetch CSTS");

		rdy = NVMEV(NVME_CSTS_REG_RDY, csts);
		if (ready) {
			if (rdy != 0) {
				if (NVME_CSTS_GET_SHST(csts) !=
				    NVME_SHST_NORMAL)
					errx(1,
			    "Invalid shutdown status for ready controller: %u",
					    (u_int)NVME_CSTS_GET_SHST(csts));
				break;
			}
		} else {
			if (rdy == 0)
				break;
		}

		if (timo == 0)
			errx(1, "Controller failed to %s", ready ?
			    "become ready" : "reset");
		timo--;
		usleep(500 * 1000);
	}
}

static void
validate_idle_csts(struct nvmf_qpair *qp)
{
	uint64_t csts;
	int error;

	error = nvmf_read_property(qp, NVMF_PROP_CSTS, 4, &csts);
	if (error != 0)
		errc(1, error, "Failed to fetch CSTS");

	if (NVMEV(NVME_CSTS_REG_RDY, csts) != 0)
		errx(1, "Idle controller is ready");

	if (NVMEV(NVME_CSTS_REG_CFS, csts) != 0)
		errx(1, "Idle controller has fatal error");
}

static void
enable_controller(struct nvmf_qpair *qp)
{
	uint64_t cc;
	int error;

	validate_idle_csts(qp);

	error = nvmf_read_property(qp, NVMF_PROP_CC, 4, &cc);
	if (error != 0)
		errc(1, error, "Failed to fetch CC");

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
		errc(1, error, "Failed to set CC");

	wait_for_ready(qp, true);
}

static struct nvmf_qpair *
connect_admin_queue(struct nvmf_association *na,
    const struct nvmf_qpair_params *params, const uint8_t hostid[16],
    uint16_t cntlid, const char *hostnqn, const char *subnqn)
{
	struct nvmf_qpair *qp;
	u_int mpsmin, mpsmax;
	int error;

	qp = nvmf_connect(na, params, 0, NVMF_MIN_ADMIN_MAX_SQ_SIZE, hostid,
	    cntlid, subnqn, hostnqn, 0);
	if (qp == NULL)
		return (NULL);

	error = nvmf_read_property(qp, NVMF_PROP_CAP, 8, &cap);
	if (error != 0)
		errc(1, error, "Failed to fetch CAP");

	/* Require the NVM command set. */
	if (NVME_CAP_HI_CSS_NVM(cap >> 32) == 0)
		errx(1, "Controller does not support the NVM command set");

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
	enable_controller(qp);

	return (qp);
}

static void
shutdown_controller(struct nvmf_qpair *qp, bool abrupt)
{
	uint64_t cc;
	int error;

	error = nvmf_read_property(qp, NVMF_PROP_CC, 4, &cc);
	if (error != 0)
		errc(1, error, "Failed to fetch CC");

	if (abrupt)
		cc |= NVMEF(NVME_CC_REG_SHN, NVME_SHN_ABRUPT);
	else
		cc |= NVMEF(NVME_CC_REG_SHN, NVME_SHN_NORMAL);

	error = nvmf_write_property(qp, NVMF_PROP_CC, 4, cc);
	if (error != 0)
		errc(1, error, "Failed to set CC to trigger shutdown");
}

static void
reset_controller(struct nvmf_qpair *qp)
{
	uint64_t cc;
	int error;

	error = nvmf_read_property(qp, NVMF_PROP_CC, 4, &cc);
	if (error != 0)
		errc(1, error, "Failed to fetch CC");

	cc &= ~NVMEM(NVME_CC_REG_EN);

	error = nvmf_write_property(qp, NVMF_PROP_CC, 4, cc);
	if (error != 0)
		errc(1, error, "Failed to set CC to reset controller");
}

int
main(int ac, char **av)
{
	const char *transport;
	char *address, *port;
	struct nvmf_association_params aparams;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin;
	char hostnqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	enum nvmf_trtype trtype;
	enum shutdown_mode mode, reenable_mode;
	u_int cntlid, delay, reenable_delay;
	int ch, error, s;
	bool flow_control;

	cntlid = NVMF_CNTLID_DYNAMIC;
	delay = 0;
	flow_control = false;
	mode = NONE;
	reenable_delay = 0;
	reenable_mode = NONE;
	transport = "tcp";
	while ((ch = getopt(ac, av, "D:FGR:c:d:gt:")) != -1) {
		switch (ch) {
		case 'D':
			reenable_delay = strtoumax(optarg, NULL, 0);
			break;
		case 'F':
			flow_control = true;
			break;
		case 'G':
			data_digests = true;
			break;
		case 'R':
			reenable_mode = parse_mode(optarg);
			break;
		case 'c':
			if (strcasecmp(optarg, "dynamic") == 0)
				cntlid = NVMF_CNTLID_DYNAMIC;
			else if (strcasecmp(optarg, "static") == 0)
				cntlid = NVMF_CNTLID_STATIC_ANY;
			else
				cntlid = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			delay = strtoumax(optarg, NULL, 0);
			break;
		case 'g':
			header_digests = true;
			break;
		case 't':
			transport = optarg;
			break;
		default:
			usage();
		}
	}

	av += optind;
	ac -= optind;

	if (ac != 3)
		usage();

	mode = parse_mode(av[0]);

	if (mode == CLOSE && reenable_mode != NONE)
		errx(1, "close mode doesn't support re-enabling");

	address = av[1];
	port = strrchr(address, ':');
	if (port == NULL || port[1] == '\0')
		errx(1, "Invalid address %s", address);
	*port = '\0';
	port++;

	memset(&aparams, 0, sizeof(aparams));
	aparams.sq_flow_control = flow_control;
	if (strcasecmp(transport, "tcp") == 0) {
		trtype = NVMF_TRTYPE_TCP;
		tcp_association_params(&aparams);
	} else
		errx(1, "Invalid transport %s", transport);

	error = nvmf_hostid_from_hostuuid(hostid);
	if (error != 0)
		errc(1, error, "Failed to generate hostid");
	error = nvmf_nqn_from_hostuuid(hostnqn);
	if (error != 0)
		errc(1, error, "Failed to generate host NQN");

	na = nvmf_allocate_association(trtype, false, &aparams);
	if (na == NULL)
		err(1, "Failed to create association");

	s = open_socket(address, port);
	memset(&qparams, 0, sizeof(qparams));
	qparams.admin = true;
	qparams.tcp.fd = s;

	admin = connect_admin_queue(na, &qparams, hostid, cntlid, hostnqn,
	    av[2]);
	if (admin == NULL)
		errx(1, "Failed to create admin queue: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	switch (mode) {
	case CLOSE:
		break;
	case NORMAL:
	case ABRUPT:
		shutdown_controller(admin, mode == ABRUPT);
		if (reenable_mode != NONE)
			wait_for_shutdown(admin);
		break;
	case RESET:
		reset_controller(admin);
		break;
	case NONE:
		__unreachable();
	}

	if (reenable_mode != NONE) {
		wait_for_ready(admin, false);
		if (reenable_delay != 0)
			sleep(reenable_delay);
		enable_controller(admin);
		switch (reenable_mode) {
		case CLOSE:
			break;
		case NORMAL:
		case ABRUPT:
			shutdown_controller(admin, mode == ABRUPT);
			break;
		case RESET:
			reset_controller(admin);
			break;
		case NONE:
			__unreachable();
		}
	}

	if (delay != 0)
		sleep(delay);

	nvmf_free_qpair(admin);
	close(s);
	return (0);
}
