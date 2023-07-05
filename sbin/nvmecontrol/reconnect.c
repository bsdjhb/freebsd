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

#include <sys/socket.h>
#include <netinet/in.h>
#include <err.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "nvmecontrol.h"

/*
 * TODO:
 * - ADMIN queue entries
 * - Number of I/O queues
 * - I/O queue entries
 * - Include MPS in handoff?
 * - MaxR2T
 * - KATO
 */

static struct options {
	const char	*dev;
	const char	*transport;
	const char	*address;
	const char	*subnqn;
	const char	*cntlid;
	bool		data_digests;
	bool		flow_control;
	bool		header_digests;
} opt = {
	.dev = NULL,
	.transport = "tcp",
	.address = NULL,
	.subnqn = NULL,
	.cntlid = "dynamic",
	.data_digests = false,
	.flow_control = false,
	.header_digests = false,
};

static char nqn[NVMF_NQN_MAX_LEN];
static uint8_t hostid[16];

static void
tcp_association_params(struct nvmf_association_params *params)
{
	params->tcp.pda = 0;
	params->tcp.header_digests = opt.header_digests;
	params->tcp.data_digests = opt.data_digests;
	/* XXX */
	params->tcp.maxr2t = 1;
}

static bool
tcp_qpair_params(struct nvmf_qpair_params *params, bool admin, int adrfam,
    const char *address, const char *port)
{
	struct addrinfo hints, *ai, *list;
	int error, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = adrfam;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(address, port, &hints, &list);
	if (error != 0) {
		warnx("%s", gai_strerror(error));
		return (false);
	}

	for (ai = list; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			continue;

		if (connect(s, ai->ai_addr, ai->ai_addrlen) != 0) {
			close(s);
			continue;
		}

		params->admin = admin;
		params->tcp.fd = s;
		freeaddrinfo(list);
		return (true);
	}
	warn("Failed to connect to controller at %s:%s", address, port);
	return (false);
}

static const char *
nvmf_transport_type(uint8_t trtype)
{
	static char buf[8];

	switch (trtype) {
	case NVMF_TRTYPE_RDMA:
		return ("RDMA");
	case NVMF_TRTYPE_FC:
		return ("Fibre Channel");
	case NVMF_TRTYPE_TCP:
		return ("TCP");
	case NVMF_TRTYPE_INTRA_HOST:
		return ("Intra-host");
	default:
		snprintf(buf, sizeof(buf), "0x%02x\n", trtype);
		return (buf);
	}
}

static int
connect_nvm_adminq(struct nvmf_association *na,
    const struct nvmf_qpair_params *params, struct nvmf_qpair **qpp,
    uint16_t cntlid, const char *subnqn, uint16_t *mqes)
{
	struct nvmf_qpair *qp;
	uint64_t cap, cc, csts;
	u_int mps, mpsmin, mpsmax;
	int error, timo;

	qp = nvmf_connect(na, params, 0, 32 /* XXX */, hostid, cntlid, subnqn,
	    nqn, NVMF_KATO_DEFAULT);
	if (qp == NULL) {
		warnx("Failed to connect to NVM controller %s: %s", subnqn,
		    nvmf_association_error(na));
		return (EX_IOERR);
	}

	/* Fetch Controller Capabilities Property */
	error = nvmf_read_property(qp, NVMF_PROP_CAP, 8, &cap);
	if (error != 0) {
		warnc(error, "Failed to fetch CAP");
		nvmf_free_qpair(qp);
		return (EX_IOERR);
	}

	/* Require the NVM command set. */
	if (NVME_CAP_HI_CSS_NVM(cap >> 32) == 0) {
		warnx("Controller %s does not support the NVM command set",
		    subnqn);
		nvmf_free_qpair(qp);
		return (EX_UNAVAILABLE);
	}

	*mqes = NVME_CAP_LO_MQES(cap);

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
	if (error != 0) {
		warnc(error, "Failed to fetch CC");
		nvmf_free_qpair(qp);
		return (EX_IOERR);
	}

	/* Clear known fields preserving any reserved fields. */
	cc &= ~(NVMEB(NVME_CC_REG_IOCQES) | NVMEB(NVME_CC_REG_IOSQES) |
	    NVMEB(NVME_CC_REG_SHN) | NVMEB(NVME_CC_REG_AMS) |
	    NVMEB(NVME_CC_REG_MPS) | NVMEB(NVME_CC_REG_CSS));

	cc |= 4 << NVME_CC_REG_IOCQES_SHIFT;	/* CQE entry size == 16 */
	cc |= 6 << NVME_CC_REG_IOSQES_SHIFT;	/* SEQ entry size == 64 */
	cc |= 0 << NVME_CC_REG_AMS_SHIFT;	/* AMS 0 (Round-robin) */
	cc |= mps << NVME_CC_REG_MPS_SHIFT;
	cc |= 0 << NVME_CC_REG_CSS_SHIFT;	/* NVM command set */
	cc |= (1 << NVME_CC_REG_EN_SHIFT);	/* EN = 1 */

	error = nvmf_write_property(qp, NVMF_PROP_CC, 4, cc);
	if (error != 0) {
		warnc(error, "Failed to set CC");
		nvmf_free_qpair(qp);
		return (EX_IOERR);
	}

	/* Wait for CSTS.RDY in Controller Status */
	timo = NVME_CAP_LO_TO(cap);
	for (;;) {
		error = nvmf_read_property(qp, NVMF_PROP_CSTS, 4, &csts);
		if (error != 0) {
			warnc(error, "Failed to fetch CSTS");
			nvmf_free_qpair(qp);
			return (EX_IOERR);
		}

		if (NVMEV(NVME_CSTS_REG_RDY, csts) != 0)
			break;

		if (timo == 0) {
			warnx("Controller failed to become ready");
			nvmf_free_qpair(qp);
			return (EX_IOERR);
		}
		timo--;
		usleep(500 * 1000);
	}

	*qpp = qp;
	return (0);
}

static bool
shutdown_controller(struct nvmf_qpair *qp)
{
	uint64_t cc;
	int error;

	error = nvmf_read_property(qp, NVMF_PROP_CC, 4, &cc);
	if (error != 0) {
		warnc(error, "Failed to fetch CC");
		nvmf_free_qpair(qp);
		return (false);
	}

	cc |= NVME_SHN_NORMAL << NVME_CC_REG_SHN_SHIFT;

	error = nvmf_write_property(qp, NVMF_PROP_CC, 4, cc);
	if (error != 0) {
		warnc(error, "Failed to set CC to trigger shutdown");
		nvmf_free_qpair(qp);
		return (false);
	}

	nvmf_free_qpair(qp);
	return (true);
}

static int
reconnect_nvm_controller(int fd, enum nvmf_trtype trtype, int adrfam,
    const char *address, const char *port, uint16_t cntlid, const char *subnqn)
{
	struct nvme_controller_data cdata;
	struct nvmf_association_params aparams;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *admin, *io[1];
	u_int queues;
	int error;
	uint16_t mqes;

	memset(&aparams, 0, sizeof(aparams));
	aparams.sq_flow_control = opt.flow_control;
	switch (trtype) {
	case NVMF_TRTYPE_TCP:
		tcp_association_params(&aparams);
		break;
	default:
		warnx("Unsupported transport %s", nvmf_transport_type(trtype));
		return (EX_UNAVAILABLE);
	}

	/* Association. */
	na = nvmf_allocate_association(trtype, false, &aparams);
	if (na == NULL) {
		warn("Failed to create association for %s", subnqn);
		return (EX_IOERR);
	}

	/* Admin queue. */
	if (!tcp_qpair_params(&qparams, true, adrfam, address, port)) {
		nvmf_free_association(na);
		return (EX_IOERR);
	}
	error = connect_nvm_adminq(na, &qparams, &admin, cntlid, subnqn, &mqes);
	if (error != 0) {
		nvmf_free_association(na);
		return (error);
	}

	/* Fetch controller data. */
	error = nvmf_host_identify_controller(admin, &cdata);
	if (error != 0) {
		shutdown_controller(admin);
		nvmf_free_association(na);
		warnc(error, "Failed to fetch controller data for %s", subnqn);
		return (EX_IOERR);
	}

	nvmf_update_assocation(na, &cdata);

	error = nvmf_host_request_queues(admin, 1, &queues);
	if (error != 0) {
		shutdown_controller(admin);
		nvmf_free_association(na);
		warnc(error, "Failed to request I/O queues");
		return (EX_IOERR);
	}

	/* I/O queue. */
	if (!tcp_qpair_params(&qparams, false, adrfam, address, port)) {
		nvmf_free_association(na);
		return (EX_IOERR);
	}
	io[0] = nvmf_connect(na, &qparams, 1, mqes + 1, hostid,
	    nvmf_cntlid(admin), subnqn, nqn, 0);
	if (io[0] == NULL) {
		warnx("Failed to create I/O queue: %s",
		    nvmf_association_error(na));
		shutdown_controller(admin);
		nvmf_free_association(na);
		return (EX_IOERR);
	}
	nvmf_free_association(na);

	error = nvmf_reconnect_host(fd, admin, 1, io, &cdata);
	if (error != 0)
		warnc(error, "Failed to handoff queues to kernel");
	return (error);
}

static void
reconnect_static(int fd, enum nvmf_trtype trtype, const char *address,
    const char *port, const char *subnqn)
{
	u_long cntlid;
	int error;

	if (port == NULL)
		errx(EX_USAGE, "Explicit port required");

	if (strcasecmp(opt.cntlid, "dynamic") == 0)
		cntlid = NVMF_CNTLID_DYNAMIC;
	else if (strcasecmp(opt.cntlid, "static") == 0)
		cntlid = NVMF_CNTLID_STATIC_ANY;
	else {
		cntlid = strtoul(opt.cntlid, NULL, 0);
		/* XXX: Right value? */
		if (cntlid > 0xfff0)
			errx(EX_USAGE, "Invalid controller ID");
	}

	error = reconnect_nvm_controller(fd, trtype, AF_UNSPEC, address, port,
	    cntlid, subnqn);
	if (error != 0)
		exit(error);
}

static void
reconnect_fn(const struct cmd *f, int argc, char *argv[])
{
	enum nvmf_trtype trtype;
	const char *address, *port;
	char *tofree;
	int error, fd;

	if (arg_parse(argc, argv, f))
		return;

	if (strcasecmp(opt.transport, "tcp") == 0) {
		trtype = NVMF_TRTYPE_TCP;
	} else
		errx(EX_USAGE, "Unsupported or invalid transport");

	error = nvmf_hostid_from_hostuuid(hostid);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to generate hostid");
	error = nvmf_nqn_from_hostuuid(nqn);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to generate host NQN");

	tofree = NULL;
	address = opt.address;
	port = strrchr(address, ':');
	if (port != NULL) {
		if (port == address || port[1] == '\0')
			errx(EX_USAGE, "Invalid address");
		tofree = strndup(address, port - address);
		address = tofree;
		port++;		/* Skip over ':'. */
	}

	open_dev(opt.dev, &fd, 1, 1);
	reconnect_static(fd, trtype, address, port, opt.subnqn);

	close(fd);
	free(tofree);
}

static const struct opts reconnect_opts[] = {
#define OPT(l, s, t, opt, addr, desc) { l, s, t, &opt.addr, desc }
	OPT("transport", 't', arg_string, opt, transport,
	    "Transport type"),
	OPT("cntlid", 'c', arg_string, opt, cntlid,
	    "Controller ID"),
	OPT("header_digests", 'H', arg_none, opt, header_digests,
	    "Enable TCP PDU header digests"),
	OPT("data_digests", 'D', arg_none, opt, data_digests,
	    "Enable TCP PDU data digests"),
	OPT("flow_control", 'F', arg_none, opt, flow_control,
	    "Request SQ flow control"),
	{ NULL, 0, arg_none, NULL, NULL }
};
#undef OPT

static const struct args reconnect_args[] = {
	{ arg_string, &opt.dev, "controller-id" },
	{ arg_string, &opt.address, "address" },
	{ arg_string, &opt.subnqn, "subnqn" },
	{ arg_none, NULL, NULL },
};

static struct cmd reconnect_cmd = {
	.name = "reconnect",
	.fn = reconnect_fn,
	.descr = "Reconnect to a fabrics controller",
	.ctx_size = sizeof(opt),
	.opts = reconnect_opts,
	.args = reconnect_args,
};

CMD_COMMAND(reconnect_cmd);
