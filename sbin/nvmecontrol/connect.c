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
#include <err.h>
#include <libnvmf.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "comnd.h"
#include "fabrics.h"

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
	const char	*transport;
	const char	*address;
	const char	*cntlid;
	bool		discover;
	bool		data_digests;
	bool		flow_control;
	bool		header_digests;
} opt = {
	.transport = "tcp",
	.address = NULL,
	.cntlid = "dynamic",
	.discover = false,
	.data_digests = false,
	.flow_control = false,
	.header_digests = false,
};

static void
tcp_association_params(struct nvmf_association_params *params)
{
	params->tcp.pda = 0;
	params->tcp.header_digests = opt.header_digests;
	params->tcp.data_digests = opt.data_digests;
	/* XXX */
	params->tcp.maxr2t = 1;
}

static int
connect_nvm_controller(enum nvmf_trtype trtype, int adrfam, const char *address,
    const char *port, uint16_t cntlid, const char *subnqn)
{
	struct nvme_controller_data cdata;
	struct nvmf_association_params aparams;
	struct nvmf_qpair *admin, *io[1];
	int error;

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

	error = connect_nvm_queues(&aparams, trtype, adrfam, address, port,
	    cntlid, subnqn, &admin, io, nitems(io), &cdata);
	if (error != 0)
		return (error);

	error = nvmf_handoff_host(admin, 1, io, &cdata);
	if (error != 0) {
		warnc(error, "Failed to handoff queues to kernel");
		return (EX_IOERR);
	}
	return (0);
}

static void
connect_discovery_entry(struct nvme_discovery_log_entry *entry)
{
	int adrfam;

	switch (entry->trtype) {
	case NVMF_TRTYPE_TCP:
		switch (entry->adrfam) {
		case NVMF_ADRFAM_IPV4:
			adrfam = AF_INET;
			break;
		case NVMF_ADRFAM_IPV6:
			adrfam = AF_INET6;
			break;
		default:
			warnx("Skipping unsupported address family for %s",
			    entry->subnqn);
			return;
		}
		switch (entry->tsas.tcp.sectype) {
		case NVME_TCP_SECURITY_NONE:
			break;
		default:
			warnx("Skipping unsupported TCP security type for %s",
			    entry->subnqn);
			return;
		}
		break;
	default:
		warnx("Skipping unsupported transport %s for %s",
		    nvmf_transport_type(entry->trtype), entry->subnqn);
		return;
	}

	/*
	 * XXX: Track portids and avoid duplicate connections for a
	 * given (subnqn,portid)?
	 */

	/* XXX: entry->aqsz? */
	connect_nvm_controller(entry->trtype, adrfam, entry->traddr,
	    entry->trsvcid, entry->cntlid, entry->subnqn);
}

static void
connect_discovery_log_page(struct nvmf_qpair *qp)
{
	struct nvme_discovery_log *log;
	int error;

	error = nvmf_host_fetch_discovery_log_page(qp, &log);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to fetch discovery log page");

	for (u_int i = 0; i < log->numrec; i++)
		connect_discovery_entry(&log->entries[i]);
	free(log);
}

static void
discover_controllers(enum nvmf_trtype trtype, const char *address,
    const char *port)
{
	struct nvmf_qpair *qp;

	qp = connect_discovery_adminq(trtype, address, port);

	connect_discovery_log_page(qp);

	nvmf_free_qpair(qp);
}

static void
connect_static(enum nvmf_trtype trtype, const char *address, const char *port,
    const char *subnqn)
{
	u_long cntlid;
	int error;

	if (port == NULL)
		errx(EX_USAGE, "Explicit port required");

	cntlid = nvmf_parse_cntlid(opt.cntlid);

	error = connect_nvm_controller(trtype, AF_UNSPEC, address, port, cntlid,
	    subnqn);
	if (error != 0)
		exit(error);
}

static void
connect_fn(const struct cmd *f, int argc, char *argv[])
{
	enum nvmf_trtype trtype;
	const char *address, *port, *subnqn;
	char *tofree;

	if (arg_parse(argc, argv, f))
		return;

	if (strcasecmp(opt.transport, "tcp") == 0) {
		trtype = NVMF_TRTYPE_TCP;
	} else
		errx(EX_USAGE, "Unsupported or invalid transport");

	nvmf_parse_address(opt.address, &address, &port, &tofree);
	if (opt.discover)
		discover_controllers(trtype, address, port);
	else {
		/*
		 * XXX: Using argv[optind] directly isn't super clean,
		 * but struct cmd doesn't support optional argments.
		 */
		subnqn = argv[optind];
		if (subnqn == NULL)
			errx(EX_USAGE,
			    "Static connections require explicit NQN");
		optind++;
		connect_static(trtype, address, port, subnqn);
	}

	free(tofree);
}

static const struct opts connect_opts[] = {
#define OPT(l, s, t, opt, addr, desc) { l, s, t, &opt.addr, desc }
	OPT("transport", 't', arg_string, opt, transport,
	    "Transport type"),
	OPT("cntlid", 'c', arg_string, opt, cntlid,
	    "Controller ID"),
	OPT("discover", 'd', arg_none, opt, discover,
	    "Connect to all controllers enumerated via discovery"),
	OPT("header_digests", 'H', arg_none, opt, header_digests,
	    "Enable TCP PDU header digests"),
	OPT("data_digests", 'D', arg_none, opt, data_digests,
	    "Enable TCP PDU data digests"),
	OPT("flow_control", 'F', arg_none, opt, flow_control,
	    "Request SQ flow control"),
	{ NULL, 0, arg_none, NULL, NULL }
};
#undef OPT

static const struct args connect_args[] = {
	{ arg_string, &opt.address, "address" },
	{ arg_none, NULL, NULL },
};

static struct cmd connect_cmd = {
	.name = "connect",
	.fn = connect_fn,
	.descr = "Connect to a fabrics controller",
	.ctx_size = sizeof(opt),
	.opts = connect_opts,
	.args = connect_args,
};

CMD_COMMAND(connect_cmd);
