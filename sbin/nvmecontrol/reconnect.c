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

#include "nvmecontrol.h"
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
	const char	*dev;
	const char	*transport;
	const char	*address;
	bool		data_digests;
	bool		flow_control;
	bool		header_digests;
} opt = {
	.dev = NULL,
	.transport = "tcp",
	.address = NULL,
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
reconnect_nvm_controller(int fd, enum nvmf_trtype trtype, int adrfam,
    const char *address, const char *port)
{
	struct nvme_controller_data cdata;
	struct nvmf_association_params aparams;
	struct nvmf_reconnect_params rparams;
	struct nvmf_qpair *admin, *io[1];
	int error;

	error = nvmf_reconnect_params(fd, &rparams);
	if (error != 0) {
		warnc(error, "Failed to fetch reconnect parameters");
		return (EX_IOERR);
	}

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
	    rparams.cntlid, rparams.subnqn, &admin, io, nitems(io), &cdata);
	if (error != 0)
		return (error);

	error = nvmf_reconnect_host(fd, admin, 1, io, &cdata);
	if (error != 0) {
		warnc(error, "Failed to handoff queues to kernel");
		return (EX_IOERR);
	}
	return (0);
}

static void
reconnect_static(int fd, enum nvmf_trtype trtype, const char *address,
    const char *port)
{
	int error;

	if (port == NULL)
		errx(EX_USAGE, "Explicit port required");

	error = reconnect_nvm_controller(fd, trtype, AF_UNSPEC, address, port);
	if (error != 0)
		exit(error);
}

static void
reconnect_fn(const struct cmd *f, int argc, char *argv[])
{
	enum nvmf_trtype trtype;
	const char *address, *port;
	char *tofree;
	int fd;

	if (arg_parse(argc, argv, f))
		return;

	if (strcasecmp(opt.transport, "tcp") == 0) {
		trtype = NVMF_TRTYPE_TCP;
	} else
		errx(EX_USAGE, "Unsupported or invalid transport");

	nvmf_parse_address(opt.address, &address, &port, &tofree);

	open_dev(opt.dev, &fd, 1, 1);
	reconnect_static(fd, trtype, address, port);

	close(fd);
	free(tofree);
}

static const struct opts reconnect_opts[] = {
#define OPT(l, s, t, opt, addr, desc) { l, s, t, &opt.addr, desc }
	OPT("transport", 't', arg_string, opt, transport,
	    "Transport type"),
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
