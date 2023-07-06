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

#include "comnd.h"
#include "nvmecontrol_ext.h"

static struct options {
	const char	*transport;
	const char	*address;
	bool		verbose;
} opt = {
	.transport = "tcp",
	.address = NULL,
	.verbose = false,
};

static void
tcp_association_params(struct nvmf_association_params *params)
{
	params->tcp.pda = 0;
	params->tcp.header_digests = false;
	params->tcp.data_digests = false;
	params->tcp.maxr2t = 1;
}

static void
tcp_qpair_params(struct nvmf_qpair_params *params)
{
	struct addrinfo hints, *ai, *list;
	const char *address, *port;
	char *tofree;
	int error, s;

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

	/* 7.4.9.3 Default port for discovery */
	if (port == NULL)
		port = "8009";

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(address, port, &hints, &list);
	free(tofree);
	if (error != 0)
		errx(EX_NOHOST, "%s", gai_strerror(error));

	for (ai = list; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			continue;

		if (connect(s, ai->ai_addr, ai->ai_addrlen) != 0) {
			close(s);
			continue;
		}

		params->admin = true;
		params->tcp.fd = s;
		freeaddrinfo(list);
		return;
	}
	err(EX_NOHOST, "Failed to connect to controller");
}

static void
identify_controller(struct nvmf_qpair *qp)
{
	struct nvme_controller_data cdata;
	int error;

	error = nvmf_host_identify_controller(qp, &cdata);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to fetch controller data");
	nvme_print_controller(&cdata);
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

static const char *
nvmf_address_family(uint8_t adrfam)
{
	static char buf[8];

	switch (adrfam) {
	case NVMF_ADRFAM_IPV4:
		return ("AF_INET");
	case NVMF_ADRFAM_IPV6:
		return ("AF_INET6");
	case NVMF_ADRFAM_IB:
		return ("InfiniBand");
	case NVMF_ADRFAM_FC:
		return ("Fibre Channel");
	case NVMF_ADRFAM_INTRA_HOST:
		return ("Intra-host");
	default:
		snprintf(buf, sizeof(buf), "0x%02x\n", adrfam);
		return (buf);
	}
}

static const char *
nvmf_subsystem_type(uint8_t subtype)
{
	static char buf[8];

	switch (subtype) {
	case NVMF_SUBTYPE_DISCOVERY:
		return ("Discovery");
	case NVMF_SUBTYPE_NVME:
		return ("NVMe");
	default:
		snprintf(buf, sizeof(buf), "0x%02x\n", subtype);
		return (buf);
	}
}

static const char *
nvmf_secure_channel(uint8_t treq)
{
	switch (treq & 0x03) {
	case NVMF_TREQ_SECURE_CHANNEL_NOT_SPECIFIED:
		return ("Not specified");
	case NVMF_TREQ_SECURE_CHANNEL_REQUIRED:
		return ("Required");
	case NVMF_TREQ_SECURE_CHANNEL_NOT_REQUIRED:
		return ("Not required");
	default:
		return ("0x03");
	}
}

static const char *
nvmf_controller_id(uint16_t cntlid)
{
	static char buf[8];

	switch (cntlid) {
	case NVMF_CNTLID_DYNAMIC:
		return ("Dynamic");
	case NVMF_CNTLID_STATIC_ANY:
		return ("Static");
	default:
		snprintf(buf, sizeof(buf), "%u", cntlid);
		return (buf);
	}
}

static const char *
nvmf_rdma_service_type(uint8_t qptype)
{
	static char buf[8];

	switch (qptype) {
	case NVMF_RDMA_QPTYPE_RELIABLE_CONNECTED:
		return ("Reliable connected");
	case NVMF_RDMA_QPTYPE_RELIABLE_DATAGRAM:
		return ("Reliable datagram");
	default:
		snprintf(buf, sizeof(buf), "0x%02x\n", qptype);
		return (buf);
	}
}

static const char *
nvmf_rdma_provider_type(uint8_t prtype)
{
	static char buf[8];

	switch (prtype) {
	case NVMF_RDMA_PRTYPE_NONE:
		return ("None");
	case NVMF_RDMA_PRTYPE_IB:
		return ("InfiniBand");
	case NVMF_RDMA_PRTYPE_ROCE:
		return ("RoCE (v1)");
	case NVMF_RDMA_PRTYPE_ROCE2:
		return ("RoCE (v2)");
	case NVMF_RDMA_PRTYPE_IWARP:
		return ("iWARP");
	default:
		snprintf(buf, sizeof(buf), "0x%02x\n", prtype);
		return (buf);
	}
}

static const char *
nvmf_rdma_cms(uint8_t cms)
{
	static char buf[8];

	switch (cms) {
	case NVMF_RDMA_CMS_RDMA_CM:
		return ("RDMA_IP_CM");
	default:
		snprintf(buf, sizeof(buf), "0x%02x\n", cms);
		return (buf);
	}
}

static const char *
nvmf_tcp_security_type(uint8_t sectype)
{
	static char buf[8];

	switch (sectype) {
	case NVME_TCP_SECURITY_NONE:
		return ("None");
	case NVME_TCP_SECURITY_TLS:
		return ("TLS");
	default:
		snprintf(buf, sizeof(buf), "0x%02x\n", sectype);
		return (buf);
	}
}

static void
print_discovery_entry(u_int i, struct nvme_discovery_log_entry *entry)
{
	printf("Entry %02d\n", i + 1);
	printf("========\n");
	printf(" Transport type:       %s\n",
	    nvmf_transport_type(entry->trtype));
	printf(" Address family:       %s\n",
	    nvmf_address_family(entry->adrfam));
	printf(" Subsystem type:       %s\n",
	    nvmf_subsystem_type(entry->subtype));
	printf(" SQ flow control:      %s\n",
	    (entry->treq & (1 << 2)) == 0 ? "required" : "optional");
	printf(" Secure Channel:       %s\n", nvmf_secure_channel(entry->treq));
	printf(" Port ID:              %u\n", entry->portid);
	printf(" Controller ID:        %s\n",
	    nvmf_controller_id(entry->cntlid));
	printf(" Max Admin SQ Size:    %u\n", entry->aqsz);
	printf(" Sub NQN:              %s\n", entry->subnqn);
	printf(" Transport address:    %s\n", entry->traddr);
	printf(" Service identifier:   %s\n", entry->trsvcid);
	switch (entry->trtype) {
	case NVMF_TRTYPE_RDMA:
		printf(" RDMA Service Type:    %s\n",
		    nvmf_rdma_service_type(entry->tsas.rdma.rdma_qptype));
		printf(" RDMA Provider Type:   %s\n",
		    nvmf_rdma_provider_type(entry->tsas.rdma.rdma_prtype));
		printf(" RDMA CMS:             %s\n",
		    nvmf_rdma_cms(entry->tsas.rdma.rdma_cms));
		printf(" Partition key:        %u\n",
		    entry->tsas.rdma.rdma_pkey);
		break;
	case NVMF_TRTYPE_TCP:
		printf(" Security Type:        %s\n",
		    nvmf_tcp_security_type(entry->tsas.tcp.sectype));
		break;
	}
}

static void
dump_discovery_log_page(struct nvmf_qpair *qp)
{
	struct nvme_discovery_log *log;
	int error;

	error = nvmf_host_fetch_discovery_log_page(qp, &log);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to fetch discovery log page");

	printf("Discovery\n");
	printf("=========\n");
	if (log->numrec == 0) {
		printf("No entries found\n");
	} else {
		for (u_int i = 0; i < log->numrec; i++)
			print_discovery_entry(i, &log->entries[i]);
	}
	free(log);
}

static void
discover(const struct cmd *f, int argc, char *argv[])
{
	enum nvmf_trtype trtype;
	struct nvmf_association_params aparams;
	struct nvmf_qpair_params qparams;
	struct nvmf_association *na;
	struct nvmf_qpair *qp;
	char nqn[NVMF_NQN_MAX_LEN];
	uint8_t hostid[16];
	uint64_t cap, cc, csts;
	int error, timo;

	if (arg_parse(argc, argv, f))
		return;

	memset(&aparams, 0, sizeof(aparams));
	aparams.sq_flow_control = true;
	if (strcasecmp(opt.transport, "tcp") == 0) {
		trtype = NVMF_TRTYPE_TCP;
		tcp_association_params(&aparams);
		tcp_qpair_params(&qparams);
	} else
		errx(EX_USAGE, "Unsupported or invalid transport");

	error = nvmf_hostid_from_hostuuid(hostid);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to generate hostid");
	error = nvmf_nqn_from_hostuuid(nqn);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to generate host NQN");

	na = nvmf_allocate_association(trtype, false, &aparams);
	if (na == NULL)
		err(EX_IOERR, "Failed to allocate connection");
	qp = nvmf_connect(na, &qparams, 0, NVME_MIN_ADMIN_ENTRIES, hostid,
	    NVMF_CNTLID_DYNAMIC, NVMF_DISCOVERY_NQN, nqn, 0);
	if (qp == NULL)
		errx(EX_IOERR, "Failed to connect to controller: %s",
		    nvmf_association_error(na));
	nvmf_free_association(na);

	/* Fetch Controller Capabilities Property */
	error = nvmf_read_property(qp, NVMF_PROP_CAP, 8, &cap);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to fetch CAP");

	/* Set Controller Configuration Property (CC.EN=1) */
	error = nvmf_read_property(qp, NVMF_PROP_CC, 4, &cc);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to fetch CC");

	/* Clear known fields preserving any reserved fields. */
	cc &= ~(NVMEB(NVME_CC_REG_SHN) | NVMEB(NVME_CC_REG_AMS) |
	    NVMEB(NVME_CC_REG_MPS) | NVMEB(NVME_CC_REG_CSS));

	/* Leave AMS, MPS, and CSS as 0. */

	cc |= (1 << NVME_CC_REG_EN_SHIFT);

	error = nvmf_write_property(qp, NVMF_PROP_CC, 4, cc);
	if (error != 0)
		errc(EX_IOERR, error, "Failed to set CC");

	/* Wait for CSTS.RDY in Controller Status */
	timo = NVME_CAP_LO_TO(cap);
	for (;;) {
		error = nvmf_read_property(qp, NVMF_PROP_CSTS, 4, &csts);
		if (error != 0)
			errc(EX_IOERR, error, "Failed to fetch CSTS");

		if (NVMEV(NVME_CSTS_REG_RDY, csts) != 0)
			break;

		if (timo == 0)
			errx(EX_IOERR, "Controller failed to become ready");
		timo--;
		usleep(500 * 1000);
	}

	/* Use Identify to fetch controller data */
	if (opt.verbose) {
		identify_controller(qp);
		printf("\n");
	}

	/* Fetch Log pages */
	dump_discovery_log_page(qp);

	nvmf_free_qpair(qp);
}

static const struct opts discover_opts[] = {
#define OPT(l, s, t, opt, addr, desc) { l, s, t, &opt.addr, desc }
	OPT("transport", 't', arg_string, opt, transport,
	    "Transport type"),
	OPT("verbose", 'v', arg_none, opt, verbose,
	    "Display the discovery controller's controller data"),
	{ NULL, 0, arg_none, NULL, NULL }
};
#undef OPT

static const struct args discover_args[] = {
	{ arg_string, &opt.address, "address" },
	{ arg_none, NULL, NULL },
};

static struct cmd discover_cmd = {
	.name = "discover",
	.fn = discover,
	.descr = "List discovery log pages from a fabrics controller",
	.ctx_size = sizeof(opt),
	.opts = discover_opts,
	.args = discover_args,
};

CMD_COMMAND(discover_cmd);
