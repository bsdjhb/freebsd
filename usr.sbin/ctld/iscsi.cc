/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2003, 2004 Silicon Graphics International Corp.
 * Copyright (c) 1997-2007 Kenneth D. Merry
 * Copyright (c) 2012 The FreeBSD Foundation
 * Copyright (c) 2017 Jakub Wojciech Klama <jceel@FreeBSD.org>
 * All rights reserved.
 * Copyright (c) 2025 Chelsio Communications, Inc.
 *
 * Portions of this software were developed by Edward Tomasz Napierala
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/time.h>
#include <assert.h>
#include <libiscsiutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_ioctl.h>

#include "ctld.h"
#include "iscsi.hh"

#define	SOCKBUF_SIZE			1048576

struct iscsi_portal final : public portal {
	iscsi_portal(struct portal_group *pg, const char *listen, bool iser,
	    struct addrinfo *ai) : portal(pg, listen, iser, ai)
	{}

	bool init_socket_options(int s) override;
	void handle_connection(int fd, const char *host,
	    const struct sockaddr *client_sa) override;
};

#ifdef ICL_KERNEL_PROXY
static void	pdu_receive_proxy(struct pdu *pdu);
static void	pdu_send_proxy(struct pdu *pdu);
#endif /* ICL_KERNEL_PROXY */
static void	pdu_fail(const struct connection *conn, const char *reason);

static uint16_t scsi_last_portal_group_tag = 0xff;

static struct connection_ops conn_ops = {
	.timed_out = timed_out,
#ifdef ICL_KERNEL_PROXY
	.pdu_receive_proxy = pdu_receive_proxy,
	.pdu_send_proxy = pdu_send_proxy,
#else
	.pdu_receive_proxy = nullptr,
	.pdu_send_proxy = nullptr,
#endif
	.fail = pdu_fail,
};

uint16_t
iscsi_new_portal_group_tag()
{
	return (++scsi_last_portal_group_tag);
}

bool
iscsi_portal::init_socket_options(int s)
{
	int sockbuf;

	sockbuf = SOCKBUF_SIZE;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sockbuf,
	    sizeof(sockbuf)) == -1) {
		log_warn("setsockopt(SO_RCVBUF) failed for %s", listen());
		return (false);
	}
	sockbuf = SOCKBUF_SIZE;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sockbuf,
	    sizeof(sockbuf)) == -1) {
		log_warn("setsockopt(SO_SNDBUF) failed for %s", listen());
		return (false);
	}
	return (true);
}

portal_up
iscsi_make_portal(struct portal_group *pg, const char *listen, bool iser,
    struct addrinfo *ai)
{
    return (std::make_unique<iscsi_portal>(pg, listen, iser, ai));
}

void
iscsi_load_kernel_module()
{
	static bool loaded;
	int saved_errno;

	if (loaded)
		return;

	saved_errno = errno;
	if (modfind("cfiscsi") == -1 && kldload("cfiscsi") == -1)
		log_warn("couldn't load cfiscsi");
	errno = saved_errno;
	loaded = true;
}

#ifdef ICL_KERNEL_PROXY

static void
pdu_receive_proxy(struct pdu *pdu)
{
	struct connection *conn;
	size_t len;

	assert(proxy_mode);
	conn = pdu->pdu_connection;

	kernel_receive(pdu);

	len = pdu_ahs_length(pdu);
	if (len > 0)
		log_errx(1, "protocol error: non-empty AHS");

	len = pdu_data_segment_length(pdu);
	assert(len <= (size_t)conn->conn_max_recv_data_segment_length);
	pdu->pdu_data_len = len;
}

static void
pdu_send_proxy(struct pdu *pdu)
{

	assert(proxy_mode);

	pdu_set_data_segment_length(pdu, pdu->pdu_data_len);
	kernel_send(pdu);
}

#endif /* ICL_KERNEL_PROXY */

static void
pdu_fail(const struct connection *conn __unused, const char *reason __unused)
{
}

iscsi_connection::iscsi_connection(struct portal *portal, int fd,
    const char *host, const struct sockaddr *client_sa)
	: conn_portal(portal), conn_initiator_addr(host)
{
	connection_init(&conn, &conn_ops, proxy_mode);
	conn.conn_socket = fd;
	memcpy(&conn_initiator_sa, client_sa, client_sa->sa_len);
}

iscsi_connection::~iscsi_connection()
{
	chap_delete(conn_chap);
}

void
iscsi_connection::kernel_handoff()
{
	struct portal_group *pg = conn_portal->portal_group();
	struct ctl_iscsi req;

	bzero(&req, sizeof(req));

	req.type = CTL_ISCSI_HANDOFF;
	strlcpy(req.data.handoff.initiator_name, conn_initiator_name.c_str(),
	    sizeof(req.data.handoff.initiator_name));
	strlcpy(req.data.handoff.initiator_addr, conn_initiator_addr.c_str(),
	    sizeof(req.data.handoff.initiator_addr));
	if (!conn_initiator_alias.empty()) {
		strlcpy(req.data.handoff.initiator_alias,
		    conn_initiator_alias.c_str(),
		    sizeof(req.data.handoff.initiator_alias));
	}
	memcpy(req.data.handoff.initiator_isid, conn_initiator_isid,
	    sizeof(req.data.handoff.initiator_isid));
	strlcpy(req.data.handoff.target_name, conn_target->name(),
	    sizeof(req.data.handoff.target_name));
	strlcpy(req.data.handoff.offload, pg->offload(),
	    sizeof(req.data.handoff.offload));
#ifdef ICL_KERNEL_PROXY
	if (proxy_mode)
		req.data.handoff.connection_id = conn.conn_socket;
	else
		req.data.handoff.socket = conn.conn_socket;
#else
	req.data.handoff.socket = conn.conn_socket;
#endif
	req.data.handoff.portal_group_tag = pg->tag();
	if (conn.conn_header_digest == CONN_DIGEST_CRC32C)
		req.data.handoff.header_digest = CTL_ISCSI_DIGEST_CRC32C;
	if (conn.conn_data_digest == CONN_DIGEST_CRC32C)
		req.data.handoff.data_digest = CTL_ISCSI_DIGEST_CRC32C;
	req.data.handoff.cmdsn = conn.conn_cmdsn;
	req.data.handoff.statsn = conn.conn_statsn;
	req.data.handoff.max_recv_data_segment_length =
	    conn.conn_max_recv_data_segment_length;
	req.data.handoff.max_send_data_segment_length =
	    conn.conn_max_send_data_segment_length;
	req.data.handoff.max_burst_length = conn.conn_max_burst_length;
	req.data.handoff.first_burst_length = conn.conn_first_burst_length;
	req.data.handoff.immediate_data = conn.conn_immediate_data;

	if (ioctl(ctl_fd, CTL_ISCSI, &req) == -1) {
		log_err(1, "error issuing CTL_ISCSI ioctl; "
		    "dropping connection");
	}

	if (req.status != CTL_ISCSI_OK) {
		log_errx(1, "error returned from CTL iSCSI handoff request: "
		    "%s; dropping connection", req.error_str);
	}
}

void
iscsi_connection::handle()
{
	login();
	if (conn_session_type == CONN_SESSION_TYPE_NORMAL) {
		kernel_handoff();
		log_debugx("connection handed off to the kernel");
	} else {
		assert(conn_session_type == CONN_SESSION_TYPE_DISCOVERY);
		discovery();
	}
}

void
iscsi_portal::handle_connection(int fd, const char *host,
    const struct sockaddr *client_sa)
{
	struct conf *conf = portal_group()->conf();

	iscsi_connection conn(this, fd, host, client_sa);
	start_timer(conf->timeout(), true);
	kernel_capsicate();
	conn.handle();
}
