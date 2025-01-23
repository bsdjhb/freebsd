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
#include <ctype.h>
#include <errno.h>
#include <libiscsiutil.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_ioctl.h>

#include "ctld.h"

#define	SOCKBUF_SIZE			1048576

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
#endif
	.fail = pdu_fail,
};

static void
iscsi_portal_group_init(struct portal_group *pg)
{
	pg->pg_tag = ++scsi_last_portal_group_tag;
}

static void
iscsi_portal_group_copy(struct portal_group *oldpg, struct portal_group *newpg)
{
	newpg->pg_tag = oldpg->pg_tag;
}

static void
iscsi_portal_init(struct portal *p __unused)
{
}

static void
iscsi_portal_init_socket(struct portal *p)
{
	int sockbuf;

	sockbuf = SOCKBUF_SIZE;
	if (setsockopt(p->p_socket, SOL_SOCKET, SO_RCVBUF, &sockbuf,
	    sizeof(sockbuf)) == -1)
		log_warn("setsockopt(SO_RCVBUF) failed for %s", p->p_listen);
	sockbuf = SOCKBUF_SIZE;
	if (setsockopt(p->p_socket, SOL_SOCKET, SO_SNDBUF, &sockbuf,
	    sizeof(sockbuf)) == -1)
		log_warn("setsockopt(SO_SNDBUF) failed for %s", p->p_listen);
}

static void
iscsi_portal_delete(struct portal *p __unused)
{
}

static void
iscsi_load_kernel_module(void)
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

static void
iscsi_kernel_port_add(struct port *port, struct ctl_req *req)
{
	struct target *targ = port->p_target;
	struct portal_group *pg = port->p_portal_group;

	iscsi_load_kernel_module();

	strlcpy(req->driver, "iscsi", sizeof(req->driver));

	nvlist_add_string(req->args_nvl, "cfiscsi_target", targ->t_name);
	nvlist_add_string(req->args_nvl, "ctld_portal_group_name", pg->pg_name);
	nvlist_add_stringf(req->args_nvl, "cfiscsi_portal_group_tag", "%u",
	    pg->pg_tag);

	if (targ->t_alias != NULL) {
		nvlist_add_string(req->args_nvl, "cfiscsi_target_alias",
		    targ->t_alias);
	}
}

static void
iscsi_kernel_port_remove(struct port *port, struct ctl_req *req)
{
	struct target *targ = port->p_target;
	struct portal_group *pg = port->p_portal_group;

	strlcpy(req->driver, "iscsi", sizeof(req->driver));

	nvlist_add_string(req->args_nvl, "cfiscsi_target", targ->t_name);
	nvlist_add_stringf(req->args_nvl, "cfiscsi_portal_group_tag",
	    "%u", pg->pg_tag);
}

static char *
iscsi_normalize_target_name(const char *name)
{
	char *t_name;
	size_t i, len;

	if (valid_iscsi_name(name, log_warnx) == false) {
		log_warnx("target name \"%s\" is invalid for iSCSI", name);
		return (NULL);
	}

	t_name = strdup(name);
	if (t_name == NULL) {
		log_warn("strdup");
		return (NULL);
	}

	/*
	 * RFC 3722 requires us to normalize the name to lowercase.
	 */
	len = strlen(t_name);
	for (i = 0; i < len; i++)
		t_name[i] = tolower(t_name[i]);

	return (t_name);
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

static struct ctld_connection *
connection_new(struct portal *portal, int fd, const char *host,
    const struct sockaddr *client_sa)
{
	struct ctld_connection *conn;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		log_err(1, "calloc");
	connection_init(&conn->conn, &conn_ops, proxy_mode);
	conn->conn.conn_socket = fd;
	conn->conn_portal = portal;
	conn->conn_initiator_addr = checked_strdup(host);
	memcpy(&conn->conn_initiator_sa, client_sa, client_sa->sa_len);

	return (conn);
}

static void
kernel_handoff(struct ctld_connection *conn)
{
	struct ctl_iscsi req;

	bzero(&req, sizeof(req));

	req.type = CTL_ISCSI_HANDOFF;
	strlcpy(req.data.handoff.initiator_name,
	    conn->conn_initiator_name, sizeof(req.data.handoff.initiator_name));
	strlcpy(req.data.handoff.initiator_addr,
	    conn->conn_initiator_addr, sizeof(req.data.handoff.initiator_addr));
	if (conn->conn_initiator_alias != NULL) {
		strlcpy(req.data.handoff.initiator_alias,
		    conn->conn_initiator_alias, sizeof(req.data.handoff.initiator_alias));
	}
	memcpy(req.data.handoff.initiator_isid, conn->conn_initiator_isid,
	    sizeof(req.data.handoff.initiator_isid));
	strlcpy(req.data.handoff.target_name,
	    conn->conn_target->t_name, sizeof(req.data.handoff.target_name));
	if (conn->conn_portal->p_portal_group->pg_offload != NULL) {
		strlcpy(req.data.handoff.offload,
		    conn->conn_portal->p_portal_group->pg_offload,
		    sizeof(req.data.handoff.offload));
	}
#ifdef ICL_KERNEL_PROXY
	if (proxy_mode)
		req.data.handoff.connection_id = conn->conn.conn_socket;
	else
		req.data.handoff.socket = conn->conn.conn_socket;
#else
	req.data.handoff.socket = conn->conn.conn_socket;
#endif
	req.data.handoff.portal_group_tag =
	    conn->conn_portal->p_portal_group->pg_tag;
	if (conn->conn.conn_header_digest == CONN_DIGEST_CRC32C)
		req.data.handoff.header_digest = CTL_ISCSI_DIGEST_CRC32C;
	if (conn->conn.conn_data_digest == CONN_DIGEST_CRC32C)
		req.data.handoff.data_digest = CTL_ISCSI_DIGEST_CRC32C;
	req.data.handoff.cmdsn = conn->conn.conn_cmdsn;
	req.data.handoff.statsn = conn->conn.conn_statsn;
	req.data.handoff.max_recv_data_segment_length =
	    conn->conn.conn_max_recv_data_segment_length;
	req.data.handoff.max_send_data_segment_length =
	    conn->conn.conn_max_send_data_segment_length;
	req.data.handoff.max_burst_length = conn->conn.conn_max_burst_length;
	req.data.handoff.first_burst_length =
	    conn->conn.conn_first_burst_length;
	req.data.handoff.immediate_data = conn->conn.conn_immediate_data;

	if (ioctl(ctl_fd, CTL_ISCSI, &req) == -1) {
		log_err(1, "error issuing CTL_ISCSI ioctl; "
		    "dropping connection");
	}

	if (req.status != CTL_ISCSI_OK) {
		log_errx(1, "error returned from CTL iSCSI handoff request: "
		    "%s; dropping connection", req.error_str);
	}
}

static void
iscsi_handle_connection(struct portal *portal, int fd, const char *host,
    const struct sockaddr *client_sa)
{
	struct portal_group *pg = portal->p_portal_group;
	struct conf *conf = pg->pg_conf;
	struct ctld_connection *conn;

	conn = connection_new(portal, fd, host, client_sa);
	set_timeout(conf->conf_timeout, true);
	kernel_capsicate();
	login(conn);
	if (conn->conn_session_type == CONN_SESSION_TYPE_NORMAL) {
		kernel_handoff(conn);
		log_debugx("connection handed off to the kernel");
	} else {
		assert(conn->conn_session_type == CONN_SESSION_TYPE_DISCOVERY);
		discovery(conn);
	}
}

struct target_protocol_ops target_iscsi = {
	.portal_group_init = iscsi_portal_group_init,
	.portal_group_copy = iscsi_portal_group_copy,
	.portal_init = iscsi_portal_init,
	.portal_init_socket = iscsi_portal_init_socket,
	.portal_delete = iscsi_portal_delete,
	.kernel_port_add = iscsi_kernel_port_add,
	.kernel_port_remove = iscsi_kernel_port_remove,
	.normalize_target_name = iscsi_normalize_target_name,
	.handle_connection = iscsi_handle_connection,
};
