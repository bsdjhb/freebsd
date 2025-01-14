/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/time.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libiscsiutil.h>
#include <libnvmf.h>
#include <libutil.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_ioctl.h>

#include "ctld.h"

#define	DEFAULT_MAXH2CDATA	(256 * 1024)

static uint16_t nvme_last_port_id = 0;

static bool
parse_bool(const nvlist_t *nvl, const char *key, bool def)
{
	const char *value;

	if (!nvlist_exists_string(nvl, key))
		return (def);

	value = nvlist_get_string(nvl, key);
	if (strcasecmp(value, "true") == 0 ||
	    strcasecmp(value, "1") == 0)
		return (true);
	if (strcasecmp(value, "false") == 0 ||
	    strcasecmp(value, "0") == 0)
		return (false);

	log_warnx("Invalid value \"%s\" for boolean option %s", value, key);
	return (def);
}

static uint64_t
parse_number(const nvlist_t *nvl, const char *key, uint64_t def, uint64_t minv,
    uint64_t maxv)
{
	const char *value;
	uint64_t uval;

	if (!nvlist_exists_string(nvl, key))
		return (def);

	value = nvlist_get_string(nvl, key);
	if (expand_number(value, &uval) == 0 && uval >= minv && uval <= maxv)
		return (uval);

	log_warnx("Invalid value \"%s\" for numeric option %s", value, key);
	return (def);
}

/* Options shared between discovery and I/O associations. */
static void
nvme_aparams_from_options(struct portal_group *pg,
    struct nvmf_association_params *params)
{
	uint64_t value;

	params->tcp.header_digests = parse_bool(pg->pg_options, "HDGST", false);
	params->tcp.data_digests = parse_bool(pg->pg_options, "DDGST", false);
	value = parse_number(pg->pg_options, "MAXH2CDATA", DEFAULT_MAXH2CDATA,
	    4096, UINT32_MAX);
	if (value % 4 != 0) {
		log_warnx("Invalid value \"%ju\" for option MAXH2CDATA",
		    (uintmax_t)value);
		value = DEFAULT_MAXH2CDATA;
	}
	params->tcp.maxh2cdata = value;
}

static struct nvmf_association_params *
nvme_init_discovery_aparams(struct portal_group *pg)
{
	struct nvmf_association_params *params;

	params = calloc(1, sizeof(*params));
	params->sq_flow_control = false;
	params->dynamic_controller_model = true;
	params->max_admin_qsize = NVME_MAX_ADMIN_ENTRIES;
	params->tcp.pda = 0;
	nvme_aparams_from_options(pg, params);

	return (params);
}

static struct nvmf_association_params *
nvme_init_io_aparams(struct portal_group *pg)
{
	struct nvmf_association_params *params;

	params = calloc(1, sizeof(*params));
	params->sq_flow_control = parse_bool(pg->pg_options, "SQFC", false);
	params->dynamic_controller_model = true;
	params->max_admin_qsize = parse_number(pg->pg_options,
	    "max_admin_qsize", NVME_MAX_ADMIN_ENTRIES, NVME_MIN_ADMIN_ENTRIES,
	    NVME_MAX_ADMIN_ENTRIES);
	params->max_io_qsize = parse_number(pg->pg_options, "max_io_qsize",
	    NVME_MAX_IO_ENTRIES, NVME_MIN_IO_ENTRIES, NVME_MAX_IO_ENTRIES);
	params->tcp.pda = 0;
	nvme_aparams_from_options(pg, params);

	return (params);
}

static void
nvme_portal_group_init(struct portal_group *pg)
{
	pg->pg_tag = ++nvme_last_port_id;
}

static void
nvme_portal_group_copy(struct portal_group *oldpg, struct portal_group *newpg)
{
	newpg->pg_tag = oldpg->pg_tag;
}

static void
nvme_portal_init(struct portal *p)
{
	struct portal_group *pg = p->p_portal_group;
	struct nvmf_association_params *aparams;
	enum nvmf_trtype trtype;

	switch (p->p_protocol) {
	case PORTAL_PROTOCOL_NVME_TCP:
		trtype = NVMF_TRTYPE_TCP;
		aparams = nvme_init_io_aparams(pg);
		break;
	case PORTAL_PROTOCOL_NVME_DISCOVERY_TCP:
		trtype = NVMF_TRTYPE_TCP;
		aparams = nvme_init_discovery_aparams(pg);
		break;
	default:
		__assert_unreachable();
	}

	p->p_nvme.aparams = aparams;
	p->p_nvme.association = nvmf_allocate_association(trtype, true,
	    aparams);
	if (p->p_nvme.association == NULL)
		log_err(1, "Failed to create NVMe controller association");
}

static void
nvme_portal_init_socket(struct portal *p __unused)
{
}

static void
nvme_portal_delete(struct portal *p)
{
	if (p->p_nvme.association != NULL)
		nvmf_free_association(p->p_nvme.association);
	free(p->p_nvme.aparams);
}

static void
nvme_load_kernel_modules(struct portal_group *pg)
{
	struct portal *p;
	static bool loaded;
	bool tcp_transport;
	int saved_errno;

	if (loaded)
		return;

	saved_errno = errno;
	if (modfind("nvmft") == -1 && kldload("nvmft") == -1)
		log_warn("couldn't load nvmft");

	tcp_transport = false;
	TAILQ_FOREACH(p, &pg->pg_portals, p_next) {
		switch (p->p_protocol) {
		case PORTAL_PROTOCOL_NVME_TCP:
			tcp_transport = true;
			break;
		}
	}
	if (tcp_transport) {
		if (modfind("nvmf/tcp") == -1 && kldload("nvmf_tcp") == -1)
			log_warn("couldn't load nvmf_tcp");
	}

	errno = saved_errno;
	loaded = true;
}

static void
nvme_kernel_port_add(struct port *port, struct ctl_req *req)
{
	struct target *targ = port->p_target;
	struct portal_group *pg = port->p_portal_group;

	nvme_load_kernel_modules(pg);

	strlcpy(req->driver, "nvmf", sizeof(req->driver));

	nvlist_add_string(req->args_nvl, "subnqn", targ->t_name);
	nvlist_add_string(req->args_nvl, "ctld_transport_group_name",
	    pg->pg_name);
	nvlist_add_stringf(req->args_nvl, "portid", "%u", pg->pg_tag);
	if (!nvlist_exists_string(req->args_nvl, "max_io_qsize"))
		nvlist_add_stringf(req->args_nvl, "max_io_qsize", "%u",
		    NVME_MAX_IO_ENTRIES);
}

static void
nvme_kernel_port_remove(struct port *port, struct ctl_req *req)
{
	struct target *targ = port->p_target;

	strlcpy(req->driver, "nvmf", sizeof(req->driver));

	nvlist_add_string(req->args_nvl, "subnqn", targ->t_name);
}

static char *
nvme_normalize_target_name(const char *name)
{
	char *t_name;
	size_t i, len;

	if (!nvmf_nqn_valid_strict(name)) {
		log_warnx("controller name \"%s\" is invalid for NVMe", name);
		return (NULL);
	}

	t_name = strdup(name);
	if (t_name == NULL) {
		log_warn("strdup");
		return (NULL);
	}

	/*
	 * Normalize the name to lowercase to match iSCSI.
	 */
	len = strlen(t_name);
	for (i = 0; i < len; i++)
		t_name[i] = tolower(t_name[i]);

	return (t_name);
}

static void
nvme_handle_io_socket(struct portal *portal, int fd)
{
	struct nvmf_fabric_connect_data data;
	struct nvmf_qpair_params qparams;
	struct ctl_nvmf req;
	const struct nvmf_fabric_connect_cmd *cmd;
	struct nvmf_capsule *nc;
	struct nvmf_qpair *qp;
	int error;

	memset(&qparams, 0, sizeof(qparams));
	qparams.tcp.fd = fd;

	nc = NULL;
	qp = nvmf_accept(portal->p_nvme.association, &qparams, &nc, &data);
	if (qp == NULL) {
		log_warnx("Failed to create NVMe I/O qpair: %s",
		    nvmf_association_error(portal->p_nvme.association));
		goto error;
	}
	cmd = nvmf_capsule_sqe(nc);

	memset(&req, 0, sizeof(req));
	req.type = CTL_NVMF_HANDOFF;
	error = nvmf_handoff_controller_qpair(qp, cmd, &data,
	    &req.data.handoff);
	if (error != 0) {
		log_warnc(error,
		    "Failed to prepare NVMe I/O qpair for handoff");
		goto error;
	}

	if (ioctl(ctl_fd, CTL_NVMF, &req) != 0)
		log_warn("ioctl(CTL_NVMF/CTL_NVMF_HANDOFF)");
	if (req.status == CTL_NVMF_ERROR)
		log_warnx("Failed to handoff NVMF connection: %s",
		    req.error_str);
	else if (req.status != CTL_NVMF_OK)
		log_warnx("Failed to handoff NVMF connection with status %d",
		    req.status);

error:
	if (nc != NULL)
		nvmf_free_capsule(nc);
	if (qp != NULL)
		nvmf_free_qpair(qp);
	close(fd);
}

static void
nvme_handle_connection(struct portal *portal, int fd, const char *host __unused,
    const struct sockaddr *client_sa)
{
	switch (portal->p_protocol) {
	case PORTAL_PROTOCOL_NVME_TCP:
		nvme_handle_io_socket(portal, fd);
		break;
	case PORTAL_PROTOCOL_NVME_DISCOVERY_TCP:
		nvme_handle_discovery_socket(portal, fd, client_sa);
		break;
	default:
		__assert_unreachable();
	}
}

struct target_protocol_ops target_nvme = {
	.portal_group_init = nvme_portal_group_init,
	.portal_group_copy = nvme_portal_group_copy,
	.portal_init = nvme_portal_init,
	.portal_init_socket = nvme_portal_init_socket,
	.portal_delete = nvme_portal_delete,
	.kernel_port_add = nvme_kernel_port_add,
	.kernel_port_remove = nvme_kernel_port_remove,
	.normalize_target_name = nvme_normalize_target_name,
	.handle_connection = nvme_handle_connection,
};
