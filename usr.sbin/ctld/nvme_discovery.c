/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023-2025 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <libiscsiutil.h>
#include <libnvmf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "ctld.h"

struct io_controller_data {
	struct nvme_discovery_log_entry entry;
	bool wildcard;
};

struct controller {
	struct nvmf_qpair *qp;

	uint64_t cap;
	uint32_t vs;
	uint32_t cc;
	uint32_t csts;

	bool shutdown;

	struct nvme_controller_data cdata;

	struct portal *portal;
	const struct sockaddr *client_sa;
	char *hostnqn;
	struct nvme_discovery_log *discovery_log;
	size_t discovery_log_len;
	int s;
};

static bool
discovery_controller_filtered(struct controller *c,
    const struct port *port)
{
	const struct portal_group *pg = c->portal->p_portal_group;
	const struct target *targ = port->p_target;
	const struct auth_group *ag;

	ag = port->p_auth_group;
	if (ag == NULL)
		ag = targ->t_auth_group;

	assert(pg->pg_discovery_auth_group != PG_FILTER_UNKNOWN);

	if (pg->pg_discovery_filter >= PG_FILTER_PORTAL &&
	    auth_portal_check(ag, TARGET_PROTOCOL_NVME,
	    (const struct sockaddr_storage *)c->client_sa) != 0) {
		log_debugx("host address does not match addresses "
		    "allowed for controller \"%s\"; skipping", targ->t_name);
		return (true);
	}


	if (pg->pg_discovery_filter >= PG_FILTER_PORTAL_NAME &&
	    auth_name_check(ag, TARGET_PROTOCOL_NVME, c->hostnqn) != 0) {
		log_debugx("HostNQN does not match NQNs "
		    "allowed for controller \"%s\"; skipping", targ->t_name);
		return (true);
	}

	/* XXX: auth not yet implemented for NVMe */

	return (false);
}

static bool
portal_uses_wildcard_address(const struct portal *p)
{
	struct addrinfo *ai = p->p_ai;

	switch (ai->ai_family) {
	case AF_INET:
	{
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)ai->ai_addr;
		return (sin->sin_addr.s_addr == htonl(INADDR_ANY));
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)ai->ai_addr;
		return (memcmp(&sin6->sin6_addr, &in6addr_any,
		    sizeof(in6addr_any)) == 0);
	}
	default:
		__assert_unreachable();
	}
}

static bool
init_discovery_log_entry(struct nvme_discovery_log_entry *entry,
    struct target *target, struct portal *portal, const char *wildcard_host)
{
	const struct nvmf_association_params *aparams = portal->p_nvme.aparams;
	struct portal_group *pg = portal->p_portal_group;
	struct sockaddr_storage ss;
	struct addrinfo *ai = portal->p_ai;
	int error;
	socklen_t len;

	/*
	 * The default TCP port for I/O controllers is zero, so fetch
	 * the sockaddr of the socket to determine which port the
	 * kernel chose.
	 */
	len = sizeof(ss);
	if (getsockname(portal->p_socket, (struct sockaddr *)&ss, &len) == -1) {
		log_warn("Failed getsockname building discovery log entry");
		return (false);
	}

	memset(entry, 0, sizeof(*entry));
	entry->trtype = NVMF_TRTYPE_TCP;
	error = getnameinfo((struct sockaddr *)&ss, len, entry->traddr,
	    sizeof(entry->traddr), entry->trsvcid, sizeof(entry->trsvcid),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (error != 0) {
		log_warnx("Failed getnameinfo building discovery log entry: %s",
		    gai_strerror(error));
		return (false);
	}

	if (portal_uses_wildcard_address(portal))
		strncpy(entry->traddr, wildcard_host, sizeof(entry->traddr));
	switch (ai->ai_family) {
	case AF_INET:
		entry->adrfam = NVMF_ADRFAM_IPV4;
		break;
	case AF_INET6:
		entry->adrfam = NVMF_ADRFAM_IPV6;
		break;
	default:
		__assert_unreachable();
	}
	entry->subtype = NVMF_SUBTYPE_NVME;
	if (!aparams->sq_flow_control)
		entry->treq |= (1 << 2);
	entry->portid = htole16(pg->pg_tag);
	entry->cntlid = htole16(NVMF_CNTLID_DYNAMIC);
	entry->aqsz = aparams->max_admin_qsize;
	strncpy(entry->subnqn, target->t_name, sizeof(entry->subnqn));
	return (true);
}

static void
build_discovery_log_page(struct controller *c)
{
	struct portal_group *pg = c->portal->p_portal_group;
	struct portal *portal;
	struct port *port;
	struct sockaddr_storage ss;
	socklen_t len;
	char wildcard_host[NI_MAXHOST];
	u_int nentries;
	int error;

	if (c->discovery_log != NULL)
		return;

	len = sizeof(ss);
	if (getsockname(c->s, (struct sockaddr *)&ss, &len) == -1) {
		log_warn("build_discovery_log_page: getsockname");
		return;
	}

	error = getnameinfo((struct sockaddr *)&ss, len, wildcard_host,
	    sizeof(wildcard_host), NULL, 0, NI_NUMERICHOST);
	if (error != 0) {
		log_warnx("build_discovery_log_page: getnameinfo: %s",
		    gai_strerror(error));
		return;
	}

	nentries = 0;
	TAILQ_FOREACH(port, &pg->pg_ports, p_pgs) {
		if (discovery_controller_filtered(c, port))
			continue;

		TAILQ_FOREACH(portal, &pg->pg_portals, p_next) {
			if (portal->p_protocol ==
			    PORTAL_PROTOCOL_NVME_DISCOVERY_TCP)
				continue;

			if (portal_uses_wildcard_address(portal) &&
			    portal->p_ai->ai_family != ss.ss_family)
				continue;

			nentries++;
		}
	}

	c->discovery_log_len = sizeof(*c->discovery_log) +
	    nentries * sizeof(struct nvme_discovery_log_entry);
	c->discovery_log = calloc(c->discovery_log_len, 1);
	c->discovery_log->genctr = htole32(pg->pg_conf->conf_genctr);
	c->discovery_log->recfmt = 0;
	nentries = 0;
	TAILQ_FOREACH(port, &pg->pg_ports, p_pgs) {
		if (discovery_controller_filtered(c, port))
			continue;

		TAILQ_FOREACH(portal, &pg->pg_portals, p_next) {
			if (portal->p_protocol ==
			    PORTAL_PROTOCOL_NVME_DISCOVERY_TCP)
				continue;

			if (portal_uses_wildcard_address(portal) &&
			    portal->p_ai->ai_family != ss.ss_family)
				continue;

			if (init_discovery_log_entry(
			    &c->discovery_log->entries[nentries],
			    port->p_target, portal, wildcard_host))
				nentries++;
		}
	}
	c->discovery_log->numrec = nentries;
}

static bool
update_cc(struct controller *c, uint32_t new_cc)
{
	uint32_t changes;

	if (c->shutdown)
		return (false);
	if (!nvmf_validate_cc(c->qp, c->cap, c->cc, new_cc))
		return (false);

	changes = c->cc ^ new_cc;
	c->cc = new_cc;

	/* Handle shutdown requests. */
	if (NVMEV(NVME_CC_REG_SHN, changes) != 0 &&
	    NVMEV(NVME_CC_REG_SHN, new_cc) != 0) {
		c->csts &= ~NVMEM(NVME_CSTS_REG_SHST);
		c->csts |= NVMEF(NVME_CSTS_REG_SHST, NVME_SHST_COMPLETE);
		c->shutdown = true;
	}

	if (NVMEV(NVME_CC_REG_EN, changes) != 0) {
		if (NVMEV(NVME_CC_REG_EN, new_cc) == 0) {
			/* Controller reset. */
			c->csts = 0;
			c->shutdown = true;
		} else
			c->csts |= NVMEF(NVME_CSTS_REG_RDY, 1);
	}
	return (true);
}

static void
handle_property_get(const struct controller *c, const struct nvmf_capsule *nc,
    const struct nvmf_fabric_prop_get_cmd *pget)
{
	struct nvmf_fabric_prop_get_rsp rsp;

	nvmf_init_cqe(&rsp, nc, 0);

	switch (le32toh(pget->ofst)) {
	case NVMF_PROP_CAP:
		if (pget->attrib.size != NVMF_PROP_SIZE_8)
			goto error;
		rsp.value.u64 = htole64(c->cap);
		break;
	case NVMF_PROP_VS:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(c->vs);
		break;
	case NVMF_PROP_CC:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(c->cc);
		break;
	case NVMF_PROP_CSTS:
		if (pget->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		rsp.value.u32.low = htole32(c->csts);
		break;
	default:
		goto error;
	}

	nvmf_send_response(nc, &rsp);
	return;
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

static void
handle_property_set(struct controller *c, const struct nvmf_capsule *nc,
    const struct nvmf_fabric_prop_set_cmd *pset)
{
	switch (le32toh(pset->ofst)) {
	case NVMF_PROP_CC:
		if (pset->attrib.size != NVMF_PROP_SIZE_4)
			goto error;
		if (!update_cc(c, le32toh(pset->value.u32.low)))
			goto error;
		break;
	default:
		goto error;
	}

	nvmf_send_success(nc);
	return;
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

static void
handle_fabrics_command(struct controller *c, const struct nvmf_capsule *nc,
    const struct nvmf_fabric_cmd *fc)
{
	switch (fc->fctype) {
	case NVMF_FABRIC_COMMAND_PROPERTY_GET:
		handle_property_get(c, nc,
		    (const struct nvmf_fabric_prop_get_cmd *)fc);
		break;
	case NVMF_FABRIC_COMMAND_PROPERTY_SET:
		handle_property_set(c, nc,
		    (const struct nvmf_fabric_prop_set_cmd *)fc);
		break;
	case NVMF_FABRIC_COMMAND_CONNECT:
		log_warnx("CONNECT command on connected queue");
		nvmf_send_generic_error(nc, NVME_SC_COMMAND_SEQUENCE_ERROR);
		break;
	case NVMF_FABRIC_COMMAND_DISCONNECT:
		log_warnx("DISCONNECT command on admin queue");
		nvmf_send_error(nc, NVME_SCT_COMMAND_SPECIFIC,
		    NVMF_FABRIC_SC_INVALID_QUEUE_TYPE);
		break;
	default:
		log_warnx("Unsupported fabrics command %#x", fc->fctype);
		nvmf_send_generic_error(nc, NVME_SC_INVALID_OPCODE);
		break;
	}
}

static void
handle_identify_command(const struct controller *c,
    const struct nvmf_capsule *nc, const struct nvme_command *cmd)
{
	uint8_t cns;

	cns = le32toh(cmd->cdw10) & 0xFF;
	switch (cns) {
	case 1:
		break;
	default:
		log_warnx("Unsupported CNS %#x for IDENTIFY", cns);
		goto error;
	}

	nvmf_send_controller_data(nc, &c->cdata, sizeof(c->cdata));
	return;
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

static void
handle_get_log_page_command(struct controller *c,
    const struct nvmf_capsule *nc, const struct nvme_command *cmd)
{
	uint64_t offset;
	uint32_t length;

	switch (nvmf_get_log_page_id(cmd)) {
	case NVME_LOG_DISCOVERY:
		break;
	default:
		log_warnx("Unsupported log page %u for discovery controller",
		    nvmf_get_log_page_id(cmd));
		goto error;
	}

	build_discovery_log_page(c);

	offset = nvmf_get_log_page_offset(cmd);
	if (offset >= c->discovery_log_len)
		goto error;

	length = nvmf_get_log_page_length(cmd);
	if (length > c->discovery_log_len - offset)
		length = c->discovery_log_len - offset;

	nvmf_send_controller_data(nc, (char *)c->discovery_log + offset,
	    length);
	return;
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

static void
controller_handle_admin_commands(struct controller *c)
{
	struct nvmf_qpair *qp = c->qp;
	const struct nvme_command *cmd;
	struct nvmf_capsule *nc;
	int error;

	for (;;) {
		error = nvmf_controller_receive_capsule(qp, &nc);
		if (error != 0) {
			if (error != ECONNRESET)
				log_warnc(error,
				    "Failed to read command capsule");
			break;
		}

		cmd = nvmf_capsule_sqe(nc);

		/*
		 * Only permit Fabrics commands while a controller is
		 * disabled.
		 */
		if (NVMEV(NVME_CC_REG_EN, c->cc) == 0 &&
		    cmd->opc != NVME_OPC_FABRICS_COMMANDS) {
			log_warnx("Unsupported admin opcode %#x while disabled\n",
			    cmd->opc);
			nvmf_send_generic_error(nc,
			    NVME_SC_COMMAND_SEQUENCE_ERROR);
			nvmf_free_capsule(nc);
			continue;
		}

		switch (cmd->opc) {
		case NVME_OPC_FABRICS_COMMANDS:
			handle_fabrics_command(c, nc,
			    (const struct nvmf_fabric_cmd *)cmd);
			break;
		case NVME_OPC_IDENTIFY:
			handle_identify_command(c, nc, cmd);
			break;
		case NVME_OPC_GET_LOG_PAGE:
			handle_get_log_page_command(c, nc, cmd);
			break;
		default:
			log_warnx("Unsupported admin opcode %#x", cmd->opc);
			nvmf_send_generic_error(nc, NVME_SC_INVALID_OPCODE);
			break;
		}
		nvmf_free_capsule(nc);
	}
}

static void
nvme_discovery(struct portal *p, int s, const struct sockaddr *client_sa,
    struct nvmf_qpair *qp, const struct nvmf_fabric_connect_data *data)
{
	struct controller c;

	memset(&c, 0, sizeof(c));
	c.portal = p;
	c.client_sa = client_sa;
	c.hostnqn = strndup(data->hostnqn, sizeof(data->hostnqn));
	c.s = s;
	c.qp = qp;
	nvmf_init_discovery_controller_data(qp, &c.cdata);
	c.cap = nvmf_controller_cap(qp);
	c.vs = c.cdata.ver;

	controller_handle_admin_commands(&c);

	free(c.discovery_log);
	free(c.hostnqn);
}

void
nvme_handle_discovery_socket(struct portal *portal, int s,
    const struct sockaddr *client_sa)
{
	struct nvmf_fabric_connect_data data;
	struct nvmf_qpair_params qparams;
	struct nvmf_capsule *nc;
	struct nvmf_qpair *qp;
	int error;

	memset(&qparams, 0, sizeof(qparams));
	qparams.tcp.fd = s;

	nc = NULL;
	qp = nvmf_accept(portal->p_nvme.association, &qparams, &nc, &data);
	if (qp == NULL) {
		log_warnx("Failed to create NVMe discovery qpair: %s",
		    nvmf_association_error(portal->p_nvme.association));
		goto error;
	}

	if (strcmp(data.subnqn, NVMF_DISCOVERY_NQN) != 0) {
		log_warnx("Discovery NVMe qpair with invalid SubNQN: %.*s",
		    (int)sizeof(data.subnqn), data.subnqn);
		nvmf_connect_invalid_parameters(nc, true,
		    offsetof(struct nvmf_fabric_connect_data, subnqn));
		goto error;
	}

	/* Just use a controller ID of 1 for all discovery controllers. */
	error = nvmf_finish_accept(nc, 1);
	if (error != 0) {
		log_warnc(error, "Failed to send NVMe CONNECT reponse");
		goto error;
	}
	nvmf_free_capsule(nc);
	nc = NULL;

	nvme_discovery(portal, s, client_sa, qp, &data);
error:
	if (nc != NULL)
		nvmf_free_capsule(nc);
	if (qp != NULL)
		nvmf_free_qpair(qp);
	close(s);
}

