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
#include <arpa/inet.h>
#include <err.h>
#include <libnvmf.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

struct discovery_thread_arg {
	struct nvmf_qpair *qp;
	int s;
};

static struct nvme_discovery_log *discovery_log;
static struct nvmf_association *discovery_na;
static pthread_mutex_t discovery_mutex;

static void
init_discovery_log_entry(struct nvme_discovery_log_entry *entry, int s,
	const char *subnqn)
{
	struct sockaddr_storage ss;
	socklen_t len;

	len = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &len) == -1)
		err(1, "getsockname");

	entry->trtype = NVMF_TRTYPE_TCP;
	switch (ss.ss_family) {
	case AF_INET:
	{
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)&ss;
		entry->adrfam = NVMF_ADRFAM_IPV4;
		snprintf(entry->trsvcid, sizeof(entry->trsvcid), "%u",
		    htons(sin->sin_port));
		if (inet_ntop(AF_INET, &sin->sin_addr, entry->traddr,
		    sizeof(entry->traddr)) == NULL)
			err(1, "inet_ntop");
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&ss;
		entry->adrfam = NVMF_ADRFAM_IPV6;
		snprintf(entry->trsvcid, sizeof(entry->trsvcid), "%u",
		    htons(sin6->sin6_port));
		if (inet_ntop(AF_INET6, &sin6->sin6_addr, entry->traddr,
		    sizeof(entry->traddr)) == NULL)
			err(1, "inet_ntop");
		break;
	}
	default:
		errx(1, "Unsupported address family %u", ss.ss_family);
	}
	entry->subtype = NVMF_SUBTYPE_NVME;
	if (!flow_control_disable)
		entry->treq |= (1 << 2);
	entry->portid = htole16(1);
	entry->cntlid = htole16(NVMF_CNTLID_DYNAMIC);
	entry->aqsz = NVME_MAX_ADMIN_ENTRIES;
	strlcpy(entry->subnqn, subnqn, sizeof(entry->subnqn));
}

void
init_discovery(int s, const char *subnqn)
{
	struct nvmf_association_params aparams;

	discovery_log = calloc(sizeof(*discovery_log) +
	    sizeof(struct nvme_discovery_log_entry), 1);

	init_discovery_log_entry(&discovery_log->entries[0], s, subnqn);
	discovery_log->numrec = 1;
	discovery_log->recfmt = 0;

	memset(&aparams, 0, sizeof(aparams));
	aparams.sq_flow_control = false;
	aparams.dynamic_controller_model = true;
	aparams.max_admin_qsize = NVME_MAX_ADMIN_ENTRIES;
	aparams.tcp.pda = 0;
	aparams.tcp.header_digests = header_digests;
	aparams.tcp.data_digests = data_digests;
	aparams.tcp.maxr2t = 1;
	discovery_na = nvmf_allocate_association(NVMF_TRTYPE_TCP, true,
	    &aparams);
	if (discovery_na == NULL)
		err(1, "Failed to create discovery association");

	pthread_mutex_init(&discovery_mutex, NULL);
}

static void *
discovery_thread(void *arg)
{
	struct discovery_thread_arg *dta = arg;
	struct nvmf_qpair *qp = dta->qp;
	const struct nvme_command *cmd;
	struct nvmf_capsule *nc;
	int error;

	pthread_detach(pthread_self());

	for (;;) {
		error = nvmf_controller_receive_capsule(qp, &nc);
		if (error != 0) {
			warnc(error, "Failed to read command capsule");
			break;
		}

		cmd = nvmf_capsule_sqe(nc);
		switch (cmd->opc) {
		default:
			warn("Discovery: unsupported opcode %#x", cmd->opc);
			nvmf_send_generic_error(nc, NVME_SC_INVALID_OPCODE);
			break;
		}
		nvmf_free_capsule(nc);
	}

	pthread_mutex_lock(&discovery_mutex);
	nvmf_free_qpair(qp);
	pthread_mutex_unlock(&discovery_mutex);

	close(dta->s);
	free(dta);
	return (NULL);
}

void
handle_discovery_socket(int s)
{
	struct nvmf_fabric_connect_data data;
	struct nvmf_qpair_params qparams;
	struct discovery_thread_arg *dta;
	struct nvmf_capsule *nc;
	struct nvmf_qpair *qp;
	pthread_t thr;
	int error;

	memset(&qparams, 0, sizeof(qparams));
	qparams.tcp.fd = s;

	nc = NULL;
	pthread_mutex_lock(&discovery_mutex);
	qp = nvmf_accept(discovery_na, &qparams, &nc, &data);
	if (qp == NULL) {
		warnx("Failed to create discovery qpair: %s",
		    nvmf_association_error(discovery_na));
		pthread_mutex_unlock(&discovery_mutex);
		goto error;
	}
	pthread_mutex_unlock(&discovery_mutex);

	if (strcmp(data.subnqn, NVMF_DISCOVERY_NQN) != 0) {
		warn("Discovery qpair with invalid SubNQN: %.*s",
		    (int)sizeof(data.subnqn), data.subnqn);
		nvmf_connect_invalid_parameters(nc, true,
		    offsetof(struct nvmf_fabric_connect_data, subnqn));
		goto error;
	}

	/* Just use a controller ID of 1 for all discovery controllers. */
	error = nvmf_finish_accept(nc, 1);
	if (error != 0) {
		warnc(error, "Failed to send CONNECT reponse");
		goto error;
	}

	dta = malloc(sizeof(*dta));
	dta->qp = qp;
	dta->s = s;
	error = pthread_create(&thr, NULL, discovery_thread, dta);
	if (error != 0) {
		warnc(error, "Failed to create discovery thread");
		free(dta);
		goto error;
	}

	nvmf_free_capsule(nc);
	return;

error:
	if (nc != NULL)
		nvmf_free_capsule(nc);
	if (qp != NULL) {
		pthread_mutex_lock(&discovery_mutex);
		nvmf_free_qpair(qp);
		pthread_mutex_unlock(&discovery_mutex);
	}
	close(s);
}
