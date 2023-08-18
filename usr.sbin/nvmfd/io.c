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

#include <sys/sysctl.h>
#include <err.h>
#include <errno.h>
#include <libnvmf.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

struct io_controller {
	struct controller *c;

	struct nvmf_qpair *admin_qpair;
	int admin_socket;

	u_int num_io_queues;
	u_int active_io_queues;
	struct nvmf_qpair **io_qpairs;
	int *io_sockets;

	uint16_t cntlid;
	char hostid[16];
	char hostnqn[NVME_NQN_FIELD_SIZE];
};

struct io_thread_data {
	struct io_controller *ioc;
	uint16_t qid;
};

static struct nvmf_association *io_na;
static pthread_cond_t io_cond;
static pthread_mutex_t io_na_mutex;
static struct io_controller *io_controller;
static const char *nqn;
static char serial[NVME_SERIAL_NUMBER_LENGTH];

void
init_io(const char *subnqn)
{
	struct nvmf_association_params aparams;
	u_long hostid;
	size_t len;

	memset(&aparams, 0, sizeof(aparams));
	aparams.sq_flow_control = !flow_control_disable;
	aparams.dynamic_controller_model = true;
	aparams.max_admin_qsize = NVME_MAX_ADMIN_ENTRIES;
	aparams.max_io_qsize = NVME_MAX_IO_ENTRIES;
	aparams.tcp.pda = 0;
	aparams.tcp.header_digests = header_digests;
	aparams.tcp.data_digests = data_digests;
	aparams.tcp.maxr2t = 1;
	aparams.tcp.maxh2cdata = 256 * 1024;
	io_na = nvmf_allocate_association(NVMF_TRTYPE_TCP, true,
	    &aparams);
	if (io_na == NULL)
		err(1, "Failed to create I/O controller association");

	nqn = subnqn;

	/* Generate a serial number from the kern.hostid node. */
	len = sizeof(hostid);
	if (sysctlbyname("kern.hostid", &hostid, &len, NULL, 0) == -1)
		err(1, "sysctl: kern.hostid");

	snprintf(serial, sizeof(serial), "HI:%lu", hostid);

	pthread_cond_init(&io_cond, NULL);
	pthread_mutex_init(&io_na_mutex, NULL);
}

static bool
handle_io_identify_command(const struct nvmf_capsule *nc,
    const struct nvme_command *cmd)
{
	struct nvme_namespace_data nsdata;
	struct iovec iov[1];
	int error;
	uint8_t cns;

	cns = le32toh(cmd->cdw10) & 0xFF;
	switch (cns) {
	case 0:
		if (nvmf_capsule_data_len(nc) != sizeof(nsdata))
			goto error;

		if (!device_namespace_data(le32toh(cmd->nsid), &nsdata)) {
			nvmf_send_generic_error(nc,
			    NVME_SC_INVALID_NAMESPACE_OR_FORMAT);
			return (true);
		}

		iov[0].iov_base = &nsdata;
		iov[0].iov_len = sizeof(nsdata);
		break;
	default:
		return (false);
	}

	error = nvmf_send_controller_data(nc, iov, nitems(iov));
	if (error != 0)
		nvmf_send_generic_error(nc, NVME_SC_DATA_TRANSFER_ERROR);
	else
		nvmf_send_success(nc);
	return (true);
error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
	return (true);
}

static void
handle_set_features(struct io_controller *ioc, const struct nvmf_capsule *nc,
    const struct nvme_command *cmd)
{
	struct nvme_completion cqe;
	uint8_t fid;

	fid = NVMEV(NVME_FEAT_SET_FID, le32toh(cmd->cdw10));
	switch (fid) {
	case NVME_FEAT_NUMBER_OF_QUEUES:
	{
		uint32_t num_queues;

		if (ioc->num_io_queues != 0) {
			nvmf_send_generic_error(nc,
			    NVME_SC_COMMAND_SEQUENCE_ERROR);
			return;
		}

		num_queues = le32toh(cmd->cdw11) & 0xffff;

		/* 5.12.1.7: 65535 is invalid. */
		if (num_queues == 65535)
			goto error;

		/* Fabrics requires the same number of SQs and CQs. */
		if (le32toh(cmd->cdw11) >> 16 != num_queues)
			goto error;

		/* Convert to 1's based */
		num_queues++;

		/* Lock to synchronize with handle_io_qpair. */
		pthread_mutex_lock(&io_na_mutex);
		ioc->num_io_queues = num_queues;
		ioc->io_qpairs = calloc(num_queues, sizeof(*ioc->io_qpairs));
		ioc->io_sockets = calloc(num_queues, sizeof(*ioc->io_sockets));
		pthread_mutex_unlock(&io_na_mutex);

		nvmf_init_cqe(&cqe, nc, 0);
		cqe.cdw0 = cmd->cdw11;
		nvmf_send_response(nc, &cqe);
		return;
	}
	default:
		warnx("Unsupported feature ID %u for SET_FEATURES", fid);
		goto error;
	}

error:
	nvmf_send_generic_error(nc, NVME_SC_INVALID_FIELD);
}

static bool
admin_command(const struct nvmf_capsule *nc, const struct nvme_command *cmd,
    void *arg)
{
	struct io_controller *ioc = arg;

	switch (cmd->opc) {
	case NVME_OPC_IDENTIFY:
		return (handle_io_identify_command(nc, cmd));
	case NVME_OPC_SET_FEATURES:
		handle_set_features(ioc, nc, cmd);
		return (true);
	case NVME_OPC_KEEP_ALIVE:
		nvmf_send_success(nc);
		return (true);
	default:
		return (false);
	}
}

static void *
admin_qpair_thread(void *arg)
{
	struct io_controller *ioc = arg;

	pthread_detach(pthread_self());

	controller_handle_admin_commands(ioc->c, admin_command, ioc);

	pthread_mutex_lock(&io_na_mutex);
	for (u_int i = 0; i < ioc->num_io_queues; i++) {
		if (ioc->io_qpairs[i] == NULL || ioc->io_sockets[i] == -1)
			continue;
		close(ioc->io_sockets[i]);
		ioc->io_sockets[i] = -1;
	}

	/* Wait for I/O threads to notice. */
	while (ioc->active_io_queues > 0)
		pthread_cond_wait(&io_cond, &io_na_mutex);

	nvmf_free_qpair(ioc->admin_qpair);
	io_controller = NULL;
	pthread_mutex_unlock(&io_na_mutex);

	free_controller(ioc->c);

	close(ioc->admin_socket);
	free(ioc);
	return (NULL);
}

static bool
handle_io_fabrics_command(const struct nvmf_capsule *nc,
    const struct nvmf_fabric_cmd *fc)
{
	switch (fc->fctype) {
	case NVMF_FABRIC_COMMAND_CONNECT:
		warnx("CONNECT command on connected queue");
		nvmf_send_generic_error(nc, NVME_SC_COMMAND_SEQUENCE_ERROR);
		break;
	case NVMF_FABRIC_COMMAND_DISCONNECT:
	{
		const struct nvmf_fabric_disconnect_cmd *dis =
		    (const struct nvmf_fabric_disconnect_cmd *)fc;
		if (dis->recfmt != htole16(0)) {
			nvmf_send_error(nc, NVME_SCT_COMMAND_SPECIFIC,
			    NVMF_FABRIC_SC_INCOMPATIBLE_FORMAT);
			break;
		}
		nvmf_send_success(nc);
		return (true);
	}
	default:
		warnx("Unsupported fabrics command %#x", fc->fctype);
		nvmf_send_generic_error(nc, NVME_SC_INVALID_OPCODE);
		break;
	}

	return (false);
}

static bool
handle_io_commands(struct nvmf_qpair *qp)
{
	const struct nvme_command *cmd;
	struct nvmf_capsule *nc;
	int error;
	bool disconnect;

	disconnect = false;

	while (!disconnect) {
		error = nvmf_controller_receive_capsule(qp, &nc);
		if (error != 0) {
			if (error != ECONNRESET)
				warnc(error, "Failed to read command capsule");
			break;
		}

		cmd = nvmf_capsule_sqe(nc);

		switch (cmd->opc) {
		case NVME_OPC_FABRICS_COMMANDS:
			disconnect = handle_io_fabrics_command(nc,
			    (const struct nvmf_fabric_cmd *)cmd);
			break;
		default:
			warnx("Unsupported opcode %#x", cmd->opc);
			nvmf_send_generic_error(nc, NVME_SC_INVALID_OPCODE);
			break;
		}
		nvmf_free_capsule(nc);
	}

	return (disconnect);
}

static void *
io_qpair_thread(void *arg)
{
	struct io_thread_data *itd = arg;
	struct nvmf_qpair *qp;
	bool disconnect;

	pthread_detach(pthread_self());

	pthread_mutex_lock(&io_na_mutex);
	qp = itd->ioc->io_qpairs[itd->qid - 1];
	pthread_mutex_unlock(&io_na_mutex);

	disconnect = handle_io_commands(qp);

	pthread_mutex_lock(&io_na_mutex);
	if (disconnect)
		itd->ioc->io_qpairs[itd->qid - 1] = NULL;
	if (itd->ioc->io_sockets[itd->qid - 1] != -1) {
		close(itd->ioc->io_sockets[itd->qid - 1]);
		itd->ioc->io_sockets[itd->qid - 1] = -1;
	}
	itd->ioc->active_io_queues--;
	if (itd->ioc->active_io_queues == 0)
		pthread_cond_broadcast(&io_cond);

	nvmf_free_qpair(qp);
	pthread_mutex_unlock(&io_na_mutex);

	free(itd);
	return (NULL);
}

static bool
handle_admin_qpair(int s, struct nvmf_qpair *qp, struct nvmf_capsule *nc,
    const struct nvmf_fabric_connect_data *data)
{
	struct nvme_controller_data cdata;
	struct io_controller *ioc;
	pthread_t thr;
	uint32_t ioccsz;
	int error;

	/* Can only have one active I/O controller at a time. */
	if (io_controller != NULL) {
		nvmf_send_error(nc, NVME_SCT_COMMAND_SPECIFIC,
		    NVMF_FABRIC_SC_CONTROLLER_BUSY);
		return (false);
	}

	error = nvmf_finish_accept(nc, 2);
	if (error != 0) {
		warnc(error, "Failed to send CONNECT response");
		return (false);
	}

	ioc = calloc(1, sizeof(*ioc));
	ioc->cntlid = 2;
	ioc->admin_qpair = qp;
	ioc->admin_socket = s;
	memcpy(ioc->hostid, data->hostid, sizeof(ioc->hostid));
	memcpy(ioc->hostnqn, data->hostnqn, sizeof(ioc->hostnqn));

	/* IOCCSZ allows for a 16k data buffer + SQE. */
	ioccsz = 16 * 1024 + sizeof(struct nvme_command);
	nvmf_init_io_controller_data(qp, serial, nqn, device_count(), ioccsz,
	    &cdata);
	ioc->c = init_controller(qp, &cdata);

	error = pthread_create(&thr, NULL, admin_qpair_thread, ioc);
	if (error != 0) {
		warnc(error, "Failed to create I/O admin qpair thread");
		free_controller(ioc->c);
		free(ioc);
		return (false);
	}

	io_controller = ioc;
	return (true);
}

static bool
handle_io_qpair(int s, struct nvmf_qpair *qp, struct nvmf_capsule *nc,
    const struct nvmf_fabric_connect_data *data, uint16_t qid)
{
	struct io_thread_data *itd;
	pthread_t thr;
	int error;

	if (io_controller == NULL) {
		warnx("Attempt to create I/O qpair without admin qpair");
		nvmf_send_generic_error(nc, NVME_SC_COMMAND_SEQUENCE_ERROR);
		return (false);
	}

	if (memcmp(io_controller->hostid, data->hostid,
	    sizeof(data->hostid)) != 0) {
		warnx("hostid mismatch for I/O qpair CONNECT");
		nvmf_connect_invalid_parameters(nc, true,
		    offsetof(struct nvmf_fabric_connect_data, hostid));
		return (false);
	}
	if (le16toh(data->cntlid) != io_controller->cntlid) {
		warnx("cntlid mismatch for I/O qpair CONNECT");
		nvmf_connect_invalid_parameters(nc, true,
		    offsetof(struct nvmf_fabric_connect_data, cntlid));
		return (false);
	}
	if (memcmp(io_controller->hostnqn, data->hostnqn,
	    sizeof(data->hostid)) != 0) {
		warnx("host NQN mismatch for I/O qpair CONNECT");
		nvmf_connect_invalid_parameters(nc, true,
		    offsetof(struct nvmf_fabric_connect_data, hostnqn));
		return (false);
	}

	if (io_controller->num_io_queues == 0) {
		warnx("Attempt to create I/O qpair without enabled queues");
		nvmf_send_generic_error(nc, NVME_SC_COMMAND_SEQUENCE_ERROR);
		return (false);
	}
	if (qid > io_controller->num_io_queues) {
		warnx("Attempt to create invalid I/O qpair %u", qid);
		nvmf_connect_invalid_parameters(nc, false,
		    offsetof(struct nvmf_fabric_connect_cmd, qid));
		return (false);
	}
	if (io_controller->io_qpairs[qid - 1] != NULL) {
		warnx("Attempt to re-create I/O qpair %u", qid);
		nvmf_send_generic_error(nc, NVME_SC_COMMAND_SEQUENCE_ERROR);
		return (false);
	}

	error = nvmf_finish_accept(nc, io_controller->cntlid);
	if (error != 0) {
		warnc(error, "Failed to send CONNECT response");
		return (false);
	}

	itd = calloc(1, sizeof(*itd));
	itd->ioc = io_controller;
	itd->qid = qid;

	error = pthread_create(&thr, NULL, io_qpair_thread, itd);
	if (error != 0) {
		warnc(error, "Failed to create I/O qpair thread");
		free(itd);
		return (false);
	}

	io_controller->active_io_queues++;
	io_controller->io_qpairs[qid - 1] = qp;
	io_controller->io_sockets[qid - 1] = s;
	return (true);
}

void
handle_io_socket(int s)
{
	struct nvmf_fabric_connect_data data;
	struct nvmf_qpair_params qparams;
	const struct nvmf_fabric_connect_cmd *cmd;
	struct nvmf_capsule *nc;
	struct nvmf_qpair *qp;
	bool ok;

	memset(&qparams, 0, sizeof(qparams));
	qparams.tcp.fd = s;

	nc = NULL;
	pthread_mutex_lock(&io_na_mutex);
	qp = nvmf_accept(io_na, &qparams, &nc, &data);
	if (qp == NULL) {
		warnx("Failed to create I/O qpair: %s",
		    nvmf_association_error(io_na));
		pthread_mutex_unlock(&io_na_mutex);
		goto error;
	}

	if (strcmp(data.subnqn, nqn) != 0) {
		warn("I/O qpair with invalid SubNQN: %.*s",
		    (int)sizeof(data.subnqn), data.subnqn);
		nvmf_connect_invalid_parameters(nc, true,
		    offsetof(struct nvmf_fabric_connect_data, subnqn));
		pthread_mutex_unlock(&io_na_mutex);
		goto error;
	}

	/* Is this an admin or I/O queue pair? */
	cmd = nvmf_capsule_sqe(nc);
	if (cmd->qid == 0)
		ok = handle_admin_qpair(s, qp, nc, &data);
	else
		ok = handle_io_qpair(s, qp, nc, &data, le16toh(cmd->qid));
	pthread_mutex_unlock(&io_na_mutex);
	if (!ok)
		goto error;

	nvmf_free_capsule(nc);
	return;

error:
	if (nc != NULL)
		nvmf_free_capsule(nc);
	if (qp != NULL) {
		pthread_mutex_lock(&io_na_mutex);
		nvmf_free_qpair(qp);
		pthread_mutex_unlock(&io_na_mutex);
	}
	close(s);
}
