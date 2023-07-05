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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid.h>

#include "libnvmf.h"
#include "internal.h"

static void
nvmf_init_sqe(void *sqe, uint8_t opcode)
{
	struct nvme_command *cmd = sqe;

	memset(cmd, 0, sizeof(*cmd));
	cmd->opc = opcode;
}

static void
nvmf_init_fabrics_sqe(void *sqe, uint8_t fctype)
{
	struct nvmf_capsule_cmd *cmd = sqe;

	nvmf_init_sqe(sqe, NVME_OPC_FABRIC);
	cmd->fctype = fctype;
}

struct nvmf_qpair *
nvmf_connect(struct nvmf_association *na,
    const struct nvmf_qpair_params *params, uint16_t qid, u_int queue_size,
    const uint8_t hostid[16], uint16_t cntlid, const char *subnqn,
    const char *hostnqn, uint32_t kato)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_fabric_connect_data data;
	const struct nvmf_fabric_connect_rsp *rsp;
	struct nvmf_qpair *qp;
	struct nvmf_capsule *ncap, *rcap;
	int error;
	uint16_t sqhd, status;

	qp = NULL;
	ncap = NULL;
	rcap = NULL;
	if (na->na_controller) {
		na_error(na, "Cannot connect on a controller");
		goto error;
	}

	if (params->admin != (qid == 0)) {
		na_error(na, "Admin queue must use Queue ID 0");
		goto error;
	}

	if (qid == 0) {
		if (queue_size < NVME_MIN_ADMIN_ENTRIES ||
		    queue_size > NVME_MAX_ADMIN_ENTRIES) {
			na_error(na, "Invalid queue size %u", queue_size);
			goto error;
		}
	} else {
		if (queue_size < NVME_MIN_IO_ENTRIES ||
		    queue_size > NVME_MAX_IO_ENTRIES) {
			na_error(na, "Invalid queue size %u", queue_size);
			goto error;
		}

		/* KATO is only for Admin queues. */
		if (kato != 0) {
			na_error(na, "Cannot set KATO on I/O queues");
			goto error;
		}
	}

	qp = nvmf_allocate_qpair(na, params);
	if (qp == NULL)
		goto error;

	nvmf_init_fabrics_sqe(&cmd, NVMF_FABRIC_COMMAND_CONNECT);
	cmd.recfmt = 0;
	cmd.qid = htole16(qid);

	/* N.B. sqsize is 0's based. */
	cmd.sqsize = htole16(queue_size - 1);
	if (!na->na_params.sq_flow_control)
		cmd.cattr |= NVMF_CONNECT_ATTR_DISABLE_SQ_FC;
	cmd.kato = htole32(kato);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL) {
		na_error(na, "Failed to allocate command capsule: %s",
		    strerror(errno));
		goto error;
	}

	memset(&data, 0, sizeof(data));
	memcpy(data.hostid, hostid, sizeof(data.hostid));
	data.cntlid = htole16(cntlid);
	strlcpy(data.subnqn, subnqn, sizeof(data.subnqn));
	strlcpy(data.hostnqn, hostnqn, sizeof(data.hostnqn));

	error = nvmf_capsule_append_data(ncap, &data, sizeof(data), true);
	if (error != 0) {
		na_error(na, "Failed to append data to CONNECT capsule: %s",
		    strerror(error));
		goto error;
	}

	error = nvmf_transmit_capsule(ncap);
	if (error != 0) {
		na_error(na, "Failed to transmit CONNECT capsule: %s",
		    strerror(errno));
		goto error;
	}

	error = nvmf_receive_capsule(qp, &rcap);
	if (error != 0) {
		na_error(na, "Failed to receive CONNECT response: %s",
		    strerror(error));
		goto error;
	}

	rsp = (const struct nvmf_fabric_connect_rsp *)&rcap->nc_cqe;
	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		if (NVME_STATUS_GET_SC(status) == NVMF_FABRIC_SC_INVALID_PARAM)
			na_error(na,
			    "CONNECT invalid parameter IATTR: %#x IPO: %#x",
			    rsp->status_code_specific.invalid.iattr,
			    rsp->status_code_specific.invalid.ipo);
		else
			na_error(na, "CONNECT failed, status %#x", status);
		goto error;
	}

	if (rcap->nc_cqe.cid != cmd.cid) {
		na_error(na, "Mismatched CID in CONNECT response");
		goto error;
	}

	if (!rcap->nc_sqhd_valid) {
		na_error(na, "CONNECT response without valid SQHD");
		goto error;
	}

	sqhd = le16toh(rsp->sqhd);
	if (sqhd == 0xffff) {
		if (na->na_params.sq_flow_control) {
			na_error(na, "Controller disabled SQ flow control");
			goto error;
		}
		qp->nq_flow_control = false;
	} else {
		qp->nq_flow_control = true;
		qp->nq_sqhd = sqhd;
		qp->nq_sqtail = sqhd;
	}

	if (rsp->status_code_specific.success.authreq) {
		na_error(na, "CONNECT response requests authentication\n");
		goto error;
	}

	qp->nq_qsize = queue_size;
	qp->nq_cntlid = le16toh(rsp->status_code_specific.success.cntlid);
	qp->nq_kato = kato;
	/* XXX: Save qid in qp? */
	return (qp);

error:
	if (rcap != NULL)
		nvmf_free_capsule(rcap);
	if (ncap != NULL)
		nvmf_free_capsule(ncap);
	if (qp != NULL)
		nvmf_free_qpair(qp);
	return (NULL);
}

uint16_t
nvmf_cntlid(struct nvmf_qpair *qp)
{
	return (qp->nq_cntlid);
}

int
nvmf_host_transmit_command(struct nvmf_capsule *ncap)
{
	struct nvmf_qpair *qp = ncap->nc_qpair;
	uint16_t new_sqtail;
	int error;

	/* Fail if the queue is full. */
	new_sqtail = (qp->nq_sqtail + 1) % qp->nq_qsize;
	if (new_sqtail == qp->nq_sqhd)
		return (EBUSY);

	ncap->nc_sqe.cid = htole16(qp->nq_cid);

	/* 4.2 Skip CID of 0xFFFF. */
	qp->nq_cid++;
	if (qp->nq_cid == 0xFFFF)
		qp->nq_cid = 0;

	error = nvmf_transmit_capsule(ncap);
	if (error != 0)
		return (error);

	qp->nq_sqtail = new_sqtail;
	return (0);
}

/* Receive a single capsule and update SQ FC accounting. */
static int
nvmf_host_receive_capsule(struct nvmf_qpair *qp, struct nvmf_capsule **rcapp)
{
	struct nvmf_capsule *rcap;
	int error;

	/* If the SQ is empty, there is no response to wait for. */
	if (qp->nq_sqhd == qp->nq_sqtail)
		return (EWOULDBLOCK);

	error = nvmf_receive_capsule(qp, &rcap);
	if (error != 0)
		return (error);

	if (qp->nq_flow_control) {
		if (rcap->nc_sqhd_valid)
			qp->nq_sqhd = le16toh(rcap->nc_cqe.sqhd);
	} else {
		/*
		 * If SQ FC is disabled, just advance the head for
		 * each response capsule received so that we track the
		 * number of outstanding commands.
		 */
		qp->nq_sqhd = (qp->nq_sqhd + 1) % qp->nq_qsize;
	}
	*rcapp = rcap;
	return (0);
}

int
nvmf_host_receive_response(struct nvmf_qpair *qp, struct nvmf_capsule **rcapp)
{
	struct nvmf_capsule *rcap;

	/* Return the oldest previously received response. */
	if (!TAILQ_EMPTY(&qp->nq_rx_capsules)) {
		rcap = TAILQ_FIRST(&qp->nq_rx_capsules);
		TAILQ_REMOVE(&qp->nq_rx_capsules, rcap, nc_link);
		*rcapp = rcap;
		return (0);
	}

	return (nvmf_host_receive_capsule(qp, rcapp));
}

int
nvmf_host_wait_for_response(struct nvmf_capsule *ncap,
    struct nvmf_capsule **rcapp)
{
	struct nvmf_qpair *qp = ncap->nc_qpair;
	struct nvmf_capsule *rcap;
	int error;

	/* Check if a response was already received. */
	TAILQ_FOREACH(rcap, &qp->nq_rx_capsules, nc_link) {
		if (rcap->nc_cqe.cid == ncap->nc_sqe.cid) {
			TAILQ_REMOVE(&qp->nq_rx_capsules, rcap, nc_link);
			*rcapp = rcap;
			return (0);
		}
	}

	/* Wait for a response. */
	for (;;) {
		error = nvmf_host_receive_capsule(qp, &rcap);
		if (error != 0)
			return (error);

		if (rcap->nc_cqe.cid != ncap->nc_sqe.cid) {
			TAILQ_INSERT_TAIL(&qp->nq_rx_capsules, rcap, nc_link);
			continue;
		}

		*rcapp = rcap;
		return (0);
	}
}

struct nvmf_capsule *
nvmf_keepalive(struct nvmf_qpair *qp)
{
	struct nvme_command cmd;

	if (!qp->nq_admin) {
		errno = EINVAL;
		return (NULL);
	}

	nvmf_init_sqe(&cmd, NVME_OPC_KEEP_ALIVE);

	return (nvmf_allocate_command(qp, &cmd));
}

static struct nvmf_capsule *
nvmf_get_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size)
{
	struct nvmf_fabric_prop_get_cmd cmd;

	nvmf_init_fabrics_sqe(&cmd, NVMF_FABRIC_COMMAND_PROPERTY_GET);
	switch (size) {
	case 4:
		cmd.attrib.size = NVMF_PROP_SIZE_4;
		break;
	case 8:
		cmd.attrib.size = NVMF_PROP_SIZE_8;
		break;
	default:
		errno = EINVAL;
		return (NULL);
	}
	cmd.ofst = htole32(offset);

	return (nvmf_allocate_command(qp, &cmd));
}

int
nvmf_read_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size,
    uint64_t *value)
{
	struct nvmf_capsule *ncap, *rcap;
	const struct nvmf_fabric_prop_get_rsp *rsp;
	uint16_t status;
	int error;

	if (!qp->nq_admin)
		return (EINVAL);

	ncap = nvmf_get_property(qp, offset, size);
	if (ncap == NULL)
		return (errno);

	error = nvmf_host_transmit_command(ncap);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	rsp = (const struct nvmf_fabric_prop_get_rsp *)&rcap->nc_cqe;
	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: PROPERTY_GET failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	if (size == 8)
		*value = le64toh(rsp->value.u64);
	else
		*value = le32toh(rsp->value.u32.low);
	nvmf_free_capsule(rcap);
	return (0);
}

static struct nvmf_capsule *
nvmf_set_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size,
    uint64_t value)
{
	struct nvmf_fabric_prop_set_cmd cmd;

	nvmf_init_fabrics_sqe(&cmd, NVMF_FABRIC_COMMAND_PROPERTY_SET);
	switch (size) {
	case 4:
		cmd.attrib.size = NVMF_PROP_SIZE_4;
		cmd.value.u32.low = htole32(value);
		break;
	case 8:
		cmd.attrib.size = NVMF_PROP_SIZE_8;
		cmd.value.u64 = htole64(value);
		break;
	default:
		errno = EINVAL;
		return (NULL);
	}
	cmd.ofst = htole32(offset);

	return (nvmf_allocate_command(qp, &cmd));
}

int
nvmf_write_property(struct nvmf_qpair *qp, uint32_t offset, uint8_t size,
    uint64_t value)
{
	struct nvmf_capsule *ncap, *rcap;
	uint16_t status;
	int error;

	if (!qp->nq_admin)
		return (EINVAL);

	ncap = nvmf_set_property(qp, offset, size, value);
	if (ncap == NULL)
		return (errno);

	error = nvmf_host_transmit_command(ncap);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: PROPERTY_SET failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	nvmf_free_capsule(rcap);
	return (0);
}

int
nvmf_hostid_from_hostuuid(uint8_t hostid[16])
{
	char hostuuid_str[64];
	uuid_t hostuuid;
	size_t len;
	uint32_t status;

	len = sizeof(hostuuid_str);
	if (sysctlbyname("kern.hostuuid", hostuuid_str, &len, NULL, 0) != 0)
		return (errno);

	uuid_from_string(hostuuid_str, &hostuuid, &status);
	switch (status) {
	case uuid_s_ok:
		break;
	case uuid_s_no_memory:
		return (ENOMEM);
	default:
		return (EINVAL);
	}

	uuid_enc_le(hostid, &hostuuid);
	return (0);
}

int
nvmf_nqn_from_hostuuid(char nqn[NVMF_NQN_MAX_LEN])
{
	char hostuuid_str[64];
	size_t len;

	len = sizeof(hostuuid_str);
	if (sysctlbyname("kern.hostuuid", hostuuid_str, &len, NULL, 0) != 0)
		return (errno);

	strlcpy(nqn, NVMF_NQN_UUID_PRE, NVMF_NQN_MAX_LEN);
	strlcat(nqn, hostuuid_str, NVMF_NQN_MAX_LEN);
	return (0);
}

int
nvmf_host_identify_controller(struct nvmf_qpair *qp,
    struct nvme_controller_data *cdata)
{
	struct nvme_command cmd;
	struct nvmf_capsule *ncap, *rcap;
	int error;
	uint16_t status;

	if (!qp->nq_admin)
		return (EINVAL);

	nvmf_init_sqe(&cmd, NVME_OPC_IDENTIFY);

	/* 5.15.1 Use CNS of 0x01 for controller data. */
	cmd.cdw10 = htole32(1);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL)
		return (errno);

	error = nvmf_capsule_append_data(ncap, cdata, sizeof(*cdata), false);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_transmit_command(ncap);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: IDENTIFY failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	nvmf_free_capsule(rcap);
	return (0);
}

int
nvmf_host_identify_namespace(struct nvmf_qpair *qp, uint32_t nsid,
    struct nvme_namespace_data *nsdata)
{
	struct nvme_command cmd;
	struct nvmf_capsule *ncap, *rcap;
	int error;
	uint16_t status;

	if (!qp->nq_admin)
		return (EINVAL);

	nvmf_init_sqe(&cmd, NVME_OPC_IDENTIFY);

	/* 5.15.1 Use CNS of 0x00 for namespace data. */
	cmd.cdw10 = htole32(0);
	cmd.nsid = htole32(nsid);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL)
		return (errno);

	error = nvmf_capsule_append_data(ncap, nsdata, sizeof(*nsdata), false);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_transmit_command(ncap);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: IDENTIFY failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	nvmf_free_capsule(rcap);
	return (0);
}

static int
nvmf_get_discovery_log_page(struct nvmf_qpair *qp, uint64_t offset, void *buf,
    size_t len)
{
	struct nvme_command cmd;
	struct nvmf_capsule *ncap, *rcap;
	size_t numd;
	int error;
	uint16_t status;

	if (len % 4 != 0 || len == 0 || offset % 4 != 0)
		return (EINVAL);

	numd = (len / 4) - 1;
	nvmf_init_sqe(&cmd, NVME_OPC_GET_LOG_PAGE);
	cmd.cdw10 = htole32(numd << 16 | NVME_LOG_DISCOVERY);
	cmd.cdw11 = htole32(numd >> 16);
	cmd.cdw12 = htole32(offset);
	cmd.cdw13 = htole32(offset >> 32);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL)
		return (errno);

	error = nvmf_capsule_append_data(ncap, buf, len, false);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_transmit_command(ncap);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	status = le16toh(rcap->nc_cqe.status);
	if (NVMEV(NVME_STATUS_SC, status) ==
	    NVMF_FABRIC_SC_LOG_RESTART_DISCOVERY) {
		nvmf_free_capsule(rcap);
		return (EAGAIN);
	}
	if (status != 0) {
		printf("NVMF: GET_LOG_PAGE failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	nvmf_free_capsule(rcap);
	return (0);
}

int
nvmf_host_fetch_discovery_log_page(struct nvmf_qpair *qp,
    struct nvme_discovery_log **logp)
{
	struct nvme_discovery_log hdr, *log;
	size_t payload_len;
	int error;

	if (!qp->nq_admin)
		return (EINVAL);

	log = NULL;
	for (;;) {
		error = nvmf_get_discovery_log_page(qp, 0, &hdr, sizeof(hdr));
		if (error != 0)
			return (error);
		nvme_discovery_log_swapbytes(&hdr);

		if (hdr.recfmt != 0) {
			printf("NVMF: Unsupported discovery log format: %d\n",
			    hdr.recfmt);
			return (EINVAL);
		}

		if (hdr.numrec > 1024) {
			printf("NVMF: Too many discovery log entries: %ju\n",
			    (uintmax_t)hdr.numrec);
			return (EFBIG);
		}

		payload_len = sizeof(log->entries[0]) * hdr.numrec;
		log = reallocf(log, sizeof(*log) + payload_len);
		if (log == NULL)
			return (ENOMEM);
		*log = hdr;
		if (hdr.numrec == 0)
			break;

		error = nvmf_get_discovery_log_page(qp, sizeof(hdr),
		    log->entries, payload_len);
		if (error == EAGAIN)
			continue;
		if (error != 0) {
			free(log);
			return (error);
		}

		/* Re-read the header and check the generation count. */
		error = nvmf_get_discovery_log_page(qp, 0, &hdr, sizeof(hdr));
		if (error != 0) {
			free(log);
			return (error);
		}
		nvme_discovery_log_swapbytes(&hdr);

		if (log->genctr != hdr.genctr)
			continue;

		for (u_int i = 0; i < log->numrec; i++)
			nvme_discovery_log_entry_swapbytes(&log->entries[i]);
		break;
	}
	*logp = log;
	return (0);
}

int
nvmf_host_request_queues(struct nvmf_qpair *qp, u_int requested, u_int *actual)
{
	struct nvme_command cmd;
	struct nvmf_capsule *ncap, *rcap;
	int error;
	uint16_t status;

	if (!qp->nq_admin || requested < 1 || requested > 65535)
		return (EINVAL);

	/* The number of queues is 0's based. */
	requested--;

	nvmf_init_sqe(&cmd, NVME_OPC_SET_FEATURES);
	cmd.cdw10 = htole32(NVME_FEAT_NUMBER_OF_QUEUES);

	/* Same number of completion and submission queues. */
	cmd.cdw11 = htole32((requested << 16) | requested);

	ncap = nvmf_allocate_command(qp, &cmd);
	if (ncap == NULL)
		return (errno);

	error = nvmf_host_transmit_command(ncap);
	if (error != 0) {
		nvmf_free_capsule(ncap);
		return (error);
	}

	error = nvmf_host_wait_for_response(ncap, &rcap);
	nvmf_free_capsule(ncap);
	if (error != 0)
		return (error);

	status = le16toh(rcap->nc_cqe.status);
	if (status != 0) {
		printf("NVMF: SET_FEATURES failed, status %#x\n", status);
		nvmf_free_capsule(rcap);
		return (EIO);
	}

	*actual = le32toh(rcap->nc_cqe.cdw0) & 0xffff;
	nvmf_free_capsule(rcap);
	return (0);
}

static bool
is_queue_pair_idle(struct nvmf_qpair *qp)
{
	if (qp->nq_sqhd != qp->nq_sqtail)
		return (false);
	if (!TAILQ_EMPTY(&qp->nq_rx_capsules))
		return (false);
	return (true);
}

static int
prepare_queues_for_handoff(struct nvmf_handoff_host *hh,
    struct nvmf_qpair *admin_qp, u_int num_queues,
    struct nvmf_qpair **io_queues, const struct nvme_controller_data *cdata)
{
	struct nvmf_handoff_qpair_params *io;
	u_int i;
	int error;

	memset(hh, 0, sizeof(*hh));

	/* All queue pairs must be idle. */
	if (!is_queue_pair_idle(admin_qp))
		return (EBUSY);
	for (i = 0; i < num_queues; i++) {
		if (!is_queue_pair_idle(io_queues[i]))
			return (EBUSY);
	}

	/* First, the admin queue. */
	hh->trtype = admin_qp->nq_association->na_trtype;
	hh->kato = admin_qp->nq_kato;
	error = nvmf_kernel_handoff_params(admin_qp, &hh->admin);
	if (error)
		return (error);

	/* Next, the I/O queues. */
	hh->num_io_queues = num_queues;
	io = calloc(num_queues, sizeof(*io));
	for (i = 0; i < num_queues; i++) {
		error = nvmf_kernel_handoff_params(io_queues[i], &io[i]);
		if (error) {
			free(io);
			return (error);
		}
	}

	hh->io = io;
	hh->cdata = cdata;
	return (0);
}

int
nvmf_handoff_host(struct nvmf_qpair *admin_qp, u_int num_queues,
    struct nvmf_qpair **io_queues, const struct nvme_controller_data *cdata)
{
	struct nvmf_handoff_host hh;
	u_int i;
	int error, fd;

	fd = open("/dev/nvmf", O_RDWR);
	if (fd == -1) {
		error = errno;
		goto out;
	}

	error = prepare_queues_for_handoff(&hh, admin_qp, num_queues, io_queues,
	    cdata);
	if (error != 0)
		goto out;

	if (ioctl(fd, NVMF_HANDOFF_HOST, &hh) == -1)
		error = errno;
	free(hh.io);

out:
	if (fd >= 0)
		close(fd);
	for (i = 0; i < num_queues; i++)
		(void)nvmf_free_qpair(io_queues[i]);
	(void)nvmf_free_qpair(admin_qp);
	return (error);
}

int
nvmf_reconnect_host(int fd, struct nvmf_qpair *admin_qp, u_int num_queues,
    struct nvmf_qpair **io_queues, const struct nvme_controller_data *cdata)
{
	struct nvmf_handoff_host hh;
	u_int i;
	int error;

	error = prepare_queues_for_handoff(&hh, admin_qp, num_queues, io_queues,
	    cdata);
	if (error != 0)
		goto out;

	if (ioctl(fd, NVMF_RECONNECT_HOST, &hh) == -1)
		error = errno;
	free(hh.io);

out:
	for (i = 0; i < num_queues; i++)
		(void)nvmf_free_qpair(io_queues[i]);
	(void)nvmf_free_qpair(admin_qp);
	return (error);
}
