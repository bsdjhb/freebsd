/*-
 * Copyright (c) 2022-2023 Chelsio Communications, Inc.
 * All rights reserved.
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

#include <sys/endian.h>
#include <sys/gsb_crc32.h>
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnvmf.h"
#include "internal.h"

struct nvmf_tcp_connection {
	struct nvmf_connection nc;

	int s;
};

#define	TCONN(nc)	((struct nvmf_tcp_connection *)(nc))

static void
nvmf_tcp_report_error(int s, bool controller, uint16_t fes, uint32_t fei,
    void *rx_pdu, size_t pdu_len, u_int hlen)
{
	struct nvme_tcp_term_req_hdr hdr;
	struct iovec iov[2];

	if (hlen != 0) {
		if (hlen > NVME_TCP_TERM_REQ_ERROR_DATA_MAX_SIZE)
			hlen = NVME_TCP_TERM_REQ_ERROR_DATA_MAX_SIZE;
		if (hlen > pdu_len)
			hlen = pdu_len;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.common.pdu_type = controller ? NVME_TCP_PDU_TYPE_C2H_TERM_REQ :
	    NVME_TCP_PDU_TYPE_H2C_TERM_REQ;
	hdr.common.hlen = sizeof(hdr);
	hdr.common.plen = sizeof(hdr) + hlen;
	hdr.fes = htole16(fes);
	le32enc(hdr.fei, fei);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = rx_pdu;
	iov[1].iov_len = hlen;

	(void)writev(s, iov, nitems(iov));
}

static int
nvmf_tcp_validate_pdu(struct nvmf_tcp_connection *ntc,
    struct nvme_tcp_common_pdu_hdr *ch, size_t pdu_len)
{
	uint32_t data_len, plen;
	uint32_t digest, rx_digest;
	u_int full_hlen, hlen, expected_hlen;
	uint8_t valid_flags;

	/* Determine how large of a PDU header to return for errors. */
	hlen = ch->hlen;
	plen = le32toh(ch->plen);
	if (hlen < sizeof(*ch) || hlen > plen)
		hlen = sizeof(*ch);

	/*
	 * Errors must be reported for the lowest incorrect field
	 * first, so validate fields in order.
	 */

	/* Validate pdu_type. */

	/* Controllers only receive PDUs with a PDU direction of 0. */
	if (ntc->nc.nc_controller != (ch->pdu_type & 0x01) == 0) {
		printf("NVMe/TCP: Invalid PDU type %u\n", ch->pdu_type);
		nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	switch (ch->pdu_type) {
	case NVME_TCP_PDU_TYPE_IC_REQ:
	case NVME_TCP_PDU_TYPE_IC_RESP:
		/* Shouldn't get these for an established connection. */
		printf("NVMe/TCP: Received Initialize Connection PDU\n");
		nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		/*
		 * 7.4.7 Termination requests with invalid PDU lengths
		 * result in an immediate connection termination
		 * without reporting an error.
		 */
		if (plen < sizeof(struct nvme_tcp_term_req_hdr) ||
		    plen > NVME_TCP_TERM_REQ_PDU_MAX_SIZE) {
			printf("NVMe/TCP: Received invalid termination request\n");
			return (ECONNRESET);
		}
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
	case NVME_TCP_PDU_TYPE_H2C_DATA:
	case NVME_TCP_PDU_TYPE_C2H_DATA:
	case NVME_TCP_PDU_TYPE_R2T:
		break;
	default:
		printf("NVMe/TCP: Invalid PDU type %u\n", ch->pdu_type);
		nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Validate flags. */
	switch (ch->pdu_type) {
	default:
		__unreachable();
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		valid_flags = NVME_TCP_CH_FLAGS_HDGSTF |
		    NVME_TCP_CH_FLAGS_DDGSTF;
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
	case NVME_TCP_PDU_TYPE_R2T:
		valid_flags = NVME_TCP_CH_FLAGS_HDGSTF;
		break;
	case NVME_TCP_PDU_TYPE_H2C_DATA:
		valid_flags = NVME_TCP_CH_FLAGS_HDGSTF |
		    NVME_TCP_CH_FLAGS_DDGSTF | NVME_TCP_H2C_DATA_FLAGS_LAST_PDU;
		break;
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		valid_flags = NVME_TCP_CH_FLAGS_HDGSTF |
		    NVME_TCP_CH_FLAGS_DDGSTF | NVME_TCP_C2H_DATA_FLAGS_LAST_PDU |
		    NVME_TCP_C2H_DATA_FLAGS_SUCCESS;
		break;
	}
	if ((ch->flags & ~valid_flags) != 0) {
		printf("NVMe/TCP: Invalid PDU header flags %#x\n", ch->flags);
		nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 1, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Validate hlen. */
	switch (ch->pdu_type) {
	default:
		__unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		expected_hlen = sizeof(struct nvme_tcp_term_req_hdr);
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		expected_hlen = sizeof(struct nvme_tcp_cmd);
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
		expected_hlen = sizeof(struct nvme_tcp_rsp);
		break;
	case NVME_TCP_PDU_TYPE_H2C_DATA:
		expected_hlen = sizeof(struct nvme_tcp_h2c_data_hdr);
		break;
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		expected_hlen = sizeof(struct nvme_tcp_c2h_data_hdr);
		break;
	case NVME_TCP_PDU_TYPE_R2T:
		expected_hlen = sizeof(struct nvme_tcp_r2t_hdr);
		break;
	}
	if (ch->hlen != expected_hlen) {
		printf("NVMe/TCP: Invalid PDU header length %u\n", ch->hlen);
		nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 2, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Validate pdo. */
	full_hlen = ch->hlen;
	if ((ch->flags & NVME_TCP_CH_FLAGS_HDGSTF) != 0)
		full_hlen += sizeof(rx_digest);
	switch (ch->pdu_type) {
	default:
		__unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
	case NVME_TCP_PDU_TYPE_R2T:
		if (ch->pdo != 0) {
			printf("NVMe/TCP: Invalid PDU data offset %u\n",
			    ch->pdo);
			nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, ch,
			    pdu_len, hlen);
			return (EBADMSG);
		}
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
	case NVME_TCP_PDU_TYPE_H2C_DATA:
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		/* Permit PDO of 0 if there is no data. */
		if (full_hlen == plen && ch->pdo == 0)
			break;

		/* XXX: NVME_TCP_PDU_PDO_MAX_OFFSET? */
		/* XXX: Should verify against any PDA we advertised. */
		if (ch->pdo < full_hlen || ch->pdo > plen) {
			printf("NVMe/TCP: Invalid PDU data offset %u\n",
			    ch->pdo);
			nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, ch,
			    pdu_len, hlen);
			return (EBADMSG);
		}
		break;
	}

	/* Validate plen. */
	if (plen < ch->hlen) {
		printf("NVMe/TCP: Invalid PDU length %u\n", plen);
		nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	if (plen == full_hlen)
		data_len = 0;
	else
		data_len = plen - ch->pdo;
	switch (ch->pdu_type) {
	default:
		__unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		/* Checked above. */
		assert(plen <= NVME_TCP_TERM_REQ_PDU_MAX_SIZE);
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
	case NVME_TCP_PDU_TYPE_H2C_DATA:
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		if ((ch->flags & NVME_TCP_CH_FLAGS_DDGSTF) != 0 &&
		    data_len <= sizeof(rx_digest)) {
			printf("NVMe/TCP: PDU %u too short for digest\n",
			    ch->pdu_type);
			nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, ch,
			    pdu_len, hlen);
			return (EBADMSG);
		}
		break;
	case NVME_TCP_PDU_TYPE_R2T:
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
		if (data_len != 0) {
			printf("NVMe/TCP: PDU %u with data length %u\n",
			    ch->pdu_type, data_len);
			nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, ch,
			    pdu_len, hlen);
			return (EBADMSG);
		}
		break;
	}

	/* Check header digest if present. */
	if ((ch->flags & NVME_TCP_CH_FLAGS_HDGSTF) != 0) {
		digest = calculate_crc32c(0xffffffff, (void *)ch, ch->hlen);
		memcpy(&rx_digest, (char *)ch + ch->hlen, sizeof(rx_digest));
		if (digest != rx_digest) {
			printf("NVMe/TCP: Header digest mismatch\n");
			nvmf_tcp_report_error(ntc->s, ntc->nc.nc_controller,
			    NVME_TCP_TERM_REQ_FES_HDGST_ERROR, rx_digest, ch,
			    pdu_len, full_hlen);
			return (EBADMSG);
		}
	}

	/* Check data digest if present. */
	if ((ch->flags & NVME_TCP_CH_FLAGS_DDGSTF) != 0) {
		data_len -= sizeof(rx_digest);
		digest = calculate_crc32c(0xffffffff, (char *)ch + ch->pdo,
		    data_len);
		memcpy(&rx_digest, (char *)ch + plen - sizeof(rx_digest),
		    sizeof(rx_digest));
		if (digest != rx_digest) {
			printf("NVMe/TCP: Data digest mismatch\n");
			return (EBADMSG);
		}
	}

	return (0);
}

int
nvmf_tcp_read_pdu(struct nvmf_connection *nc,
    struct nvme_tcp_common_pdu_hdr **pdu)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc);
	struct nvme_tcp_common_pdu_hdr ch;
	ssize_t nread;
	uint32_t plen;
	int error;

	*pdu = NULL;
	nread = read(ntc->s, &ch, sizeof(ch));
	if (nread < 0)
		return (errno);
	if (nread == 0)
		return (0);
	if ((size_t)nread != sizeof(ch))
		return (EBADMSG);

	plen = le32toh(ch.plen);

	/*
	 * Validate a header with garbage lengths to trigger
	 * an error message without reading more.
	 */
	if (plen < sizeof(ch) || ch.hlen > plen) {
		error = nvmf_tcp_validate_pdu(ntc, &ch, sizeof(ch));
		assert(error != 0);
		return (error);
	}

	/* Read the rest of the PDU. */
	*pdu = malloc(plen);
	memcpy(*pdu, &ch, sizeof(ch));
	nread = read(ntc->s, (*pdu) + 1, plen - sizeof(ch));
	if (nread < 0)
		return (errno);
	if ((size_t)nread != plen - sizeof(ch))
		return (EBADMSG);
	error = nvmf_tcp_validate_pdu(ntc, *pdu, plen);
	if (error != 0) {
		free(*pdu);
		*pdu = NULL;
	}
	return (error);
}

static int
nvmf_tcp_validate_ic_pdu(int s, bool controller,
    struct nvme_tcp_common_pdu_hdr *ch, size_t pdu_len)
{
	uint32_t plen;
	u_int hlen;

	/* Determine how large of a PDU header to return for errors. */
	hlen = ch->hlen;
	plen = le32toh(ch->plen);
	if (hlen < sizeof(*ch) || hlen > plen)
		hlen = sizeof(*ch);

	/*
	 * Errors must be reported for the lowest incorrect field
	 * first, so validate fields in order.
	 */

	/* Validate pdu_type. */

	/* Controllers only receive PDUs with a PDU direction of 0. */
	if (controller != (ch->pdu_type & 0x01) == 0) {
		printf("NVMe/TCP: Invalid PDU type %u\n", ch->pdu_type);
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	switch (ch->pdu_type) {
	case NVME_TCP_PDU_TYPE_IC_REQ:
	case NVME_TCP_PDU_TYPE_IC_RESP:
		break;
	default:
		printf("NVMe/TCP: Invalid PDU type %u\n", ch->pdu_type);
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Validate flags. */
	if (ch->flags != 0) {
		printf("NVMe/TCP: Invalid PDU header flags %#x\n", ch->flags);
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 1, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Validate hlen. */
	if (ch->hlen != 128) {
		printf("NVMe/TCP: Invalid PDU header length %u\n", ch->hlen);
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 2, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Validate pdo. */
	if (ch->pdo != 0) {
		printf("NVMe/TCP: Invalid PDU data offset %u\n", ch->pdo);
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Validate plen. */
	if (plen != 128) {
		printf("NVMe/TCP: Invalid PDU length %u\n", plen);
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	return (0);
}

int
nvmf_tcp_read_ic_req(int s, struct nvme_tcp_ic_req *pdu)
{
	ssize_t nread;

	nread = read(s, pdu, sizeof(*pdu));
	if (nread < 0)
		return (errno);
	if (nread == 0)
		return (ECONNRESET);
	if ((size_t)nread != sizeof(*pdu))
		return (EBADMSG);

	return (nvmf_tcp_validate_ic_pdu(s, false, &pdu->common,
	    sizeof(*pdu)));	
}

int
nvmf_tcp_read_ic_resp(int s, struct nvme_tcp_ic_resp *pdu)
{
	ssize_t nread;

	nread = read(s, pdu, sizeof(*pdu));
	if (nread < 0)
		return (errno);
	if (nread == 0)
		return (ECONNRESET);
	if ((size_t)nread != sizeof(*pdu))
		return (EBADMSG);

	return (nvmf_tcp_validate_ic_pdu(s, true, &pdu->common, sizeof(*pdu)));	
}

static struct nvmf_connection *
tcp_allocate_connection(bool controller __unused,
    const union nvmf_connection_params *params)
{
	struct nvmf_tcp_connection *ntc;

	ntc = calloc(1, sizeof(*ntc));
	ntc->s = params->tcp.fd;

	return (&ntc->nc);
}

static void
tcp_free_connection(struct nvmf_connection *nc)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc);

	close(ntc->s);
	free(ntc);
}

static struct nvmf_qpair *
tcp_allocate_qpair(struct nvmf_connection *nc __unused)
{
	struct nvmf_qpair *qp;

	qp = calloc(1, sizeof(*qp));
	return (qp);
}

static void
tcp_free_qpair(struct nvmf_qpair *qp)
{
	free(qp);
}

static struct nvmf_capsule *
tcp_allocate_command(struct nvmf_qpair *qp __unused)
{
	struct nvmf_capsule *nc;

	nc = calloc(1, sizeof(*nc));
	nc->nc_qe_len = sizeof(struct nvmf_fabric_connect_cmd);
	nc->nc_qe = malloc(nc->nc_qe_len);
	return (nc);
}

static struct nvmf_capsule *
tcp_allocate_response(struct nvmf_qpair *qp __unused)
{
	struct nvmf_capsule *nc;

	nc = calloc(1, sizeof(*nc));
	nc->nc_qe_len = sizeof(struct nvmf_fabric_connect_rsp);
	nc->nc_qe = malloc(nc->nc_qe_len);
	return (nc);
}

static void
tcp_free_capsule(struct nvmf_capsule *nc)
{
	free(nc->nc_data);
	free(nc->nc_qe);
	free(nc);
}

static int
tcp_transmit_capsule(struct nvmf_capsule *nc __unused)
{
	/* TODO */
	return (EINVAL);
}

#if 0
static int
tcp_receive_capsule(struct nvmf_connection *nc, struct nvmf_capsule **nc)
{
	/* TODO */
}
#endif

struct nvmf_transport_ops tcp_ops = {
	.allocate_connection = tcp_allocate_connection,
	.free_connection = tcp_free_connection,
	.allocate_qpair = tcp_allocate_qpair,
	.free_qpair = tcp_free_qpair,
	.allocate_command = tcp_allocate_command,
	.allocate_response = tcp_allocate_response,
	.free_capsule = tcp_free_capsule,
	.transmit_capsule = tcp_transmit_capsule,
#if 0
	.receive_capsule = tcp_receive_capsule,
#endif
};
