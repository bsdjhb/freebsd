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
#include <sys/queue.h>
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnvmf.h"
#include "internal.h"

struct nvmf_tcp_qpair;

struct nvmf_tcp_buffer {
	struct nvmf_tcp_qpair *nb_qpair;

	struct iovec *nb_data_iov;
	u_int	nb_data_iovcnt;
	size_t	nb_data_len;
	size_t	nb_data_xfered;

	uint16_t nb_xferid;

	TAILQ_ENTRY(nvmf_tcp_buffer) link;
};

struct nvmf_tcp_connection {
	struct nvmf_connection nc;
	int s;

	uint8_t	txpda;
	uint8_t rxpda;
	bool header_digests;
	bool data_digests;
	union {
		uint32_t maxr2t;
		uint32_t maxh2cdata;
	};
	uint32_t max_io_icd;
};

struct nvmf_tcp_rxpdu {
	struct nvme_tcp_common_pdu_hdr *hdr;
	uint32_t data_len;
};

struct nvmf_tcp_capsule {
	struct nvmf_capsule nc;

	struct nvmf_tcp_rxpdu rx_pdu;

	TAILQ_ENTRY(nvmf_tcp_capsule) link;
};

struct nvmf_tcp_qpair {
	struct nvmf_qpair qp;

	uint32_t max_icd;
	uint16_t next_ttag;

	TAILQ_HEAD(, nvmf_tcp_buffer) tx_buffers;
	TAILQ_HEAD(, nvmf_tcp_buffer) rx_buffers;
	TAILQ_HEAD(, nvmf_tcp_capsule) rx_capsules;
};

#define	TCONN(nc)	((struct nvmf_tcp_connection *)(nc))
#define	TCAP(nc)	((struct nvmf_tcp_capsule *)(nc))
#define	TQP(qp)		((struct nvmf_tcp_qpair *)(qp))

static const char zero_padding[NVME_TCP_PDU_PDO_MAX_OFFSET];

static uint32_t
compute_digest_iov(const struct iovec *iov, u_int iovcnt)
{
	uint32_t digest;

	digest = 0xffffffff;
	while (iovcnt > 0) {
		digest = calculate_crc32c(digest, iov->iov_base, iov->iov_len);
		iov++;
		iovcnt--;
	}
	return (digest);
}

static uint32_t
compute_digest(const void *buf, size_t len)
{
	return (calculate_crc32c(0xffffffff, buf, len));
}

static void
nvmf_tcp_report_error(int s, bool controller, uint16_t fes, uint32_t fei,
    const void *rx_pdu, size_t pdu_len, u_int hlen)
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
	iov[1].iov_base = __DECONST(void *, rx_pdu);
	iov[1].iov_len = hlen;

	(void)writev(s, iov, nitems(iov));
}

static int
nvmf_tcp_validate_pdu(struct nvmf_tcp_connection *ntc,
    struct nvmf_tcp_rxpdu *pdu, size_t pdu_len)
{
	const struct nvme_tcp_common_pdu_hdr *ch;
	uint32_t data_len, plen;
	uint32_t digest, rx_digest;
	u_int full_hlen, hlen, expected_hlen;
	uint8_t valid_flags;

	/* Determine how large of a PDU header to return for errors. */
	ch = pdu->hdr;
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

		if (ch->pdo < full_hlen || ch->pdo > plen ||
		    ch->pdo % ntc->rxpda != 0) {
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
		digest = compute_digest(ch, ch->hlen);
		memcpy(&rx_digest, (const char *)ch + ch->hlen,
		    sizeof(rx_digest));
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
		digest = compute_digest((const char *)ch + ch->pdo, data_len);
		memcpy(&rx_digest, (const char *)ch + plen - sizeof(rx_digest),
		    sizeof(rx_digest));
		if (digest != rx_digest) {
			printf("NVMe/TCP: Data digest mismatch\n");
			return (EBADMSG);
		}
	}

	pdu->data_len = data_len;
	return (0);
}

static int
nvmf_tcp_read_pdu(struct nvmf_connection *nc, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc);
	struct nvme_tcp_common_pdu_hdr ch;
	ssize_t nread;
	uint32_t plen;
	int error;

	memset(pdu, 0, sizeof(*pdu));
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
		pdu->hdr = &ch;
		error = nvmf_tcp_validate_pdu(ntc, pdu, sizeof(ch));
		pdu->hdr = NULL;
		assert(error != 0);
		return (error);
	}

	/* Read the rest of the PDU. */
	pdu->hdr = malloc(plen);
	memcpy(pdu->hdr, &ch, sizeof(ch));
	nread = read(ntc->s, pdu->hdr + 1, plen - sizeof(ch));
	if (nread < 0)
		return (errno);
	if ((size_t)nread != plen - sizeof(ch))
		return (EBADMSG);
	error = nvmf_tcp_validate_pdu(ntc, pdu, plen);
	if (error != 0) {
		free(pdu->hdr);
		pdu->hdr = NULL;
	}
	return (error);
}

static int
nvmf_tcp_save_command_capsule(struct nvmf_tcp_qpair *qp,
    struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_cmd *cmd;
	struct nvme_sgl_descriptor *sgl;
	struct nvmf_capsule *nc;
	struct nvmf_tcp_capsule *tc;

	cmd = (void *)pdu->hdr;

	nc = nvmf_allocate_command(&qp->qp, &cmd->ccsqe);
	if (nc == NULL)
		return (ENOMEM);

	tc = TCAP(nc);
	tc->rx_pdu = *pdu;

	if (NVMEV(NVME_CMD_PSDT, nc->nc_sqe.fuse) == NVME_PSDT_SGL) {
		/* TODO: Validate SGL, reject invalid SGL with SGL DESCRIPTOR TYPE INVALID */
		sgl = (struct nvme_sgl_descriptor *)&cmd->ccsqe.prp1;
		if (sgl->address != 0 ||
		    sgl->unkeyed.type != NVME_SGL_TYPE_DATA_BLOCK) {
			printf("NVMe/TCP: Invalid SGL in Command Capsule\n");
			/* TODO: Send back failure response. */
			nvmf_free_capsule(nc);
			return (0);
		}

		switch (sgl->unkeyed.subtype) {
		case NVME_SGL_SUBTYPE_OFFSET:
			if (pdu->data_len == 0) {
				printf("NVMe/TCP: In-capsule SGL in Command Capsule without data\n");
				/* TODO: Send back failure response. */
				nvmf_free_capsule(nc);
				return (0);
			}
			if (pdu->data_len != le32toh(sgl->unkeyed.length)) {
				printf("NVMe/TCP: Command Capsule with mismatched ICD length\n");
				/* TODO: Send back failure response. */
				nvmf_free_capsule(nc);
				return (0);
			}
			break;
		case NVME_SGL_SUBTYPE_TRANSPORT:
			if (pdu->data_len != 0) {
				printf("NVMe/TCP: Command Buffer SGL with ICD\n");
				/* TODO: Send back failure response. */
				nvmf_free_capsule(nc);
				return (0);
			}
			break;
		default:
			printf("NVMe/TCP: Invalid SGL in Command Capsule\n");
			/* TODO: Send back failure response. */
			nvmf_free_capsule(nc);
			return (0);
		}
	} else if (pdu->data_len != 0) {
		printf("NVMe/TCP: Command Capsule without SGL with data\n");
		/* TODO: Send back failure response. */
		nvmf_free_capsule(nc);
		return (0);
	}

	TAILQ_INSERT_TAIL(&qp->rx_capsules, tc, link);
	return (0);
}

static int
nvmf_tcp_receive_pdu(struct nvmf_tcp_qpair *qp)
{
	struct nvmf_tcp_rxpdu pdu;
	int error;

	error = nvmf_tcp_read_pdu(qp->qp.nq_connection, &pdu);
	if (error != 0)
		return (error);

	switch (pdu.hdr->pdu_type) {
	default:
		__unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		return (ECONNRESET);
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		return (nvmf_tcp_save_command_capsule(qp, &pdu));
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
	case NVME_TCP_PDU_TYPE_H2C_DATA:
	case NVME_TCP_PDU_TYPE_C2H_DATA:
	case NVME_TCP_PDU_TYPE_R2T:
		return (EDOOFUS);
	}
}

static int
nvmf_tcp_validate_ic_pdu(int s, bool controller,
    const struct nvme_tcp_common_pdu_hdr *ch, size_t pdu_len)
{
	const struct nvme_tcp_ic_req *pdu;
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

	/* Validate fields common to both ICReq and ICResp. */
	pdu = (const struct nvme_tcp_ic_req *)ch;
	if (le16toh(pdu->pfv) != 0) {
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER,
		    8, ch, pdu_len, hlen);
		return (EBADMSG);
	}

	if (pdu->hpda > NVME_TCP_CPDA_MAX) {
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 10, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	if (pdu->dgst.bits.reserved != 0) {
		nvmf_tcp_report_error(s, controller,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 11, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	return (0);
}

static int
nvmf_tcp_write_pdu(int s, void *pdu, size_t len)
{
	ssize_t nwritten;

	nwritten = write(s, pdu, len);
	if (nwritten < 0)
		return (errno);
	if ((size_t)nwritten != len)
		return (ECONNRESET);
	return (0);
}

static int
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

static int
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

	if (params->ioccsz < 4)
		return (NULL);

	ntc = calloc(1, sizeof(*ntc));
	ntc->s = params->tcp.fd;
	ntc->max_io_icd = (params->ioccsz - 4) * 16;

	return (&ntc->nc);
}

static int
tcp_connect(struct nvmf_connection *nc,
    const union nvmf_connection_params *params)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc);
	struct nvme_tcp_ic_req ic_req;
	struct nvme_tcp_ic_resp ic_resp;
	int error;

	if (!nc->nc_controller)
		return (EINVAL);

	memset(&ic_req, 0, sizeof(ic_req));
	ic_req.common.pdu_type = NVME_TCP_PDU_TYPE_IC_REQ;
	ic_req.common.hlen = sizeof(ic_req);
	ic_req.common.plen = htole32(sizeof(ic_req));
	ic_req.pfv = htole16(0);
	ic_req.hpda = params->tcp.pda;
	if (params->tcp.header_digests)
		ic_req.dgst.bits.hdgst_enable = 1;
	if (params->tcp.data_digests)
		ic_req.dgst.bits.ddgst_enable = 1;
	ic_req.maxr2t = htole32(params->tcp.maxr2t);

	error = nvmf_tcp_write_pdu(ntc->s, &ic_req, sizeof(ic_req));
	if (error != 0)
		return (error);

	error = nvmf_tcp_read_ic_resp(ntc->s, &ic_resp);
	if (error != 0)
		return (error);

	/* Ensure the host didn't enable digests we didn't request. */
	if ((!params->tcp.header_digests &&
	    ic_resp.dgst.bits.hdgst_enable != 0) ||
	    (!params->tcp.data_digests &&
	    ic_resp.dgst.bits.ddgst_enable != 0)) {
		nvmf_tcp_report_error(ntc->s, true,
		    NVME_TCP_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER,
		    11, &ic_resp, sizeof(ic_resp), sizeof(ic_resp));
		return (EBADMSG);
	}

	/*
	 * XXX: Is there an upper-bound to enforce here?  Perhaps pick
	 * some large value and report larger values as an unsupported
	 * parameter?
	 */
	if (le32toh(ic_resp.maxh2cdata) < 4096) {
		nvmf_tcp_report_error(ntc->s, true,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 12, &ic_resp,
		    sizeof(ic_resp), sizeof(ic_resp));
		return (EBADMSG);
	}

	ntc->txpda = params->tcp.pda * 4;
	ntc->rxpda = ic_resp.cpda * 4;
	ntc->header_digests = ic_resp.dgst.bits.hdgst_enable != 0;
	ntc->data_digests = ic_resp.dgst.bits.ddgst_enable != 0;
	ntc->maxh2cdata = le32toh(ic_resp.maxh2cdata);
	return (0);
}

static int
tcp_accept(struct nvmf_connection *nc,
    const union nvmf_connection_params *params)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc);
	struct nvme_tcp_ic_req ic_req;
	struct nvme_tcp_ic_resp ic_resp;
	int error;

	if (nc->nc_controller)
		return (EINVAL);

	error = nvmf_tcp_read_ic_req(ntc->s, &ic_req);
	if (error != 0)
		return (error);

	memset(&ic_resp, 0, sizeof(ic_resp));
	ic_resp.common.pdu_type = NVME_TCP_PDU_TYPE_IC_RESP;
	ic_resp.common.hlen = sizeof(ic_req);
	ic_resp.common.plen = htole32(sizeof(ic_req));
	ic_resp.pfv = htole16(0);
	ic_resp.cpda = params->tcp.pda;
	if (params->tcp.header_digests && ic_req.dgst.bits.hdgst_enable != 0)
		ic_resp.dgst.bits.hdgst_enable = 1;
	if (params->tcp.data_digests && ic_req.dgst.bits.ddgst_enable != 0)
		ic_resp.dgst.bits.ddgst_enable = 1;
	ic_resp.maxh2cdata = htole32(params->tcp.maxh2cdata);

	error = nvmf_tcp_write_pdu(ntc->s, &ic_req, sizeof(ic_req));
	if (error != 0)
		return (error);

	ntc->txpda = params->tcp.pda * 4;
	ntc->rxpda = ic_req.hpda * 4;
	ntc->header_digests = ic_resp.dgst.bits.hdgst_enable != 0;
	ntc->data_digests = ic_resp.dgst.bits.ddgst_enable != 0;
	ntc->maxr2t = le32toh(ic_req.maxr2t);
	return (0);
}

static void
tcp_free_connection(struct nvmf_connection *nc)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc);

	close(ntc->s);
	free(ntc);
}

static struct nvmf_qpair *
tcp_allocate_qpair(struct nvmf_connection *nc, bool admin)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc);
	struct nvmf_tcp_qpair *qp;

	qp = calloc(1, sizeof(*qp));
	if (admin)
		/* 7.4.3 */
		qp->max_icd = 8192;
	else
		qp->max_icd = ntc->max_io_icd;
	TAILQ_INIT(&qp->rx_buffers);
	TAILQ_INIT(&qp->tx_buffers);

	return (&qp->qp);
}

static void
tcp_free_qpair(struct nvmf_qpair *qp)
{
	free(qp);
}

static struct nvmf_capsule *
tcp_allocate_capsule(struct nvmf_qpair *qp __unused)
{
	struct nvmf_tcp_capsule *nc;

	nc = calloc(1, sizeof(*nc));
	return (&nc->nc);
}

static void
tcp_free_capsule(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_capsule *tc = TCAP(nc);

	free(tc->rx_pdu.hdr);
	free(tc);
}

static struct nvmf_tcp_buffer *
tcp_alloc_command_buffer(struct nvmf_tcp_qpair *qp, struct iovec *iov,
    u_int iovcnt, size_t data_len, uint16_t xferid, bool receive)
{
	struct nvmf_tcp_buffer *nb;

	nb = malloc(sizeof(*nb));
	nb->nb_qpair = qp;
	nb->nb_data_iov = iov;
	nb->nb_data_iovcnt = iovcnt;
	nb->nb_data_len = data_len;
	nb->nb_data_xfered = 0;
	nb->nb_xferid = xferid;

	if (receive)
		TAILQ_INSERT_TAIL(&qp->rx_buffers, nb, link);
	else
		TAILQ_INSERT_TAIL(&qp->tx_buffers, nb, link);
	return (nb);
}

static int
tcp_transmit_command(struct nvmf_capsule *nc, bool send_data)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc->nc_qpair->nq_connection);
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct nvme_tcp_cmd cmd;
	struct nvme_command *sqe;
	struct iovec *iov, *iov2;
	ssize_t nwritten;
	uint32_t data_digest, header_digest, pad, plen;
	u_int iovcnt;
	bool use_icd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.common.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_CMD;
	if (ntc->header_digests)
		cmd.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
	cmd.common.hlen = sizeof(cmd);
	cmd.ccsqe = nc->nc_sqe;
	sqe = &cmd.ccsqe;
	plen = sizeof(cmd);
	iovcnt = 1;

	/* Populate SGL in SQE. */
	use_icd = false;
	if (nc->nc_data_len != 0) {
		struct nvme_sgl_descriptor *sgl;

		sgl = (struct nvme_sgl_descriptor *)&sqe->prp1;
		memset(sgl, 0, sizeof(*sgl));
		sgl->address = 0;
		sgl->unkeyed.length = htole32(nc->nc_data_len);
		sgl->unkeyed.type = NVME_SGL_TYPE_DATA_BLOCK;
		if (send_data && nc->nc_data_len <= qp->max_icd) {
			/* Use in-capsule data. */
			sgl->unkeyed.subtype = NVME_SGL_SUBTYPE_OFFSET;
			use_icd = true;
		} else {
			/* Use a command buffer. */
			sgl->unkeyed.subtype = NVME_SGL_SUBTYPE_TRANSPORT;
		}
		sqe->fuse &= ~NVMEB(NVME_CMD_PSDT);
		sqe->fuse |= NVME_PSDT_SGL << NVME_CMD_PSDT_SHIFT;
	}

	if (ntc->header_digests) {
		cmd.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(header_digest);
		iovcnt++;
	}

	pad = 0;
	if (use_icd) {
		if (ntc->txpda == 0)
			cmd.common.pdo = plen;
		else {
			cmd.common.pdo = roundup2(plen, ntc->txpda);
			pad = cmd.common.pdo - plen;
			if (pad != 0) {
				iovcnt++;
				plen += pad;
			}
		}

		iovcnt += nc->nc_data_iovcnt;
		if (ntc->data_digests) {
			cmd.common.flags |= NVME_TCP_CH_FLAGS_DDGSTF;
			plen += sizeof(data_digest);
			iovcnt++;

			data_digest = compute_digest_iov(nc->nc_data_iov,
			    nc->nc_data_iovcnt);
		}
	}

	cmd.common.plen = htole32(plen);
	if (ntc->header_digests)
		header_digest = compute_digest(&cmd, sizeof(cmd));

	iov = alloca(iovcnt * sizeof(*iov));
	iov2 = iov;

	/* CH + PSH */
	iov2->iov_base = &cmd;
	iov2->iov_len = sizeof(cmd);
	iov2++;

	/* HDGST */
	if (ntc->header_digests) {
		iov2->iov_base = &header_digest;
		iov2->iov_len = sizeof(header_digest);
		iov2++;
	}

	if (use_icd) {
		/* PAD */
		if (pad != 0) {
			iov2->iov_base = __DECONST(char *, zero_padding);
			iov2->iov_len = pad;
			iov2++;
		}

		/* DATA */
		memcpy(iov2, nc->nc_data_iov, nc->nc_data_iovcnt *
		    sizeof(*iov2));
		iov2 += nc->nc_data_iovcnt;

		/* DDGST */
		if (ntc->data_digests) {
			iov2->iov_base = &data_digest;
			iov2->iov_len = sizeof(data_digest);
			iov2++;
		}
	}

	/* Send command capsule. */
	nwritten = writev(ntc->s, iov, iovcnt);
	if (nwritten < 0)
		return (errno);
	if ((size_t)nwritten != plen)
		return (ECONNRESET);

	/*
	 * If data will be transferred using a command buffer, allocate a
	 * buffer structure and queue it.
	 */
	if (nc->nc_data_len != 0 && !use_icd)
		tcp_alloc_command_buffer(qp, nc->nc_data_iov,
		    nc->nc_data_iovcnt, nc->nc_data_len, sqe->cid, !send_data);

	return (0);
}

static int
tcp_transmit_response(struct nvmf_capsule *nc __unused)
{
	return (EINVAL);
}

static int
tcp_transmit_capsule(struct nvmf_capsule *nc, bool send_data)
{
	if (nc->nc_qe_len == sizeof(struct nvme_command))
		return (tcp_transmit_command(nc, send_data));
	else
		return (tcp_transmit_response(nc));
}

static int
tcp_receive_capsule(struct nvmf_qpair *nq __unused, struct nvmf_capsule **nc __unused)
{
	/* TODO */
	return (EOPNOTSUPP);
}

/* NB: cid and ttag are both in transport-order already. */
static int
tcp_send_r2t(struct nvmf_tcp_connection *ntc, uint16_t cid, uint16_t ttag,
    uint32_t data_offset, uint32_t data_len)
{
	struct {
		struct nvme_tcp_r2t_hdr hdr;
		uint32_t digest;
	} r2t;
	uint32_t plen;

	memset(&r2t, 0, sizeof(r2t));
	r2t.hdr.common.pdu_type = NVME_TCP_PDU_TYPE_R2T;
	r2t.hdr.common.hlen = sizeof(r2t.hdr);
	plen = sizeof(r2t.hdr);
	if (ntc->header_digests) {
		r2t.hdr.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(r2t.digest);
	}
	r2t.hdr.common.plen = htole32(plen);
	r2t.hdr.cccid = cid;
	r2t.hdr.ttag = ttag;
	r2t.hdr.r2to = htole32(data_offset);
	r2t.hdr.r2tl = htole32(data_len);

	if (ntc->header_digests)
		r2t.digest = compute_digest(&r2t.hdr, sizeof(r2t.hdr));

	return (nvmf_tcp_write_pdu(ntc->s, &r2t, plen));
}

static int
tcp_receive_r2t_data(struct nvmf_capsule *nc, uint32_t data_offset,
    uint32_t data_len, struct iovec *iov, u_int iovcnt)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc->nc_qpair->nq_connection);
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	int error;
	uint16_t ttag;

	/*
	 * Don't bother byte-swapping ttag as it is just a cookie
	 * value returned by the other end as-is.
	 */
	ttag = qp->next_ttag++;

	error = tcp_send_r2t(ntc, nc->nc_sqe.cid, ttag, data_offset, data_len);
	if (error != 0)
		return (error);

	tcp_alloc_command_buffer(qp, iov, iovcnt, data_len, ttag, true);
	return (0);
}

static int
tcp_receive_icd_data(struct nvmf_tcp_capsule *tc, uint32_t data_offset,
    struct iovec *iov, u_int iovcnt)
{
	const char *icd;
	u_int i;

	icd = (const char *)tc->rx_pdu.hdr + tc->rx_pdu.hdr->pdo + data_offset;
	for (i = 0; i < iovcnt; i++) {
		memcpy(iov[i].iov_base, icd, iov[i].iov_len);
		icd += iov[i].iov_len;
	}
	return (0);
}

static int
tcp_receive_controller_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct iovec *iov, u_int iovcnt)
{
	struct nvmf_tcp_connection *ntc = TCONN(nc->nc_qpair->nq_connection);
	struct nvmf_tcp_capsule *tc = TCAP(nc);
	struct nvme_sgl_descriptor *sgl;
	size_t data_len, iov_len;
	u_int i;

	if (nc->nc_qe_len != sizeof(struct nvme_command) ||
	    ntc->nc.nc_controller)
		return (EINVAL);

	iov_len = 0;
	for (i = 0; i < iovcnt; i++)
		iov_len += iov[i].iov_len;

	sgl = (struct nvme_sgl_descriptor *)&nc->nc_sqe.prp1;
	data_len = le32toh(sgl->unkeyed.length);
	if (data_offset + iov_len > data_len)
		return (EFBIG);

	if (sgl->unkeyed.subtype == NVME_SGL_SUBTYPE_OFFSET)
		return (tcp_receive_icd_data(tc, data_offset, iov, iovcnt));
	else
		return (tcp_receive_r2t_data(nc, data_offset, iov_len, iov,
		    iovcnt));
}

struct nvmf_transport_ops tcp_ops = {
	.allocate_connection = tcp_allocate_connection,
	.connect = tcp_connect,
	.accept = tcp_accept,
	.free_connection = tcp_free_connection,
	.allocate_qpair = tcp_allocate_qpair,
	.free_qpair = tcp_free_qpair,
	.allocate_capsule = tcp_allocate_capsule,
	.free_capsule = tcp_free_capsule,
	.transmit_capsule = tcp_transmit_capsule,
	.receive_capsule = tcp_receive_capsule,
	.receive_controller_data = tcp_receive_controller_data,
};
