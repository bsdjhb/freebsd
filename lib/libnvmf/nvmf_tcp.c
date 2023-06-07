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

struct nvmf_tcp_command_buffer {
	struct nvmf_tcp_qpair *qp;

	struct iovec *iov;
	u_int	iovcnt;
	uint32_t data_offset;
	size_t	data_len;
	size_t	data_xfered;

	uint16_t cid;
	uint16_t ttag;

	LIST_ENTRY(nvmf_tcp_command_buffer) link;
};

LIST_HEAD(nvmf_tcp_command_buffer_list, nvmf_tcp_command_buffer);

struct nvmf_tcp_association {
	struct nvmf_association na;

	uint32_t ioccsz;
};

struct nvmf_tcp_rxpdu {
	struct nvme_tcp_common_pdu_hdr *hdr;
	uint32_t data_len;
};

struct nvmf_tcp_capsule {
	struct nvmf_capsule nc;

	struct nvmf_tcp_rxpdu rx_pdu;
	struct nvmf_tcp_command_buffer *cb;

	TAILQ_ENTRY(nvmf_tcp_capsule) link;
};

struct nvmf_tcp_qpair {
	struct nvmf_qpair qp;
	int s;

	uint8_t	txpda;
	uint8_t rxpda;
	bool header_digests;
	bool data_digests;
	uint32_t maxr2t;
	uint32_t maxh2cdata;
	uint32_t max_icd;	/* Host only */
	uint16_t next_ttag;	/* Controller only */

	struct nvmf_tcp_command_buffer_list tx_buffers;
	struct nvmf_tcp_command_buffer_list rx_buffers;
	TAILQ_HEAD(, nvmf_tcp_capsule) rx_capsules;
};

#define	TASSOC(nc)	((struct nvmf_tcp_association *)(na))
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
	digest ^= 0xffffffff;
	return (digest);
}

static uint32_t
compute_digest(const void *buf, size_t len)
{
	return (calculate_crc32c(0xffffffff, buf, len) ^ 0xffffffff);
}

static struct nvmf_tcp_command_buffer *
tcp_alloc_command_buffer(struct nvmf_tcp_qpair *qp, struct iovec *iov,
    u_int iovcnt, uint32_t data_offset, size_t data_len, uint16_t cid,
    uint16_t ttag, bool receive)
{
	struct nvmf_tcp_command_buffer *cb;

	cb = malloc(sizeof(*cb));
	cb->qp = qp;
	cb->iov = iov;
	cb->iovcnt = iovcnt;
	cb->data_offset = data_offset;
	cb->data_len = data_len;
	cb->data_xfered = 0;
	cb->cid = cid;
	cb->ttag = ttag;

	if (receive)
		LIST_INSERT_HEAD(&qp->rx_buffers, cb, link);
	else
		LIST_INSERT_HEAD(&qp->tx_buffers, cb, link);
	return (cb);
}

static struct nvmf_tcp_command_buffer *
tcp_find_command_buffer(struct nvmf_tcp_qpair *qp, uint16_t cid, uint16_t ttag,
    bool receive)
{
	struct nvmf_tcp_command_buffer_list *list;
	struct nvmf_tcp_command_buffer *cb;

	list = receive ? &qp->rx_buffers : &qp->tx_buffers;
	LIST_FOREACH(cb, list, link) {
		if (cb->cid == cid && cb->ttag == ttag)
			return (cb);
	}
	return (NULL);
}

static void
tcp_free_command_buffer(struct nvmf_tcp_command_buffer *cb)
{
	LIST_REMOVE(cb, link);
	free(cb);
}

static int
nvmf_tcp_write_pdu(struct nvmf_tcp_qpair *qp, const void *pdu, size_t len)
{
	ssize_t nwritten;
	const char *cp;

	cp = pdu;
	while (len != 0) {
		nwritten = write(qp->s, cp, len);
		if (nwritten < 0)
			return (errno);
		len -= nwritten;
		cp += nwritten;
	}
	return (0);
}

static int
nvmf_tcp_write_pdu_iov(struct nvmf_tcp_qpair *qp, struct iovec *iov,
    u_int iovcnt, size_t len)
{
	ssize_t nwritten;

	for (;;) {
		nwritten = writev(qp->s, iov, iovcnt);
		if (nwritten < 0)
			return (errno);

		len -= nwritten;
		if (len == 0)
			return (0);

		while (iov->iov_len <= (size_t)nwritten) {
			nwritten -= iov->iov_len;
			iovcnt--;
			iov++;
		}

		iov->iov_base = (char *)iov->iov_base + nwritten;
		iov->iov_len -= nwritten;
	}
}

static void
nvmf_tcp_report_error(struct nvmf_tcp_qpair *qp, uint16_t fes,
    uint32_t fei, const void *rx_pdu, size_t pdu_len, u_int hlen)
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
	hdr.common.pdu_type = qp->qp.nq_association->na_controller ?
	    NVME_TCP_PDU_TYPE_C2H_TERM_REQ : NVME_TCP_PDU_TYPE_H2C_TERM_REQ;
	hdr.common.hlen = sizeof(hdr);
	hdr.common.plen = sizeof(hdr) + hlen;
	hdr.fes = htole16(fes);
	le32enc(hdr.fei, fei);
	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = __DECONST(void *, rx_pdu);
	iov[1].iov_len = hlen;

	(void)nvmf_tcp_write_pdu_iov(qp, iov, nitems(iov), sizeof(hdr) + hlen);
	close(qp->s);
	qp->s = -1;
}

static int
nvmf_tcp_validate_pdu(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu,
    size_t pdu_len)
{
	const struct nvme_tcp_common_pdu_hdr *ch;
	uint32_t data_len, plen;
	uint32_t digest, rx_digest;
	u_int full_hlen, hlen, expected_hlen;
	uint8_t digest_flags, valid_flags;

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
	if (qp->qp.nq_association->na_controller !=
	    (ch->pdu_type & 0x01) == 0) {
		printf("NVMe/TCP: Invalid PDU type %u\n", ch->pdu_type);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	switch (ch->pdu_type) {
	case NVME_TCP_PDU_TYPE_IC_REQ:
	case NVME_TCP_PDU_TYPE_IC_RESP:
		/* Shouldn't get these for an established connection. */
		printf("NVMe/TCP: Received Initialize Connection PDU\n");
		nvmf_tcp_report_error(qp,
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
			close(qp->s);
			qp->s = -1;
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
		nvmf_tcp_report_error(qp,
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
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 1, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* Verify that digests are present if enabled. */
	digest_flags = 0;
	if (qp->header_digests)
		digest_flags |= NVME_TCP_CH_FLAGS_HDGSTF;
	if (qp->data_digests)
		digest_flags |= NVME_TCP_CH_FLAGS_DDGSTF;
	if ((digest_flags & valid_flags) !=
	    (ch->flags & (NVME_TCP_CH_FLAGS_HDGSTF |
	    NVME_TCP_CH_FLAGS_DDGSTF))) {
		printf("NVMe/TCP: Invalid PDU header flags %#x\n", ch->flags);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 1, ch, pdu_len,
		    hlen);
		return (EBADMSG);
	}

	/* 7.4.5.2: SUCCESS in C2H requires LAST_PDU */
	if (ch->pdu_type == NVME_TCP_PDU_TYPE_C2H_DATA &&
	    (ch->flags & (NVME_TCP_C2H_DATA_FLAGS_LAST_PDU |
	    NVME_TCP_C2H_DATA_FLAGS_SUCCESS)) ==
	    NVME_TCP_C2H_DATA_FLAGS_SUCCESS) {
		printf("NVMe/TCP: Invalid PDU header flags %#x\n", ch->flags);
		nvmf_tcp_report_error(qp,
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
		nvmf_tcp_report_error(qp,
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
			nvmf_tcp_report_error(qp,
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
		    ch->pdo % qp->rxpda != 0) {
			printf("NVMe/TCP: Invalid PDU data offset %u\n",
			    ch->pdo);
			nvmf_tcp_report_error(qp,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, ch,
			    pdu_len, hlen);
			return (EBADMSG);
		}
		break;
	}

	/* Validate plen. */
	if (plen < ch->hlen) {
		printf("NVMe/TCP: Invalid PDU length %u\n", plen);
		nvmf_tcp_report_error(qp,
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
			nvmf_tcp_report_error(qp,
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
			nvmf_tcp_report_error(qp,
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
			nvmf_tcp_report_error(qp,
			    NVME_TCP_TERM_REQ_FES_HDGST_ERROR, rx_digest, ch,
			    pdu_len, hlen);
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

/*
 * Read data from a socket, retrying until the data has been fully
 * read or an error occurs.
 */
static int
nvmf_tcp_read_buffer(int s, void *buf, size_t len)
{
	ssize_t nread;
	char *cp;

	cp = buf;
	while (len != 0) {
		nread = read(s, cp, len);
		if (nread < 0)
			return (errno);
		if (nread == 0)
			return (ECONNRESET);
		len -= nread;
		cp += nread;
	}
	return (0);
}

static int
nvmf_tcp_read_pdu(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_common_pdu_hdr ch;
	uint32_t plen;
	int error;

	memset(pdu, 0, sizeof(*pdu));
	error = nvmf_tcp_read_buffer(qp->s, &ch, sizeof(ch));
	if (error != 0)
		return (error);

	plen = le32toh(ch.plen);

	/*
	 * Validate a header with garbage lengths to trigger
	 * an error message without reading more.
	 */
	if (plen < sizeof(ch) || ch.hlen > plen) {
		pdu->hdr = &ch;
		error = nvmf_tcp_validate_pdu(qp, pdu, sizeof(ch));
		pdu->hdr = NULL;
		assert(error != 0);
		return (error);
	}

	/* Read the rest of the PDU. */
	pdu->hdr = malloc(plen);
	memcpy(pdu->hdr, &ch, sizeof(ch));
	error = nvmf_tcp_read_buffer(qp->s, pdu->hdr + 1, plen - sizeof(ch));
	if (error != 0)
		return (error);
	error = nvmf_tcp_validate_pdu(qp, pdu, plen);
	if (error != 0) {
		free(pdu->hdr);
		pdu->hdr = NULL;
	}
	return (error);
}

static void
nvmf_tcp_free_pdu(struct nvmf_tcp_rxpdu *pdu)
{
	free(pdu->hdr);
	pdu->hdr = NULL;
}

static int
nvmf_tcp_handle_term_req(struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_term_req_hdr *hdr;

	hdr = (void *)pdu->hdr;

	printf("NVMe/TCP: Received termination request: fes %#x fei %#x\n",
	    le16toh(hdr->fes), le32dec(hdr->fei));
	nvmf_tcp_free_pdu(pdu);
	return (ECONNRESET);
}

static int
nvmf_tcp_save_command_capsule(struct nvmf_tcp_qpair *qp,
    struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_cmd *cmd;
	struct nvmf_capsule *nc;
	struct nvmf_tcp_capsule *tc;

	cmd = (void *)pdu->hdr;

	nc = nvmf_allocate_command(&qp->qp, &cmd->ccsqe);
	if (nc == NULL)
		return (ENOMEM);

	tc = TCAP(nc);
	tc->rx_pdu = *pdu;

	TAILQ_INSERT_TAIL(&qp->rx_capsules, tc, link);
	return (0);
}

static int
nvmf_tcp_save_response_capsule(struct nvmf_tcp_qpair *qp,
    struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_rsp *rsp;
	struct nvmf_capsule *nc;
	struct nvmf_tcp_capsule *tc;

	rsp = (void *)pdu->hdr;

	nc = nvmf_allocate_response(&qp->qp, &rsp->rccqe);
	if (nc == NULL)
		return (ENOMEM);

	nc->nc_sqhd_valid = true;
	tc = TCAP(nc);
	tc->rx_pdu = *pdu;

	TAILQ_INSERT_TAIL(&qp->rx_capsules, tc, link);
	return (0);
}

static int
nvmf_tcp_handle_h2c_data(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_h2c_data_hdr *h2c;
	struct nvmf_tcp_command_buffer *cb;
	uint32_t data_len, data_offset;
	const char *icd;

	h2c = (void *)pdu->hdr;
	if (le32toh(h2c->datal) > qp->maxh2cdata) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED, 0,
		    pdu->hdr, le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	cb = tcp_find_command_buffer(qp, h2c->cccid, h2c->ttag, true);
	if (cb == NULL) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_h2c_data_hdr, ttag), pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_len = le32toh(h2c->datal);
	if (data_len != pdu->data_len) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_h2c_data_hdr, datal), pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_offset = le32toh(h2c->datao);
	if (data_offset < cb->data_offset ||
	    data_offset + data_len > cb->data_offset + cb->data_len) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0,
		    pdu->hdr, le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if (data_offset != cb->data_offset + cb->data_xfered) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if ((cb->data_xfered + data_len == cb->data_len) !=
	    ((pdu->hdr->flags & NVME_TCP_H2C_DATA_FLAGS_LAST_PDU) != 0)) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	cb->data_xfered += data_len;
	data_offset -= cb->data_offset;
	icd = (const char *)pdu->hdr + pdu->hdr->pdo;
	for (u_int i = 0; i < cb->iovcnt && data_len != 0; i++) {
		size_t todo;

		if (data_offset >= cb->iov[i].iov_len) {
			data_offset -= cb->iov[i].iov_len;
			continue;
		}

		todo = cb->iov[i].iov_len - data_offset;
		if (todo > data_len)
			todo = data_len;

		memcpy((char *)cb->iov[i].iov_base + data_offset, icd, todo);
		data_offset = 0;
		icd += todo;
		data_len -= todo;
	}

	nvmf_tcp_free_pdu(pdu);
	return (0);
}

static int
nvmf_tcp_handle_c2h_data(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_c2h_data_hdr *c2h;
	struct nvmf_tcp_command_buffer *cb;
	uint32_t data_len, data_offset;
	const char *icd;

	c2h = (void *)pdu->hdr;

	cb = tcp_find_command_buffer(qp, c2h->cccid, 0, true);
	if (cb == NULL) {
		/*
		 * XXX: Could be PDU sequence error if cccid is for a
		 * command that doesn't use a command buffer.
		 */
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_c2h_data_hdr, cccid), pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_len = le32toh(c2h->datal);
	if (data_len != pdu->data_len) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_c2h_data_hdr, datal), pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_offset = le32toh(c2h->datao);
	if (data_offset < cb->data_offset ||
	    data_offset + data_len > cb->data_offset + cb->data_len) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0,
		    pdu->hdr, le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if (data_offset != cb->data_offset + cb->data_xfered) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if ((cb->data_xfered + data_len == cb->data_len) !=
	    ((pdu->hdr->flags & NVME_TCP_C2H_DATA_FLAGS_LAST_PDU) != 0)) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	cb->data_xfered += data_len;
	data_offset -= cb->data_offset;
	icd = (const char *)pdu->hdr + pdu->hdr->pdo;
	for (u_int i = 0; i < cb->iovcnt && data_len != 0; i++) {
		size_t todo;

		if (data_offset >= cb->iov[i].iov_len) {
			data_offset -= cb->iov[i].iov_len;
			continue;
		}

		todo = cb->iov[i].iov_len - data_offset;
		if (todo > data_len)
			todo = data_len;

		memcpy((char *)cb->iov[i].iov_base + data_offset, icd, todo);
		data_offset = 0;
		icd += todo;
		data_len -= todo;
	}

	if ((pdu->hdr->flags & NVME_TCP_C2H_DATA_FLAGS_SUCCESS) != 0) {
		struct nvme_completion cqe;
		struct nvmf_tcp_capsule *tc;
		struct nvmf_capsule *nc;

		memset(&cqe, 0, sizeof(cqe));
		cqe.cid = cb->cid;

		nc = nvmf_allocate_response(&qp->qp, &cqe);
		if (nc == NULL) {
			nvmf_tcp_free_pdu(pdu);
			return (ENOMEM);
		}
		nc->nc_sqhd_valid = false;

		tc = TCAP(nc);
		TAILQ_INSERT_TAIL(&qp->rx_capsules, tc, link);
	}

	nvmf_tcp_free_pdu(pdu);
	return (0);
}

/* NB: cid and ttag and little-endian already. */
static int
tcp_send_h2c_pdu(struct nvmf_tcp_qpair *qp, uint16_t cid, uint16_t ttag,
    uint32_t data_offset, void *buf, size_t len, bool last_pdu)
{
	struct {
		struct nvme_tcp_h2c_data_hdr hdr;
		uint32_t digest;
	} h2c;
	struct iovec iov[4];
	u_int iovcnt;
	uint32_t data_digest, pad, plen;

	memset(&h2c, 0, sizeof(h2c));
	h2c.hdr.common.pdu_type = NVME_TCP_PDU_TYPE_H2C_DATA;
	h2c.hdr.common.hlen = sizeof(h2c.hdr);
	plen = sizeof(h2c.hdr);
	if (last_pdu)
		h2c.hdr.common.flags |= NVME_TCP_H2C_DATA_FLAGS_LAST_PDU;
	if (qp->header_digests) {
		h2c.hdr.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(h2c.digest);
	}
	h2c.hdr.common.pdo = roundup2(plen, qp->txpda);
	pad = h2c.hdr.common.pdo - plen;
	h2c.hdr.cccid = cid;
	h2c.hdr.ttag = ttag;
	h2c.hdr.datao = htole32(data_offset);
	h2c.hdr.datal = htole32(len);

	/* CH + PSH + optional HDGST */
	iov[0].iov_base = &h2c;
	iov[0].iov_len = plen;
	iovcnt = 1;

	if (pad != 0) {
		/* PAD */
		plen += pad;
		iov[iovcnt].iov_base = __DECONST(char *, zero_padding);
		iov[iovcnt].iov_len = pad;
		iovcnt++;
	}

	/* DATA */
	plen += len;
	iov[iovcnt].iov_base = buf;
	iov[iovcnt].iov_len = len;
	iovcnt++;

	/* DDGST */
	if (qp->data_digests) {
		h2c.hdr.common.flags |= NVME_TCP_CH_FLAGS_DDGSTF;
		plen += sizeof(data_digest);
		iov[iovcnt].iov_base = &data_digest;
		iov[iovcnt].iov_len = sizeof(data_digest);
		iovcnt++;

		data_digest = compute_digest(buf, len);
	}

	h2c.hdr.common.plen = htole32(plen);
	if (qp->header_digests)
		h2c.digest = compute_digest(&h2c.hdr, sizeof(h2c.hdr));

	return (nvmf_tcp_write_pdu_iov(qp, iov, iovcnt, plen));
}

/* Sends one or more H2C_DATA PDUs, subject to MAXH2CDATA. */
static int
tcp_send_h2c_pdus(struct nvmf_tcp_qpair *qp, uint16_t cid, uint16_t ttag,
    uint32_t data_offset, void *buf, size_t len, bool last_pdu)
{
	char *p;

	p = buf;
	while (len != 0) {
		size_t todo;
		int error;

		todo = len;
		if (todo > qp->maxh2cdata)
			todo = qp->maxh2cdata;
		error = tcp_send_h2c_pdu(qp, cid, ttag, data_offset, p, todo,
		    last_pdu && todo == len);
		if (error != 0)
			return (error);
		p += todo;
		len -= todo;
	}
	return (0);
}

static int
nvmf_tcp_handle_r2t(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvmf_tcp_command_buffer *cb;
	struct nvme_tcp_r2t_hdr *r2t;
	uint32_t data_len, data_offset, skip;
	int error;

	r2t = (void *)pdu->hdr;

	cb = tcp_find_command_buffer(qp, r2t->cccid, 0, false);
	if (cb == NULL) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_r2t_hdr, cccid), pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_offset = le32toh(r2t->r2to);
	if (data_offset != cb->data_xfered) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->hdr,
		    le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	/*
	 * XXX: The spec does not specify how to handle R2T tranfers
	 * out of range of the original command.
	 */
	data_len = le32toh(r2t->r2tl);
	if (data_offset + data_len > cb->data_len) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0,
		    pdu->hdr, le32toh(pdu->hdr->plen), pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	cb->data_xfered += data_len;

	/*
	 * Write out one or more H2C_DATA PDUs containing the
	 * requested data.  To avoid copying and constructing more
	 * iovecs, send one iovec entry from the command buffer at a
	 * time.
	 */
	skip = data_offset;
	error = 0;
	for (u_int i = 0; i < cb->iovcnt && data_len != 0; i++) {
		size_t todo;

		if (skip >= cb->iov[i].iov_len) {
			skip -= cb->iov[i].iov_len;
			continue;
		}

		todo = cb->iov[i].iov_len - skip;
		if (todo > data_len)
			todo = data_len;

		error = tcp_send_h2c_pdus(qp, r2t->cccid, r2t->ttag,
		    data_offset, (char *)cb->iov[i].iov_base + skip, todo,
		    todo == data_len);
		if (error != 0)
			break;
		skip = 0;
		data_offset += todo;
		data_len -= todo;
	}

	nvmf_tcp_free_pdu(pdu);
	return (error);
}

static int
nvmf_tcp_receive_pdu(struct nvmf_tcp_qpair *qp)
{
	struct nvmf_tcp_rxpdu pdu;
	int error;

	error = nvmf_tcp_read_pdu(qp, &pdu);
	if (error != 0)
		return (error);

	switch (pdu.hdr->pdu_type) {
	default:
		__unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		return (nvmf_tcp_handle_term_req(&pdu));
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		return (nvmf_tcp_save_command_capsule(qp, &pdu));
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
		return (nvmf_tcp_save_response_capsule(qp, &pdu));
	case NVME_TCP_PDU_TYPE_H2C_DATA:
		return (nvmf_tcp_handle_h2c_data(qp, &pdu));
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		return (nvmf_tcp_handle_c2h_data(qp, &pdu));
	case NVME_TCP_PDU_TYPE_R2T:
		return (nvmf_tcp_handle_r2t(qp, &pdu));
	}
}

static bool
nvmf_tcp_validate_ic_pdu(struct nvmf_association *na, struct nvmf_tcp_qpair *qp,
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
	if (na->na_controller != (ch->pdu_type & 0x01) == 0) {
		na_error(na, "NVMe/TCP: Invalid PDU type %u", ch->pdu_type);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (false);
	}

	switch (ch->pdu_type) {
	case NVME_TCP_PDU_TYPE_IC_REQ:
	case NVME_TCP_PDU_TYPE_IC_RESP:
		break;
	default:
		na_error(na, "NVMe/TCP: Invalid PDU type %u", ch->pdu_type);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, ch, pdu_len,
		    hlen);
		return (false);
	}

	/* Validate flags. */
	if (ch->flags != 0) {
		na_error(na, "NVMe/TCP: Invalid PDU header flags %#x",
		    ch->flags);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 1, ch, pdu_len,
		    hlen);
		return (false);
	}

	/* Validate hlen. */
	if (ch->hlen != 128) {
		na_error(na, "NVMe/TCP: Invalid PDU header length %u",
		    ch->hlen);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 2, ch, pdu_len,
		    hlen);
		return (false);
	}

	/* Validate pdo. */
	if (ch->pdo != 0) {
		na_error(na, "NVMe/TCP: Invalid PDU data offset %u", ch->pdo);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, ch, pdu_len,
		    hlen);
		return (false);
	}

	/* Validate plen. */
	if (plen != 128) {
		na_error(na, "NVMe/TCP: Invalid PDU length %u", plen);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, ch, pdu_len,
		    hlen);
		return (false);
	}

	/* Validate fields common to both ICReq and ICResp. */
	pdu = (const struct nvme_tcp_ic_req *)ch;
	if (le16toh(pdu->pfv) != 0) {
		na_error(na, "NVMe/TCP: Unsupported PDU version %u",
		    le16toh(pdu->pfv));
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER,
		    8, ch, pdu_len, hlen);
		return (false);
	}

	if (pdu->hpda > NVME_TCP_CPDA_MAX) {
		na_error(na, "NVMe/TCP: Unsupported PDA %u", pdu->hpda);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 10, ch, pdu_len,
		    hlen);
		return (false);
	}

	if (pdu->dgst.bits.reserved != 0) {
		na_error(na, "NVMe/TCP: Invalid digest settings");
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 11, ch, pdu_len,
		    hlen);
		return (false);
	}

	return (true);
}

static bool
nvmf_tcp_read_ic_req(struct nvmf_association *na, struct nvmf_tcp_qpair *qp,
    struct nvme_tcp_ic_req *pdu)
{
	int error;

	error = nvmf_tcp_read_buffer(qp->s, pdu, sizeof(*pdu));
	if (error != 0) {
		na_error(qp->qp.nq_association,
		    "NVMe/TCP: Failed to read IC request: %s", strerror(error));
		return (false);
	}

	return (nvmf_tcp_validate_ic_pdu(na, qp, &pdu->common, sizeof(*pdu)));
}

static bool
nvmf_tcp_read_ic_resp(struct nvmf_association *na, struct nvmf_tcp_qpair *qp,
    struct nvme_tcp_ic_resp *pdu)
{
	int error;

	error = nvmf_tcp_read_buffer(qp->s, pdu, sizeof(*pdu));
	if (error != 0) {
		na_error(qp->qp.nq_association,
		    "NVMe/TCP: Failed to read IC response: %s",
		    strerror(error));
		return (false);
	}

	return (nvmf_tcp_validate_ic_pdu(na, qp, &pdu->common, sizeof(*pdu)));
}

static struct nvmf_association *
tcp_allocate_association(bool controller __unused,
    const struct nvmf_association_params *params __unused)
{
	struct nvmf_tcp_association *ta;

	ta = calloc(1, sizeof(*ta));

	return (&ta->na);
}

static void
tcp_update_association(struct nvmf_association *na,
    const struct nvme_controller_data *cdata)
{
	struct nvmf_tcp_association *ta = TASSOC(na);

	ta->ioccsz = le32toh(cdata->ioccsz);
}

static void
tcp_free_association(struct nvmf_association *na)
{
	free(na);
}

static bool
tcp_connect(struct nvmf_tcp_qpair *qp, struct nvmf_association *na, bool admin)
{
	const struct nvmf_association_params *params = &na->na_params;
	struct nvmf_tcp_association *ta = TASSOC(na);
	struct nvme_tcp_ic_req ic_req;
	struct nvme_tcp_ic_resp ic_resp;
	int error;

	if (!admin) {
		if (ta->ioccsz == 0) {
			na_error(na, "TCP I/O queues require cdata");
			return (false);
		}
		if (ta->ioccsz < 4) {
			na_error(na, "Invalid IOCCSZ %u", ta->ioccsz);
			return (false);
		}
	}

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

	error = nvmf_tcp_write_pdu(qp, &ic_req, sizeof(ic_req));
	if (error != 0) {
		na_error(na, "Failed to write IC request: %s", strerror(error));
		return (false);
	}

	if (!nvmf_tcp_read_ic_resp(na, qp, &ic_resp))
		return (false);

	/* Ensure the controller didn't enable digests we didn't request. */
	if ((!params->tcp.header_digests &&
	    ic_resp.dgst.bits.hdgst_enable != 0) ||
	    (!params->tcp.data_digests &&
	    ic_resp.dgst.bits.ddgst_enable != 0)) {
		na_error(na, "Controller enabled unrequested digests");
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_DATA_UNSUPPORTED_PARAMETER,
		    11, &ic_resp, sizeof(ic_resp), sizeof(ic_resp));
		return (false);
	}

	/*
	 * XXX: Is there an upper-bound to enforce here?  Perhaps pick
	 * some large value and report larger values as an unsupported
	 * parameter?
	 */
	if (le32toh(ic_resp.maxh2cdata) < 4096) {
		na_error(na, "Invalid MAXH2CDATA %u",
		    le32toh(ic_resp.maxh2cdata));
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 12, &ic_resp,
		    sizeof(ic_resp), sizeof(ic_resp));
		return (false);
	}

	qp->txpda = (params->tcp.pda + 1) * 4;
	qp->rxpda = (ic_resp.cpda + 1) * 4;
	qp->header_digests = ic_resp.dgst.bits.hdgst_enable != 0;
	qp->data_digests = ic_resp.dgst.bits.ddgst_enable != 0;
	qp->maxr2t = params->tcp.maxr2t;
	qp->maxh2cdata = le32toh(ic_resp.maxh2cdata);
	if (admin)
		/* 7.4.3 */
		qp->max_icd = 8192;
	else
		qp->max_icd = (ta->ioccsz - 4) * 16;

	return (0);
}

static bool
tcp_accept(struct nvmf_tcp_qpair *qp, struct nvmf_association *na)
{
	const struct nvmf_association_params *params = &na->na_params;
	struct nvme_tcp_ic_req ic_req;
	struct nvme_tcp_ic_resp ic_resp;
	int error;

	if (!nvmf_tcp_read_ic_req(na, qp, &ic_req))
		return (false);

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

	error = nvmf_tcp_write_pdu(qp, &ic_req, sizeof(ic_req));
	if (error != 0) {
		na_error(na, "Failed to write IC response: %s",
		    strerror(error));
		return (false);
	}

	qp->txpda = (params->tcp.pda + 1) * 4;
	qp->rxpda = (ic_req.hpda + 1) * 4;
	qp->header_digests = ic_resp.dgst.bits.hdgst_enable != 0;
	qp->data_digests = ic_resp.dgst.bits.ddgst_enable != 0;
	qp->maxr2t = le32toh(ic_req.maxr2t);
	qp->maxh2cdata = params->tcp.maxh2cdata;
	qp->max_icd = 0;	/* XXX */
	return (0);
}

static struct nvmf_qpair *
tcp_allocate_qpair(struct nvmf_association *na,
    const struct nvmf_qpair_params *qparams)
{
	const struct nvmf_association_params *aparams = &na->na_params;
	struct nvmf_tcp_qpair *qp;
	int error;

	if (aparams->tcp.pda > NVME_TCP_CPDA_MAX) {
		na_error(na, "Invalid PDA");
		return (NULL);
	}

	qp = calloc(1, sizeof(*qp));
	qp->s = qparams->tcp.fd;
	LIST_INIT(&qp->rx_buffers);
	LIST_INIT(&qp->tx_buffers);
	TAILQ_INIT(&qp->rx_capsules);
	if (na->na_controller)
		error = tcp_accept(qp, na);
	else
		error = tcp_connect(qp, na, qparams->admin);
	if (error != 0) {
		free(qp);
		return (NULL);
	}

	return (&qp->qp);
}

static void
tcp_free_qpair(struct nvmf_qpair *nq)
{
	struct nvmf_tcp_qpair *qp = TQP(nq);
	struct nvmf_tcp_capsule *ntc, *tc;
	struct nvmf_tcp_command_buffer *ncb, *cb;

	TAILQ_FOREACH_SAFE(tc, &qp->rx_capsules, link, ntc) {
		TAILQ_REMOVE(&qp->rx_capsules, tc, link);
		nvmf_free_capsule(&tc->nc);
	}
	LIST_FOREACH_SAFE(cb, &qp->rx_buffers, link, ncb) {
		tcp_free_command_buffer(cb);
	}
	LIST_FOREACH_SAFE(cb, &qp->tx_buffers, link, ncb) {
		tcp_free_command_buffer(cb);
	}
	free(qp);
}

static int
tcp_kernel_handoff_params(struct nvmf_qpair *nq,
    struct nvmf_handoff_qpair_params *qparams)
{
	struct nvmf_tcp_qpair *qp = TQP(nq);

	qparams->tcp.fd = qp->s;
	qparams->tcp.rxpda = qp->rxpda;
	qparams->tcp.txpda = qp->txpda;
	qparams->tcp.header_digests = qp->header_digests;
	qparams->tcp.data_digests = qp->data_digests;
	qparams->tcp.maxr2t = qp->maxr2t;
	qparams->tcp.maxh2cdata = qp->maxh2cdata;
	qparams->tcp.max_icd = qp->max_icd;

	return (0);
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

	nvmf_tcp_free_pdu(&tc->rx_pdu);
	if (tc->cb != NULL)
		tcp_free_command_buffer(tc->cb);
	free(tc);
}

static int
tcp_transmit_command(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct nvmf_tcp_capsule *tc = TCAP(nc);
	struct nvme_tcp_cmd cmd;
	struct iovec *iov, *iov2;
	uint32_t data_digest, header_digest, pad, plen;
	u_int iovcnt;
	int error;
	bool use_icd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.common.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_CMD;
	if (qp->header_digests)
		cmd.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
	cmd.common.hlen = sizeof(cmd);
	cmd.ccsqe = nc->nc_sqe;
	plen = sizeof(cmd);
	iovcnt = 1;

	/* Populate SGL in SQE. */
	use_icd = false;
	if (nc->nc_data_len != 0) {
		struct nvme_sgl_descriptor *sgl;

		sgl = (struct nvme_sgl_descriptor *)&cmd.ccsqe.prp1;
		memset(sgl, 0, sizeof(*sgl));
		sgl->address = 0;
		sgl->unkeyed.length = htole32(nc->nc_data_len);
		sgl->unkeyed.type = NVME_SGL_TYPE_DATA_BLOCK;
		if (nc->nc_send_data && nc->nc_data_len <= qp->max_icd) {
			/* Use in-capsule data. */
			sgl->unkeyed.subtype = NVME_SGL_SUBTYPE_OFFSET;
			use_icd = true;
		} else {
			/* Use a command buffer. */
			sgl->unkeyed.subtype = NVME_SGL_SUBTYPE_TRANSPORT;
		}
	}

	if (qp->header_digests) {
		cmd.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(header_digest);
		iovcnt++;
	}

	pad = 0;
	if (use_icd) {
		cmd.common.pdo = roundup2(plen, qp->txpda);
		pad = cmd.common.pdo - plen;
		if (pad != 0) {
			iovcnt++;
			plen += pad;
		}

		plen += nc->nc_data_len;

		iovcnt += nc->nc_data_iovcnt;
		if (qp->data_digests) {
			cmd.common.flags |= NVME_TCP_CH_FLAGS_DDGSTF;
			plen += sizeof(data_digest);
			iovcnt++;

			data_digest = compute_digest_iov(nc->nc_data_iov,
			    nc->nc_data_iovcnt);
		}
	}

	cmd.common.plen = htole32(plen);
	if (qp->header_digests)
		header_digest = compute_digest(&cmd, sizeof(cmd));

	iov = alloca(iovcnt * sizeof(*iov));
	iov2 = iov;

	/* CH + PSH */
	iov2->iov_base = &cmd;
	iov2->iov_len = sizeof(cmd);
	iov2++;

	/* HDGST */
	if (qp->header_digests) {
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
		if (qp->data_digests) {
			iov2->iov_base = &data_digest;
			iov2->iov_len = sizeof(data_digest);
			iov2++;
		}
	}

	/* Send command capsule. */
	error = nvmf_tcp_write_pdu_iov(qp, iov, iovcnt, plen);
	if (error != 0)
		return (error);

	/*
	 * If data will be transferred using a command buffer, allocate a
	 * buffer structure and queue it.
	 */
	if (nc->nc_data_len != 0 && !use_icd)
		tc->cb = tcp_alloc_command_buffer(qp, nc->nc_data_iov,
		    nc->nc_data_iovcnt, 0, nc->nc_data_len, cmd.ccsqe.cid, 0,
		    !nc->nc_send_data);

	return (0);
}

static int
tcp_transmit_response(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct {
		struct nvme_tcp_rsp hdr;
		uint32_t digest;
	} rsp;
	uint32_t plen;

	memset(&rsp, 0, sizeof(rsp));
	rsp.hdr.common.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_RESP;
	rsp.hdr.common.hlen = sizeof(rsp.hdr);
	plen = sizeof(rsp.hdr);
	if (qp->header_digests) {
		rsp.hdr.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(rsp.digest);
	}
	rsp.hdr.common.plen = htole32(plen);
	rsp.hdr.rccqe = nc->nc_cqe;

	if (qp->header_digests)
		rsp.digest = compute_digest(&rsp.hdr, sizeof(rsp.hdr));

	return (nvmf_tcp_write_pdu(qp, &rsp, plen));
}

static int
tcp_transmit_capsule(struct nvmf_capsule *nc)
{
	if (nc->nc_qe_len == sizeof(struct nvme_command))
		return (tcp_transmit_command(nc));
	else
		return (tcp_transmit_response(nc));
}

static int
tcp_receive_capsule(struct nvmf_qpair *nq, struct nvmf_capsule **nc)
{
	struct nvmf_tcp_qpair *qp = TQP(nq);
	struct nvmf_tcp_capsule *tc;
	int error;

	while (TAILQ_EMPTY(&qp->rx_capsules)) {
		error = nvmf_tcp_receive_pdu(qp);
		if (error != 0)
			return (error);
	}
	tc = TAILQ_FIRST(&qp->rx_capsules);
	TAILQ_REMOVE(&qp->rx_capsules, tc, link);
	*nc = &tc->nc;
	return (0);
}

static uint8_t
tcp_validate_command_capsule(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_capsule *tc = TCAP(nc);
	struct nvme_sgl_descriptor *sgl;

	assert(tc->rx_pdu.hdr != NULL);

	sgl = (struct nvme_sgl_descriptor *)&nc->nc_sqe.prp1;
	if (sgl->unkeyed.type != NVME_SGL_TYPE_DATA_BLOCK) {
		printf("NVMe/TCP: Invalid SGL type in Command Capsule\n");
		return (NVME_SC_SGL_DESCRIPTOR_TYPE_INVALID);
	}

	if (sgl->address != 0) {
		printf("NVMe/TCP: Invalid SGL offset in Command Capsule\n");
		return (NVME_SC_SGL_OFFSET_INVALID);
	}

	switch (sgl->unkeyed.subtype) {
	case NVME_SGL_SUBTYPE_OFFSET:
		if (tc->rx_pdu.data_len != le32toh(sgl->unkeyed.length)) {
			printf("NVMe/TCP: Command Capsule with mismatched ICD length\n");
			return (NVME_SC_DATA_SGL_LENGTH_INVALID);
		}
		break;
	case NVME_SGL_SUBTYPE_TRANSPORT:
		if (tc->rx_pdu.data_len != 0) {
			printf("NVMe/TCP: Command Buffer SGL with ICD\n");
			return (NVME_SC_INVALID_FIELD);
		}
		break;
	default:
		printf("NVMe/TCP: Invalid SGL subtype in Command Capsule\n");
		return (NVME_SC_SGL_DESCRIPTOR_TYPE_INVALID);
	}

	return (NVME_SC_SUCCESS);
}

/* NB: cid and ttag are both little-endian already. */
static int
tcp_send_r2t(struct nvmf_tcp_qpair *qp, uint16_t cid, uint16_t ttag,
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
	if (qp->header_digests) {
		r2t.hdr.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(r2t.digest);
	}
	r2t.hdr.common.plen = htole32(plen);
	r2t.hdr.cccid = cid;
	r2t.hdr.ttag = ttag;
	r2t.hdr.r2to = htole32(data_offset);
	r2t.hdr.r2tl = htole32(data_len);

	if (qp->header_digests)
		r2t.digest = compute_digest(&r2t.hdr, sizeof(r2t.hdr));

	return (nvmf_tcp_write_pdu(qp, &r2t, plen));
}

static int
tcp_receive_r2t_data(struct nvmf_capsule *nc, uint32_t data_offset,
    uint32_t data_len, struct iovec *iov, u_int iovcnt)
{
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct nvmf_tcp_command_buffer *cb;
	int error;
	uint16_t ttag;

	/*
	 * Don't bother byte-swapping ttag as it is just a cookie
	 * value returned by the other end as-is.
	 */
	ttag = qp->next_ttag++;

	error = tcp_send_r2t(qp, nc->nc_sqe.cid, ttag, data_offset, data_len);
	if (error != 0)
		return (error);

	cb = tcp_alloc_command_buffer(qp, iov, iovcnt, data_offset, data_len,
	    nc->nc_sqe.cid, ttag, true);

	/* Parse received PDUs until the data transfer is complete. */
	while (cb->data_xfered < cb->data_len) {
		error = nvmf_tcp_receive_pdu(qp);
		if (error != 0)
			break;
	}
	tcp_free_command_buffer(cb);
	return (error);
}

static int
tcp_receive_icd_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct iovec *iov, u_int iovcnt)
{
	struct nvmf_tcp_capsule *tc = TCAP(nc);
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
	struct nvmf_association *na = nc->nc_qpair->nq_association;
	struct nvme_sgl_descriptor *sgl;
	size_t data_len, iov_len;
	u_int i;

	if (nc->nc_qe_len != sizeof(struct nvme_command) || !na->na_controller)
		return (EINVAL);

	iov_len = 0;
	for (i = 0; i < iovcnt; i++)
		iov_len += iov[i].iov_len;

	sgl = (struct nvme_sgl_descriptor *)&nc->nc_sqe.prp1;
	data_len = le32toh(sgl->unkeyed.length);
	if (data_offset + iov_len > data_len)
		return (EFBIG);

	if (sgl->unkeyed.subtype == NVME_SGL_SUBTYPE_OFFSET)
		return (tcp_receive_icd_data(nc, data_offset, iov, iovcnt));
	else
		return (tcp_receive_r2t_data(nc, data_offset, iov_len, iov,
		    iovcnt));
}

/* NB: cid is little-endian already. */
static int
tcp_send_c2h_pdu(struct nvmf_tcp_qpair *qp, uint16_t cid,
    uint32_t data_offset, void *buf, size_t len, bool last_pdu)
{
	struct {
		struct nvme_tcp_c2h_data_hdr hdr;
		uint32_t digest;
	} c2h;
	struct iovec iov[4];
	u_int iovcnt;
	uint32_t data_digest, pad, plen;

	memset(&c2h, 0, sizeof(c2h));
	c2h.hdr.common.pdu_type = NVME_TCP_PDU_TYPE_C2H_DATA;
	c2h.hdr.common.hlen = sizeof(c2h.hdr);
	plen = sizeof(c2h.hdr);
	if (last_pdu)
		c2h.hdr.common.flags |= NVME_TCP_C2H_DATA_FLAGS_LAST_PDU;
	if (qp->header_digests) {
		c2h.hdr.common.flags |= NVME_TCP_CH_FLAGS_HDGSTF;
		plen += sizeof(c2h.digest);
	}
	c2h.hdr.common.pdo = roundup2(plen, qp->txpda);
	pad = c2h.hdr.common.pdo - plen;
	c2h.hdr.cccid = cid;
	c2h.hdr.datao = htole32(data_offset);
	c2h.hdr.datal = htole32(len);

	/* CH + PSH + optional HDGST */
	iov[0].iov_base = &c2h;
	iov[0].iov_len = plen;
	iovcnt = 1;

	if (pad != 0) {
		/* PAD */
		plen += pad;
		iov[iovcnt].iov_base = __DECONST(char *, zero_padding);
		iov[iovcnt].iov_len = pad;
		iovcnt++;
	}

	/* DATA */
	plen += len;
	iov[iovcnt].iov_base = buf;
	iov[iovcnt].iov_len = len;
	iovcnt++;

	/* DDGST */
	if (qp->data_digests) {
		c2h.hdr.common.flags |= NVME_TCP_CH_FLAGS_DDGSTF;
		plen += sizeof(data_digest);
		iov[iovcnt].iov_base = &data_digest;
		iov[iovcnt].iov_len = sizeof(data_digest);
		iovcnt++;

		data_digest = compute_digest(buf, len);
	}

	c2h.hdr.common.plen = htole32(plen);
	if (qp->header_digests)
		c2h.digest = compute_digest(&c2h.hdr, sizeof(c2h.hdr));

	return (nvmf_tcp_write_pdu_iov(qp, iov, iovcnt, plen));
}

static int
tcp_send_controller_data(struct nvmf_capsule *nc, struct iovec *iov,
    u_int iovcnt)
{
	struct nvmf_association *na = nc->nc_qpair->nq_association;
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct nvme_sgl_descriptor *sgl;
	size_t iov_len;
	uint32_t data_len, data_offset;
	u_int i;
	int error;

	if (nc->nc_qe_len != sizeof(struct nvme_command) || !na->na_controller)
		return (EINVAL);

	iov_len = 0;
	for (i = 0; i < iovcnt; i++)
		iov_len += iov[i].iov_len;

	sgl = (struct nvme_sgl_descriptor *)&nc->nc_sqe.prp1;
	data_len = le32toh(sgl->unkeyed.length);
	if (iov_len != data_len)
		return (EFBIG);

	if (sgl->unkeyed.subtype == NVME_SGL_SUBTYPE_OFFSET)
		return (EINVAL);

	/*
	 * Write out one or more C2H_DATA PDUs containing the data.
	 * To avoid copying and constructing more iovecs, send one
	 * iovec entry at a time.
	 */
	data_offset = 0;
	for (i = 0; i < iovcnt; i++) {
		error = tcp_send_c2h_pdu(qp, nc->nc_sqe.cid, data_offset,
		    iov[i].iov_base, iov[i].iov_len, i == iovcnt);
		if (error != 0)
			return (error);
	}
	return (0);
}

struct nvmf_transport_ops tcp_ops = {
	.allocate_association = tcp_allocate_association,
	.update_association = tcp_update_association,
	.free_association = tcp_free_association,
	.allocate_qpair = tcp_allocate_qpair,
	.free_qpair = tcp_free_qpair,
	.kernel_handoff_params = tcp_kernel_handoff_params,
	.allocate_capsule = tcp_allocate_capsule,
	.free_capsule = tcp_free_capsule,
	.transmit_capsule = tcp_transmit_capsule,
	.receive_capsule = tcp_receive_capsule,
	.validate_command_capsule = tcp_validate_command_capsule,
	.receive_controller_data = tcp_receive_controller_data,
	.send_controller_data = tcp_send_controller_data,
};
