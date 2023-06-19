/*-
 * Copyright (c) 2022 Chelsio Communications, Inc.
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

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/bio.h>
#include <sys/file.h>
#include <sys/gsb_crc32.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <machine/bus.h>
#include <netinet/in.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/nvmf_transport_internal.h>

struct nvmf_tcp_qpair;

struct nvmf_tcp_command_buffer {
	struct nvmf_tcp_qpair *qp;

	struct nvmf_io_request io;
	size_t	data_len;
	size_t	data_xfered;
	uint32_t data_offset;

	u_int	refs;
	int	error;

	uint16_t cid;
	uint16_t ttag;

	LIST_ENTRY(nvmf_tcp_command_buffer) link;
};

struct nvmf_tcp_command_buffer_list {
	LIST_HEAD(, nvmf_tcp_command_buffer) head;
	struct mtx lock;
};

struct nvmf_tcp_qpair {
	struct nvmf_qpair qp;

	struct socket *so;

	uint8_t	txpda;
	uint8_t rxpda;
	bool header_digests;
	bool data_digests;
	uint32_t maxr2t;
	uint32_t maxh2cdata;
	uint32_t maxc2hdata;
	uint32_t max_icd;	/* Host only */
	uint16_t next_ttag;	/* Controller only */

	/* Receive state. */
	struct thread *rx_thread;
	struct cv rx_cv;
	bool	rx_shutdown;

	/* Transmit state. */
	struct thread *tx_thread;
	struct cv tx_cv;
	bool	tx_shutdown;
	struct mbufq tx_pdus;
	STAILQ_HEAD(, nvmf_tcp_capsule) tx_capsules;

	struct nvmf_tcp_command_buffer_list tx_buffers;
	struct nvmf_tcp_command_buffer_list rx_buffers;
};

struct nvmf_tcp_rxpdu {
	struct mbuf *m;
	struct nvme_tcp_common_pdu_hdr *hdr;
	uint32_t data_len;
	bool data_digest_mismatch;
};

struct nvmf_tcp_capsule {
	struct nvmf_capsule nc;

	struct nvmf_tcp_rxpdu rx_pdu;

	STAILQ_ENTRY(nvmf_tcp_capsule) link;
};

#define	TCAP(nc)	((struct nvmf_tcp_capsule *)(nc))
#define	TQP(qp)		((struct nvmf_tcp_qpair *)(qp))

static void	tcp_free_capsule(struct nvmf_capsule *nc);
static void	tcp_free_qpair(struct nvmf_qpair *nq);

SYSCTL_NODE(_kern_nvmf, OID_AUTO, tcp, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "TCP transport");
static u_int max_c2hdata = 256 * 1024;
SYSCTL_UINT(_kern_nvmf_tcp, OID_AUTO, max_c2hdata, CTLFLAG_RWTUN, &max_c2hdata,
    0, "Maximum size of data payload in a C2H_DATA PDU");

static MALLOC_DEFINE(M_NVMF_TCP, "nvmf_tcp", "NVMe over TCP");

static int
mbuf_crc32c_helper(void *arg, void *data, u_int len)
{
	uint32_t *digestp = arg;

	*digestp = calculate_crc32c(*digestp, data, len);
	return (0);
}

static uint32_t
mbuf_crc32c(struct mbuf *m, u_int offset, u_int len)
{
	uint32_t digest = 0xffffffff;

	m_apply(m, offset, len, mbuf_crc32c_helper, &digest);
	digest = digest ^ 0xffffffff;

	return (digest);
}

static uint32_t
compute_digest(const void *buf, size_t len)
{
	return (calculate_crc32c(0xffffffff, buf, len) ^ 0xffffffff);
}

static struct nvmf_tcp_command_buffer *
tcp_alloc_command_buffer(struct nvmf_tcp_qpair *qp,
    const struct nvmf_io_request *io, uint32_t data_offset, size_t data_len,
    uint16_t cid)
{
	struct nvmf_tcp_command_buffer *cb;

	cb = malloc(sizeof(*cb), M_NVMF_TCP, M_WAITOK);
	cb->qp = qp;
	cb->io = *io;
	cb->data_offset = data_offset;
	cb->data_len = data_len;
	cb->data_xfered = 0;
	refcount_init(&cb->refs, 1);
	cb->error = 0;
	cb->cid = cid;
	cb->ttag = 0;

	return (cb);
}

static void
tcp_hold_command_buffer(struct nvmf_tcp_command_buffer *cb)
{
	refcount_acquire(&cb->refs);
}

static void
tcp_free_command_buffer(struct nvmf_tcp_command_buffer *cb)
{
	nvmf_complete_io_request(&cb->io, cb->data_xfered, cb->error);
	free(cb, M_NVMF_TCP);
}

static void
tcp_release_command_buffer(struct nvmf_tcp_command_buffer *cb)
{
	if (refcount_release(&cb->refs))
		tcp_free_command_buffer(cb);
}

static void
tcp_add_command_buffer(struct nvmf_tcp_command_buffer_list *list,
    struct nvmf_tcp_command_buffer *cb)
{
	mtx_assert(&list->lock, MA_OWNED);
	LIST_INSERT_HEAD(&list->head, cb, link);
}

static struct nvmf_tcp_command_buffer *
tcp_find_command_buffer(struct nvmf_tcp_command_buffer_list *list,
    uint16_t cid, uint16_t ttag)
{
	struct nvmf_tcp_command_buffer *cb;

	mtx_assert(&list->lock, MA_OWNED);
	LIST_FOREACH(cb, &list->head, link) {
		if (cb->cid == cid && cb->ttag == ttag)
			return (cb);
	}
	return (NULL);
}

static void
tcp_remove_command_buffer(struct nvmf_tcp_command_buffer_list *list,
    struct nvmf_tcp_command_buffer *cb)
{
	mtx_assert(&list->lock, MA_OWNED);
	LIST_REMOVE(cb, link);
}

static void
tcp_purge_command_buffer(struct nvmf_tcp_command_buffer_list *list,
    uint16_t cid, uint16_t ttag)
{
	struct nvmf_tcp_command_buffer *cb;

	mtx_lock(&list->lock);
	cb = tcp_find_command_buffer(list, cid, ttag);
	if (cb != NULL) {
		tcp_remove_command_buffer(list, cb);
		mtx_unlock(&list->lock);
		tcp_release_command_buffer(cb);
	} else
		mtx_unlock(&list->lock);
}

static void
nvmf_tcp_write_pdu(struct nvmf_tcp_qpair *qp, struct mbuf *m)
{
	struct socket *so = qp->so;

	SOCKBUF_LOCK(&so->so_snd);
	mbufq_enqueue(&qp->tx_pdus, m);
	/* XXX: Do we need to handle sb_hiwat being wrong? */
	if (sowriteable(so))
		cv_signal(&qp->tx_cv);
	SOCKBUF_UNLOCK(&so->so_snd);
}

static void
nvmf_tcp_report_error(struct nvmf_tcp_qpair *qp, uint16_t fes, uint32_t fei,
    struct mbuf *rx_pdu, u_int hlen)
{
	struct nvme_tcp_term_req_hdr *hdr;
	struct mbuf *m;

	if (hlen != 0) {
		hlen = min(hlen, NVME_TCP_TERM_REQ_ERROR_DATA_MAX_SIZE);
		hlen = min(hlen, m_length(rx_pdu, NULL));
	}

	m = m_get2(sizeof(*hdr) + hlen, M_WAITOK, MT_DATA, 0);
	m->m_len = sizeof(*hdr) + hlen;
	hdr = mtod(m, void *);
	memset(hdr, 0, sizeof(*hdr));
	hdr->common.pdu_type = qp->qp.nq_controller ?
	    NVME_TCP_PDU_TYPE_C2H_TERM_REQ : NVME_TCP_PDU_TYPE_H2C_TERM_REQ;
	hdr->common.hlen = sizeof(*hdr);
	hdr->common.plen = sizeof(*hdr) + hlen;
	hdr->fes = htole16(fes);
	le32enc(hdr->fei, fei);
	if (hlen != 0)
		m_copydata(rx_pdu, 0, hlen, (caddr_t)(hdr + 1));

	nvmf_tcp_write_pdu(qp, m);
}

static int
nvmf_tcp_validate_pdu(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	const struct nvme_tcp_common_pdu_hdr *ch;
	struct mbuf *m = pdu->m;
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
	if (qp->qp.nq_controller != (ch->pdu_type & 0x01) == 0) {
		printf("NVMe/TCP: Invalid PDU type %u\n", ch->pdu_type);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, m, hlen);
		return (EBADMSG);
	}

	switch (ch->pdu_type) {
	case NVME_TCP_PDU_TYPE_IC_REQ:
	case NVME_TCP_PDU_TYPE_IC_RESP:
		/* Shouldn't get these in the kernel. */
		printf("NVMe/TCP: Received Initialize Connection PDU\n");
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, m, hlen);
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
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, m, hlen);
		return (EBADMSG);
	}

	/* Validate flags. */
	switch (ch->pdu_type) {
	default:
		__assert_unreachable();
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
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 1, m, hlen);
		return (EBADMSG);
	}

	/* 7.4.5.2: SUCCESS in C2H requires LAST_PDU */
	if (ch->pdu_type == NVME_TCP_PDU_TYPE_C2H_DATA &&
	    (ch->flags & (NVME_TCP_C2H_DATA_FLAGS_LAST_PDU |
	    NVME_TCP_C2H_DATA_FLAGS_SUCCESS)) ==
	    NVME_TCP_C2H_DATA_FLAGS_SUCCESS) {
		printf("NVMe/TCP: Invalid PDU header flags %#x\n", ch->flags);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 1, m, hlen);
		return (EBADMSG);
	}

	/* Validate hlen. */
	switch (ch->pdu_type) {
	default:
		__assert_unreachable();
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
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 2, m, hlen);
		return (EBADMSG);
	}

	/* Validate pdo. */
	full_hlen = ch->hlen;
	if ((ch->flags & NVME_TCP_CH_FLAGS_HDGSTF) != 0)
		full_hlen += sizeof(rx_digest);
	switch (ch->pdu_type) {
	default:
		__assert_unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
	case NVME_TCP_PDU_TYPE_R2T:
		if (ch->pdo != 0) {
			printf("NVMe/TCP: Invalid PDU data offset %u\n",
			    ch->pdo);
			nvmf_tcp_report_error(qp,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, m,
			    hlen);
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
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, m,
			    hlen);
			return (EBADMSG);
		}
		break;
	}

	/* Validate plen. */
	if (plen < ch->hlen) {
		printf("NVMe/TCP: Invalid PDU length %u\n", plen);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, m, hlen);
		return (EBADMSG);
	}

	if (plen == full_hlen)
		data_len = 0;
	else
		data_len = plen - ch->pdo;
	switch (ch->pdu_type) {
	default:
		__assert_unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		/* Checked above. */
		MPASS(plen <= NVME_TCP_TERM_REQ_PDU_MAX_SIZE);
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
	case NVME_TCP_PDU_TYPE_H2C_DATA:
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		if ((ch->flags & NVME_TCP_CH_FLAGS_DDGSTF) != 0 &&
		    data_len <= sizeof(rx_digest)) {
			printf("NVMe/TCP: PDU %u too short for digest\n",
			    ch->pdu_type);
			nvmf_tcp_report_error(qp,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, m,
			    hlen);
			return (EBADMSG);
		}
		break;
	case NVME_TCP_PDU_TYPE_R2T:
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
		if (data_len != 0) {
			printf("NVMe/TCP: PDU %u with data length %u\n",
			    ch->pdu_type, data_len);
			nvmf_tcp_report_error(qp,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 4, m,
			    hlen);
			return (EBADMSG);
		}
		break;
	}

	/* Check header digest if present. */
	if ((ch->flags & NVME_TCP_CH_FLAGS_HDGSTF) != 0) {
		digest = mbuf_crc32c(m, 0, ch->hlen);
		m_copydata(m, ch->hlen, sizeof(rx_digest), (caddr_t)&rx_digest);
		if (digest != rx_digest) {
			printf("NVMe/TCP: Header digest mismatch\n");
			nvmf_tcp_report_error(qp,
			    NVME_TCP_TERM_REQ_FES_HDGST_ERROR, rx_digest, m,
			    full_hlen);
			return (EBADMSG);
		}
	}

	/* Check data digest if present. */
	pdu->data_digest_mismatch = false;
	if ((ch->flags & NVME_TCP_CH_FLAGS_DDGSTF) != 0) {
		data_len -= sizeof(rx_digest);
		digest = mbuf_crc32c(m, ch->pdo, data_len);
		m_copydata(m, plen - sizeof(rx_digest), sizeof(rx_digest),
		    (caddr_t)&rx_digest);
		if (digest != rx_digest) {
			printf("NVMe/TCP: Data digest mismatch\n");
			pdu->data_digest_mismatch = true;
		}
	}

	pdu->data_len = data_len;
	return (0);
}

static void
nvmf_tcp_free_pdu(struct nvmf_tcp_rxpdu *pdu)
{
	m_freem(pdu->m);
	pdu->m = NULL;
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

	nc = nvmf_allocate_command(&qp->qp, &cmd->ccsqe, M_WAITOK);

	tc = TCAP(nc);
	tc->rx_pdu = *pdu;

	nvmf_capsule_received(&qp->qp, nc);
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

	nc = nvmf_allocate_response(&qp->qp, &rsp->rccqe, M_WAITOK);

	nc->nc_sqhd_valid = true;
	tc = TCAP(nc);
	tc->rx_pdu = *pdu;

	/*
	 * Once the CQE has been received, no further transfers to the
	 * command buffer for the associated CID can occur.
	 */
	tcp_purge_command_buffer(&qp->rx_buffers, rsp->rccqe.cid, 0);
	tcp_purge_command_buffer(&qp->tx_buffers, rsp->rccqe.cid, 0);

	nvmf_capsule_received(&qp->qp, nc);
	return (0);
}

/*
 * Construct a PDU that contains an optional data payload.  This
 * includes dealing with digests and the length fields in the common
 * header.
 */
static struct mbuf *
nvmf_tcp_construct_pdu(struct nvmf_tcp_qpair *qp, void *hdr, size_t hlen,
    struct mbuf *data, uint32_t data_len)
{
	struct nvme_tcp_common_pdu_hdr *ch;
	struct mbuf *top;
	uint32_t digest, pad, pdo, plen, mlen;

	plen = hlen;
	if (qp->header_digests)
		plen += sizeof(digest);
	if (data_len != 0) {
		KASSERT(m_length(data, NULL) == data_len, ("length mismatch"));
		pdo = roundup2(plen, qp->txpda);
		pad = pdo - plen;
		plen = pdo + data_len;
		if (qp->data_digests)
			plen += sizeof(digest);
		mlen = pdo;
	} else {
		KASSERT(data == NULL, ("payload mbuf with zero length"));
		pdo = 0;
		pad = 0;
		mlen = plen;
	}

	top = m_get2(mlen, M_WAITOK, MT_DATA, 0);
	top->m_len = mlen;
	ch = mtod(top, void *);
	memcpy(ch, hdr, hlen);
	ch->hlen = hlen;
	if (qp->header_digests)
		ch->flags |= NVME_TCP_CH_FLAGS_HDGSTF;
	if (qp->data_digests && data_len != 0)
		ch->flags |= NVME_TCP_CH_FLAGS_DDGSTF;
	ch->pdo = pdo;
	ch->plen = htole32(plen);

	/* HDGST */
	if (qp->header_digests) {
		digest = compute_digest(ch, hlen);
		memcpy((char *)ch + hlen, &digest, sizeof(digest));
	}

	if (pad != 0) {
		/* PAD */
		memset((char *)ch + pdo - pad, 0, pad);
	}

	if (data_len != 0) {
		/* DATA */
		top->m_next = data;

		/* DDGST */
		if (qp->data_digests) {
			digest = mbuf_crc32c(data, 0, data_len);

			/* XXX: Can't use m_append as it uses M_NOWAIT. */
			while (data->m_next != NULL)
				data = data->m_next;

			data->m_next = m_get(M_WAITOK, MT_DATA);
			data->m_next->m_len = sizeof(digest);
			memcpy(mtod(data->m_next, void *), &digest,
			    sizeof(digest));
		}
	}

	return (top);
}

/*
 * Copy len bytes starting at offset skip from an mbuf chain into an
 * I/O buffer at destination offset io_offset.
 */
static void
mbuf_copyto_io(struct mbuf *m, u_int skip, u_int len,
    struct nvmf_io_request *io, u_int io_offset)
{
	u_int todo;

	while (m->m_len <= skip) {
		skip -= m->m_len;
		m = m->m_next;
	}
	while (len != 0) {
		MPASS((m->m_flags & M_EXTPG) == 0);

		todo = m->m_len - skip;
		if (todo > len)
			todo = len;

		memdesc_copyback(&io->io_mem, io->io_offset + io_offset,
		    todo, mtod(m, const char *) + skip);
		skip = 0;
		io_offset += todo;
		len -= todo;
		m = m->m_next;
	}
}

static int
nvmf_tcp_handle_h2c_data(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_h2c_data_hdr *h2c;
	struct nvmf_tcp_command_buffer *cb;
	uint32_t data_len, data_offset;

	h2c = (void *)pdu->hdr;
	if (le32toh(h2c->datal) > qp->maxh2cdata) {
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_LIMIT_EXCEEDED, 0,
		    pdu->m, pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	mtx_lock(&qp->rx_buffers.lock);
	cb = tcp_find_command_buffer(&qp->rx_buffers, h2c->cccid, h2c->ttag);
	if (cb == NULL) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_h2c_data_hdr, ttag), pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	/* For a data digest mismatch, fail the I/O request. */
	if (pdu->data_digest_mismatch) {
		cb->error = EINTEGRITY;
		tcp_remove_command_buffer(&qp->rx_buffers, cb);
		mtx_unlock(&qp->rx_buffers.lock);
		tcp_release_command_buffer(cb);
		return (0);
	}

	data_len = le32toh(h2c->datal);
	if (data_len != pdu->data_len) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_h2c_data_hdr, datal), pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_offset = le32toh(h2c->datao);
	if (data_offset < cb->data_offset ||
	    data_offset + data_len > cb->data_offset + cb->data_len) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0, pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if (data_offset != cb->data_offset + cb->data_xfered) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if ((cb->data_xfered + data_len == cb->data_len) !=
	    ((pdu->hdr->flags & NVME_TCP_H2C_DATA_FLAGS_LAST_PDU) != 0)) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	cb->data_xfered += data_len;
	data_offset -= cb->data_offset;
	if (cb->data_xfered == cb->data_len) {
		tcp_remove_command_buffer(&qp->rx_buffers, cb);

		/*
		 * XXX: Should decrement count of active R2T's and mark
		 * ttag for this R2T unused.
		 */
	} else
		tcp_hold_command_buffer(cb);
	mtx_unlock(&qp->rx_buffers.lock);

	mbuf_copyto_io(pdu->m, pdu->hdr->pdo, data_len, &cb->io, data_offset);

	tcp_release_command_buffer(cb);
	nvmf_tcp_free_pdu(pdu);
	return (0);
}

static int
nvmf_tcp_handle_c2h_data(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvme_tcp_c2h_data_hdr *c2h;
	struct nvmf_tcp_command_buffer *cb;
	uint32_t cid, data_len, data_offset;

	c2h = (void *)pdu->hdr;

	mtx_lock(&qp->rx_buffers.lock);
	cb = tcp_find_command_buffer(&qp->rx_buffers, c2h->cccid, 0);
	if (cb == NULL) {
		mtx_unlock(&qp->rx_buffers.lock);
		/*
		 * XXX: Could be PDU sequence error if cccid is for a
		 * command that doesn't use a command buffer.
		 */
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_c2h_data_hdr, cccid), pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	/* For a data digest mismatch, fail the I/O request. */
	if (pdu->data_digest_mismatch) {
		cb->error = EINTEGRITY;
		tcp_remove_command_buffer(&qp->rx_buffers, cb);
		mtx_unlock(&qp->rx_buffers.lock);
		tcp_release_command_buffer(cb);
		return (0);
	}

	data_len = le32toh(c2h->datal);
	if (data_len != pdu->data_len) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_c2h_data_hdr, datal), pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_offset = le32toh(c2h->datao);
	if (data_offset < cb->data_offset ||
	    data_offset + data_len > cb->data_offset + cb->data_len) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0,
		    pdu->m, pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if (data_offset != cb->data_offset + cb->data_xfered) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	if ((cb->data_xfered + data_len == cb->data_len) !=
	    ((pdu->hdr->flags & NVME_TCP_C2H_DATA_FLAGS_LAST_PDU) != 0)) {
		mtx_unlock(&qp->rx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	cb->data_xfered += data_len;
	data_offset -= cb->data_offset;
	if (cb->data_xfered == cb->data_len)
		tcp_remove_command_buffer(&qp->rx_buffers, cb);
	else
		tcp_hold_command_buffer(cb);
	mtx_unlock(&qp->rx_buffers.lock);

	mbuf_copyto_io(pdu->m, pdu->hdr->pdo, data_len, &cb->io, data_offset);

	cid = cb->cid;
	tcp_release_command_buffer(cb);

	if ((pdu->hdr->flags & NVME_TCP_C2H_DATA_FLAGS_SUCCESS) != 0) {
		struct nvme_completion cqe;
		struct nvmf_capsule *nc;

		memset(&cqe, 0, sizeof(cqe));
		cqe.cid = cid;

		nc = nvmf_allocate_response(&qp->qp, &cqe, M_WAITOK);
		nc->nc_sqhd_valid = false;

		nvmf_capsule_received(&qp->qp, nc);
	}

	nvmf_tcp_free_pdu(pdu);
	return (0);
}

/* Called when m_free drops refcount to 0. */
static void
nvmf_tcp_mbuf_done(struct mbuf *m)
{
	struct nvmf_tcp_command_buffer *cb = m->m_ext.ext_arg1;

	tcp_free_command_buffer(cb);
}

static struct mbuf *
nvmf_tcp_mbuf(struct nvmf_tcp_command_buffer *cb, void *data, size_t len)
{
	struct mbuf *m;

	m = m_get(M_WAITOK, MT_DATA);
	m->m_flags |= M_RDONLY;
	m_extaddref(m, data, len, &cb->refs, nvmf_tcp_mbuf_done, cb, NULL);
	m->m_len = len;
	return (m);
}

static void
nvmf_tcp_free_mext_pg(struct mbuf *m)
{
	struct nvmf_tcp_command_buffer *cb = m->m_ext.ext_arg1;

	M_ASSERTEXTPG(m);
	tcp_release_command_buffer(cb);
}

static struct mbuf *
nvmf_tcp_mext_pg(struct nvmf_tcp_command_buffer *cb)
{
	struct mbuf *m;

	m = mb_alloc_ext_pgs(M_WAITOK, nvmf_tcp_free_mext_pg);
	m->m_ext.ext_arg1 = cb;
	tcp_hold_command_buffer(cb);
	return (m);
}

static struct mbuf *
nvmf_tcp_mbuf_vaddr(struct nvmf_tcp_command_buffer *cb,
    void *buf, uint32_t data_len, uint32_t *actual_len)
{
	*actual_len = data_len;
	return (nvmf_tcp_mbuf(cb, buf, data_len));
}

static bool
can_append_paddr(struct mbuf *m, vm_paddr_t pa)
{
	u_int last_len;

	/* Can always append to an empty mbuf. */
	if (m->m_epg_npgs == 0)
		return (true);

	/* Can't append to a full mbuf. */
	if (m->m_epg_npgs == MBUF_PEXT_MAX_PGS)
		return (false);

	/* Can't append a non-page-aligned address to a non-empty mbuf. */
	if ((pa & PAGE_MASK) != 0)
		return (false);

	/* Can't append if the last page is not a full page. */
	last_len = m->m_epg_last_len;
	if (m->m_epg_npgs == 1)
		last_len += m->m_epg_1st_off;
	return (last_len == PAGE_SIZE);
}

/*
 * Returns amount of data added to an M_EXTPG mbuf.
 */
static size_t
append_paddr_range(struct mbuf *m, vm_paddr_t pa, size_t len)
{
	size_t appended;

	appended = 0;

	/* Append the first page. */
	if (m->m_epg_npgs == 0) {
		m->m_epg_pa[0] = trunc_page(pa);
		m->m_epg_npgs = 1;
		m->m_epg_1st_off = pa & PAGE_MASK;
		m->m_epg_last_len = PAGE_SIZE - m->m_epg_1st_off;
		if (m->m_epg_last_len > len)
			m->m_epg_last_len = len;
		m->m_len = m->m_epg_last_len;
		len -= m->m_epg_last_len;
		pa += m->m_epg_last_len;
		appended += m->m_epg_last_len;
	}

	/* Full pages. */
	while (len >= PAGE_SIZE && m->m_epg_npgs < MBUF_PEXT_MAX_PGS) {
		m->m_epg_pa[m->m_epg_npgs] = pa;
		m->m_epg_npgs++;
		m->m_epg_last_len = PAGE_SIZE;
		m->m_len += PAGE_SIZE;
		pa += PAGE_SIZE;
		len -= PAGE_SIZE;
		appended += PAGE_SIZE;
	}

	/* Final partial page. */
	if (len > 0 && m->m_epg_npgs < MBUF_PEXT_MAX_PGS) {
		KASSERT(len < PAGE_SIZE, ("final page is full page"));
		m->m_epg_pa[m->m_epg_npgs] = pa;
		m->m_epg_npgs++;
		m->m_epg_last_len = len;
		m->m_len += len;
		appended += len;
	}

	return (appended);
}

static struct mbuf *
nvmf_tcp_mbuf_paddr(struct nvmf_tcp_command_buffer *cb, vm_paddr_t pa,
    uint32_t data_len, uint32_t *actual_len, bool can_truncate)
{
	struct mbuf *m, *tail;
	uint32_t len;

	if (can_truncate) {
		vm_paddr_t end;

		/*
		 * Trim any partial page at the end, but not if it's
		 * the only page.
		 */
		end = trunc_page(pa + data_len);
		if (end > pa)
			data_len = end - pa;
	}
	*actual_len = data_len;

	m = tail = nvmf_tcp_mext_pg(cb);
	while (data_len > 0) {
		if (!can_append_paddr(tail, pa)) {
			MBUF_EXT_PGS_ASSERT_SANITY(tail);
			tail->m_next = nvmf_tcp_mext_pg(cb);
			tail = tail->m_next;
		}

		len = append_paddr_range(tail, pa, data_len);
		KASSERT(len > 0, ("did not append anything"));

		pa += len;
		data_len -= len;
	}

	MBUF_EXT_PGS_ASSERT_SANITY(tail);
	return (m);
}

static struct mbuf *
nvmf_tcp_mbuf_vlist(struct nvmf_tcp_command_buffer *cb,
    struct bus_dma_segment *vlist, u_int sglist_cnt, size_t offset,
    uint32_t data_len, uint32_t *actual_len)
{
	struct mbuf *m, *n, *tail;
	uint32_t todo;

	*actual_len = data_len;

	while (vlist->ds_len <= offset) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		offset -= vlist->ds_len;
		vlist++;
		sglist_cnt--;
	}

	m = tail = NULL;
	while (data_len > 0) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		todo = data_len;
		if (todo > vlist->ds_len - offset)
			todo = vlist->ds_len - offset;

		n = nvmf_tcp_mbuf(cb, (char *)(uintptr_t)vlist->ds_addr +
		    offset, todo);

		if (m == NULL) {
			m = n;
			tail = m;
		} else {
			tail->m_next = n;
			tail = n;
		}

		offset = 0;
		vlist++;
		sglist_cnt--;
		data_len -= todo;
	}

	return (m);
}

static struct mbuf *
nvmf_tcp_mbuf_plist(struct nvmf_tcp_command_buffer *cb,
    struct bus_dma_segment *plist, u_int sglist_cnt, size_t offset,
    uint32_t data_len, uint32_t *actual_len, bool can_truncate)
{
	vm_paddr_t pa;
	struct mbuf *m, *tail;
	uint32_t done, len, todo;

	while (plist->ds_len <= offset) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		offset -= plist->ds_len;
		plist++;
		sglist_cnt--;
	}

	len = 0;
	m = tail = nvmf_tcp_mext_pg(cb);
	while (data_len > 0) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		pa = plist->ds_addr + offset;
		todo = data_len;
		if (todo > plist->ds_len - offset)
			todo = plist->ds_len - offset;

		/*
		 * If truncation is enabled, avoid sending a final
		 * partial page, but only if there is more data
		 * available in the current segment.  Also, at least
		 * some data must be sent, so only drop the final page
		 * for this segment if the segment spans multiple
		 * pages or some other data is already queued.
		 */
		else if (can_truncate) {
			vm_paddr_t end;

			end = trunc_page(pa + data_len);
			if (end <= pa && len != 0) {
				/*
				 * This last segment is only a partial
				 * page.
				 */
				data_len = 0;
				break;
			}
			todo = end - pa;
		}

		offset = 0;
		data_len -= todo;
		len += todo;

		while (todo > 0) {
			if (!can_append_paddr(tail, pa)) {
				MBUF_EXT_PGS_ASSERT_SANITY(tail);
				tail->m_next = nvmf_tcp_mext_pg(cb);
				tail = tail->m_next;
			}

			done = append_paddr_range(tail, pa, todo);
			KASSERT(done > 0, ("did not append anything"));

			pa += done;
			todo -= done;
		}
	}

	MBUF_EXT_PGS_ASSERT_SANITY(tail);
	*actual_len = len;
	return (m);
}

static struct mbuf *
nvmf_tcp_mbuf_vmpages(struct nvmf_tcp_command_buffer *cb, vm_page_t *ma,
    size_t offset, uint32_t data_len, uint32_t *actual_len, bool can_truncate)
{
	struct mbuf *m, *tail;

	while (offset >= PAGE_SIZE) {
		ma++;
		offset -= PAGE_SIZE;
	}

	if (can_truncate) {
		size_t end;

		/*
		 * Trim any partial page at the end, but not if it's
		 * the only page.
		 */
		end = trunc_page(offset + data_len);
		if (end > offset)
			data_len = end - offset;
	}
	*actual_len = data_len;

	m = tail = nvmf_tcp_mext_pg(cb);

	/* First page. */
	m->m_epg_pa[0] = VM_PAGE_TO_PHYS(*ma);
	ma++;
	m->m_epg_npgs = 1;
	m->m_epg_1st_off = offset;
	m->m_epg_last_len = PAGE_SIZE - offset;
	if (m->m_epg_last_len > data_len)
		m->m_epg_last_len = data_len;
	m->m_len = m->m_epg_last_len;
	data_len -= m->m_epg_last_len;

	/* Full pages. */
	while (data_len >= PAGE_SIZE) {
		if (tail->m_epg_npgs == MBUF_PEXT_MAX_PGS) {
			MBUF_EXT_PGS_ASSERT_SANITY(tail);
			tail->m_next = nvmf_tcp_mext_pg(cb);
			tail = tail->m_next;
		}

		tail->m_epg_pa[tail->m_epg_npgs] = VM_PAGE_TO_PHYS(*ma);
		ma++;
		tail->m_epg_npgs++;
		tail->m_epg_last_len = PAGE_SIZE;
		tail->m_len += PAGE_SIZE;
		data_len -= PAGE_SIZE;
	}

	/* Last partial page. */
	if (data_len > 0) {
		if (tail->m_epg_npgs == MBUF_PEXT_MAX_PGS) {
			MBUF_EXT_PGS_ASSERT_SANITY(tail);
			tail->m_next = nvmf_tcp_mext_pg(cb);
			tail = tail->m_next;
		}

		tail->m_epg_pa[tail->m_epg_npgs] = VM_PAGE_TO_PHYS(*ma);
		ma++;
		tail->m_epg_npgs++;
		tail->m_epg_last_len = data_len;
		tail->m_len += data_len;
	}

	MBUF_EXT_PGS_ASSERT_SANITY(tail);
	return (m);
}

static struct mbuf *
nvmf_tcp_mbuf_bio(struct nvmf_tcp_command_buffer *cb, struct bio *bio,
    size_t offset, uint32_t data_len, uint32_t *actual_len, bool can_truncate)
{
	KASSERT(offset + data_len <= bio->bio_bcount, ("out of bounds"));

	if ((bio->bio_flags & BIO_VLIST) != 0) {
		return (nvmf_tcp_mbuf_vlist(cb,
		    (bus_dma_segment_t *)bio->bio_data, bio->bio_ma_n, offset,
		    data_len, actual_len));
	}

	if ((bio->bio_flags & BIO_UNMAPPED) != 0) {
		return (nvmf_tcp_mbuf_vmpages(cb, bio->bio_ma,
		    bio->bio_ma_offset + offset, data_len, actual_len,
		    can_truncate));
	}

	return (nvmf_tcp_mbuf_vaddr(cb, bio->bio_data + offset, data_len,
	    actual_len));
}

/* Somewhat similar to m_copym but avoids a partial mbuf at the end. */
static struct mbuf *
nvmf_tcp_mbuf_subset(struct nvmf_tcp_command_buffer *cb,
    struct mbuf *m0, size_t offset, uint32_t data_len, uint32_t *actual_len,
    bool can_truncate)
{
	struct mbuf *m, *tail;
	uint32_t len;

	while (offset >= m0->m_len) {
		offset -= m0->m_len;
		m0 = m0->m_next;
	}

	/* Always return at least one mbuf. */
	len = m0->m_len - offset;
	if (len > data_len)
		len = data_len;

	m = m_get(M_WAITOK, MT_DATA);
	m->m_len = len;
	if (m0->m_flags & (M_EXT|M_EXTPG)) {
		m->m_data = m0->m_data + offset;
		mb_dupcl(m, m0);
	} else
		memcpy(mtod(m, void *), mtod(m0, char *) + offset, m->m_len);

	tail = m;
	m0 = m0->m_next;
	data_len -= len;
	while (data_len > 0) {
		/*
		 * If truncation is enabled, don't send any partial
		 * mbufs besides the first one.
		 */
		if (can_truncate && m0->m_len > data_len)
			break;

		tail->m_next = m_get(M_WAITOK, MT_DATA);
		tail = tail->m_next;
		tail->m_len = m0->m_len;
		if (m0->m_flags & (M_EXT|M_EXTPG)) {
			tail->m_data = m0->m_data;
			mb_dupcl(tail, m0);
		} else
			memcpy(mtod(tail, void *), mtod(m0, char *),
			    tail->m_len);

		len += tail->m_len;
		data_len -= tail->m_len;
	}
	*actual_len = len;
	return (m);
}

static struct mbuf *
nvmf_tcp_mbuf_ccb(struct nvmf_tcp_command_buffer *cb, union ccb *ccb,
    size_t offset, uint32_t data_len, uint32_t *actual_len, bool can_truncate)
{
	struct ccb_hdr *ccb_h;
	void *data_ptr;
	uint32_t dxfer_len;
	uint16_t sglist_cnt;

	ccb_h = &ccb->ccb_h;
	switch (ccb_h->func_code) {
	case XPT_SCSI_IO: {
		struct ccb_scsiio *csio;

		csio = &ccb->csio;
		data_ptr = csio->data_ptr;
		dxfer_len = csio->dxfer_len;
		sglist_cnt = csio->sglist_cnt;
		break;
	}
	case XPT_CONT_TARGET_IO: {
		struct ccb_scsiio *ctio;

		ctio = &ccb->ctio;
		data_ptr = ctio->data_ptr;
		dxfer_len = ctio->dxfer_len;
		sglist_cnt = ctio->sglist_cnt;
		break;
	}
	case XPT_ATA_IO: {
		struct ccb_ataio *ataio;

		ataio = &ccb->ataio;
		data_ptr = ataio->data_ptr;
		dxfer_len = ataio->dxfer_len;
		sglist_cnt = 0;
		break;
	}
	case XPT_NVME_IO:
	case XPT_NVME_ADMIN: {
		struct ccb_nvmeio *nvmeio;

		nvmeio = &ccb->nvmeio;
		data_ptr = nvmeio->data_ptr;
		dxfer_len = nvmeio->dxfer_len;
		sglist_cnt = nvmeio->sglist_cnt;
		break;
	}
	default:
		panic("%s: Unsupported func code %d", __func__,
		    ccb_h->func_code);
	}

	KASSERT(offset + data_len <= dxfer_len, ("out of bounds"));

	switch ((ccb_h->flags & CAM_DATA_MASK)) {
	case CAM_DATA_VADDR:
		return (nvmf_tcp_mbuf_vaddr(cb, (char *)data_ptr + offset,
		    data_len, actual_len));
	case CAM_DATA_PADDR:
		return (nvmf_tcp_mbuf_paddr(cb,
		    (vm_paddr_t)(uintptr_t)data_ptr + offset, data_len,
		    actual_len, can_truncate));
	case CAM_DATA_SG:
		return (nvmf_tcp_mbuf_vlist(cb, (bus_dma_segment_t *)data_ptr,
		    sglist_cnt, offset, data_len, actual_len));
	case CAM_DATA_SG_PADDR:
		return (nvmf_tcp_mbuf_plist(cb, (bus_dma_segment_t *)data_ptr,
		    sglist_cnt, offset, data_len, actual_len, can_truncate));
	case CAM_DATA_BIO:
		return (nvmf_tcp_mbuf_bio(cb, (struct bio *)data_ptr, offset,
		    data_len, actual_len, can_truncate));
	default:
		panic("%s: flags 0x%X unimplemented", __func__,
		    ccb_h->flags);
	}
}

/*
 * Return an mbuf chain for a range of data belonging to a command
 * buffer.
 *
 * The mbuf chain uses M_EXT mbufs which hold references on the
 * command buffer so that it remains "alive" until the data has been
 * fully transmitted.  If truncate_ok is true, then the mbuf chain
 * might return a short chain to avoid gratuitously splitting up a
 * page.
 */
static struct mbuf *
nvmf_tcp_command_buffer_mbuf(struct nvmf_tcp_command_buffer *cb,
    uint32_t data_offset, uint32_t data_len, uint32_t *actual_len,
    bool can_truncate)
{
	const struct memdesc *mem = &cb->io.io_mem;
	struct mbuf *m;
	uint32_t len;

	switch (cb->io.io_mem.md_type) {
	case MEMDESC_VADDR:
		m = nvmf_tcp_mbuf_vaddr(cb, (char *)mem->u.md_vaddr +
		    cb->io.io_offset + data_offset, data_len, &len);
		break;
	case MEMDESC_PADDR:
		m = nvmf_tcp_mbuf_paddr(cb, mem->u.md_paddr +
		    cb->io.io_offset + data_offset, data_len, &len,
		    can_truncate);
		break;
	case MEMDESC_VLIST:
		m = nvmf_tcp_mbuf_vlist(cb, mem->u.md_list, mem->md_opaque,
		    cb->io.io_offset + data_offset, data_len, &len);
		break;
	case MEMDESC_PLIST:
		m = nvmf_tcp_mbuf_plist(cb, mem->u.md_list, mem->md_opaque,
		    cb->io.io_offset + data_offset, data_len, &len,
		    can_truncate);
		break;
	case MEMDESC_BIO:
		m = nvmf_tcp_mbuf_bio(cb, mem->u.md_bio, cb->io.io_offset +
		    data_offset, data_len, &len, can_truncate);
		break;
	case MEMDESC_UIO:
		panic("uio not supported");
	case MEMDESC_MBUF:
		m = nvmf_tcp_mbuf_subset(cb, mem->u.md_mbuf, cb->io.io_offset +
		    data_offset, data_len, &len, can_truncate);
		break;
	case MEMDESC_CCB:
		m = nvmf_tcp_mbuf_ccb(cb, mem->u.md_ccb, cb->io.io_offset +
		    data_offset, data_len, &len, can_truncate);
		break;
	default:
		__assert_unreachable();
	}

	if (!can_truncate)
		KASSERT(len == data_len, ("short chain with no limit"));
	KASSERT(m_length(m, NULL) == len, ("length mismatch"));
	if (actual_len != NULL)
		*actual_len = len;
	return (m);
}

/* NB: cid and ttag and little-endian already. */
static void
tcp_send_h2c_pdu(struct nvmf_tcp_qpair *qp, uint16_t cid, uint16_t ttag,
    uint32_t data_offset, struct mbuf *m, size_t len, bool last_pdu)
{
	struct nvme_tcp_h2c_data_hdr h2c;
	struct mbuf *top;

	memset(&h2c, 0, sizeof(h2c));
	h2c.common.pdu_type = NVME_TCP_PDU_TYPE_H2C_DATA;
	if (last_pdu)
		h2c.common.flags |= NVME_TCP_H2C_DATA_FLAGS_LAST_PDU;
	h2c.cccid = cid;
	h2c.ttag = ttag;
	h2c.datao = htole32(data_offset);
	h2c.datal = htole32(len);

	top = nvmf_tcp_construct_pdu(qp, &h2c, sizeof(h2c), m, len);
	nvmf_tcp_write_pdu(qp, top);
}

static int
nvmf_tcp_handle_r2t(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_rxpdu *pdu)
{
	struct nvmf_tcp_command_buffer *cb;
	struct nvme_tcp_r2t_hdr *r2t;
	uint32_t data_len, data_offset;

	r2t = (void *)pdu->hdr;

	mtx_lock(&qp->tx_buffers.lock);
	cb = tcp_find_command_buffer(&qp->tx_buffers, r2t->cccid, 0);
	if (cb == NULL) {
		mtx_unlock(&qp->tx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD,
		    offsetof(struct nvme_tcp_r2t_hdr, cccid), pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	data_offset = le32toh(r2t->r2to);
	if (data_offset != cb->data_xfered) {
		mtx_unlock(&qp->tx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_PDU_SEQUENCE_ERROR, 0, pdu->m,
		    pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	/*
	 * XXX: The spec does not specify how to handle R2T tranfers
	 * out of range of the original command.
	 */
	data_len = le32toh(r2t->r2tl);
	if (data_offset + data_len > cb->data_len) {
		mtx_unlock(&qp->tx_buffers.lock);
		nvmf_tcp_report_error(qp,
		    NVME_TCP_TERM_REQ_FES_DATA_TRANSFER_OUT_OF_RANGE, 0,
		    pdu->m, pdu->hdr->hlen);
		nvmf_tcp_free_pdu(pdu);
		return (EBADMSG);
	}

	cb->data_xfered += data_len;
	if (cb->data_xfered == cb->data_len)
		tcp_remove_command_buffer(&qp->tx_buffers, cb);
	else
		tcp_hold_command_buffer(cb);
	mtx_unlock(&qp->tx_buffers.lock);

	/*
	 * Queue one or more H2C_DATA PDUs containing the requested
	 * data.
	 */
	while (data_len > 0) {
		struct mbuf *m;
		uint32_t sent, todo;

		todo = data_len;
		if (todo > qp->maxh2cdata)
			todo = qp->maxh2cdata;
		m = nvmf_tcp_command_buffer_mbuf(cb, data_offset, todo, &sent,
		    todo < data_len);
		tcp_send_h2c_pdu(qp, r2t->cccid, r2t->ttag, data_offset, m,
		    sent, sent == data_len);

		data_offset += sent;
		data_len -= sent;
	}

	tcp_release_command_buffer(cb);
	nvmf_tcp_free_pdu(pdu);
	return (0);
}

/* A variant of m_pullup that uses M_WAITOK instead of failing. */
static struct mbuf *
pullup_pdu_hdr(struct mbuf *m, int len)
{
	struct mbuf *n, *p;

	KASSERT(len <= MCLBYTES, ("%s: len too large", __func__));
	if (m->m_len >= len)
		return (m);

	n = m_get2(len, M_WAITOK, MT_DATA, 0);
	n->m_len = len;
	m_copydata(m, 0, len, mtod(n, void *));

	while (m != NULL && m->m_len <= len) {
		p = m->m_next;
		len -= m->m_len;
		m_free(m);
		m = p;
	}
	if (len > 0) {
		m->m_data += len;
		m->m_len -= len;
	}
	n->m_next = m;
	return (n);
}

static int
nvmf_tcp_dispatch_pdu(struct nvmf_tcp_qpair *qp,
    const struct nvme_tcp_common_pdu_hdr *ch, struct nvmf_tcp_rxpdu *pdu)
{
	/* Ensure the PDU header is contiguous. */
	pdu->m = pullup_pdu_hdr(pdu->m, ch->hlen);
	pdu->hdr = mtod(pdu->m, void *);

	switch (ch->pdu_type) {
	default:
		__assert_unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		return (nvmf_tcp_handle_term_req(pdu));
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		return (nvmf_tcp_save_command_capsule(qp, pdu));
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
		return (nvmf_tcp_save_response_capsule(qp, pdu));
	case NVME_TCP_PDU_TYPE_H2C_DATA:
		return (nvmf_tcp_handle_h2c_data(qp, pdu));
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		return (nvmf_tcp_handle_c2h_data(qp, pdu));
	case NVME_TCP_PDU_TYPE_R2T:
		return (nvmf_tcp_handle_r2t(qp, pdu));
	}
}

static void
nvmf_tcp_receive(void *arg)
{
	struct nvmf_tcp_qpair *qp = arg;
	struct socket *so = qp->so;
	struct nvmf_tcp_rxpdu pdu;
	struct nvme_tcp_common_pdu_hdr ch;
	struct uio uio;
	struct iovec iov[1];
	struct mbuf *m, *n, *tail;
	u_int avail, needed;
	int error, flags;
	bool have_header;

	m = tail = NULL;
	have_header = false;
	SOCKBUF_LOCK(&so->so_rcv);
	while (!qp->rx_shutdown) {
		/* Wait until there is enough data for the next step. */
		if (so->so_error != 0) {
			SOCKBUF_UNLOCK(&so->so_rcv);
		error:
			m_freem(m);
			nvmf_qpair_error(&qp->qp);
			SOCKBUF_LOCK(&so->so_rcv);
			while (!qp->rx_shutdown)
				cv_wait(&qp->rx_cv, SOCKBUF_MTX(&so->so_rcv));
			break;
		}
		avail = sbavail(&so->so_rcv);
		if (avail == 0 || (!have_header && avail < sizeof(ch))) {
			cv_wait(&qp->rx_cv, SOCKBUF_MTX(&so->so_rcv));
			continue;
		}
		SOCKBUF_UNLOCK(&so->so_rcv);

		if (!have_header) {
			KASSERT(m == NULL, ("%s: m != NULL but no header",
			    __func__));
			memset(&uio, 0, sizeof(uio));
			iov[0].iov_base = &ch;
			iov[0].iov_len = sizeof(ch);
			uio.uio_iov = iov;
			uio.uio_iovcnt = 1;
			uio.uio_resid = sizeof(ch);
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_rw = UIO_READ;
			flags = MSG_DONTWAIT | MSG_PEEK;

			error = soreceive(so, NULL, &uio, NULL, NULL, &flags);
			if (error != 0)
				goto error;
			KASSERT(uio.uio_resid == 0, ("%s: short CH read",
			    __func__));

			have_header = true;
			needed = le32toh(ch.plen);

			/*
			 * Malformed PDUs will be reported as errors
			 * by nvmf_tcp_validate_pdu.  Just pass along
			 * garbage headers if the lengths mismatch.
			 */
			if (needed < sizeof(ch) || ch.hlen > needed)
				needed = sizeof(ch);

			memset(&uio, 0, sizeof(uio));
			uio.uio_resid = needed;
		}

		flags = MSG_DONTWAIT;
		error = soreceive(so, NULL, &uio, &n, NULL, &flags);
		if (error != 0)
			goto error;

		if (m == NULL)
			m = n;
		else
			tail->m_next = n;

		if (uio.uio_resid != 0) {
			tail = n;
			while (tail->m_next != NULL)
				tail = tail->m_next;

			SOCKBUF_LOCK(&so->so_rcv);
			continue;
		}
#ifdef INVARIANTS
		tail = NULL;
#endif

		pdu.m = m;
		m = NULL;
		pdu.hdr = &ch;
		error = nvmf_tcp_validate_pdu(qp, &pdu);
		if (error != 0)
			m_freem(pdu.m);
		else
			error = nvmf_tcp_dispatch_pdu(qp, &ch, &pdu);
		if (error != 0) {
			/*
			 * If we received a termination request, close
			 * the connection immediately.
			 */
			if (error == ECONNRESET)
				goto error;

			/*
			 * Wait for up to 30 seconds for the socket to
			 * be closed by the other end.
			 */
			SOCKBUF_LOCK(&so->so_rcv);
			if (soreadable(so)) {
				error = cv_timedwait(&qp->rx_cv,
				    SOCKBUF_MTX(&so->so_rcv), 30 * hz);
				if (error == ETIMEDOUT)
					printf("NVMe/TCP: Timed out after sending terminate request\n");
			}
			SOCKBUF_UNLOCK(&so->so_rcv);
			goto error;
		}

		have_header = false;
		SOCKBUF_LOCK(&so->so_rcv);
	}
	SOCKBUF_UNLOCK(&so->so_rcv);
	kthread_exit();
}

static struct mbuf *
tcp_command_pdu(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_capsule *tc)
{
	struct nvmf_capsule *nc = &tc->nc;
	struct nvmf_tcp_command_buffer *cb;
	struct nvme_tcp_cmd cmd;
	struct mbuf *top, *m;
	bool use_icd;

	use_icd = false;
	cb = NULL;
	m = NULL;

	if (nc->nc_data.io_len != 0) {
		cb = tcp_alloc_command_buffer(qp, &nc->nc_data, 0,
		    nc->nc_data.io_len, nc->nc_sqe.cid);

		if (nc->nc_send_data && nc->nc_data.io_len <= qp->max_icd) {
			use_icd = true;
			m = nvmf_tcp_command_buffer_mbuf(cb, 0,
			    nc->nc_data.io_len, NULL, false);
			cb->data_xfered = nc->nc_data.io_len;
			tcp_release_command_buffer(cb);
		} else if (nc->nc_send_data) {
			mtx_lock(&qp->tx_buffers.lock);
			tcp_add_command_buffer(&qp->tx_buffers, cb);
			mtx_unlock(&qp->tx_buffers.lock);
		} else {
			mtx_lock(&qp->rx_buffers.lock);
			tcp_add_command_buffer(&qp->rx_buffers, cb);
			mtx_unlock(&qp->rx_buffers.lock);
		}
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.common.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_CMD;
	cmd.ccsqe = nc->nc_sqe;

	/* Populate SGL in SQE. */
	if (nc->nc_data.io_len != 0) {
		struct nvme_sgl_descriptor *sgl;

		sgl = (struct nvme_sgl_descriptor *)&cmd.ccsqe.prp1;
		memset(sgl, 0, sizeof(*sgl));
		sgl->address = 0;
		sgl->unkeyed.length = htole32(nc->nc_data.io_len);
		sgl->unkeyed.type = NVME_SGL_TYPE_DATA_BLOCK;
		if (use_icd) {
			/* Use in-capsule data. */
			sgl->unkeyed.subtype = NVME_SGL_SUBTYPE_OFFSET;
		} else {
			/* Use a command buffer. */
			sgl->unkeyed.subtype = NVME_SGL_SUBTYPE_TRANSPORT;
		}
	}

	top = nvmf_tcp_construct_pdu(qp, &cmd, sizeof(cmd), m, m != NULL ?
	    nc->nc_data.io_len : 0);
	return (top);
}

static struct mbuf *
tcp_response_pdu(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_capsule *tc)
{
	struct nvmf_capsule *nc = &tc->nc;
	struct nvme_tcp_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.common.pdu_type = NVME_TCP_PDU_TYPE_CAPSULE_RESP;
	rsp.rccqe = nc->nc_cqe;

	return (nvmf_tcp_construct_pdu(qp, &rsp, sizeof(rsp), NULL, 0));
}

static struct mbuf *
capsule_to_pdu(struct nvmf_tcp_qpair *qp, struct nvmf_tcp_capsule *tc)
{
	if (tc->nc.nc_qe_len == sizeof(struct nvme_command))
		return (tcp_command_pdu(qp, tc));
	else
		return (tcp_response_pdu(qp, tc));
}

static void
nvmf_tcp_send(void *arg)
{
	struct nvmf_tcp_qpair *qp = arg;
	struct nvmf_tcp_capsule *tc;
	struct socket *so = qp->so;
	struct mbuf *m, *n, *p;
	u_int avail, tosend;
	int error;

	m = NULL;
	SOCKBUF_LOCK(&so->so_snd);
	while (!qp->tx_shutdown) {
		if (so->so_error != 0) {
			SOCKBUF_UNLOCK(&so->so_snd);
		error:
			m_freem(m);
			nvmf_qpair_error(&qp->qp);
			SOCKBUF_LOCK(&so->so_snd);
			while (!qp->tx_shutdown)
				cv_wait(&qp->tx_cv, SOCKBUF_MTX(&so->so_snd));
			break;
		}

		if (m == NULL) {
			/* Next PDU to send. */
			m = mbufq_dequeue(&qp->tx_pdus);
		}
		if (m == NULL) {
			if (STAILQ_EMPTY(&qp->tx_capsules)) {
				cv_wait(&qp->tx_cv, SOCKBUF_MTX(&so->so_snd));
				continue;
			}

			/* Convert a capsule into a PDU. */
			tc = STAILQ_FIRST(&qp->tx_capsules);
			STAILQ_REMOVE_HEAD(&qp->tx_capsules, link);
			SOCKBUF_UNLOCK(&so->so_snd);

			n = capsule_to_pdu(qp, tc);

			SOCKBUF_LOCK(&so->so_snd);
			mbufq_enqueue(&qp->tx_pdus, n);
			continue;
		}

		/*
		 * Wait until there is enough room to send some data.
		 * If the socket buffer is empty, always send at least
		 * one mbuf even if the mbuf is larger than avail.
		 */
		avail = sbavail(&so->so_snd);
		if (avail < m->m_len && sbused(&so->so_snd) != 0) {
			cv_wait(&qp->tx_cv, SOCKBUF_MTX(&so->so_snd));
			continue;
		}
		SOCKBUF_UNLOCK(&so->so_snd);

		/* See how much data can be sent. */
		tosend = m->m_len;
		n = m->m_next;
		p = m;
		while (n != NULL && tosend + n->m_len <= avail) {
			tosend += n->m_len;
			p = n;
			n = n->m_next;
		}
		KASSERT(p->m_next == n, ("%s: p not before n", __func__));
		p->m_next = NULL;

		KASSERT(m_length(m, NULL) == tosend,
		    ("%s: length mismatch", __func__));
		error = sosend(so, NULL, NULL, m, NULL, MSG_DONTWAIT, NULL);
		if (error != 0) {
			m_freem(n);
			goto error;
		}
		m = n;
		SOCKBUF_LOCK(&so->so_snd);
	}
	SOCKBUF_UNLOCK(&so->so_snd);
	kthread_exit();
}

static int
nvmf_soupcall_receive(struct socket *so, void *arg, int waitflag)
{
	struct nvmf_tcp_qpair *qp = arg;

	if (soreadable(so))
		cv_signal(&qp->rx_cv);
	return (SU_OK);
}

static int
nvmf_soupcall_send(struct socket *so, void *arg, int waitflag)
{
	struct nvmf_tcp_qpair *qp = arg;

	if (sowriteable(so))
		cv_signal(&qp->tx_cv);
	return (SU_OK);
}

static struct nvmf_qpair *
tcp_allocate_qpair(bool controller __unused,
    const struct nvmf_handoff_qpair_params *params)
{
	struct nvmf_tcp_qpair *qp;
	struct socket *so;
	struct file *fp;
	cap_rights_t rights;
	int error;

	error = fget(curthread, params->tcp.fd, cap_rights_init_one(&rights,
	    CAP_SOCK_CLIENT), &fp);
	if (error != 0)
		return (NULL);
	if (fp->f_type != DTYPE_SOCKET) {
		fdrop(fp, curthread);
		return (NULL);
	}
	so = fp->f_data;
	if (so->so_type != SOCK_STREAM ||
	    so->so_proto->pr_protocol != IPPROTO_TCP) {
		fdrop(fp, curthread);
		return (NULL);
	}

	/* Claim socket from file descriptor. */
	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	fdrop(fp, curthread);

	qp = malloc(sizeof(*qp), M_NVMF_TCP, M_WAITOK | M_ZERO);
	qp->so = so;
	qp->txpda = params->tcp.txpda;
	qp->rxpda = params->tcp.rxpda;
	qp->header_digests = params->tcp.header_digests;
	qp->data_digests = params->tcp.data_digests;
	qp->maxr2t = params->tcp.maxr2t;
	qp->maxh2cdata = params->tcp.maxh2cdata;
	qp->maxc2hdata = max_c2hdata;
	qp->max_icd = params->tcp.max_icd;

	LIST_INIT(&qp->rx_buffers.head);
	LIST_INIT(&qp->tx_buffers.head);
	mtx_init(&qp->rx_buffers.lock, "nvmf/tcp rx buffers", NULL, MTX_DEF);
	mtx_init(&qp->tx_buffers.lock, "nvmf/tcp tx buffers", NULL, MTX_DEF);

	cv_init(&qp->rx_cv, "-");
	cv_init(&qp->tx_cv, "-");
	mbufq_init(&qp->tx_pdus, 0);
	STAILQ_INIT(&qp->tx_capsules);

	/* Register socket upcalls. */
	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, nvmf_soupcall_receive, qp);
	SOCKBUF_UNLOCK(&so->so_rcv);
	SOCKBUF_LOCK(&so->so_snd);
	soupcall_set(so, SO_SND, nvmf_soupcall_send, qp);
	SOCKBUF_UNLOCK(&so->so_snd);

	/* Spin up kthreads. */
	error = kthread_add(nvmf_tcp_receive, qp, NULL, &qp->rx_thread, 0, 0,
	    "nvmef tcp rx");
	if (error != 0) {
		tcp_free_qpair(&qp->qp);
		return (NULL);
	}
	error = kthread_add(nvmf_tcp_send, qp, NULL, &qp->tx_thread, 0, 0,
	    "nvmef tcp tx");
	if (error != 0) {
		tcp_free_qpair(&qp->qp);
		return (NULL);
	}

	return (&qp->qp);
}

static void
tcp_free_qpair(struct nvmf_qpair *nq)
{
	struct nvmf_tcp_qpair *qp = TQP(nq);
	struct nvmf_tcp_command_buffer *ncb, *cb;
	struct nvmf_tcp_capsule *ntc, *tc;
	struct socket *so = qp->so;

	/* Shut down kthreads and clear upcalls */
	SOCKBUF_LOCK(&so->so_snd);
	qp->tx_shutdown = true;
	if (qp->tx_thread != NULL) {
		cv_signal(&qp->tx_cv);
		mtx_sleep(qp->tx_thread, SOCKBUF_MTX(&so->so_snd), 0,
		    "nvtcptx", 0);
	}
	soupcall_clear(so, SO_SND);
	SOCKBUF_UNLOCK(&so->so_snd);

	SOCKBUF_LOCK(&so->so_rcv);
	qp->rx_shutdown = true;
	if (qp->rx_thread != NULL) {
		cv_signal(&qp->rx_cv);
		mtx_sleep(qp->rx_thread, SOCKBUF_MTX(&so->so_rcv), 0,
		    "nvtcprx", 0);
	}
	soupcall_clear(so, SO_RCV);
	SOCKBUF_UNLOCK(&so->so_rcv);

	STAILQ_FOREACH_SAFE(tc, &qp->tx_capsules, link, ntc) {
		tcp_free_capsule(&tc->nc);
	}
	mbufq_drain(&qp->tx_pdus);

	cv_destroy(&qp->tx_cv);
	cv_destroy(&qp->rx_cv);

	mtx_lock(&qp->rx_buffers.lock);
	LIST_FOREACH_SAFE(cb, &qp->rx_buffers.head, link, ncb) {
		tcp_remove_command_buffer(&qp->rx_buffers, cb);
		mtx_unlock(&qp->rx_buffers.lock);
		tcp_release_command_buffer(cb);
		mtx_lock(&qp->rx_buffers.lock);
	}
	mtx_destroy(&qp->rx_buffers.lock);

	mtx_lock(&qp->tx_buffers.lock);
	LIST_FOREACH_SAFE(cb, &qp->tx_buffers.head, link, ncb) {
		tcp_remove_command_buffer(&qp->tx_buffers, cb);
		mtx_unlock(&qp->tx_buffers.lock);
		tcp_release_command_buffer(cb);
		mtx_lock(&qp->tx_buffers.lock);
	}
	mtx_destroy(&qp->tx_buffers.lock);

	soclose(so);

	free(qp, M_NVMF_TCP);
}

static struct nvmf_capsule *
tcp_allocate_capsule(struct nvmf_qpair *qp, int how)
{
	struct nvmf_tcp_capsule *nc;

	nc = malloc(sizeof(*nc), M_NVMF_TCP, how | M_ZERO);
	if (nc == NULL)
		return (NULL);
	return (&nc->nc);
}

static void
tcp_free_capsule(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_capsule *tc = TCAP(nc);

	nvmf_tcp_free_pdu(&tc->rx_pdu);
	free(nc, M_NVMF_TCP);
}

static int
tcp_transmit_capsule(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct nvmf_tcp_capsule *tc = TCAP(nc);
	struct socket *so = qp->so;

	SOCKBUF_LOCK(&so->so_snd);
	STAILQ_INSERT_TAIL(&qp->tx_capsules, tc, link);
	if (sowriteable(so))
		cv_signal(&qp->tx_cv);
	SOCKBUF_UNLOCK(&so->so_snd);
	return (0);
}

static uint8_t
tcp_validate_command_capsule(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_capsule *tc = TCAP(nc);
	struct nvme_sgl_descriptor *sgl;

	KASSERT(tc->rx_pdu.hdr != NULL, ("capsule wasn't received"));

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
static void
tcp_send_r2t(struct nvmf_tcp_qpair *qp, uint16_t cid, uint16_t ttag,
    uint32_t data_offset, uint32_t data_len)
{
	struct nvme_tcp_r2t_hdr r2t;
	struct mbuf *m;

	memset(&r2t, 0, sizeof(r2t));
	r2t.common.pdu_type = NVME_TCP_PDU_TYPE_R2T;
	r2t.cccid = cid;
	r2t.ttag = ttag;
	r2t.r2to = htole32(data_offset);
	r2t.r2tl = htole32(data_len);

	m = nvmf_tcp_construct_pdu(qp, &r2t, sizeof(r2t), NULL, 0);
	nvmf_tcp_write_pdu(qp, m);
}

static void
tcp_receive_r2t_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct nvmf_io_request *io)
{
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct nvmf_tcp_command_buffer *cb;
	uint16_t ttag;

	cb = tcp_alloc_command_buffer(qp, io, data_offset, io->io_len,
	    nc->nc_sqe.cid);

	/*
	 * Don't bother byte-swapping ttag as it is just a cookie
	 * value returned by the other end as-is.
	 *
	 * XXX: This should probably be searching the current list of
	 * buffers to allocate a ttag.
	 */
	mtx_lock(&qp->rx_buffers.lock);
	ttag = qp->next_ttag++;
	cb->ttag = ttag;

	tcp_add_command_buffer(&qp->rx_buffers, cb);
	mtx_unlock(&qp->rx_buffers.lock);

	/*
	 * XXX: Should be checking qp->maxr2t here and queueing the
	 * r2t if there are too many in flight.
	 */
	tcp_send_r2t(qp, nc->nc_sqe.cid, ttag, data_offset, io->io_len);
}

static void
tcp_receive_icd_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct nvmf_io_request *io)
{
	struct nvmf_tcp_capsule *tc = TCAP(nc);

	mbuf_copyto_io(tc->rx_pdu.m, tc->rx_pdu.hdr->pdo + data_offset,
	    io->io_len, io, 0);
	nvmf_complete_io_request(io, io->io_len, 0);
}

static int
tcp_receive_controller_data(struct nvmf_capsule *nc, uint32_t data_offset,
    struct nvmf_io_request *io)
{
	struct nvme_sgl_descriptor *sgl;
	size_t data_len;

	if (nc->nc_qe_len != sizeof(struct nvme_command) ||
	    !nc->nc_qpair->nq_controller)
		return (EINVAL);

	sgl = (struct nvme_sgl_descriptor *)&nc->nc_sqe.prp1;
	data_len = le32toh(sgl->unkeyed.length);
	if (data_offset + io->io_len > data_len)
		return (EFBIG);

	if (sgl->unkeyed.subtype == NVME_SGL_SUBTYPE_OFFSET)
		tcp_receive_icd_data(nc, data_offset, io);
	else
		tcp_receive_r2t_data(nc, data_offset, io);
	return (0);
}

/* NB: cid is little-endian already. */
static void
tcp_send_c2h_pdu(struct nvmf_tcp_qpair *qp, uint16_t cid, uint32_t data_offset,
    struct mbuf *m, size_t len, bool last_pdu)
{
	struct nvme_tcp_c2h_data_hdr c2h;
	struct mbuf *top;

	memset(&c2h, 0, sizeof(c2h));
	c2h.common.pdu_type = NVME_TCP_PDU_TYPE_C2H_DATA;
	if (last_pdu)
		c2h.common.flags |= NVME_TCP_C2H_DATA_FLAGS_LAST_PDU;
	c2h.cccid = cid;
	c2h.datao = htole32(data_offset);
	c2h.datal = htole32(len);

	top = nvmf_tcp_construct_pdu(qp, &c2h, sizeof(c2h), m, len);
	nvmf_tcp_write_pdu(qp, top);
}

static int
tcp_send_controller_data(struct nvmf_capsule *nc, struct nvmf_io_request *io)
{
	struct nvmf_tcp_qpair *qp = TQP(nc->nc_qpair);
	struct nvmf_tcp_command_buffer *cb;
	struct nvme_sgl_descriptor *sgl;
	uint32_t data_len, data_offset;

	if (nc->nc_qe_len != sizeof(struct nvme_command) ||
	    !qp->qp.nq_controller)
		return (EINVAL);

	sgl = (struct nvme_sgl_descriptor *)&nc->nc_sqe.prp1;
	data_len = le32toh(sgl->unkeyed.length);
	if (io->io_len != data_len)
		return (EFBIG);

	if (sgl->unkeyed.subtype == NVME_SGL_SUBTYPE_OFFSET)
		return (EINVAL);

	/* Allocate a command buffer for the mbufs to hold a reference on. */
	cb = tcp_alloc_command_buffer(qp, io, 0, io->io_len, nc->nc_sqe.cid);

	/* Queue one more C2H_DATA PDUs containing the data from io. */
	data_offset = 0;
	while (data_len > 0) {
		struct mbuf *m;
		uint32_t sent, todo;

		todo = data_len;
		if (todo > qp->maxc2hdata)
			todo = qp->maxc2hdata;
		m = nvmf_tcp_command_buffer_mbuf(cb, data_offset, todo, &sent,
		    todo < data_len);
		tcp_send_c2h_pdu(qp, nc->nc_sqe.cid, data_offset, m, sent,
		    sent == data_len);

		data_offset += sent;
		data_len -= sent;
	}

	tcp_release_command_buffer(cb);
	return (0);
}

struct nvmf_transport_ops tcp_ops = {
	.allocate_qpair = tcp_allocate_qpair,
	.free_qpair = tcp_free_qpair,
	.allocate_capsule = tcp_allocate_capsule,
	.free_capsule = tcp_free_capsule,
	.transmit_capsule = tcp_transmit_capsule,
	.validate_command_capsule = tcp_validate_command_capsule,
	.receive_controller_data = tcp_receive_controller_data,
	.send_controller_data = tcp_send_controller_data,
	.trtype = NVMF_TRTYPE_TCP,
	.priority = 0,
};

NVMF_TRANSPORT(tcp, tcp_ops);
