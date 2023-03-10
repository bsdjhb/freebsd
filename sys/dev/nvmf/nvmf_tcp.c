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
#include <sys/uio.h>
#include <netinet/in.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>

struct nvmf_tcp_capsule {
	struct nvmf_capsule nc;

	STAILQ_ENTRY(nvmf_tcp_capsule) link;
};

struct nvmf_tcp_connection {
	struct nvmf_connection nc;
	struct socket *so;

	bool	controller;
	uint8_t	pda;
	uint8_t	dgst;
	uint32_t maxr2t;
	uint32_t maxh2cdata;

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
};

#define	TCONN(nc)	((struct nvmf_tcp_connection *)(nc))
#define	TCAPSULE(nc)	((struct nvmf_tcp_capsule *)(nc))

static void	tcp_free_capsule(struct nvmf_capsule *nc);
static void	tcp_free_connection(struct nvmf_connection *nc);

static MALLOC_DEFINE(M_NVMF_TCP, "nvmf_tcp", "NVMe over TCP");

static int
mbuf_crc32c_helper(void *arg, void *data, u_int len)
{
	uint32_t *digestp = arg;

	*digestp = calculate_crc32c(*digestp, data, len);
	return (0);
}

static int
mbuf_crc32c(struct mbuf *m, u_int offset, u_int len)
{
	uint32_t digest = 0xffffffff;

	m_apply(m, offset, len, mbuf_crc32c_helper, &digest);
	digest = digest ^ 0xffffffff;

	return (digest);
}

static void
nvmf_tcp_report_error(struct nvmf_tcp_connection *tc, uint16_t fes,
    uint32_t fei, struct mbuf *rx_pdu, u_int hlen)
{
	struct nvme_tcp_term_req_hdr *hdr;
	struct socket *so = tc->so;
	struct mbuf *m;

	if (hlen != 0) {
		hlen = min(hlen, NVME_TCP_TERM_REQ_ERROR_DATA_MAX_SIZE);
		hlen = min(hlen, m_length(rx_pdu, NULL));
	}

	m = m_get2(sizeof(*hdr) + hlen, M_WAITOK, MT_DATA, M_PKTHDR);
	MPASS(m->m_len == sizeof(*hdr) + hlen);
	hdr = mtod(m, void *);
	memset(hdr, 0, sizeof(*hdr));
	hdr->common.pdu_type = tc->controller ? NVME_TCP_PDU_TYPE_C2H_TERM_REQ :
	    NVME_TCP_PDU_TYPE_H2C_TERM_REQ;
	hdr->common.hlen = sizeof(*hdr);
	hdr->common.plen = sizeof(*hdr) + hlen;
	hdr->fes = htole16(fes);
	le32enc(hdr->fei, fei);
	if (hlen != 0)
		m_copydata(rx_pdu, 0, hlen, (caddr_t)(hdr + 1));

	SOCKBUF_LOCK(&so->so_snd);
	mbufq_drain(&tc->tx_pdus);
	mbufq_enqueue(&tc->tx_pdus, m);
	/* XXX: Do we need to handle sb_hiwat being wrong? */
	if (sowriteable(so))
		cv_signal(&tc->tx_cv);
	SOCKBUF_UNLOCK(&so->so_snd);
}

static int
nvmf_tcp_parse_pdu(struct nvmf_tcp_connection *tc,
    struct nvme_tcp_common_pdu_hdr *ch, struct mbuf *m)
{
	uint32_t data_len, plen;
	uint32_t digest, rx_digest;
	u_int full_hlen, hlen, expected_hlen;
	uint8_t valid_flags;
	bool data_digest_mismatch;

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
	if (tc->controller != (ch->pdu_type & 0x01) == 0) {
		printf("NVMe/TCP: Invalid PDU type %u\n", ch->pdu_type);
		nvmf_tcp_report_error(tc,
		    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 0, m, hlen);
		return (EBADMSG);
	}

	switch (ch->pdu_type) {
	case NVME_TCP_PDU_TYPE_IC_REQ:
	case NVME_TCP_PDU_TYPE_IC_RESP:
		/* Shouldn't get these in the kernel. */
		printf("NVMe/TCP: Received Initialize Connection PDU\n");
		nvmf_tcp_report_error(tc,
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
		nvmf_tcp_report_error(tc,
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
		nvmf_tcp_report_error(tc,
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
		nvmf_tcp_report_error(tc,
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
			nvmf_tcp_report_error(tc,
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

		/* XXX: NVME_TCP_PDU_PDO_MAX_OFFSET? */
		/* XXX: Should verify against any PDA we advertised. */
		if (ch->pdo < full_hlen || ch->pdo > plen) {
			printf("NVMe/TCP: Invalid PDU data offset %u\n",
			    ch->pdo);
			nvmf_tcp_report_error(tc,
			    NVME_TCP_TERM_REQ_FES_INVALID_HEADER_FIELD, 3, m,
			    hlen);
			return (EBADMSG);
		}
		break;
	}

	/* Validate plen. */
	if (plen < ch->hlen) {
		printf("NVMe/TCP: Invalid PDU length %u\n", plen);
		nvmf_tcp_report_error(tc,
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
			nvmf_tcp_report_error(tc,
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
			nvmf_tcp_report_error(tc,
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
			nvmf_tcp_report_error(tc,
			    NVME_TCP_TERM_REQ_FES_HDGST_ERROR, rx_digest, m,
			    full_hlen);
			return (EBADMSG);
		}
	}

	/* Check data digest if present. */
	data_digest_mismatch = false;
	if ((ch->flags & NVME_TCP_CH_FLAGS_DDGSTF) != 0) {
		data_len -= sizeof(rx_digest);
		digest = mbuf_crc32c(m, ch->pdo, data_len);
		m_copydata(m, plen - sizeof(rx_digest), sizeof(rx_digest),
		    (caddr_t)&rx_digest);
		if (digest != rx_digest) {
			printf("NVMe/TCP: Data digest mismatch\n");
			data_digest_mismatch = true;
		}
	}

	switch (ch->pdu_type) {
	default:
		__assert_unreachable();
		break;
	case NVME_TCP_PDU_TYPE_H2C_TERM_REQ:
	case NVME_TCP_PDU_TYPE_C2H_TERM_REQ:
		MPASS(!data_digest_mismatch);
		/* TODO */
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_CMD:
		/* TODO */
		break;
	case NVME_TCP_PDU_TYPE_CAPSULE_RESP:
		MPASS(!data_digest_mismatch);
		/* TODO */
		break;
	case NVME_TCP_PDU_TYPE_H2C_DATA:
		/* TODO */
		break;
	case NVME_TCP_PDU_TYPE_C2H_DATA:
		/* TODO */
		break;
	case NVME_TCP_PDU_TYPE_R2T:
		MPASS(!data_digest_mismatch);
		/* TODO */
		break;
	}

	/* XXX */
	return (EDOOFUS);
}

static void
nvmf_tcp_receive(void *arg)
{
	struct nvmf_tcp_connection *tc = arg;
	struct socket *so = tc->so;
	struct nvme_tcp_common_pdu_hdr ch;
	struct uio uio;
	struct iovec iov[1];
	struct mbuf *m;
	u_int avail, needed;
	int error, flags;
	bool have_header;

	have_header = false;
	needed = sizeof(ch);
	SOCKBUF_LOCK(&so->so_rcv);
	while (!tc->rx_shutdown) {
		/* Wait until there is enough data for the next step. */
		if (so->so_error != 0) {
			SOCKBUF_UNLOCK(&so->so_rcv);
		error:
			nvmf_connection_error(&tc->nc);
			SOCKBUF_LOCK(&so->so_rcv);
			while (!tc->rx_shutdown)
				cv_wait(&tc->rx_cv, SOCKBUF_MTX(&so->so_rcv));
			break;
		}
		avail = sbavail(&so->so_rcv);
		if (avail < needed) {
			cv_wait(&tc->rx_cv, SOCKBUF_MTX(&so->so_rcv));
			continue;
		}
		SOCKBUF_UNLOCK(&so->so_rcv);

		if (!have_header) {
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
			if (error != 0 || uio.uio_resid != 0)
				goto error;

			have_header = true;
			needed = le32toh(ch.plen);

			/*
			 * Malformed PDUs will be reported as errors
			 * by nvmf_tcp_parse_pdu.  Just pass along
			 * garbage headers if the lengths mismatch.
			 */
			if (needed < sizeof(ch) || ch.hlen > needed)
				needed = sizeof(ch);

			if (avail < needed) {
				SOCKBUF_LOCK(&so->so_rcv);
				continue;
			}
		}

		memset(&uio, 0, sizeof(uio));
		uio.uio_resid = needed;
		flags = MSG_DONTWAIT;
		error = soreceive(so, NULL, &uio, &m, NULL, &flags);
		if (error != 0 || uio.uio_resid != 0)
			goto error;

		error = nvmf_tcp_parse_pdu(tc, &ch, m);
		if (error != 0) {
			m_freem(m);

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
				error = cv_timedwait(&tc->rx_cv,
				    SOCKBUF_MTX(&so->so_rcv), 30 * hz);
				if (error == ETIMEDOUT)
					printf("NVMe/TCP: Timed out after sending terminate request\n");
			}
			SOCKBUF_UNLOCK(&so->so_rcv);
			goto error;
		}

		have_header = false;
		needed = sizeof(ch);
	}
	SOCKBUF_UNLOCK(&so->so_rcv);
	kthread_exit();
}

static struct mbuf *
capsule_to_pdu(struct nvmf_tcp_connection *tc, struct nvmf_tcp_capsule *tcap)
{
	/* XXX */
	return (NULL);
}

static void
nvmf_tcp_send(void *arg)
{
	struct nvmf_tcp_connection *tc = arg;
	struct nvmf_tcp_capsule *tcap;
	struct socket *so = tc->so;
	struct mbuf *m;
	u_int avail;
	int error;

	SOCKBUF_LOCK(&so->so_snd);
	while (!tc->tx_shutdown) {
		if (so->so_error != 0) {
			SOCKBUF_UNLOCK(&so->so_snd);
		error:
			nvmf_connection_error(&tc->nc);
			SOCKBUF_LOCK(&so->so_snd);
			while (!tc->tx_shutdown)
				cv_wait(&tc->tx_cv, SOCKBUF_MTX(&so->so_snd));
			break;
		}

		/* Next PDU to send. */
		m = mbufq_first(&tc->tx_pdus);
		if (m == NULL) {
			if (STAILQ_EMPTY(&tc->tx_capsules)) {
				cv_wait(&tc->tx_cv, SOCKBUF_MTX(&so->so_snd));
				continue;
			}

			/* Convert a capsule into a PDU. */
			tcap = STAILQ_FIRST(&tc->tx_capsules);
			STAILQ_REMOVE_HEAD(&tc->tx_capsules, link);
			SOCKBUF_UNLOCK(&so->so_snd);

			m = capsule_to_pdu(tc, tcap);

			SOCKBUF_LOCK(&so->so_snd);
			mbufq_enqueue(&tc->tx_pdus, m);
			continue;
		}

		/* Wait until there is enough room to send this PDU. */
		avail = sbavail(&so->so_snd);
		if (avail < m->m_pkthdr.len) {
			cv_wait(&tc->tx_cv, SOCKBUF_MTX(&so->so_snd));
			continue;
		}
		SOCKBUF_UNLOCK(&so->so_snd);

		error = sosend(so, NULL, NULL, m, NULL, MSG_DONTWAIT, NULL);
		if (error != 0)
			goto error;
	}
	SOCKBUF_UNLOCK(&so->so_snd);
	kthread_exit();
}

static int
nvmf_soupcall_receive(struct socket *so, void *arg, int waitflag)
{
	struct nvmf_tcp_connection *tc = arg;

	if (soreadable(so))
		cv_signal(&tc->rx_cv);
	return (SU_OK);
}

static int
nvmf_soupcall_send(struct socket *so, void *arg, int waitflag)
{
	struct nvmf_tcp_connection *tc = arg;

	if (sowriteable(so))
		cv_signal(&tc->tx_cv);
	return (SU_OK);
}

static struct nvmf_connection *
tcp_allocate_connection(bool controller,
    const union nvmf_connection_params *params)
{
	struct nvmf_tcp_connection *tc;
	struct socket *so;
	struct file *fp;
	cap_rights_t rights;
	u_long recvspace, sendspace;
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

	/* Ensure socket send buffers are large enough to hold at least one PDU. */
	recvspace = ulmax(so->so_rcv.sb_hiwat, NVMF_TCP_MAX_PDU_SIZE);
	sendspace = ulmax(so->so_snd.sb_hiwat, NVMF_TCP_MAX_PDU_SIZE);
	error = soreserve(so, recvspace, sendspace);
	if (error != 0) {
		fdrop(fp, curthread);
		return (NULL);
	}

	/* Claim socket from file descriptor. */
	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	fdrop(fp, curthread);

	tc = malloc(sizeof(*tc), M_NVMF_TCP, M_WAITOK | M_ZERO);
	tc->so = so;
	tc->controller = controller;
	tc->pda = params->tcp.pda;
	tc->dgst = params->tcp.dgst;
	tc->maxr2t = params->tcp.maxr2t;
	tc->maxh2cdata = params->tcp.maxh2cdata;
	cv_init(&tc->rx_cv, "-");
	cv_init(&tc->tx_cv, "-");
	mbufq_init(&tc->tx_pdus, INT_MAX);
	STAILQ_INIT(&tc->tx_capsules);

	/* Register socket upcalls. */
	SOCKBUF_LOCK(&so->so_snd);
	soupcall_set(so, SO_SND, nvmf_soupcall_send, tc);
	SOCKBUF_UNLOCK(&so->so_snd);
	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, nvmf_soupcall_receive, tc);
	SOCKBUF_UNLOCK(&so->so_rcv);

	/* Spin up kthreads. */
	error = kthread_add(nvmf_tcp_receive, tc, NULL, &tc->rx_thread, 0, 0,
	    "nvmef tcp rx");
	if (error != 0) {
		tcp_free_connection(&tc->nc);
		return (NULL);
	}
	error = kthread_add(nvmf_tcp_send, tc, NULL, &tc->tx_thread, 0, 0,
	    "nvmef tcp tx");
	if (error != 0) {
		tcp_free_connection(&tc->nc);
		return (NULL);
	}

	return (&tc->nc);
}

static void
tcp_free_connection(struct nvmf_connection *nc)
{
	struct nvmf_tcp_connection *tc = TCONN(nc);
	struct nvmf_tcp_capsule *tcap, *ncap;
	struct socket *so = tc->so;

	/* Shut down kthreads. */
	SOCKBUF_LOCK(&so->so_rcv);
	tc->rx_shutdown = true;
	if (tc->rx_thread != NULL) {
		cv_signal(&tc->rx_cv);
		mtx_sleep(tc->rx_thread, SOCKBUF_MTX(&so->so_rcv), 0,
		    "nvtcprx", 0);
	}
	SOCKBUF_UNLOCK(&so->so_rcv);

	SOCKBUF_LOCK(&so->so_snd);
	tc->tx_shutdown = true;
	if (tc->tx_thread != NULL) {
		cv_signal(&tc->tx_cv);
		mtx_sleep(tc->tx_thread, SOCKBUF_MTX(&so->so_snd), 0,
		    "nvtcptx", 0);
	}
	SOCKBUF_UNLOCK(&so->so_snd);

	SOCKBUF_LOCK(&so->so_snd);
	soupcall_clear(so, SO_SND);
	SOCKBUF_UNLOCK(&so->so_snd);
	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_clear(so, SO_RCV);
	SOCKBUF_UNLOCK(&so->so_rcv);

	STAILQ_FOREACH_SAFE(tcap, &tc->tx_capsules, link, ncap) {
		tcp_free_capsule(&tcap->nc);
	}
	mbufq_drain(&tc->tx_pdus);

	soclose(so);

	cv_destroy(&tc->rx_cv);
	free(tc, M_NVMF_TCP);
}

static struct nvmf_qpair *
tcp_allocate_qpair(struct nvmf_connection *nc)
{
	struct nvmf_qpair *qp;

	qp = malloc(sizeof(*qp), M_NVMF_TCP, M_WAITOK | M_ZERO);
	return (qp);
}

static void
tcp_free_qpair(struct nvmf_qpair *qp)
{
	free(qp, M_NVMF_TCP);
}

static struct nvmf_capsule *
tcp_allocate_command(struct nvmf_qpair *qp)
{
	struct nvmf_tcp_capsule *nc;

	nc = malloc(sizeof(*nc) + sizeof(struct nvmf_fabric_connect_cmd),
	    M_NVMF_TCP, M_WAITOK | M_ZERO);
	nc->nc.nc_qe = nc + 1;
	nc->nc.nc_qe_len = sizeof(struct nvmf_fabric_connect_cmd);
	return (&nc->nc);
}

static struct nvmf_capsule *
tcp_allocate_response(struct nvmf_qpair *qp)
{
	struct nvmf_tcp_capsule *nc;

	nc = malloc(sizeof(*nc) + sizeof(struct nvmf_fabric_connect_rsp),
	    M_NVMF_TCP, M_WAITOK | M_ZERO);
	nc->nc.nc_qe = nc + 1;
	nc->nc.nc_qe_len = sizeof(struct nvmf_fabric_connect_rsp);
	return (&nc->nc);
}

static void
tcp_free_capsule(struct nvmf_capsule *nc)
{
	free(nc, M_NVMF_TCP);
}

static int
tcp_transmit_capsule(struct nvmf_capsule *nc)
{
	struct nvmf_tcp_connection *tc = TCONN(nc->nc_qpair->nq_connection);
	struct nvmf_tcp_capsule *tcap = TCAPSULE(nc);
	struct socket *so = tc->so;

	SOCKBUF_LOCK(&so->so_snd);
	STAILQ_INSERT_TAIL(&tc->tx_capsules, tcap, link);
	if (sowriteable(so))
		cv_signal(&tc->tx_cv);
	SOCKBUF_UNLOCK(&so->so_snd);
}

struct nvmf_transport_ops tcp_ops = {
	.allocate_connection = tcp_allocate_connection,
	.free_connection = tcp_free_connection,
	.allocate_qpair = tcp_allocate_qpair,
	.free_qpair = tcp_free_qpair,
	.allocate_command = tcp_allocate_command,
	.allocate_response = tcp_allocate_response,
	.free_capsule = tcp_free_capsule,
	.transmit_capsule = tcp_transmit_capsule,
	.trtype = NVMF_TRTYPE_TCP,
};

NVMF_TRANSPORT(tcp, tcp_ops);
