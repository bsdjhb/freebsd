/*-
 * Copyright (c) 2012 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: Navdeep Parhar <np@FreeBSD.org>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/aio.h>
#include <sys/file.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/module.h>
#include <sys/protosw.h>
#include <sys/proc.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>		/* XXX */
#include <sys/taskqueue.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/tcp_var.h>
#define TCPSTATES
#include <netinet/tcp_fsm.h>
#include <netinet/toecore.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>

#ifdef TCP_OFFLOAD
#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_tcb.h"
#include "tom/t4_tom.h"

VNET_DECLARE(int, tcp_do_autorcvbuf);
#define V_tcp_do_autorcvbuf VNET(tcp_do_autorcvbuf)
VNET_DECLARE(int, tcp_autorcvbuf_inc);
#define V_tcp_autorcvbuf_inc VNET(tcp_autorcvbuf_inc)
VNET_DECLARE(int, tcp_autorcvbuf_max);
#define V_tcp_autorcvbuf_max VNET(tcp_autorcvbuf_max)

/* XXX: For debugging. */
#ifdef DEV_NETMAP
SYSCTL_DECL(_hw_cxgbe);
#else
SYSCTL_NODE(_hw, OID_AUTO, cxgbe, CTLFLAG_RD, 0, "cxgbe parameters");
#endif
SYSCTL_NODE(_hw_cxgbe, OID_AUTO, ddp, CTLFLAG_RD, NULL, "DDP stats");

static int ddp_aio_enable = 0;
SYSCTL_INT(_hw_cxgbe_ddp, OID_AUTO, aio_enable, CTLFLAG_RW, &ddp_aio_enable,
    0, "Use DDP for aio_read()");
static unsigned long ddp_aio_placed = 0;
SYSCTL_ULONG(_hw_cxgbe_ddp, OID_AUTO, aio_placed, CTLFLAG_RW, &ddp_aio_placed,
    0, "AIO requests completed via DDP");
static unsigned long ddp_aio_copied = 0;
SYSCTL_ULONG(_hw_cxgbe_ddp, OID_AUTO, aio_copied, CTLFLAG_RW, &ddp_aio_copied,
    0, "AIO requests completed via copies");
static unsigned long ddp_aio_mixed = 0;
SYSCTL_ULONG(_hw_cxgbe_ddp, OID_AUTO, aio_mixed, CTLFLAG_RW, &ddp_aio_mixed,
    0, "AIO requests completed via copies and DDP");

#if 0
static struct mbuf *get_ddp_mbuf(int len);
#endif
static void aio_ddp_requeue(void *context, int pending);
static void ddp_complete_all(struct toepcb *toep, struct sockbuf *sb,
    long status, int error);
static void unwire_ddp_buffer(struct ddp_buffer *db);

#define PPOD_SZ(n)	((n) * sizeof(struct pagepod))
#define PPOD_SIZE	(PPOD_SZ(1))

/* XXX: must match A_ULP_RX_TDDP_PSZ */
static int t4_ddp_pgsz[] = {4096, 4096 << 2, 4096 << 4, 4096 << 6};

#define MAX_DDP_BUFFER_SIZE		(M_TCB_RX_DDP_BUF0_LEN)
static int
alloc_ppods(struct tom_data *td, int n, u_int *ppod_addr)
{
	vmem_addr_t v;
	int rc;

	MPASS(n > 0);

	rc = vmem_alloc(td->ppod_arena, PPOD_SZ(n), M_NOWAIT | M_FIRSTFIT, &v);
	*ppod_addr = (u_int)v;

	return (rc);
}

static void
free_ppods(struct tom_data *td, u_int ppod_addr, int n)
{

	MPASS(n > 0);

	vmem_free(td->ppod_arena, (vmem_addr_t)ppod_addr, PPOD_SZ(n));
}

static inline int
pages_to_nppods(int npages, int ddp_pgsz)
{
	int nsegs = npages * PAGE_SIZE / ddp_pgsz;

	return (howmany(nsegs, PPOD_PAGES));
}

static void
free_ddp_buffer(struct tom_data *td, struct ddp_buffer *db)
{

	if (db == NULL)
		return;

	if (db->cbe) {
		unwire_ddp_buffer(db);

		/*
		 * XXX: If we are un-offloading the socket then we
		 * should requeue these on the socket somehow.  If we
		 * got a FIN from the remote end, then this completes
		 * any remaining requests with an EOF read.
		 */
		aio_complete(db->cbe, 0, 0);
	}
		
	if (db->pages)
		free(db->pages, M_CXGBE);

	if (db->nppods > 0)
		free_ppods(td, db->ppod_addr, db->nppods);

	free(db, M_CXGBE);
}

void
ddp_init_toep(struct toepcb *toep)
{

	TAILQ_INIT(&toep->ddp_aiojobq);
	TASK_INIT(&toep->ddp_requeue_task, 0, aio_ddp_requeue, toep);
	toep->ddp_active_id = -1;
}

void
release_ddp_resources(struct toepcb *toep)
{
	int i;

	/* XXX: Can't drain as this is called with INP lock held. */
	taskqueue_cancel(taskqueue_thread, &toep->ddp_requeue_task, NULL);
	for (i = 0; i < nitems(toep->db); i++) {
		if (toep->db[i] != NULL) {
			free_ddp_buffer(toep->td, toep->db[i]);
			toep->db[i] = NULL;
		}
	}
}

/* XXX: handle_ddp_data code duplication */
void
insert_ddp_data(struct toepcb *toep, uint32_t n)
{
	struct inpcb *inp = toep->inp;
	struct tcpcb *tp = intotcpcb(inp);
	struct sockbuf *sb = &inp->inp_socket->so_rcv;
	struct ddp_buffer *db;
	struct aiocblist *cbe;
	size_t placed;
	long copied;
	unsigned int db_flag, db_idx;

	INP_WLOCK_ASSERT(inp);
	SOCKBUF_LOCK_ASSERT(sb);

	tp->rcv_nxt += n;
#ifndef USE_DDP_RX_FLOW_CONTROL
	KASSERT(tp->rcv_wnd >= n, ("%s: negative window size", __func__));
	tp->rcv_wnd -= n;
#endif
#if 0
	KASSERT(toep->sb_cc >= sbused(sb),
	    ("%s: sb %p has more data (%d) than last time (%d).",
	    __func__, sb, sbused(sb), toep->sb_cc));
	toep->rx_credits += toep->sb_cc - sbused(sb);
#else
	/*
	 * XXX: Not at all sure what to do here since we now bypass the
	 * socket buffer.
	 */
	toep->rx_credits += n;
#endif
#ifdef USE_DDP_RX_FLOW_CONTROL
	toep->rx_credits -= n;	/* adjust for F_RX_FC_DDP */
#endif
	while (toep->ddp_active_count > 0) {
		MPASS(toep->ddp_active_id != -1);
		db_idx = toep->ddp_active_id;
		db_flag = db_idx == 1 ? DDP_BUF1_ACTIVE : DDP_BUF0_ACTIVE;
		MPASS((toep->ddp_flags & db_flag) != 0);
		db = toep->db[db_idx];
		cbe = db->cbe;
		copied = cbe->uaiocb._aiocb_private.status;
		placed = n;
		if (placed > cbe->uaiocb.aio_nbytes - copied)
			placed = cbe->uaiocb.aio_nbytes - copied;
		if (copied + placed != 0) {
			CTR4(KTR_CXGBE,
			    "%s: completing %p (copied %ld, placed %lu)",
			    __func__, cbe, copied, placed);
			/* XXX: This always completes if there is some data. */
			aio_complete(cbe, copied + placed, 0);
			if (copied != 0 && placed != 0)
				ddp_aio_mixed++;
			else if (copied != 0)
				ddp_aio_copied++;
			else
				ddp_aio_placed++;
		} else {
			TAILQ_INSERT_HEAD(&toep->ddp_aiojobq, cbe, list);
			toep->ddp_waiting_count++;
		}
		n -= placed;
		toep->ddp_active_count--;
		if (toep->ddp_active_count == 0) {
			KASSERT(toep->db[db_idx ^ 1] == NULL ||
			    toep->db[db_idx ^ 1]->cbe == NULL,
			    ("%s: active_count mismatch", __func__));
			toep->ddp_active_id = -1;
		} else
			toep->ddp_active_id ^= 1;
		toep->ddp_flags &= ~db_flag;
	}

	MPASS(n == 0);
	if (toep->ddp_waiting_count > 0 && sbavail(sb) != 0)
		taskqueue_enqueue(taskqueue_thread, &toep->ddp_requeue_task);
}

/* SET_TCB_FIELD sent as a ULP command looks like this */
#define LEN__SET_TCB_FIELD_ULP (sizeof(struct ulp_txpkt) + \
    sizeof(struct ulptx_idata) + sizeof(struct cpl_set_tcb_field_core))

/* RX_DATA_ACK sent as a ULP command looks like this */
#define LEN__RX_DATA_ACK_ULP (sizeof(struct ulp_txpkt) + \
    sizeof(struct ulptx_idata) + sizeof(struct cpl_rx_data_ack_core))

static inline void *
mk_set_tcb_field_ulp(struct ulp_txpkt *ulpmc, struct toepcb *toep,
    uint64_t word, uint64_t mask, uint64_t val)
{
	struct ulptx_idata *ulpsc;
	struct cpl_set_tcb_field_core *req;

	ulpmc->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	ulpmc->len = htobe32(howmany(LEN__SET_TCB_FIELD_ULP, 16));

	ulpsc = (struct ulptx_idata *)(ulpmc + 1);
	ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	ulpsc->len = htobe32(sizeof(*req));

	req = (struct cpl_set_tcb_field_core *)(ulpsc + 1);
	OPCODE_TID(req) = htobe32(MK_OPCODE_TID(CPL_SET_TCB_FIELD, toep->tid));
	req->reply_ctrl = htobe16(V_NO_REPLY(1) |
	    V_QUEUENO(toep->ofld_rxq->iq.abs_id));
	req->word_cookie = htobe16(V_WORD(word) | V_COOKIE(0));
        req->mask = htobe64(mask);
        req->val = htobe64(val);

	ulpsc = (struct ulptx_idata *)(req + 1);
	if (LEN__SET_TCB_FIELD_ULP % 16) {
		ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_NOOP));
		ulpsc->len = htobe32(0);
		return (ulpsc + 1);
	}
	return (ulpsc);
}

static inline void *
mk_rx_data_ack_ulp(struct ulp_txpkt *ulpmc, struct toepcb *toep)
{
	struct ulptx_idata *ulpsc;
	struct cpl_rx_data_ack_core *req;

	ulpmc->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	ulpmc->len = htobe32(howmany(LEN__RX_DATA_ACK_ULP, 16));

	ulpsc = (struct ulptx_idata *)(ulpmc + 1);
	ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	ulpsc->len = htobe32(sizeof(*req));

	req = (struct cpl_rx_data_ack_core *)(ulpsc + 1);
	OPCODE_TID(req) = htobe32(MK_OPCODE_TID(CPL_RX_DATA_ACK, toep->tid));
	req->credit_dack = htobe32(F_RX_MODULATE_RX);

	ulpsc = (struct ulptx_idata *)(req + 1);
	if (LEN__RX_DATA_ACK_ULP % 16) {
		ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_NOOP));
		ulpsc->len = htobe32(0);
		return (ulpsc + 1);
	}
	return (ulpsc);
}

#if 0
static inline uint64_t
select_ddp_flags(struct socket *so, int flags, int db_idx)
{
	uint64_t ddp_flags = V_TF_DDP_INDICATE_OUT(0);
	int waitall = flags & MSG_WAITALL;
	int nb = so->so_state & SS_NBIO || flags & (MSG_DONTWAIT | MSG_NBIO);

	KASSERT(db_idx == 0 || db_idx == 1,
	    ("%s: bad DDP buffer index %d", __func__, db_idx));

	if (db_idx == 0) {
		ddp_flags |= V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_ACTIVE_BUF(0);
		if (waitall)
			ddp_flags |= V_TF_DDP_PUSH_DISABLE_0(1);
		else if (nb)
			ddp_flags |= V_TF_DDP_BUF0_FLUSH(1);
		else
			ddp_flags |= V_TF_DDP_BUF0_FLUSH(0);
	} else {
		ddp_flags |= V_TF_DDP_BUF1_VALID(1) | V_TF_DDP_ACTIVE_BUF(1);
		if (waitall)
			ddp_flags |= V_TF_DDP_PUSH_DISABLE_1(1);
		else if (nb)
			ddp_flags |= V_TF_DDP_BUF1_FLUSH(1);
		else
			ddp_flags |= V_TF_DDP_BUF1_FLUSH(0);
	}

	return (ddp_flags);
}
#endif

static struct wrqe *
mk_update_tcb_for_ddp(struct adapter *sc, struct toepcb *toep, int db_idx,
    int offset, uint64_t ddp_flags, uint64_t ddp_flags_mask)
{
	struct ddp_buffer *db = toep->db[db_idx];
	struct wrqe *wr;
	struct work_request_hdr *wrh;
	struct ulp_txpkt *ulpmc;
	int len;

	KASSERT(db_idx == 0 || db_idx == 1,
	    ("%s: bad DDP buffer index %d", __func__, db_idx));

	/*
	 * We'll send a compound work request that has 3 SET_TCB_FIELDs and an
	 * RX_DATA_ACK (with RX_MODULATE to speed up delivery).
	 *
	 * The work request header is 16B and always ends at a 16B boundary.
	 * The ULPTX master commands that follow must all end at 16B boundaries
	 * too so we round up the size to 16.
	 */
	len = sizeof(*wrh) + 3 * roundup2(LEN__SET_TCB_FIELD_ULP, 16) +
	    roundup2(LEN__RX_DATA_ACK_ULP, 16);

	wr = alloc_wrqe(len, toep->ctrlq);
	if (wr == NULL)
		return (NULL);
	wrh = wrtod(wr);
	INIT_ULPTX_WRH(wrh, len, 1, 0);	/* atomic */
	ulpmc = (struct ulp_txpkt *)(wrh + 1);

	/* Write the buffer's tag */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
	    W_TCB_RX_DDP_BUF0_TAG + db_idx,
	    V_TCB_RX_DDP_BUF0_TAG(M_TCB_RX_DDP_BUF0_TAG),
	    V_TCB_RX_DDP_BUF0_TAG(db->tag));

	/* Update the current offset in the DDP buffer and its total length */
	if (db_idx == 0)
		ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
		    W_TCB_RX_DDP_BUF0_OFFSET,
		    V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |
		    V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
		    V_TCB_RX_DDP_BUF0_OFFSET(offset) |
		    V_TCB_RX_DDP_BUF0_LEN(db->len));
	else
		ulpmc = mk_set_tcb_field_ulp(ulpmc, toep,
		    W_TCB_RX_DDP_BUF1_OFFSET,
		    V_TCB_RX_DDP_BUF1_OFFSET(M_TCB_RX_DDP_BUF1_OFFSET) |
		    V_TCB_RX_DDP_BUF1_LEN((u64)M_TCB_RX_DDP_BUF1_LEN << 32),
		    V_TCB_RX_DDP_BUF1_OFFSET(offset) |
		    V_TCB_RX_DDP_BUF1_LEN((u64)db->len << 32));

	/* Update DDP flags */
	ulpmc = mk_set_tcb_field_ulp(ulpmc, toep, W_TCB_RX_DDP_FLAGS,
	    ddp_flags, ddp_flags_mask);

	/* Gratuitous RX_DATA_ACK with RX_MODULATE set to speed up delivery. */
	ulpmc = mk_rx_data_ack_ulp(ulpmc, toep);

	return (wr);
}

#if 0
static void
discourage_ddp(struct toepcb *toep)
{

	if (toep->ddp_score && --toep->ddp_score == 0) {
		toep->ddp_flags &= ~DDP_OK;
		toep->ddp_disabled = time_uptime;
		CTR3(KTR_CXGBE, "%s: tid %u !DDP_OK @ %u",
		    __func__, toep->tid, time_uptime);
	}
}
#endif

static int
handle_ddp_data(struct toepcb *toep, __be32 ddp_report, __be32 rcv_nxt, int len)
{
	uint32_t report = be32toh(ddp_report);
	unsigned int db_flag, db_idx;
	struct inpcb *inp = toep->inp;
	struct ddp_buffer *db;
	struct tcpcb *tp;
	struct socket *so;
	struct sockbuf *sb;
	struct aiocblist *cbe;
	long copied;

	db_idx = report & F_DDP_BUF_IDX ? 1 : 0;
	db_flag = report & F_DDP_BUF_IDX ? DDP_BUF1_ACTIVE : DDP_BUF0_ACTIVE;

	if (__predict_false(!(report & F_DDP_INV)))
		CXGBE_UNIMPLEMENTED("DDP buffer still valid");

	INP_WLOCK(inp);
	so = inp_inpcbtosocket(inp);
	sb = &so->so_rcv;
	SOCKBUF_LOCK(sb);

	KASSERT(toep->ddp_active_id == db_idx,
	    ("completed DDP buffer (%d) != active_id (%d)", db_idx,
	    toep->ddp_active_id));
	toep->ddp_active_count--;
	if (toep->ddp_active_count == 0) {
		KASSERT(toep->db[db_idx ^ 1] == NULL ||
		    toep->db[db_idx ^ 1]->cbe == NULL,
		    ("%s: active_count mismatch", __func__));
		toep->ddp_active_id = -1;
	} else
		toep->ddp_active_id ^= 1;
	db = toep->db[db_idx];
	cbe = db->cbe;

	if (__predict_false(inp->inp_flags & (INP_DROPPED | INP_TIMEWAIT))) {
		/*
		 * This can happen due to an administrative tcpdrop(8).
		 * Just fail the request with ECONNRESET.
		 */
		CTR5(KTR_CXGBE, "%s: tid %u, seq 0x%x, len %d, inp_flags 0x%x",
		    __func__, toep->tid, be32toh(rcv_nxt), len, inp->inp_flags);
		aio_complete(cbe, -1, db->cancel_pending ? ECANCELED :
		    ECONNRESET);
		goto completed;
	}

	tp = intotcpcb(inp);

	/*
	 * For RX_DDP_COMPLETE, len will be zero and rcv_nxt is the
	 * sequence number of the next byte to receive.  The length of
	 * the data received for this message must be computed by
	 * comparing the new and old values of rcv_nxt.
	 * 
	 * For RX_DATA_DDP, len might be non-zero, but it is only the
	 * length of the most recent DMA.  It does not include the
	 * total length of the data received since the previous update
	 * for this DDP buffer.  rcv_nxt is the sequence number of the
	 * first received byte from the most recent DMA.
	 */
	len += be32toh(rcv_nxt) - tp->rcv_nxt;
	tp->rcv_nxt += len;
	tp->t_rcvtime = ticks;
#ifndef USE_DDP_RX_FLOW_CONTROL
	KASSERT(tp->rcv_wnd >= len, ("%s: negative window size", __func__));
	tp->rcv_wnd -= len;
#endif
	CTR4(KTR_CXGBE, "%s: DDP[%d] placed %d bytes (%#x)", __func__, db_idx,
	    len, report);

	/* receive buffer autosize */
	if (sb->sb_flags & SB_AUTOSIZE &&
	    V_tcp_do_autorcvbuf &&
	    sb->sb_hiwat < V_tcp_autorcvbuf_max &&
	    len > (sbspace(sb) / 8 * 7)) {
		unsigned int hiwat = sb->sb_hiwat;
		unsigned int newsize = min(hiwat + V_tcp_autorcvbuf_inc,
		    V_tcp_autorcvbuf_max);

		if (!sbreserve_locked(sb, newsize, so, NULL))
			sb->sb_flags &= ~SB_AUTOSIZE;
		else
			toep->rx_credits += newsize - hiwat;
	}

#if 0
	KASSERT(toep->sb_cc >= sbused(sb),
	    ("%s: sb %p has more data (%d) than last time (%d).",
	    __func__, sb, sbused(sb), toep->sb_cc));
	toep->rx_credits += toep->sb_cc - sbused(sb);
#else
	/*
	 * XXX: Not at all sure what to do here since we now bypass the
	 * socket buffer.
	 */
	toep->rx_credits += len;
#endif
#ifdef USE_DDP_RX_FLOW_CONTROL
	toep->rx_credits -= len;	/* adjust for F_RX_FC_DDP */
#endif

	copied = cbe->uaiocb._aiocb_private.status;
	if (db->cancel_pending && copied + len == 0) {
		CTR2(KTR_CXGBE, "%s: cancelling %p", __func__, cbe);
		aio_complete(cbe, -1, ECANCELED);
	} else {
		CTR4(KTR_CXGBE, "%s: completing %p (copied %ld, placed %d)",
		    __func__, cbe, copied, len);
		aio_complete(cbe, copied + len, 0);
		if (copied != 0)
			ddp_aio_mixed++;
		else
			ddp_aio_placed++;
	}

completed:
	db->cancel_pending = 0;
	db->cbe = NULL;
	KASSERT(toep->ddp_flags & db_flag,
	    ("%s: DDP buffer not active. toep %p, ddp_flags 0x%x, report 0x%x",
	    __func__, toep, toep->ddp_flags, report));
	toep->ddp_flags &= ~db_flag;
	if (toep->ddp_waiting_count > 0)
		taskqueue_enqueue(taskqueue_thread, &toep->ddp_requeue_task);
	SOCKBUF_UNLOCK(sb);
	INP_WUNLOCK(inp);

	return (0);
}

void
handle_ddp_indicate(struct toepcb *toep, struct sockbuf *sb)
{

	SOCKBUF_LOCK_ASSERT(sb);
	MPASS(toep->ddp_active_count == 0);
	MPASS((toep->ddp_flags & (DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE)) == 0);
	if (toep->ddp_waiting_count == 0) {
		/*
		 * The pending requests that triggered the request for an
		 * an indicate were cancelled.  Those cancels should have
		 * already disabled DDP.  Just ignore this as the data is
		 * going into the socket buffer anyway.
		 */
		return;
	}
	CTR3(KTR_CXGBE, "%s: tid %d indicated (%d waiting)", __func__,
	    toep->tid, toep->ddp_waiting_count);
	taskqueue_enqueue(taskqueue_thread, &toep->ddp_requeue_task);
}

enum {
	DDP_BUF0_INVALIDATED = 0x10,
	DDP_BUF1_INVALIDATED
};

void
handle_ddp_tcb_rpl(struct toepcb *toep, const struct cpl_set_tcb_rpl *cpl)
{
	unsigned int db_flag, db_idx;
	struct inpcb *inp = toep->inp;
	struct ddp_buffer *db;
	struct socket *so;
	struct sockbuf *sb;
	struct aiocblist *cbe;
	long copied;
	
	if (cpl->status != CPL_ERR_NONE)
		panic("XXX: tcp_rpl failed: %d", cpl->status);

	switch (cpl->cookie) {
	case DDP_BUF0_INVALIDATED:
	case DDP_BUF1_INVALIDATED:
		/*
		 * XXX: This duplicates a lot of code with handle_ddp_data().
		 */
		db_idx = cpl->cookie - DDP_BUF0_INVALIDATED;
		db_flag = db_idx == 1 ? DDP_BUF1_ACTIVE : DDP_BUF0_ACTIVE;
		INP_WLOCK(inp);
		so = inp_inpcbtosocket(inp);
		sb = &so->so_rcv;
		SOCKBUF_LOCK(sb);
		db = toep->db[db_idx];
		if (db == NULL || db->cbe == NULL || !db->cancel_pending) {
			/*
			 * The buffer completed while the invalidation was
			 * in flight.  Nothing more to do.
			 */
			SOCKBUF_UNLOCK(sb);
			INP_WUNLOCK(inp);
			return;
		}

		toep->ddp_active_count--;
		if (toep->ddp_active_id == db_idx) {
			if (toep->ddp_active_count == 0) {
				KASSERT(toep->db[db_idx ^ 1] == NULL ||
				    toep->db[db_idx ^ 1]->cbe == NULL,
				    ("%s: active_count mismatch", __func__));
				toep->ddp_active_id = -1;
			} else
				toep->ddp_active_id ^= 1;
		} else {
			KASSERT(toep->ddp_active_count != 0 &&
			    toep->ddp_active_id != -1,
			    ("%s: active count mismatch", __func__));
		}

		/*
		 * XXX: It's not clear what happens if there is data
		 * placed when the buffer is invalidated.  I suspect we
		 * need to read the TCB to see how much data was placed.
		 *
		 * For now this just pretends like nothing was placed.
		 *
		 * XXX: Note that if we did check the PCB we would need to
		 * also take care of updating the tp, etc.
		 */
		cbe = db->cbe;
		copied = cbe->uaiocb._aiocb_private.status;
		if (copied == 0) {
			CTR2(KTR_CXGBE, "%s: cancelling %p", __func__, cbe);
			aio_complete(cbe, -1, ECANCELED);
		} else {
			CTR3(KTR_CXGBE, "%s: completing %p (copied %ld)",
			    __func__, cbe, copied);
			aio_complete(cbe, copied, 0);
			ddp_aio_copied++;
		}

		db->cancel_pending = 0;
		db->cbe = NULL;
		KASSERT(toep->ddp_flags & db_flag,
		    ("%s: DDP buffer not active. toep %p, ddp_flags 0x%x",
		    __func__, toep, toep->ddp_flags));
		toep->ddp_flags &= ~db_flag;
		if (toep->ddp_waiting_count > 0)
			taskqueue_enqueue(taskqueue_thread,
			    &toep->ddp_requeue_task);
		SOCKBUF_UNLOCK(sb);
		INP_WUNLOCK(inp);
		break;
	default:
		panic("XXX: unknown tcb_rpl cookie %#x", cpl->cookie);
	}
}

void
handle_ddp_close(struct toepcb *toep, struct tcpcb *tp, struct sockbuf *sb,
    __be32 rcv_nxt)
{
	struct ddp_buffer *db;
	struct aiocblist *cbe;
	long copied;
	unsigned int db_flag, db_idx;
	int len, placed;

	SOCKBUF_LOCK_ASSERT(sb);
	INP_WLOCK_ASSERT(toep->inp);
	len = be32toh(rcv_nxt) - tp->rcv_nxt;

	tp->rcv_nxt += len;
#if 0
	KASSERT(toep->sb_cc >= sbused(sb),
	    ("%s: sb %p has more data (%d) than last time (%d).",
	    __func__, sb, sbused(sb), toep->sb_cc));
	toep->rx_credits += toep->sb_cc - sbused(sb);
#else
	/*
	 * XXX: Not at all sure what to do here since we now bypass the
	 * socket buffer.
	 */
	toep->rx_credits += len;
#endif
#ifdef USE_DDP_RX_FLOW_CONTROL
	toep->rx_credits -= len;	/* adjust for F_RX_FC_DDP */
#endif

	while (toep->ddp_active_count > 0) {
		MPASS(toep->ddp_active_id != -1);
		db_idx = toep->ddp_active_id;
		db_flag = db_idx == 1 ? DDP_BUF1_ACTIVE : DDP_BUF0_ACTIVE;
		MPASS((toep->ddp_flags & db_flag) != 0);
		db = toep->db[db_idx];
		cbe = db->cbe;
		copied = cbe->uaiocb._aiocb_private.status;
		placed = len;
		if (placed > cbe->uaiocb.aio_nbytes - copied)
			placed = cbe->uaiocb.aio_nbytes - copied;
		CTR4(KTR_CXGBE, "%s: tid %d completed buf %d len %d", __func__,
		    toep->tid, db_idx, placed);
		aio_complete(cbe, copied + placed, 0);
		if (copied != 0 && placed != 0)
			ddp_aio_mixed++;
		else if (copied != 0)
			ddp_aio_copied++;
		else if (placed != 0)
			ddp_aio_placed++;
		len -= placed;
		toep->ddp_active_count--;
		if (toep->ddp_active_count == 0) {
			KASSERT(toep->db[db_idx ^ 1] == NULL ||
			    toep->db[db_idx ^ 1]->cbe == NULL,
			    ("%s: active_count mismatch", __func__));
			toep->ddp_active_id = -1;
		} else
			toep->ddp_active_id ^= 1;
		toep->ddp_flags &= ~db_flag;
	}

	MPASS(len == 0);
	ddp_complete_all(toep, sb, 0, 0);
}

#define DDP_ERR (F_DDP_PPOD_MISMATCH | F_DDP_LLIMIT_ERR | F_DDP_ULIMIT_ERR |\
	 F_DDP_PPOD_PARITY_ERR | F_DDP_PADDING_ERR | F_DDP_OFFSET_ERR |\
	 F_DDP_INVALID_TAG | F_DDP_COLOR_ERR | F_DDP_TID_MISMATCH |\
	 F_DDP_INVALID_PPOD | F_DDP_HDRCRC_ERR | F_DDP_DATACRC_ERR)

static int
do_rx_data_ddp(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_rx_data_ddp *cpl = (const void *)(rss + 1);
	unsigned int tid = GET_TID(cpl);
	uint32_t vld;
	struct toepcb *toep = lookup_tid(sc, tid);

	KASSERT(m == NULL, ("%s: wasn't expecting payload", __func__));
	KASSERT(toep->tid == tid, ("%s: toep tid/atid mismatch", __func__));
	KASSERT(!(toep->flags & TPF_SYNQE),
	    ("%s: toep %p claims to be a synq entry", __func__, toep));

	vld = be32toh(cpl->ddpvld);
	if (__predict_false(vld & DDP_ERR)) {
		panic("%s: DDP error 0x%x (tid %d, toep %p)",
		    __func__, vld, tid, toep);
	}

	if (toep->ulp_mode == ULP_MODE_ISCSI) {
		sc->cpl_handler[CPL_RX_ISCSI_DDP](iq, rss, m);
		return (0);
	}

	handle_ddp_data(toep, cpl->u.ddp_report, cpl->seq, be16toh(cpl->len));

	return (0);
}

static int
do_rx_ddp_complete(struct sge_iq *iq, const struct rss_header *rss,
    struct mbuf *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_rx_ddp_complete *cpl = (const void *)(rss + 1);
	unsigned int tid = GET_TID(cpl);
	struct toepcb *toep = lookup_tid(sc, tid);

	KASSERT(m == NULL, ("%s: wasn't expecting payload", __func__));
	KASSERT(toep->tid == tid, ("%s: toep tid/atid mismatch", __func__));
	KASSERT(!(toep->flags & TPF_SYNQE),
	    ("%s: toep %p claims to be a synq entry", __func__, toep));

	handle_ddp_data(toep, cpl->ddp_report, cpl->rcv_nxt, 0);

	return (0);
}

void
enable_ddp(struct adapter *sc, struct toepcb *toep)
{

	KASSERT((toep->ddp_flags & (DDP_ON | DDP_OK | DDP_SC_REQ)) == DDP_OK,
	    ("%s: toep %p has bad ddp_flags 0x%x",
	    __func__, toep, toep->ddp_flags));

	CTR3(KTR_CXGBE, "%s: tid %u (time %u)",
	    __func__, toep->tid, time_uptime);

	toep->ddp_flags |= DDP_SC_REQ;
	t4_set_tcb_field(sc, toep, 1, W_TCB_RX_DDP_FLAGS,
	    V_TF_DDP_OFF(1) | V_TF_DDP_INDICATE_OUT(1) |
	    V_TF_DDP_BUF0_INDICATE(1) | V_TF_DDP_BUF1_INDICATE(1) |
	    V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_BUF1_VALID(1),
	    V_TF_DDP_BUF0_INDICATE(1) | V_TF_DDP_BUF1_INDICATE(1));
	t4_set_tcb_field(sc, toep, 1, W_TCB_T_FLAGS,
	    V_TF_RCV_COALESCE_ENABLE(1), 0);
}

static inline void
disable_ddp(struct adapter *sc, struct toepcb *toep)
{

	KASSERT((toep->ddp_flags & (DDP_ON | DDP_SC_REQ)) == DDP_ON,
	    ("%s: toep %p has bad ddp_flags 0x%x",
	    __func__, toep, toep->ddp_flags));

	CTR3(KTR_CXGBE, "%s: tid %u (time %u)",
	    __func__, toep->tid, time_uptime);

	toep->ddp_flags |= DDP_SC_REQ;
	t4_set_tcb_field(sc, toep, 1, W_TCB_T_FLAGS,
	    V_TF_RCV_COALESCE_ENABLE(1), V_TF_RCV_COALESCE_ENABLE(1));
	t4_set_tcb_field(sc, toep, 1, W_TCB_RX_DDP_FLAGS, V_TF_DDP_OFF(1),
	    V_TF_DDP_OFF(1));
}

#if 0
static int
hold_uio(struct uio *uio, vm_page_t **ppages, int *pnpages)
{
	struct vm_map *map;
	struct iovec *iov;
	vm_offset_t start, end;
	vm_page_t *pp;
	int n;

	KASSERT(uio->uio_iovcnt == 1,
	    ("%s: uio_iovcnt %d", __func__, uio->uio_iovcnt));
	KASSERT(uio->uio_td->td_proc == curproc,
	    ("%s: uio proc (%p) is not curproc (%p)",
	    __func__, uio->uio_td->td_proc, curproc));

	map = &curproc->p_vmspace->vm_map;
	iov = &uio->uio_iov[0];
	start = trunc_page((uintptr_t)iov->iov_base);
	end = round_page((vm_offset_t)iov->iov_base + iov->iov_len);
	n = howmany(end - start, PAGE_SIZE);

	if (end - start > MAX_DDP_BUFFER_SIZE)
		return (E2BIG);

	pp = malloc(n * sizeof(vm_page_t), M_CXGBE, M_NOWAIT);
	if (pp == NULL)
		return (ENOMEM);

	if (vm_fault_quick_hold_pages(map, (vm_offset_t)iov->iov_base,
	    iov->iov_len, VM_PROT_WRITE, pp, n) < 0) {
		free(pp, M_CXGBE);
		return (EFAULT);
	}

	*ppages = pp;
	*pnpages = n;

	return (0);
}
#endif

static int
bufcmp(struct ddp_buffer *db, vm_page_t *pages, int npages, int offset, int len)
{
	int i;

	if (db == NULL || db->npages != npages || db->offset != offset ||
	    db->len != len || db->cbe != NULL)
		return (1);

	for (i = 0; i < npages; i++) {
		if (pages[i]->phys_addr != db->pages[i]->phys_addr)
			return (1);
	}

	return (0);
}

static int
calculate_hcf(int n1, int n2)
{
	int a, b, t;

	if (n1 <= n2) {
		a = n1;
		b = n2;
	} else {
		a = n2;
		b = n1;
	}

	while (a != 0) {
		t = a;
		a = b % a;
		b = t;
	}

	return (b);
}

static struct ddp_buffer *
alloc_ddp_buffer(struct tom_data *td, vm_page_t *pages, int npages, int offset,
    int len)
{
	int i, hcf, seglen, idx, ppod, nppods;
	struct ddp_buffer *db;

	/*
	 * The DDP page size is unrelated to the VM page size.  We combine
	 * contiguous physical pages into larger segments to get the best DDP
	 * page size possible.  This is the largest of the four sizes in
	 * A_ULP_RX_TDDP_PSZ that evenly divides the HCF of the segment sizes in
	 * the page list.
	 */
	hcf = 0;
	for (i = 0; i < npages; i++) {
		seglen = PAGE_SIZE;
		while (i < npages - 1 &&
		    pages[i]->phys_addr + PAGE_SIZE == pages[i + 1]->phys_addr) {
			seglen += PAGE_SIZE;
			i++;
		}

		hcf = calculate_hcf(hcf, seglen);
		if (hcf < t4_ddp_pgsz[1]) {
			idx = 0;
			goto have_pgsz;	/* give up, short circuit */
		}
	}

	if (hcf % t4_ddp_pgsz[0] != 0) {
		/* hmmm.  This could only happen when PAGE_SIZE < 4K */
		KASSERT(PAGE_SIZE < 4096,
		    ("%s: PAGE_SIZE %d, hcf %d", __func__, PAGE_SIZE, hcf));
		CTR3(KTR_CXGBE, "%s: PAGE_SIZE %d, hcf %d",
		    __func__, PAGE_SIZE, hcf);
		return (NULL);
	}

	for (idx = nitems(t4_ddp_pgsz) - 1; idx > 0; idx--) {
		if (hcf % t4_ddp_pgsz[idx] == 0)
			break;
	}
have_pgsz:
	MPASS(idx <= M_PPOD_PGSZ);

	db = malloc(sizeof(*db), M_CXGBE, M_NOWAIT);
	if (db == NULL) {
		CTR1(KTR_CXGBE, "%s: malloc failed.", __func__);
		return (NULL);
	}

	nppods = pages_to_nppods(npages, t4_ddp_pgsz[idx]);
	if (alloc_ppods(td, nppods, &db->ppod_addr) != 0) {
		free(db, M_CXGBE);
		CTR4(KTR_CXGBE, "%s: no pods, nppods %d, resid %d, pgsz %d",
		    __func__, nppods, len, t4_ddp_pgsz[idx]);
		return (NULL);
	}
	ppod = (db->ppod_addr - td->ppod_start) / PPOD_SIZE;

	db->tag = V_PPOD_PGSZ(idx) | V_PPOD_TAG(ppod);
	db->nppods = nppods;
	db->npages = npages;
	db->pages = pages;
	db->offset = offset;
	db->len = len;

	CTR6(KTR_CXGBE, "New DDP buffer.  "
	    "ddp_pgsz %d, ppod 0x%x, npages %d, nppods %d, offset %d, len %d",
	    t4_ddp_pgsz[idx], ppod, db->npages, db->nppods, db->offset,
	    db->len);

	return (db);
}

#define NUM_ULP_TX_SC_IMM_PPODS (256 / PPOD_SIZE)

static int
write_page_pods(struct adapter *sc, struct toepcb *toep, struct ddp_buffer *db)
{
	struct wrqe *wr;
	struct ulp_mem_io *ulpmc;
	struct ulptx_idata *ulpsc;
	struct pagepod *ppod;
	int i, j, k, n, chunk, len, ddp_pgsz, idx;
	u_int ppod_addr;
	uint32_t cmd;

	cmd = htobe32(V_ULPTX_CMD(ULP_TX_MEM_WRITE));
	if (is_t4(sc))
		cmd |= htobe32(F_ULP_MEMIO_ORDER);
	else
		cmd |= htobe32(F_T5_ULP_MEMIO_IMM);
	ddp_pgsz = t4_ddp_pgsz[G_PPOD_PGSZ(db->tag)];
	ppod_addr = db->ppod_addr;
	for (i = 0; i < db->nppods; ppod_addr += chunk) {

		/* How many page pods are we writing in this cycle */
		n = min(db->nppods - i, NUM_ULP_TX_SC_IMM_PPODS);
		chunk = PPOD_SZ(n);
		len = roundup2(sizeof(*ulpmc) + sizeof(*ulpsc) + chunk, 16);

		wr = alloc_wrqe(len, toep->ctrlq);
		if (wr == NULL)
			return (ENOMEM);	/* ok to just bail out */
		ulpmc = wrtod(wr);

		INIT_ULPTX_WR(ulpmc, len, 0, 0);
		ulpmc->cmd = cmd;
		ulpmc->dlen = htobe32(V_ULP_MEMIO_DATA_LEN(chunk / 32));
		ulpmc->len16 = htobe32(howmany(len - sizeof(ulpmc->wr), 16));
		ulpmc->lock_addr = htobe32(V_ULP_MEMIO_ADDR(ppod_addr >> 5));

		ulpsc = (struct ulptx_idata *)(ulpmc + 1);
		ulpsc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
		ulpsc->len = htobe32(chunk);

		ppod = (struct pagepod *)(ulpsc + 1);
		for (j = 0; j < n; i++, j++, ppod++) {
			ppod->vld_tid_pgsz_tag_color = htobe64(F_PPOD_VALID |
			    V_PPOD_TID(toep->tid) | db->tag);
			ppod->len_offset = htobe64(V_PPOD_LEN(db->len) |
			    V_PPOD_OFST(db->offset));
			ppod->rsvd = 0;
			idx = i * PPOD_PAGES * (ddp_pgsz / PAGE_SIZE);
			for (k = 0; k < nitems(ppod->addr); k++) {
				if (idx < db->npages) {
					ppod->addr[k] =
					    htobe64(db->pages[idx]->phys_addr);
					idx += ddp_pgsz / PAGE_SIZE;
				} else
					ppod->addr[k] = 0;
#if 0
				CTR5(KTR_CXGBE,
				    "%s: tid %d ppod[%d]->addr[%d] = %p",
				    __func__, toep->tid, i, k,
				    htobe64(ppod->addr[k]));
#endif
			}

		}

		t4_wrq_tx(sc, wr);
	}

	return (0);
}

/*
 * Reuse, or allocate (and program the page pods for) a new DDP buffer.  The
 * "pages" array is handed over to this function and should not be used in any
 * way by the caller after that.
 */
static int
select_ddp_buffer(struct adapter *sc, struct toepcb *toep, vm_page_t *pages,
    int npages, int db_off, int db_len)
{
	struct ddp_buffer *db;
	struct tom_data *td = sc->tom_softc;
	int i, empty_slot = -1;

	/* Try to reuse */
	for (i = 0; i < nitems(toep->db); i++) {
		if (bufcmp(toep->db[i], pages, npages, db_off, db_len) ==
		    0) {
			free(pages, M_CXGBE);
			return (i);	/* pages still held */
		} else if (toep->db[i] == NULL && empty_slot < 0)
			empty_slot = i;
	}

	/* Allocate new buffer, write its page pods. */
	db = alloc_ddp_buffer(td, pages, npages, db_off, db_len);
	if (db == NULL) {
		vm_page_unhold_pages(pages, npages);
		free(pages, M_CXGBE);
		return (-1);
	}
	if (write_page_pods(sc, toep, db) != 0) {
		vm_page_unhold_pages(pages, npages);
		free_ddp_buffer(td, db);
		return (-1);
	}

	i = empty_slot;
	if (i < 0) {
		i = arc4random() % nitems(toep->db);
		if (toep->db[i]->cbe != NULL)
			i ^= 1;
		MPASS(toep->db[i]->cbe == NULL);
		MPASS((toep->ddp_flags & (i == 0 ? DDP_BUF0_ACTIVE :
		    DDP_BUF1_ACTIVE)) == 0);
		free_ddp_buffer(td, toep->db[i]);
	}
	toep->db[i] = db;

	CTR5(KTR_CXGBE, "%s: tid %d, DDP buffer[%d] = %p (tag 0x%x)",
	    __func__, toep->tid, i, db, db->tag);

	return (i);
}

static void
wire_ddp_buffer(struct ddp_buffer *db)
{
	int i;
	vm_page_t p;

	for (i = 0; i < db->npages; i++) {
		p = db->pages[i];
		vm_page_lock(p);
		vm_page_wire(p);
		vm_page_unhold(p);
		vm_page_unlock(p);
	}
}

static void
unwire_ddp_buffer(struct ddp_buffer *db)
{
	int i;
	vm_page_t p;

	for (i = 0; i < db->npages; i++) {
		p = db->pages[i];
		vm_page_lock(p);
		vm_page_unwire(p, PQ_INACTIVE);
		vm_page_unlock(p);
	}
}

#if 0
static int
handle_ddp(struct socket *so, struct uio *uio, int flags, int error)
{
	struct sockbuf *sb = &so->so_rcv;
	struct tcpcb *tp = so_sototcpcb(so);
	struct toepcb *toep = tp->t_toe;
	struct adapter *sc = td_adapter(toep->td);
	vm_page_t *pages;
	int npages, db_idx, rc, buf_flag;
	struct ddp_buffer *db;
	struct wrqe *wr;
	uint64_t ddp_flags;

	SOCKBUF_LOCK_ASSERT(sb);

#if 0
	if (sbused(sb) + sc->tt.ddp_thres > uio->uio_resid) {
		CTR4(KTR_CXGBE, "%s: sb_cc %d, threshold %d, resid %d",
		    __func__, sbused(sb), sc->tt.ddp_thres, uio->uio_resid);
	}
#endif

	/* XXX: too eager to disable DDP, could handle NBIO better than this. */
	if (sbused(sb) >= uio->uio_resid || uio->uio_resid < sc->tt.ddp_thres ||
	    uio->uio_resid > MAX_DDP_BUFFER_SIZE || uio->uio_iovcnt > 1 ||
	    so->so_state & SS_NBIO || flags & (MSG_DONTWAIT | MSG_NBIO) ||
	    error || so->so_error || sb->sb_state & SBS_CANTRCVMORE)
		goto no_ddp;

	/*
	 * Fault in and then hold the pages of the uio buffers.  We'll wire them
	 * a bit later if everything else works out.
	 */
	SOCKBUF_UNLOCK(sb);
	if (hold_uio(uio, &pages, &npages) != 0) {
		SOCKBUF_LOCK(sb);
		goto no_ddp;
	}
	SOCKBUF_LOCK(sb);
	if (__predict_false(so->so_error || sb->sb_state & SBS_CANTRCVMORE)) {
		vm_page_unhold_pages(pages, npages);
		free(pages, M_CXGBE);
		goto no_ddp;
	}

	/*
	 * Figure out which one of the two DDP buffers to use this time.
	 */
	db_idx = select_ddp_buffer(sc, toep, pages, npages,
	    (uintptr_t)uio->uio_iov->iov_base & PAGE_MASK, uio->uio_resid);
	pages = NULL;	/* handed off to select_ddp_buffer */
	if (db_idx < 0)
		goto no_ddp;
	db = toep->db[db_idx];
	buf_flag = db_idx == 0 ? DDP_BUF0_ACTIVE : DDP_BUF1_ACTIVE;

	/*
	 * Build the compound work request that tells the chip where to DMA the
	 * payload.
	 */
	ddp_flags = select_ddp_flags(so, flags, db_idx);
	wr = mk_update_tcb_for_ddp(sc, toep, db_idx, sbused(sb), ddp_flags);
	if (wr == NULL) {
		/*
		 * Just unhold the pages.  The DDP buffer's software state is
		 * left as-is in the toep.  The page pods were written
		 * successfully and we may have an opportunity to use it in the
		 * future.
		 */
		vm_page_unhold_pages(db->pages, db->npages);
		goto no_ddp;
	}

	/* Wire (and then unhold) the pages, and give the chip the go-ahead. */
	wire_ddp_buffer(db);
	t4_wrq_tx(sc, wr);
	sb->sb_flags &= ~SB_DDP_INDICATE;
	toep->ddp_flags |= buf_flag;

	/*
	 * Wait for the DDP operation to complete and then unwire the pages.
	 * The return code from the sbwait will be the final return code of this
	 * function.  But we do need to wait for DDP no matter what.
	 */
	rc = sbwait(sb);
	while (toep->ddp_flags & buf_flag) {
		/* XXXGL: shouldn't here be sbwait() call? */
		sb->sb_flags |= SB_WAIT;
		msleep(&sb->sb_acc, &sb->sb_mtx, PSOCK , "sbwait", 0);
	}
	unwire_ddp_buffer(db);
	return (rc);
no_ddp:
	disable_ddp(sc, toep);
	discourage_ddp(toep);
	sb->sb_flags &= ~SB_DDP_INDICATE;
	return (0);
}
#endif

void
t4_init_ddp(struct adapter *sc, struct tom_data *td)
{

	td->ppod_start = sc->vres.ddp.start;
	td->ppod_arena = vmem_create("DDP page pods", sc->vres.ddp.start,
	    sc->vres.ddp.size, 1, 32, M_FIRSTFIT | M_NOWAIT);

	t4_register_cpl_handler(sc, CPL_RX_DATA_DDP, do_rx_data_ddp);
	t4_register_cpl_handler(sc, CPL_RX_DDP_COMPLETE, do_rx_ddp_complete);
}

void
t4_uninit_ddp(struct adapter *sc __unused, struct tom_data *td)
{

	if (td->ppod_arena != NULL) {
		vmem_destroy(td->ppod_arena);
		td->ppod_arena = NULL;
	}
}

#if 0
#define	VNET_SO_ASSERT(so)						\
	VNET_ASSERT(curvnet != NULL,					\
	    ("%s:%d curvnet is NULL, so=%p", __func__, __LINE__, (so)));
#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? 0 : SBL_WAIT)
static int
soreceive_rcvoob(struct socket *so, struct uio *uio, int flags)
{

	CXGBE_UNIMPLEMENTED(__func__);
}

static char ddp_magic_str[] = "nothing to see here";

static struct mbuf *
get_ddp_mbuf(int len)
{
	struct mbuf *m;

	m = m_get(M_NOWAIT, MT_DATA);
	if (m == NULL)
		CXGBE_UNIMPLEMENTED("mbuf alloc failure");
	m->m_len = len;
	m->m_data = &ddp_magic_str[0];

	return (m);
}

static inline int
is_ddp_mbuf(struct mbuf *m)
{

	return (m->m_data == &ddp_magic_str[0]);
}

/*
 * Copy an mbuf chain into a uio limited by len if set.
 */
static int
m_mbuftouio_ddp(struct uio *uio, struct mbuf *m, int len)
{
	int error, length, total;
	int progress = 0;

	if (len > 0)
		total = min(uio->uio_resid, len);
	else
		total = uio->uio_resid;

	/* Fill the uio with data from the mbufs. */
	for (; m != NULL; m = m->m_next) {
		length = min(m->m_len, total - progress);

		if (is_ddp_mbuf(m)) {
			enum uio_seg segflag = uio->uio_segflg;

			uio->uio_segflg	= UIO_NOCOPY;
			error = uiomove(mtod(m, void *), length, uio);
			uio->uio_segflg	= segflag;
		} else
			error = uiomove(mtod(m, void *), length, uio);
		if (error)
			return (error);

		progress += length;
	}

	return (0);
}

/*
 * Based on soreceive_stream() in uipc_socket.c
 */
int
t4_soreceive_ddp(struct socket *so, struct sockaddr **psa, struct uio *uio,
    struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	int len = 0, error = 0, flags, oresid, ddp_handled = 0;
	struct sockbuf *sb;
	struct mbuf *m, *n = NULL;

	/* We only do stream sockets. */
	if (so->so_type != SOCK_STREAM)
		return (EINVAL);
	if (psa != NULL)
		*psa = NULL;
	if (controlp != NULL)
		return (EINVAL);
	if (flagsp != NULL)
		flags = *flagsp &~ MSG_EOR;
	else
		flags = 0;
	if (flags & MSG_OOB)
		return (soreceive_rcvoob(so, uio, flags));
	if (mp0 != NULL)
		*mp0 = NULL;

	sb = &so->so_rcv;

	/* Prevent other readers from entering the socket. */
	error = sblock(sb, SBLOCKWAIT(flags));
	SOCKBUF_LOCK(sb);
	if (error)
		goto out;

	/* Easy one, no space to copyout anything. */
	if (uio->uio_resid == 0) {
		error = EINVAL;
		goto out;
	}
	oresid = uio->uio_resid;

	/* We will never ever get anything unless we are or were connected. */
	if (!(so->so_state & (SS_ISCONNECTED|SS_ISDISCONNECTED))) {
		error = ENOTCONN;
		goto out;
	}

restart:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);

	if (sb->sb_flags & SB_DDP_INDICATE && !ddp_handled) {

		/* uio should be just as it was at entry */
		KASSERT(oresid == uio->uio_resid,
		    ("%s: oresid = %d, uio_resid = %zd, sbavail = %d",
		    __func__, oresid, uio->uio_resid, sbavail(sb)));

		error = handle_ddp(so, uio, flags, 0);
		ddp_handled = 1;
		if (error)
			goto out;
	}

	/* Abort if socket has reported problems. */
	if (so->so_error) {
		if (sbavail(sb))
			goto deliver;
		if (oresid > uio->uio_resid)
			goto out;
		error = so->so_error;
		if (!(flags & MSG_PEEK))
			so->so_error = 0;
		goto out;
	}

	/* Door is closed.  Deliver what is left, if any. */
	if (sb->sb_state & SBS_CANTRCVMORE) {
		if (sbavail(sb))
			goto deliver;
		else
			goto out;
	}

	/* Socket buffer is empty and we shall not block. */
	if (sbavail(sb) == 0 &&
	    ((so->so_state & SS_NBIO) || (flags & (MSG_DONTWAIT|MSG_NBIO)))) {
		error = EAGAIN;
		goto out;
	}

	/* Socket buffer got some data that we shall deliver now. */
	if (sbavail(sb) > 0 && !(flags & MSG_WAITALL) &&
	    ((so->so_state & SS_NBIO) ||
	     (flags & (MSG_DONTWAIT|MSG_NBIO)) ||
	     sbavail(sb) >= sb->sb_lowat ||
	     sbavail(sb) >= uio->uio_resid ||
	     sbavail(sb) >= sb->sb_hiwat) ) {
		goto deliver;
	}

	/* On MSG_WAITALL we must wait until all data or error arrives. */
	if ((flags & MSG_WAITALL) &&
	    (sbavail(sb) >= uio->uio_resid || sbavail(sb) >= sb->sb_lowat))
		goto deliver;

	/*
	 * Wait and block until (more) data comes in.
	 * NB: Drops the sockbuf lock during wait.
	 */
	error = sbwait(sb);
	if (error) {
		if (sb->sb_flags & SB_DDP_INDICATE && !ddp_handled) {
			(void) handle_ddp(so, uio, flags, 1);
			ddp_handled = 1;
		}
		goto out;
	}
	goto restart;

deliver:
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);
	KASSERT(sbavail(sb) > 0, ("%s: sockbuf empty", __func__));
	KASSERT(sb->sb_mb != NULL, ("%s: sb_mb == NULL", __func__));

	if (sb->sb_flags & SB_DDP_INDICATE && !ddp_handled)
		goto restart;

	/* Statistics. */
	if (uio->uio_td)
		uio->uio_td->td_ru.ru_msgrcv++;

	/* Fill uio until full or current end of socket buffer is reached. */
	len = min(uio->uio_resid, sbavail(sb));
	if (mp0 != NULL) {
		/* Dequeue as many mbufs as possible. */
		if (!(flags & MSG_PEEK) && len >= sb->sb_mb->m_len) {
			for (*mp0 = m = sb->sb_mb;
			     m != NULL && m->m_len <= len;
			     m = m->m_next) {
				len -= m->m_len;
				uio->uio_resid -= m->m_len;
				sbfree(sb, m);
				n = m;
			}
			sb->sb_mb = m;
			if (sb->sb_mb == NULL)
				SB_EMPTY_FIXUP(sb);
			n->m_next = NULL;
		}
		/* Copy the remainder. */
		if (len > 0) {
			KASSERT(sb->sb_mb != NULL,
			    ("%s: len > 0 && sb->sb_mb empty", __func__));

			m = m_copym(sb->sb_mb, 0, len, M_NOWAIT);
			if (m == NULL)
				len = 0;	/* Don't flush data from sockbuf. */
			else
				uio->uio_resid -= m->m_len;
			if (*mp0 != NULL)
				n->m_next = m;
			else
				*mp0 = m;
			if (*mp0 == NULL) {
				error = ENOBUFS;
				goto out;
			}
		}
	} else {
		/* NB: Must unlock socket buffer as uiomove may sleep. */
		SOCKBUF_UNLOCK(sb);
		error = m_mbuftouio_ddp(uio, sb->sb_mb, len);
		SOCKBUF_LOCK(sb);
		if (error)
			goto out;
	}
	SBLASTRECORDCHK(sb);
	SBLASTMBUFCHK(sb);

	/*
	 * Remove the delivered data from the socket buffer unless we
	 * were only peeking.
	 */
	if (!(flags & MSG_PEEK)) {
		if (len > 0)
			sbdrop_locked(sb, len);

		/* Notify protocol that we drained some data. */
		if ((so->so_proto->pr_flags & PR_WANTRCVD) &&
		    (((flags & MSG_WAITALL) && uio->uio_resid > 0) ||
		     !(flags & MSG_SOCALLBCK))) {
			SOCKBUF_UNLOCK(sb);
			VNET_SO_ASSERT(so);
			(*so->so_proto->pr_usrreqs->pru_rcvd)(so, flags);
			SOCKBUF_LOCK(sb);
		}
	}

	/*
	 * For MSG_WAITALL we may have to loop again and wait for
	 * more data to come in.
	 */
	if ((flags & MSG_WAITALL) && uio->uio_resid > 0)
		goto restart;
out:
	SOCKBUF_LOCK_ASSERT(sb);
	SBLASTRECORDCHK(sb);
	SBLASTMBUFCHK(sb);
	SOCKBUF_UNLOCK(sb);
	sbunlock(sb);
	return (error);
}
#endif

static int
hold_aio(struct aiocblist *aiocbe, vm_page_t **ppages, int *pnpages,
    vm_offset_t *ppgoff)
{
	struct vm_map *map;
	vm_offset_t start, end;
	vm_page_t *pp;
	int n;

	/*
	 * The AIO subsystem will cancel and drain all requests before
	 * permitting a process to exit or exec, so p_vmspace should
	 * be stable here.
	 */
	map = &aiocbe->userproc->p_vmspace->vm_map;
	start = (uintptr_t)aiocbe->uaiocb.aio_buf;
	*ppgoff = start & PAGE_MASK;
	end = round_page(start + aiocbe->uaiocb.aio_nbytes);
	start = trunc_page(start);

	if (end - start > MAX_DDP_BUFFER_SIZE)
		/*
		 * TODO: What we should do is DDP in chunks.
		 * Alternatively we could return a short read.
		 */
		panic("large aio buffer not yet implemented");

	n = atop(end - start);
	pp = malloc(n * sizeof(vm_page_t), M_CXGBE, M_WAITOK);
	if (vm_fault_quick_hold_pages(map, start, end - start,
	    VM_PROT_WRITE, pp, n) < 0) {
		free(pp, M_CXGBE);
		return (EFAULT);
	}

	*ppages = pp;
	*pnpages = n;
	return (0);
}

static void
ddp_complete_all(struct toepcb *toep, struct sockbuf *sb, long status,
    int error)
{
	struct aiocblist *cbe;

	SOCKBUF_LOCK_ASSERT(sb);
	while (!TAILQ_EMPTY(&toep->ddp_aiojobq)) {
		cbe = TAILQ_FIRST(&toep->ddp_aiojobq);
		TAILQ_REMOVE(&toep->ddp_aiojobq, cbe, list);
		toep->ddp_waiting_count--;
		aio_complete(cbe, status, error);
	}
}

static void
aio_ddp_requeue(void *context, int pending)
{
	struct toepcb *toep = context;
	struct inpcb *inp = toep->inp;
	struct socket *so = inp->inp_socket;
	struct sockbuf *sb = &so->so_rcv;
	struct adapter *sc = td_adapter(toep->td);
	struct aiocblist *cbe;
	struct ddp_buffer *db;
	vm_offset_t pgoff;
	size_t copied, offset, resid;
	vm_page_t *pages;
	struct mbuf *m;
	uint64_t ddp_flags, ddp_flags_mask;
	struct wrqe *wr;
	int buf_flag, db_idx, error, npages;

	SOCKBUF_LOCK(sb);

	/* We will never ever get anything unless we are or were connected. */
	if (!(so->so_state & (SS_ISCONNECTED|SS_ISDISCONNECTED))) {
		ddp_complete_all(toep, sb, -1, ENOTCONN);
		SOCKBUF_UNLOCK(sb);
		return;
	}

restart:
	KASSERT(toep->ddp_queueing == NULL,
	    ("%s: still queueing at restart", __func__));
	if (toep->ddp_waiting_count == 0 ||
	    toep->ddp_active_count == nitems(toep->db)) {
		SOCKBUF_UNLOCK(sb);
		return;
	}

	KASSERT(toep->ddp_active_count == 0 || sbavail(sb) == 0,
	    ("%s: pending sockbuf data and DDP is active", __func__));

	/* Abort if socket has reported problems. */
	/* XXX: Wait for any queued DDP's to finish and/or flush them? */
	if (so->so_error && sbavail(sb) == 0) {
		error = so->so_error;
		so->so_error = 0;
		cbe = TAILQ_FIRST(&toep->ddp_aiojobq);
		toep->ddp_waiting_count--;
		TAILQ_REMOVE(&toep->ddp_aiojobq, cbe, list);
		aio_complete(cbe, -1, error);
		goto restart;
	}

	/*
	 * Door is closed.  If there is pending data in the socket buffer,
	 * deliver it.  If there are pending DDP requests, wait for those
	 * to complete.  Once they have completed, return EOF reads.
	 */
	if (sb->sb_state & SBS_CANTRCVMORE && sbavail(sb) == 0) {
		if (toep->ddp_active_count != 0) {
			SOCKBUF_UNLOCK(sb);
			return;
		}
		ddp_complete_all(toep, sb, 0, 0);
		SOCKBUF_UNLOCK(sb);
		return;
	}

	/*
	 * If the DDP is not enabled and there is no pending socket buffer
	 * data, try to enable DDP.
	 */
	if (sbavail(sb) == 0 && (toep->ddp_flags & DDP_ON) == 0) {
		if ((toep->ddp_flags & DDP_SC_REQ) == 0 && ddp_aio_enable)
			enable_ddp(sc, toep);
		SOCKBUF_UNLOCK(sb);
		return;
	}

	/* Take the next job to prep it for DDP. */
	cbe = TAILQ_FIRST(&toep->ddp_aiojobq);
	toep->ddp_waiting_count--;
	TAILQ_REMOVE(&toep->ddp_aiojobq, cbe, list);
	toep->ddp_queueing = cbe;
	SOCKBUF_UNLOCK(sb);

	error = hold_aio(cbe, &pages, &npages, &pgoff);
	if (error != 0) {
		aio_complete(cbe, -1, error);
		SOCKBUF_LOCK(sb);
		toep->ddp_queueing = NULL;
		goto restart;
	}

	SOCKBUF_LOCK(sb);

	if (so->so_error && sbavail(sb) == 0) {
		error = so->so_error;
		so->so_error = 0;
		vm_page_unhold_pages(pages, npages);
		aio_complete(cbe, -1, error);
		toep->ddp_queueing = NULL;
		goto restart;
	}		

	if (sb->sb_state & SBS_CANTRCVMORE && sbavail(sb) == 0) {
		vm_page_unhold_pages(pages, npages);
		if (toep->ddp_active_count != 0) {
			TAILQ_INSERT_HEAD(&toep->ddp_aiojobq, cbe, list);
			toep->ddp_waiting_count++;
			toep->ddp_queueing = NULL;
			SOCKBUF_UNLOCK(sb);
			return;
		}
		aio_complete(cbe, 0, 0);
		ddp_complete_all(toep, sb, 0, 0);
		SOCKBUF_UNLOCK(sb);
		return;
	}	

	/*
	 * If there is pending data in the socket buffer (either
	 * from before the requests were queued or a DDP indicate),
	 * copy those mbufs out directly.
	 */
	copied = 0;
	offset = pgoff + cbe->uaiocb._aiocb_private.status;
	MPASS(cbe->uaiocb._aiocb_private.status <= cbe->uaiocb.aio_nbytes);
	resid = cbe->uaiocb.aio_nbytes - cbe->uaiocb._aiocb_private.status;
	m = sb->sb_mb;
	KASSERT(m == NULL || toep->ddp_active_count == 0,
	    ("%s: sockbuf data with active DDP", __func__));
	while (m != NULL && resid > 0) {
		struct iovec iov[1];
		struct uio uio;
		int error;

		iov[0].iov_base = mtod(m, void *);
		iov[0].iov_len = m->m_len;
		if (iov[0].iov_len > resid)
			iov[0].iov_len = resid;
		uio.uio_iov = iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = iov[0].iov_len;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_WRITE;
		error = uiomove_fromphys(pages, offset + copied, uio.uio_resid,
		    &uio);
		MPASS(error == 0 && uio.uio_resid == 0);
		copied += uio.uio_offset;
		resid -= uio.uio_offset;
		m = m->m_next;
	}
	if (copied != 0) {
		sbdrop_locked(sb, copied);
		cbe->uaiocb._aiocb_private.status += copied;
		if (resid == 0 || !ddp_aio_enable) {
			/*
			 * We filled the entire buffer with socket data,
			 * or DDP is not being used, so complete the
			 * request.
			 */
			SOCKBUF_UNLOCK(sb);
			vm_page_unhold_pages(pages, npages);
			aio_complete(cbe, copied, 0);
			SOCKBUF_LOCK(sb);
			ddp_aio_copied++;
			toep->ddp_queueing = NULL;
			goto restart;
		}

		/*
		 * If DDP is not enabled, requeue this request and restart.
		 * This will either enable DDP or wait for more data to
		 * arrive on the socket buffer.
		 */
		if ((toep->ddp_flags & (DDP_ON | DDP_SC_REQ)) != DDP_ON) {
			vm_page_unhold_pages(pages, npages);
			TAILQ_INSERT_HEAD(&toep->ddp_aiojobq, cbe, list);
			toep->ddp_waiting_count++;
			toep->ddp_queueing = NULL;
			goto restart;
		}
		MPASS(sbavail(sb) == 0);
	}	

	db_idx = select_ddp_buffer(sc, toep, pages, npages, pgoff,
	    cbe->uaiocb.aio_nbytes);
	pages = NULL;
	if (db_idx < 0) {
		TAILQ_INSERT_HEAD(&toep->ddp_aiojobq, cbe, list);
		toep->ddp_waiting_count++;
		toep->ddp_queueing = NULL;
		SOCKBUF_UNLOCK(sb);

		/*
		 * XXX: Need to retry this later.  Mostly need a trigger
		 * when page pods are freed up.
		 */
		printf("%s: select_ddp_buffer failed\n", __func__);
		return;
	}
	db = toep->db[db_idx];
	buf_flag = db_idx == 0 ? DDP_BUF0_ACTIVE : DDP_BUF1_ACTIVE;

	/*
	 * XXX: Not sure what to do about SS_NBIO.  The stock aio would
	 * wait for some data to come in and then do a non-blocking read
	 * of the socket to get whatever was there.  I don't want to set
	 * the FLUSH flag as that does an immediate flush.  However, I
	 * do want a sort of "flush on first data" flag.  There doesn't
	 * seem to be anything equivalent.  On the other hand, if a
	 * protocol cares it is probably using PSH and the PUSH timer
	 * completions is probably good enough.
	 */
	ddp_flags = 0;
	ddp_flags_mask = V_TF_DDP_INDICATE_OUT(1);
	buf_flag = 0;
	if (db_idx == 0) {
		ddp_flags |= V_TF_DDP_BUF0_VALID(1);
		ddp_flags_mask |= V_TF_DDP_PSH_NO_INVALIDATE0(1) |
		    V_TF_DDP_PUSH_DISABLE_0(1) | V_TF_DDP_PSHF_ENABLE_0(1) |
		    V_TF_DDP_BUF0_FLUSH(1) | V_TF_DDP_BUF0_VALID(1);
		buf_flag |= DDP_BUF0_ACTIVE;
	} else {
		ddp_flags |= V_TF_DDP_BUF1_VALID(1);
		ddp_flags_mask |= V_TF_DDP_PSH_NO_INVALIDATE1(1) |
		    V_TF_DDP_PUSH_DISABLE_1(1) | V_TF_DDP_PSHF_ENABLE_1(1) |
		    V_TF_DDP_BUF1_FLUSH(1) | V_TF_DDP_BUF1_VALID(1);
		buf_flag |= DDP_BUF1_ACTIVE;
	}
	MPASS((toep->ddp_flags & buf_flag) == 0);
	if ((toep->ddp_flags & (DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE)) == 0) {
		if (db_idx == 1)
			ddp_flags |= V_TF_DDP_ACTIVE_BUF(1);
		ddp_flags_mask |= V_TF_DDP_ACTIVE_BUF(1);
	}

	CTR5(KTR_CXGBE, "%s: scheduling %p for DDP[%d] (flags %#lx/%#lx)",
	    __func__, cbe, db_idx, ddp_flags, ddp_flags_mask);
	wr = mk_update_tcb_for_ddp(sc, toep, db_idx,
	    cbe->uaiocb._aiocb_private.status, ddp_flags, ddp_flags_mask);
	if (wr == NULL) {
		/*
		 * Need to unload the pages though the page pods are
		 * left intact in case they can be reused in the
		 * future.  Need a way to kick a retry here.
		 *
		 * XXX: We know the fixed size needed and could
		 * preallocate this using a blocking request at the
		 * start of the task to avoid having to handle this
		 * edge case.
		 */
		vm_page_unhold_pages(db->pages, db->npages);
		SOCKBUF_UNLOCK(sb);
		printf("%s: mk_update_tcb_for_ddp failed\n", __func__);
		return;
	}

	/*
	 * Hmmm: The AIO phys path just uses held pages and doesn't bother
	 * wiring.  OTOH, those requests expect the I/O to be satisified
	 * as soon as the hardware can service the request.  They aren't
	 * waiting for something to send packets.  It remains to be seen
	 * if it would be better to just leave them held and skip the
	 * wiring/unwiring.
	 */

	/* Wire (and then unhold) the pages, and give the chip the go-ahead. */
	wire_ddp_buffer(db);
	t4_wrq_tx(sc, wr);
#if 0
	sb->sb_flags &= ~SB_DDP_INDICATE;  /* XXX: Not sure? */
#endif
	db->cancel_pending = 0;
	db->cbe = cbe;
	toep->ddp_queueing = NULL;
	toep->ddp_flags |= buf_flag;
	toep->ddp_active_count++;
	if (toep->ddp_active_count == 1) {
		MPASS(toep->ddp_active_id == -1);
		toep->ddp_active_id = db_idx;
	}
	goto restart;
}

static int
t4_aio_cancel_ddp(struct aiocblist *cbe)
{
	struct socket *so = cbe->fd_file->f_data;
	struct tcpcb *tp = so_sototcpcb(so);
	struct toepcb *toep = tp->t_toe;
	struct adapter *sc = td_adapter(toep->td);
	struct sockbuf *sb = &so->so_rcv;
	uint64_t valid_flag;
	int i;

	/* NB: Called with AIO_LOCK(ki) held. */

	/* XXX: This isn't ideal, but is ok for a prototype. */
	if (!SOCKBUF_TRYLOCK(sb))
		return (EINPROGRESS);

	/*
	 * If this job is currently being queued by the task handler,
	 * just punt.
	 */
	if (cbe == toep->ddp_queueing) {
		CTR2(KTR_CXGBE, "%s: request %p queueing", __func__, cbe);
		SOCKBUF_UNLOCK(sb);
		return (EINPROGRESS);
	}

	for (i = 0; i < nitems(toep->db); i++) {
		if (toep->db[i] != NULL && toep->db[i]->cbe == cbe) {
			/* Cancel is pending or DDP has completed. */
			if (toep->db[i]->cancel_pending) {
				CTR2(KTR_CXGBE,
				    "%s: request %p already pending", __func__,
				    cbe);
				SOCKBUF_UNLOCK(sb);
				return (EINPROGRESS);
			}

			/*
			 * Flush this buffer.  It will be cancelled or
			 * partially completed once the card ACKs the
			 * flush.
			 */
#if 0
			valid_flag = i == 0 ? V_TF_DDP_BUF0_FLUSH(1) :
			    V_TF_DDP_BUF1_FLUSH(1);
			t4_set_tcb_field(sc, toep, 1, W_TCB_RX_DDP_FLAGS,
			    valid_flag, valid_flag);
#else
			valid_flag = i == 0 ? V_TF_DDP_BUF0_VALID(1) :
			    V_TF_DDP_BUF1_VALID(1);
			t4_set_tcb_field_rpl(sc, toep, 1, W_TCB_RX_DDP_FLAGS,
			    valid_flag, 0, i + DDP_BUF0_INVALIDATED);
#endif
			toep->db[i]->cancel_pending = 1;
			CTR2(KTR_CXGBE, "%s: request %p marked pending",
			    __func__, cbe);
			SOCKBUF_UNLOCK(sb);
			return (EINPROGRESS);
		}
	}

	TAILQ_REMOVE(&toep->ddp_aiojobq, cbe, list);
	toep->ddp_waiting_count--;
	if (toep->ddp_active_count + toep->ddp_waiting_count == 0) {
		toep->ddp_flags &= ~DDP_OK;
		if ((toep->ddp_flags & (DDP_ON | DDP_SC_REQ)) == DDP_ON)
			disable_ddp(sc, toep);
	}
	CTR2(KTR_CXGBE, "%s: request %p dequeued", __func__, cbe);
	SOCKBUF_UNLOCK(sb);
	return (0);
}

int
t4_aio_queue_ddp(struct socket *so, struct aiocblist *cbe)
{
	struct tcpcb *tp = so_sototcpcb(so);
	struct toepcb *toep = tp->t_toe;
	struct adapter *sc = td_adapter(toep->td);
	struct sockbuf *sb = &so->so_rcv;


	/* Ignore writes. */
	if (cbe->uaiocb.aio_lio_opcode != LIO_READ)
		return (EOPNOTSUPP);

	SOCKBUF_LOCK(sb);

	/*
	 * XXX: Think about possibly returning errors for ENOTCONN,
	 * etc.  Perhaps the caller would only queue the request
	 * if it failed with EOPNOTSUPP?
	 */

	CTR2(KTR_CXGBE, "%s: queueing %p", __func__, cbe);
	aio_queue(cbe, t4_aio_cancel_ddp);
	TAILQ_INSERT_TAIL(&toep->ddp_aiojobq, cbe, list);
	cbe->uaiocb._aiocb_private.status = 0;
	toep->ddp_waiting_count++;
	toep->ddp_flags |= DDP_OK;
	if ((toep->ddp_flags & (DDP_ON | DDP_SC_REQ)) == 0) {
		/*
		 * Wait for the card to ACK that DDP is enabled before
		 * queueing any buffers.  Currently this waits for an
		 * indicate to arrive.  It is not clear if it is possible
		 * to force an ACK of the enable request sooner if there
		 * is no data pending.  (Would be nice to not always
		 * require a copy of the indicated data.)
		 *
		 * XXX: Might want to limit the indicate size to the
		 * first queued request. (TODO)
		 *
		 * XXX: Could use a TCB_SET_FIELD_RPL message to know
		 * that DDP was enabled.
		 */
		if (ddp_aio_enable)
			enable_ddp(sc, toep);
	} else if (toep->ddp_flags & DDP_ON &&
	    (toep->ddp_flags & (DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE)) !=
	    (DDP_BUF0_ACTIVE | DDP_BUF1_ACTIVE)) {
		/*
		 * XXX: We could possibly do some of this work inline
		 * instead of queueing the task?
		 */
		taskqueue_enqueue(taskqueue_thread, &toep->ddp_requeue_task);
	}
	SOCKBUF_UNLOCK(sb);
	return (0);
}

MODULE_DEPEND(t4_tom, aio, 1, 1, 1);
#endif
