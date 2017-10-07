/*-
 * Copyright (c) 2017 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <np@FreeBSD.org>
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

#include "opt_inet.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/toecore.h>

#ifdef TCP_OFFLOAD
#include "common/common.h"
#include "common/t4_tcb.h"
#include "tom/t4_tom.h"

/*
 * TODO:
 * - socket options
 * - transmit TLS records via CPL_TX_TLS_SFO
 * - how to receive TLS data?
 * - handshake timer?
 */

static void
t4_set_tls_tcb_field(struct toepcb *toep, uint16_t word, uint64_t mask,
    uint64_t val)
{
	struct adapter *sc = td_adapter(toep->td);

	t4_set_tcb_field(sc, toep->ctrlq, toep->tid, word, mask, val, 0, 0,
	    toep->ofld_rxq->iq.abs_id);
}

/* Set TLS Key-Id in TCB */
static void
t4_set_tls_keyid(struct toepcb *toep, unsigned int key_id)
{

	t4_set_tls_tcb_field(toep, W_TCB_RX_TLS_KEY_TAG,
			 V_TCB_RX_TLS_KEY_TAG(M_TCB_RX_TLS_BUF_TAG),
			 V_TCB_RX_TLS_KEY_TAG(key_id));
}

/* Clear TF_RX_QUIESCE to re-enable receive. */
static void
t4_clear_rx_quiesce(struct toepcb *toep)
{

	t4_set_tls_tcb_field(toep, W_TCB_T_FLAGS, V_TF_RX_QUIESCE(1), 0);
}

static void
tls_clr_ofld_mode(struct toepcb *toep)
{

	/* XXX: Stop handshake timer. */

	/* Operate in PDU extraction mode only. */
	t4_set_tls_tcb_field(toep, W_TCB_ULP_RAW,
	    V_TCB_ULP_RAW(V_TF_TLS_ENABLE(1)),
	    V_TCB_ULP_RAW(V_TF_TLS_ENABLE(1)));
	t4_clear_rx_quiesce(toep);
}

static void
tls_clr_quiesce(struct toepcb *toep)
{

	/* XXX: Stop handshake timer. */

	t4_clear_rx_quiesce(toep);
}

static unsigned int
get_proto_ver(int proto_ver)
{
	switch (proto_ver) {
	case TLS1_2_VERSION:
		return TLS_1_2_VERSION;
	case TLS1_1_VERSION:
		return TLS_1_1_VERSION;
	case DTLS1_2_VERSION:
		return DTLS_1_2_VERSION;
	default:
		return TLS_VERSION_MAX;
	}
}

/* TLS Key bitmap processing */
int
tls_init_kmap(struct adapter *sc, struct tom_data *td)
{

	td->key_map = vmem_create("T4TLS key map", 0, sc->vres.key.size,
	    TLS_KEY_CONTEXT_SZ, 0, M_FIRSTFIT | M_NOWAIT);
	if (td->key_map == NULL)
		return (ENOMEM);
	return (0);
}

void
tls_free_kmap(struct tom_data *td)
{

	if (td->key_map != NULL)
		vmem_destroy(td->key_map);
}

static int
get_new_keyid(struct toepcb *toep, struct tls_key_context *k_ctx)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
	struct tom_data *td = toep->td;
	vmem_addr_t keyid;

	if (vmem_alloc(td->key_map, TLS_KEY_CONTEXT_SZ, M_NOWAIT | M_FIRSTFIT,
	    &keyid) != 0)
		return (-1);

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		tls_ofld->rx_key_id = keyid;
	} else {
		tls_ofld->tx_key_id = keyid;
	}
	return (keyid);
}

static void
clear_tls_keyid(struct toepcb *toep)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
	struct tom_data *td = toep->td;

	if (tls_ofld->rx_key_id >= 0) {
		vmem_free(td->key_map, tls_ofld->rx_key_id, TLS_KEY_CONTEXT_SZ);
		tls_ofld->rx_key_id = -1;
	}
	if (tls_ofld->tx_key_id >= 0) {
		vmem_free(td->key_map, tls_ofld->tx_key_id, TLS_KEY_CONTEXT_SZ);
		tls_ofld->tx_key_id = -1;
	}
}

static int
get_keyid(struct tls_ofld_info *tls_ofld, unsigned int ops)
{
	return (ops & KEY_WRITE_RX ? tls_ofld->rx_key_id : 
		((ops & KEY_WRITE_TX) ? tls_ofld->rx_key_id : -1)); 
}

/* Send request to get the key-id */
static int
tls_program_key_id(struct toepcb *toep, struct tls_key_context *k_ctx)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
#if 0
	int error;

	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *td = TOM_DATA(tdev);
#endif
	int kwrlen, kctxlen, keyid, len;
#if 0
	struct sk_buff *skb;
#endif
	struct tls_key_req *kwr;
	struct tls_keyctx *kctx;

	kwrlen = roundup2(sizeof(*kwr), 16);
	kctxlen = roundup2(sizeof(*kctx), 32);
	len = kwrlen + kctxlen;

	/* Dont initialize key for re-neg */
	if (!G_KEY_CLR_LOC(k_ctx->l_p_key)) {
		if ((keyid = get_new_keyid(toep, k_ctx)) < 0) {
			return (ENOSPC);
		}
	} else {
		keyid = get_keyid(tls_ofld, k_ctx->l_p_key);
	}

#if 0
	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	kwr = (struct tls_key_req *)__skb_put(skb, len);
	memset(kwr, 0, kwrlen);

	kwr->wr_hi =
		cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) |
			    F_FW_WR_COMPL |
			    F_FW_WR_ATOMIC);
	kwr->wr_mid =
		cpu_to_be32(V_FW_WR_LEN16(DIV_ROUND_UP(len, 16)) |
		      V_FW_WR_FLOWID(cplios->tid));
	kwr->protocol = get_proto_ver(k_ctx->proto_ver);
	kwr->mfs = htons(tls_ofld->k_ctx->frag_size);
	tls_ofld->fcplenmax = get_tp_plen_max(tls_ofld);
	kwr->reneg_to_write_rx = k_ctx->l_p_key;

	/* master command */
	kwr->cmd = cpu_to_be32(V_ULPTX_CMD(ULP_TX_MEM_WRITE) |
			 V_T5_ULP_MEMIO_ORDER(1) |
			 V_T5_ULP_MEMIO_IMM(1));
	kwr->dlen = cpu_to_be32(V_ULP_MEMIO_DATA_LEN(kctxlen >> 5));
	kwr->len16 = cpu_to_be32((cplios->tid << 8) |
				 DIV_ROUND_UP(len - sizeof(struct work_request_hdr), 16));
	kwr->kaddr = cpu_to_be32(V_ULP_MEMIO_ADDR(keyid_to_addr(td->kmap.start, keyid)));

	/* sub command */
	kwr->sc_more = cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));	
	kwr->sc_len = cpu_to_be32(kctxlen);

	kctx = (struct tls_keyctx *)(kwr + 1);
	memset(kctx, 0, kctxlen);

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_TX)
		prepare_txkey_wr(kctx, k_ctx);
	else if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX)
		prepare_rxkey_wr(kctx, k_ctx);

	set_wr_txq(skb, CPL_PRIORITY_DATA, tls_ofld->tx_qid);
	tls_ofld->key_rqst = 0;
	cplios->wr_credits -= DIV_ROUND_UP(len, 16);
	cplios->wr_unacked += DIV_ROUND_UP(len, 16);
	enqueue_wr(sk, skb);
	cxgb4_ofld_send(cplios->egress_dev, skb);
#endif

	return (0);
}

/* Store a key received from SSL in DDR. */
static int
program_key_context(struct tcpcb *tp, struct toepcb *toep,
    struct tls_key_context *uk_ctx)
{
	struct adapter *sc = td_adapter(toep->td);
	struct tls_ofld_info *tls_ofld = &toep->tls;
	struct tls_key_context *k_ctx;
	int error;

	if (tp->t_state != TCPS_ESTABLISHED) {
		/*
		 * XXX: Matches Linux driver, but not sure this is a
		 * very appropriate error.
		 */
		return (ENOENT);
	}

	/* XXX: Stop handshake timer. */

	k_ctx = &tls_ofld->k_ctx;

	/* Don't copy the 'tx' and 'rx' fields. */
	memcpy(&k_ctx->l_p_key, &uk_ctx->l_p_key,
	    sizeof(*k_ctx) - offsetof(struct tls_key_context, l_p_key));

	/* TLS version != 1.1 and !1.2 OR DTLS != 1.2 */
	if (get_proto_ver(k_ctx->proto_ver) > DTLS_1_2_VERSION) {
		if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
			tls_ofld->rx_key_id = -1;
			t4_clear_rx_quiesce(toep);
		} else {
			tls_ofld->tx_key_id = -1;
		}
		return (0);
	}

	if (k_ctx->state.enc_mode == CH_EVP_CIPH_GCM_MODE) {
		k_ctx->iv_size = 4;
		k_ctx->mac_first = 0;
		k_ctx->hmac_ctrl = 0;
	} else {
		k_ctx->iv_size = 8; /* for CBC, iv is 16B, unit of 2B */
		k_ctx->mac_first = 1;
	}

	tls_ofld->scmd0.seqno_numivs =
		(V_SCMD_SEQ_NO_CTRL(3) |
		 V_SCMD_PROTO_VERSION(get_proto_ver(k_ctx->proto_ver)) |
		 V_SCMD_ENC_DEC_CTRL(SCMD_ENCDECCTRL_ENCRYPT) |
		 V_SCMD_CIPH_AUTH_SEQ_CTRL((k_ctx->mac_first == 0)) |
		 V_SCMD_CIPH_MODE(k_ctx->state.enc_mode) |
		 V_SCMD_AUTH_MODE(k_ctx->state.auth_mode) |
		 V_SCMD_HMAC_CTRL(k_ctx->hmac_ctrl) |
		 V_SCMD_IV_SIZE(k_ctx->iv_size) |
		 V_SCMD_NUM_IVS(1));

	tls_ofld->scmd0.ivgen_hdrlen =
		(V_SCMD_IV_GEN_CTRL(k_ctx->iv_ctrl) |
		 V_SCMD_KEY_CTX_INLINE(0) |
		 V_SCMD_TLS_FRAG_ENABLE(1));

	tls_ofld->mac_length = k_ctx->mac_secret_size;

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		k_ctx->rx = uk_ctx->rx;
		/* Dont initialize key for re-neg */
		if (!G_KEY_CLR_LOC(k_ctx->l_p_key))
			tls_ofld->rx_key_id = -1;
	} else {
		k_ctx->tx = uk_ctx->tx;
		/* Dont initialize key for re-neg */
		if (!G_KEY_CLR_LOC(k_ctx->l_p_key))
			tls_ofld->tx_key_id = -1;
	}

	/* Flush pending data before new Tx key becomes active */
	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_TX) {
		t4_push_frames(sc, toep, 0);
		tls_ofld->tx_seq_no = 0;
	}

	if ((G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) ||
	    (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_DDR)) {
		error = tls_program_key_id(toep, k_ctx);
		if (error) {
			t4_clear_rx_quiesce(toep);
			tls_ofld->tx_key_id = -1;
			tls_ofld->rx_key_id = -1;
			return (error);
		}
	}

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		/*
		 * RX key tags are an index into the key portion of MA
		 * memory stored as an offset from the base address in
		 * units of 64 bytes.
		 */
		t4_set_tls_keyid(toep, tls_ofld->rx_key_id / 64);
		t4_set_tls_tcb_field(toep, W_TCB_ULP_RAW,
				 V_TCB_ULP_RAW(M_TCB_ULP_RAW),
				 V_TCB_ULP_RAW((V_TF_TLS_KEY_SIZE(3) |
						V_TF_TLS_CONTROL(1) |
						V_TF_TLS_ACTIVE(1) |
						V_TF_TLS_ENABLE(1))));
		t4_set_tls_tcb_field(toep, W_TCB_TLS_SEQ,
				 V_TCB_TLS_SEQ(M_TCB_TLS_SEQ),
				 V_TCB_TLS_SEQ(0));
		t4_clear_rx_quiesce(toep);
	} else {
		if (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_IMMEDIATE)
			tls_ofld->tx_key_id = 1;
	}

	return (0);
}

int
t4_ctloutput_tls(struct socket *so, struct sockopt *sopt)
{
	struct tls_key_context uk_ctx;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct toepcb *toep;
	int error, optval;

	error = 0;
	if (sopt->sopt_dir == SOPT_SET &&
	    sopt->sopt_name == TCP_TLSOM_SET_TLS_CONTEXT) {
		error = sooptcopyin(sopt, &uk_ctx, sizeof(uk_ctx),
		    sizeof(uk_ctx));
		if (error)
			return (error);
	}

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_ctloutput: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);
	toep = tp->t_toe;
	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case TCP_TLSOM_SET_TLS_CONTEXT:
			error = program_key_context(tp, toep, &uk_ctx);
			INP_WUNLOCK(inp);
			break;
		case TCP_TLSOM_CLR_TLS_TOM:
			tls_clr_ofld_mode(toep);
			INP_WUNLOCK(inp);
			break;
		case TCP_TLSOM_CLR_QUIES:
			tls_clr_quiesce(toep);
			INP_WUNLOCK(inp);
			break;
		default:
			INP_WUNLOCK(inp);
			error = EOPNOTSUPP;
			break;
		}
		break;
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case TCP_TLSOM_GET_TLS_TOM:
			optval = is_tls_offload(toep);
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;
		default:
			INP_WUNLOCK(inp);
			error = EOPNOTSUPP;
			break;
		}
		break;
	}
	return (error);
}

void
tls_init_toep(struct toepcb *toep)
{

	toep->tls.rx_key_id = -1;
	toep->tls.tx_key_id = -1;
}

void
tls_uninit_toep(struct toepcb *toep)
{
}
#endif	/* TCP_OFFLOAD */
