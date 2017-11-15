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
#include <sys/sglist.h>
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
#include "tom/t4_tom_l2t.h"
#include "tom/t4_tom.h"

/* XXX: Remove after rebasing on r324539. */
VNET_DECLARE(int, tcp_do_autosndbuf);
#define V_tcp_do_autosndbuf VNET(tcp_do_autosndbuf)
VNET_DECLARE(int, tcp_autosndbuf_inc);
#define V_tcp_autosndbuf_inc VNET(tcp_autosndbuf_inc)
VNET_DECLARE(int, tcp_autosndbuf_max);
#define V_tcp_autosndbuf_max VNET(tcp_autosndbuf_max)

/*
 * TODO:
 * + socket options
 * + transmit TLS records via CPL_TX_TLS_SFO
 *   + TLS handling in chelsio_sendpage / chelsio_sendmsg will move to
 *     t4_push_frames, and state won't be cached in mbuf
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

/* TLS and DTLS common routines */
int
tls_tx_key(struct toepcb *toep)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;

	return (tls_ofld->tx_key_addr >= 0);
}

int
tls_rx_key(struct toepcb *toep)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;

	return (tls_ofld->rx_key_addr >= 0);
}

static int
key_size(struct toepcb *toep)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;

	return ((tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_IMMEDIATE) ?
		tls_ofld->k_ctx.tx_key_info_size : KEY_IN_DDR_SIZE);
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

/*
 * Calculate the TLS data expansion size
 */
static int
tls_expansion_size(struct toepcb *toep, int data_len, int full_pdus_only,
    unsigned short *pdus_per_ulp)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
	struct tls_scmd *scmd = &tls_ofld->scmd0;
	int expn_size = 0, frag_count = 0, pad_per_pdu = 0,
	    pad_last_pdu = 0, last_frag_size = 0, max_frag_size = 0;
	int exp_per_pdu = 0;
	int hdr_len = TLS_HEADER_LENGTH;

	do {
		max_frag_size = tls_ofld->k_ctx.frag_size;
		if (G_SCMD_CIPH_MODE(scmd->seqno_numivs) ==
		   SCMD_CIPH_MODE_AES_GCM) {
			frag_count = (data_len / max_frag_size);
			exp_per_pdu = GCM_TAG_SIZE + AEAD_EXPLICIT_DATA_SIZE +
				hdr_len;
			expn_size =  frag_count * exp_per_pdu;
			if (full_pdus_only) {
				*pdus_per_ulp = data_len / (exp_per_pdu +
					max_frag_size);
				if (*pdus_per_ulp > 32)
					*pdus_per_ulp = 32;
				else if(!*pdus_per_ulp)
					*pdus_per_ulp = 1;
				expn_size = (*pdus_per_ulp) * exp_per_pdu;
				break;
			}	
			if ((last_frag_size = data_len % max_frag_size) > 0) {
				frag_count += 1;
				expn_size += exp_per_pdu;
			}
			break;
		} else if (G_SCMD_CIPH_MODE(scmd->seqno_numivs) !=
			   SCMD_CIPH_MODE_NOP) {
			/* Calculate the number of fragments we can make */
			frag_count  = (data_len / max_frag_size);
			if (frag_count > 0) {
				pad_per_pdu = (((howmany((max_frag_size +
						       tls_ofld->mac_length),
						      CIPHER_BLOCK_SIZE)) *
						CIPHER_BLOCK_SIZE) -
					       (max_frag_size +
						tls_ofld->mac_length));
				if (!pad_per_pdu)
					pad_per_pdu = CIPHER_BLOCK_SIZE;
				exp_per_pdu = pad_per_pdu +
				       	tls_ofld->mac_length +
					hdr_len + CIPHER_BLOCK_SIZE;
				expn_size = frag_count * exp_per_pdu;
			}
			if (full_pdus_only) { 
				*pdus_per_ulp = data_len / (exp_per_pdu +
					max_frag_size);
				if (*pdus_per_ulp > 32)
					*pdus_per_ulp = 32;
				else if (!*pdus_per_ulp)
					*pdus_per_ulp = 1;
				expn_size = (*pdus_per_ulp) * exp_per_pdu;
				break;
			}
			/* Consider the last fragment */
			if ((last_frag_size = data_len % max_frag_size) > 0) {
				pad_last_pdu = (((howmany((last_frag_size +
							tls_ofld->mac_length),
						       CIPHER_BLOCK_SIZE)) *
						 CIPHER_BLOCK_SIZE) -
						(last_frag_size +
						 tls_ofld->mac_length));
				if (!pad_last_pdu)
					pad_last_pdu = CIPHER_BLOCK_SIZE;
				expn_size += (pad_last_pdu +
					      tls_ofld->mac_length + hdr_len +
					      CIPHER_BLOCK_SIZE);
			}
		}
	} while (0);

	return (expn_size);
}

/* Copy Key to WR */
static void
tls_copy_tx_key(struct toepcb *toep, void *dst)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
	struct ulptx_sc_memrd *sc_memrd;
	struct ulptx_idata *sc;

	if (tls_ofld->k_ctx.tx_key_info_size <= 0)
		return;

	if (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_DDR) {
		sc = dst;
		sc->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_NOOP));
		sc->len = htobe32(0);
		sc_memrd = (struct ulptx_sc_memrd *)(sc + 1);
		sc_memrd->cmd_to_len = htobe32(V_ULPTX_CMD(ULP_TX_SC_MEMRD) |
		    V_ULP_TX_SC_MORE(1) |
		    V_ULPTX_LEN16(tls_ofld->k_ctx.tx_key_info_size >> 4));
		sc_memrd->addr = htobe32(tls_ofld->tx_key_addr >> 5);
	} else if (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_IMMEDIATE) {
		memcpy(dst, &tls_ofld->k_ctx.tx,
		    tls_ofld->k_ctx.tx_key_info_size);
	}
}

/* TLS/DTLS content type  for CPL SFO */
static inline unsigned char
tls_content_type(unsigned char content_type)
{
	/*
	 * XXX: Shouldn't this map CONTENT_TYPE_APP_DATA to DATA and
	 * default to "CUSTOM" for all other types including
	 * heartbeat?
	 */
	switch (content_type) {
	case CONTENT_TYPE_CCS:
		return CPL_TX_TLS_SFO_TYPE_CCS;
	case CONTENT_TYPE_ALERT:
		return CPL_TX_TLS_SFO_TYPE_ALERT;
	case CONTENT_TYPE_HANDSHAKE:
		return CPL_TX_TLS_SFO_TYPE_HANDSHAKE;
	case CONTENT_TYPE_HEARTBEAT:
		return CPL_TX_TLS_SFO_TYPE_HEARTBEAT;
	}
	return CPL_TX_TLS_SFO_TYPE_DATA;
}

static unsigned char
get_cipher_key_size(unsigned int ck_size)
{
	switch (ck_size) {
	case AES_NOP: /* NOP */
		return 15;
	case AES_128: /* AES128 */
		return CH_CK_SIZE_128;
	case AES_192: /* AES192 */
		return CH_CK_SIZE_192;
	case AES_256: /* AES256 */
		return CH_CK_SIZE_256;
	default:
		return CH_CK_SIZE_256;
	}
}

static unsigned char
get_mac_key_size(unsigned int mk_size)
{
	switch (mk_size) {
	case SHA_NOP: /* NOP */
		return CH_MK_SIZE_128;
	case SHA_GHASH: /* GHASH */
	case SHA_512: /* SHA512 */
		return CH_MK_SIZE_512;
	case SHA_224: /* SHA2-224 */
		return CH_MK_SIZE_192;
	case SHA_256: /* SHA2-256*/
		return CH_MK_SIZE_256;
	case SHA_384: /* SHA384 */
		return CH_MK_SIZE_512;
	case SHA1: /* SHA1 */
	default:
		return CH_MK_SIZE_160;
	}
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

static void
tls_rxkey_flit1(struct tls_keyctx *kwr, struct tls_key_context *kctx)
{

	if (kctx->state.enc_mode == CH_EVP_CIPH_GCM_MODE) {
		kwr->u.rxhdr.ivinsert_to_authinsrt =
		    htobe64(V_TLS_KEYCTX_TX_WR_IVINSERT(6ULL) |
			V_TLS_KEYCTX_TX_WR_AADSTRTOFST(1ULL) |
			V_TLS_KEYCTX_TX_WR_AADSTOPOFST(5ULL) |
			V_TLS_KEYCTX_TX_WR_AUTHSRTOFST(14ULL) |
			V_TLS_KEYCTX_TX_WR_AUTHSTOPOFST(16ULL) |
			V_TLS_KEYCTX_TX_WR_CIPHERSRTOFST(14ULL) |
			V_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST(0ULL) |
			V_TLS_KEYCTX_TX_WR_AUTHINSRT(16ULL));
		kwr->u.rxhdr.ivpresent_to_rxmk_size &=
			~(V_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT(1));
		kwr->u.rxhdr.authmode_to_rxvalid &=
			~(V_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL(1));
	} else {
		kwr->u.rxhdr.ivinsert_to_authinsrt =
		    htobe64(V_TLS_KEYCTX_TX_WR_IVINSERT(6ULL) |
			V_TLS_KEYCTX_TX_WR_AADSTRTOFST(1ULL) |
			V_TLS_KEYCTX_TX_WR_AADSTOPOFST(5ULL) |
			V_TLS_KEYCTX_TX_WR_AUTHSRTOFST(22ULL) |
			V_TLS_KEYCTX_TX_WR_AUTHSTOPOFST(0ULL) |
			V_TLS_KEYCTX_TX_WR_CIPHERSRTOFST(22ULL) |
			V_TLS_KEYCTX_TX_WR_CIPHERSTOPOFST(0ULL) |
			V_TLS_KEYCTX_TX_WR_AUTHINSRT(0ULL));
	}
}

/* Rx key */
static void
prepare_rxkey_wr(struct tls_keyctx *kwr, struct tls_key_context *kctx)
{
	unsigned int ck_size = kctx->cipher_secret_size;
	unsigned int mk_size = kctx->mac_secret_size;
	int proto_ver = kctx->proto_ver;

	kwr->u.rxhdr.flitcnt_hmacctrl =
		((kctx->tx_key_info_size >> 4) << 3) | kctx->hmac_ctrl;

	kwr->u.rxhdr.protover_ciphmode =
		V_TLS_KEYCTX_TX_WR_PROTOVER(get_proto_ver(proto_ver)) |
		V_TLS_KEYCTX_TX_WR_CIPHMODE(kctx->state.enc_mode);

	kwr->u.rxhdr.authmode_to_rxvalid =
		V_TLS_KEYCTX_TX_WR_AUTHMODE(kctx->state.auth_mode) |
		V_TLS_KEYCTX_TX_WR_CIPHAUTHSEQCTRL(1) |
		V_TLS_KEYCTX_TX_WR_SEQNUMCTRL(3) |
		V_TLS_KEYCTX_TX_WR_RXVALID(1);

	kwr->u.rxhdr.ivpresent_to_rxmk_size =
		V_TLS_KEYCTX_TX_WR_IVPRESENT(0) |
		V_TLS_KEYCTX_TX_WR_RXOPAD_PRESENT(1) |
		V_TLS_KEYCTX_TX_WR_RXCK_SIZE(get_cipher_key_size(ck_size)) |
		V_TLS_KEYCTX_TX_WR_RXMK_SIZE(get_mac_key_size(mk_size));

	tls_rxkey_flit1(kwr, kctx);

	/* No key reversal for GCM */
	if (kctx->state.enc_mode != CH_EVP_CIPH_GCM_MODE) {
		t4_aes_getdeckey(kwr->keys.edkey, kctx->rx.key,
				 (kctx->cipher_secret_size << 3));
		memcpy(kwr->keys.edkey + kctx->cipher_secret_size,
		       kctx->rx.key + kctx->cipher_secret_size,
		       (IPAD_SIZE + OPAD_SIZE));
	} else {
		memcpy(kwr->keys.edkey, kctx->rx.key,
		       (kctx->tx_key_info_size - SALT_SIZE));
		memcpy(kwr->u.rxhdr.rxsalt, kctx->rx.salt, SALT_SIZE);
	}
}

/* Tx key */
static void
prepare_txkey_wr(struct tls_keyctx *kwr, struct tls_key_context *kctx)
{
	unsigned int ck_size = kctx->cipher_secret_size;
	unsigned int mk_size = kctx->mac_secret_size;

	kwr->u.txhdr.ctxlen =
		(kctx->tx_key_info_size >> 4);
	kwr->u.txhdr.dualck_to_txvalid =
		V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(1) |
		V_TLS_KEYCTX_TX_WR_SALT_PRESENT(1) |
		V_TLS_KEYCTX_TX_WR_TXCK_SIZE(get_cipher_key_size(ck_size)) |
		V_TLS_KEYCTX_TX_WR_TXMK_SIZE(get_mac_key_size(mk_size)) |
		V_TLS_KEYCTX_TX_WR_TXVALID(1);

	memcpy(kwr->keys.edkey, kctx->tx.key, HDR_KCTX_SIZE);
	if (kctx->state.enc_mode == CH_EVP_CIPH_GCM_MODE) {
		memcpy(kwr->u.txhdr.txsalt, kctx->tx.salt, SALT_SIZE);
		kwr->u.txhdr.dualck_to_txvalid &=
			~(V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(1));
	}
	kwr->u.txhdr.dualck_to_txvalid = htons(kwr->u.txhdr.dualck_to_txvalid);
}

/* TLS Key memory management */
int
tls_init_kmap(struct adapter *sc, struct tom_data *td)
{

	td->key_map = vmem_create("T4TLS key map", sc->vres.key.start,
	    sc->vres.key.size, 8, 0, M_FIRSTFIT | M_NOWAIT);
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
	struct tom_data *td = toep->td;
	vmem_addr_t addr;

	if (vmem_alloc(td->key_map, TLS_KEY_CONTEXT_SZ, M_NOWAIT | M_FIRSTFIT,
	    &addr) != 0)
		return (-1);

	return (addr);
}

static void
free_keyid(struct toepcb *toep, int keyid)
{
	struct tom_data *td = toep->td;

	vmem_free(td->key_map, keyid, TLS_KEY_CONTEXT_SZ);
}

static void
clear_tls_keyid(struct toepcb *toep)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;

	if (tls_ofld->rx_key_addr >= 0) {
		free_keyid(toep, tls_ofld->rx_key_addr);
		tls_ofld->rx_key_addr = -1;
	}
	if (tls_ofld->tx_key_addr >= 0) {
		free_keyid(toep, tls_ofld->tx_key_addr);
		tls_ofld->tx_key_addr = -1;
	}
}

static int
get_keyid(struct tls_ofld_info *tls_ofld, unsigned int ops)
{
	return (ops & KEY_WRITE_RX ? tls_ofld->rx_key_addr : 
		((ops & KEY_WRITE_TX) ? tls_ofld->rx_key_addr : -1)); 
}

static int
get_tp_plen_max(struct tls_ofld_info *tls_ofld)
{
	int plen = ((min(3*4096, TP_TX_PG_SZ))/1448) * 1448;

	return (tls_ofld->k_ctx.frag_size <= 8192 ? plen : FC_TP_PLEN_MAX);	
}

/* Send request to get the key-id */
static int
tls_program_key_id(struct toepcb *toep, struct tls_key_context *k_ctx)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
	struct adapter *sc = td_adapter(toep->td);
	struct ofld_tx_sdesc *txsd;
	int kwrlen, kctxlen, keyid, len;
	struct wrqe *wr;
	struct tls_key_req *kwr;
	struct tls_keyctx *kctx;

	kwrlen = roundup2(sizeof(*kwr), 16);
	kctxlen = roundup2(sizeof(*kctx), 32);
	len = kwrlen + kctxlen;

	if (toep->txsd_avail == 0)
		return (EAGAIN);
		
	/* Dont initialize key for re-neg */
	if (!G_KEY_CLR_LOC(k_ctx->l_p_key)) {
		if ((keyid = get_new_keyid(toep, k_ctx)) < 0) {
			return (ENOSPC);
		}
	} else {
		keyid = get_keyid(tls_ofld, k_ctx->l_p_key);
	}

	wr = alloc_wrqe(len, toep->ofld_txq);
	if (wr == NULL) {
		free_keyid(toep, keyid);
		return (ENOMEM);
	}
	kwr = wrtod(wr);
	memset(kwr, 0, kwrlen);

	kwr->wr_hi = htobe32(V_FW_WR_OP(FW_ULPTX_WR) | F_FW_WR_COMPL |
	    F_FW_WR_ATOMIC);
	kwr->wr_mid = htobe32(V_FW_WR_LEN16(DIV_ROUND_UP(len, 16)) |
	    V_FW_WR_FLOWID(toep->tid));
	kwr->protocol = get_proto_ver(k_ctx->proto_ver);
	kwr->mfs = htons(k_ctx->frag_size);
	kwr->reneg_to_write_rx = k_ctx->l_p_key;

	/* master command */
	kwr->cmd = htobe32(V_ULPTX_CMD(ULP_TX_MEM_WRITE) |
	    V_T5_ULP_MEMIO_ORDER(1) | V_T5_ULP_MEMIO_IMM(1));
	kwr->dlen = htobe32(V_ULP_MEMIO_DATA_LEN(kctxlen >> 5));
	kwr->len16 = htobe32((toep->tid << 8) |
	    DIV_ROUND_UP(len - sizeof(struct work_request_hdr), 16));
	kwr->kaddr = htobe32(V_ULP_MEMIO_ADDR(keyid >> 5));

	/* sub command */
	kwr->sc_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));	
	kwr->sc_len = htobe32(kctxlen);

	/* XXX: This assumes that kwrlen == sizeof(*kwr). */
	kctx = (struct tls_keyctx *)(kwr + 1);
	memset(kctx, 0, kctxlen);

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_TX) {
		tls_ofld->tx_key_addr = keyid;
		prepare_txkey_wr(kctx, k_ctx);
	} else if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		tls_ofld->rx_key_addr = keyid;
		prepare_rxkey_wr(kctx, k_ctx);
	}

	txsd = &toep->txsd[toep->txsd_pidx];
	txsd->tx_credits = DIV_ROUND_UP(len, 16);
	txsd->plen = 0;
	toep->tx_credits -= txsd->tx_credits;
	if (__predict_false(++toep->txsd_pidx == toep->txsd_total))
		toep->txsd_pidx = 0;
	toep->txsd_avail--;

	t4_wrq_tx(sc, wr);

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
	int error, key_offset;

	if (tp->t_state != TCPS_ESTABLISHED) {
		/*
		 * XXX: Matches Linux driver, but not sure this is a
		 * very appropriate error.
		 */
		return (ENOENT);
	}

	/* XXX: Stop handshake timer. */

	CTR4(KTR_CXGBE, "%s: %d %s proto_ver %#x", __func__, toep->tid,
	    G_KEY_GET_LOC(uk_ctx->l_p_key) == KEY_WRITE_RX ? "KEY_WRITE_RX" :
	    "KEY_WRITE_TX", uk_ctx->proto_ver);

	if (G_KEY_GET_LOC(uk_ctx->l_p_key) == KEY_WRITE_RX &&
	    toep->ulp_mode != ULP_MODE_TLS)
		return (EOPNOTSUPP);

	/* Don't copy the 'tx' and 'rx' fields. */
	k_ctx = &tls_ofld->k_ctx;
	memcpy(&k_ctx->l_p_key, &uk_ctx->l_p_key,
	    sizeof(*k_ctx) - offsetof(struct tls_key_context, l_p_key));

	/* TLS version != 1.1 and !1.2 OR DTLS != 1.2 */
	if (get_proto_ver(k_ctx->proto_ver) > DTLS_1_2_VERSION) {
		if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
			tls_ofld->rx_key_addr = -1;
			t4_clear_rx_quiesce(toep);
		} else {
			tls_ofld->tx_key_addr = -1;
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
		 V_SCMD_IV_SIZE(k_ctx->iv_size));

	tls_ofld->scmd0.ivgen_hdrlen =
		(V_SCMD_IV_GEN_CTRL(k_ctx->iv_ctrl) |
		 V_SCMD_KEY_CTX_INLINE(0) |
		 V_SCMD_TLS_FRAG_ENABLE(1));

	tls_ofld->mac_length = k_ctx->mac_secret_size;

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		k_ctx->rx = uk_ctx->rx;
		/* Dont initialize key for re-neg */
		if (!G_KEY_CLR_LOC(k_ctx->l_p_key))
			tls_ofld->rx_key_addr = -1;
	} else {
		k_ctx->tx = uk_ctx->tx;
		/* Dont initialize key for re-neg */
		if (!G_KEY_CLR_LOC(k_ctx->l_p_key))
			tls_ofld->tx_key_addr = -1;
	}

	/* Flush pending data before new Tx key becomes active */
	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_TX) {
		struct sockbuf *sb;

		/* XXX: This might not drain everything. */
		t4_push_frames(sc, toep, 0);
		sb = &toep->inp->inp_socket->so_snd;
		SOCKBUF_LOCK(sb);

		/* XXX: This asserts that everything has been pushed. */
		MPASS(sb->sb_sndptr == NULL || sb->sb_sndptr->m_next == NULL);
		sb->sb_sndptr = NULL;
		tls_ofld->sb_off = sbavail(sb);
		SOCKBUF_UNLOCK(sb);
		tls_ofld->tx_seq_no = 0;
	}

	if ((G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) ||
	    (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_DDR)) {
		error = tls_program_key_id(toep, k_ctx);
		if (error) {
			/* XXX: Only clear quiesce for KEY_WRITE_RX? */
			t4_clear_rx_quiesce(toep);
			return (error);
		}
	}

	if (G_KEY_GET_LOC(k_ctx->l_p_key) == KEY_WRITE_RX) {
		/*
		 * RX key tags are an index into the key portion of MA
		 * memory stored as an offset from the base address in
		 * units of 64 bytes.
		 */
		key_offset = tls_ofld->rx_key_addr - sc->vres.key.start;
		t4_set_tls_keyid(toep, key_offset / 64);
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
		unsigned short pdus_per_ulp;

		if (tls_ofld->key_location == TLS_SFO_WR_CONTEXTLOC_IMMEDIATE)
			tls_ofld->tx_key_addr = 1;

		tls_ofld->fcplenmax = get_tp_plen_max(tls_ofld);
		tls_ofld->expn_per_ulp = tls_expansion_size(toep,
				tls_ofld->fcplenmax, 1, &pdus_per_ulp);
		tls_ofld->pdus_per_ulp = pdus_per_ulp;
		tls_ofld->adjusted_plen = tls_ofld->pdus_per_ulp *
			((tls_ofld->expn_per_ulp/tls_ofld->pdus_per_ulp) +
			 tls_ofld->k_ctx.frag_size);
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
			if (toep->ulp_mode == ULP_MODE_TLS) {
				CTR2(KTR_CXGBE, "%s: CLR_TLS_TOM tid %d",
				    __func__, toep->tid);
				tls_clr_ofld_mode(toep);
			} else
				error = EOPNOTSUPP;
			INP_WUNLOCK(inp);
			break;
		case TCP_TLSOM_CLR_QUIES:
			if (toep->ulp_mode == ULP_MODE_TLS) {
				CTR2(KTR_CXGBE, "%s: CLR_QUIES tid %d",
				    __func__, toep->tid);
				tls_clr_quiesce(toep);
			} else
				error = EOPNOTSUPP;
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
			/* TLS TX is permitted on any TOE socket. */
			optval = 0;
			if (can_tls_offload(td_adapter(toep->td))) {
				switch (toep->ulp_mode) {
				case ULP_MODE_NONE:
				case ULP_MODE_TCPDDP:
				case ULP_MODE_TLS:
					optval = 1;
					break;
				}
			}
			CTR3(KTR_CXGBE, "%s: GET_TLS_TOM tid %d = %d",
			    __func__, toep->tid, optval);
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
	struct tls_ofld_info *tls_ofld = &toep->tls;

	tls_ofld->key_location = TLS_SFO_WR_CONTEXTLOC_DDR;
	tls_ofld->rx_key_addr = -1;
	tls_ofld->tx_key_addr = -1;
}

void
tls_uninit_toep(struct toepcb *toep)
{

	clear_tls_keyid(toep);
}

#define MAX_OFLD_TX_CREDITS (SGE_MAX_WR_LEN / 16)
#define	MIN_OFLD_TLSTX_CREDITS(toep)					\
	(howmany(sizeof(struct fw_tlstx_data_wr) +			\
	    sizeof(struct cpl_tx_tls_sfo) + key_size((toep)) +		\
	    CIPHER_BLOCK_SIZE + 1, 16))

static inline u_int
max_imm_tls_space(int tx_credits)
{
	const int n = 2;	/* Use only up to 2 desc for imm. data WR */
	int space;

	KASSERT(tx_credits >= 0 &&
		tx_credits <= MAX_OFLD_TX_CREDITS,
		("%s: %d credits", __func__, tx_credits));

	if (tx_credits >= (n * EQ_ESIZE) / 16)
		space = (n * EQ_ESIZE);
	else
		space = tx_credits * 16;
	return (space);
}

static int
count_mbuf_segs(struct mbuf *m, int skip, int len, int *max_nsegs_1mbufp)
{
	int max_nsegs_1mbuf, n, nsegs;

	while (skip >= m->m_len) {
		skip -= m->m_len;
		m = m->m_next;
	}

	nsegs = 0;
	max_nsegs_1mbuf = 0;
	while (len > 0) {
		n = sglist_count(mtod(m, char *) + skip, m->m_len - skip);
		if (n > max_nsegs_1mbuf)
			max_nsegs_1mbuf = n;
		nsegs += n;
		len -= m->m_len - skip;
		skip = 0;
		m = m->m_next;
	}
	*max_nsegs_1mbufp = max_nsegs_1mbuf;
	return (nsegs);
}

static void
write_tlstx_wr(struct fw_tlstx_data_wr *txwr, struct toepcb *toep,
    unsigned int immdlen, unsigned int plen, unsigned int expn,
    unsigned int pdus, uint8_t credits, int shove, int imm_ivs)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
	unsigned int len = plen + expn;

	txwr->op_to_immdlen = htobe32(V_WR_OP(FW_TLSTX_DATA_WR) |
	    V_FW_TLSTX_DATA_WR_COMPL(1) |
	    V_FW_TLSTX_DATA_WR_IMMDLEN(immdlen));
	txwr->flowid_len16 = htobe32(V_FW_TLSTX_DATA_WR_FLOWID(toep->tid) |
	    V_FW_TLSTX_DATA_WR_LEN16(credits));
	txwr->plen = htobe32(len);
	txwr->lsodisable_to_flags = htobe32(V_TX_ULP_MODE(ULP_MODE_TLS) |
	    V_TX_URG(0) | /* F_T6_TX_FORCE | */ V_TX_SHOVE(shove));
	txwr->ctxloc_to_exp = htobe32(V_FW_TLSTX_DATA_WR_NUMIVS(pdus) |
	    V_FW_TLSTX_DATA_WR_EXP(expn) |
	    V_FW_TLSTX_DATA_WR_CTXLOC(tls_ofld->key_location) |
	    V_FW_TLSTX_DATA_WR_IVDSGL(!imm_ivs) |
	    V_FW_TLSTX_DATA_WR_KEYSIZE(tls_ofld->k_ctx.tx_key_info_size >> 4));
	txwr->mfs = htobe16(tls_ofld->k_ctx.frag_size);
	txwr->adjustedplen_pkd = htobe16(
	    V_FW_TLSTX_DATA_WR_ADJUSTEDPLEN(tls_ofld->adjusted_plen));
	txwr->expinplenmax_pkd = htobe16(
	    V_FW_TLSTX_DATA_WR_EXPINPLENMAX(tls_ofld->expn_per_ulp));
	txwr->pdusinplenmax_pkd = htobe16(
	    V_FW_TLSTX_DATA_WR_PDUSINPLENMAX(tls_ofld->pdus_per_ulp));
}

static void
write_tlstx_cpl(struct cpl_tx_tls_sfo *cpl, struct toepcb *toep,
    struct tls_hdr *tls_hdr, unsigned int plen, unsigned int pdus)
{
	struct tls_ofld_info *tls_ofld = &toep->tls;
	int data_type, seglen;

	if (plen < tls_ofld->k_ctx.frag_size)
		seglen = plen;
	else
		seglen = tls_ofld->k_ctx.frag_size;
	data_type = tls_content_type(tls_hdr->type);
	cpl->op_to_seg_len = htobe32(V_CPL_TX_TLS_SFO_OPCODE(CPL_TX_TLS_SFO) |
	    V_CPL_TX_TLS_SFO_DATA_TYPE(data_type) |
	    V_CPL_TX_TLS_SFO_CPL_LEN(2) | V_CPL_TX_TLS_SFO_SEG_LEN(seglen));
	cpl->pld_len = htobe32(plen);
	if (data_type == CPL_TX_TLS_SFO_TYPE_HEARTBEAT)
		cpl->type_protover = htobe32(
		    V_CPL_TX_TLS_SFO_TYPE(tls_hdr->type));
	cpl->seqno_numivs = htobe32(tls_ofld->scmd0.seqno_numivs |
	    V_SCMD_NUM_IVS(pdus));
	cpl->ivgen_hdrlen = htobe32(tls_ofld->scmd0.ivgen_hdrlen);
	cpl->scmd1 = htobe64(tls_ofld->tx_seq_no);
	tls_ofld->tx_seq_no += pdus;
}

/*
 * Similar to write_tx_sgl() except that it accepts an optional
 * trailer buffer for IVs.
 */
static void
write_tlstx_sgl(void *dst, struct mbuf *start, int skip, int plen,
    void *iv_buffer, int iv_len, int nsegs, int n)
{
	struct mbuf *m;
	struct ulptx_sgl *usgl = dst;
	int i, j, rc;
	struct sglist sg;
	struct sglist_seg segs[n];

	KASSERT(nsegs > 0, ("%s: nsegs 0", __func__));

	sglist_init(&sg, n, segs);
	usgl->cmd_nsge = htobe32(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
	    V_ULPTX_NSGE(nsegs));

	for (m = start; skip >= m->m_len; m = m->m_next)
		skip -= m->m_len;

	i = -1;
	for (m = start; plen > 0; m = m->m_next) {
		rc = sglist_append(&sg, mtod(m, char *) + skip,
		    m->m_len - skip);
		if (__predict_false(rc != 0))
			panic("%s: sglist_append %d", __func__, rc);
		plen -= m->m_len - skip;
		skip = 0;

		for (j = 0; j < sg.sg_nseg; i++, j++) {
			if (i < 0) {
				usgl->len0 = htobe32(segs[j].ss_len);
				usgl->addr0 = htobe64(segs[j].ss_paddr);
			} else {
				usgl->sge[i / 2].len[i & 1] =
				    htobe32(segs[j].ss_len);
				usgl->sge[i / 2].addr[i & 1] =
				    htobe64(segs[j].ss_paddr);
			}
#ifdef INVARIANTS
			nsegs--;
#endif
		}
		sglist_reset(&sg);
	}
	if (iv_buffer != NULL) {
		rc = sglist_append(&sg, iv_buffer, iv_len);
		if (__predict_false(rc != 0))
			panic("%s: sglist_append %d", __func__, rc);
		
		for (j = 0; j < sg.sg_nseg; i++, j++) {
			if (i < 0) {
				usgl->len0 = htobe32(segs[j].ss_len);
				usgl->addr0 = htobe64(segs[j].ss_paddr);
			} else {
				usgl->sge[i / 2].len[i & 1] =
				    htobe32(segs[j].ss_len);
				usgl->sge[i / 2].addr[i & 1] =
				    htobe64(segs[j].ss_paddr);
			}
#ifdef INVARIANTS
			nsegs--;
#endif
		}
	}
	if (i & 1)
		usgl->sge[i / 2].len[1] = htobe32(0);
	KASSERT(nsegs == 0, ("%s: nsegs %d, start %p, iv_buffer %p",
	    __func__, nsegs, start, iv_buffer));
}

/*
 * Similar to t4_push_frames() but handles TLS sockets when TLS offload
 * is enabled.  Rather than transmitting bulk data, the socket buffer
 * contains TLS records.  The work request requires a full TLS record,
 * so batch mbufs up until a full TLS record is seen.  This requires
 * reading the TLS header out of the start of each record to determine
 * its length.
 */
void
t4_push_tls_records(struct adapter *sc, struct toepcb *toep, int drop)
{
	struct tls_hdr thdr;
	struct mbuf *sndptr;
	struct fw_tlstx_data_wr *txwr;
	struct cpl_tx_tls_sfo *cpl;
	struct wrqe *wr;
	u_int plen, nsegs, credits, space, max_nsegs_1mbuf, wr_len;
	u_int expn_size, iv_len, pdus, sndptroff;
	struct tls_ofld_info *tls_ofld = &toep->tls;
	struct inpcb *inp = toep->inp;
	struct tcpcb *tp = intotcpcb(inp);
	struct socket *so = inp->inp_socket;
	struct sockbuf *sb = &so->so_snd;
	int tls_size, tx_credits, shove, /* compl,*/ sowwakeup;
	struct ofld_tx_sdesc *txsd;
	bool imm_ivs, imm_payload;
	void *iv_buffer, *iv_dst, *buf;

	INP_WLOCK_ASSERT(inp);
	KASSERT(toep->flags & TPF_FLOWC_WR_SENT,
	    ("%s: flowc_wr not sent for tid %u.", __func__, toep->tid));

	KASSERT(toep->ulp_mode == ULP_MODE_NONE ||
	    toep->ulp_mode == ULP_MODE_TCPDDP || toep->ulp_mode == ULP_MODE_TLS,
	    ("%s: ulp_mode %u for toep %p", __func__, toep->ulp_mode, toep));
	KASSERT(tls_tx_key(toep),
	    ("%s: TX key not set for toep %p", __func__, toep));

#ifdef VERBOSE_TRACES
	CTR4(KTR_CXGBE, "%s: tid %d toep flags %#x tp flags %#x drop %d",
	    __func__, toep->tid, toep->flags, tp->t_flags);
#endif
	if (__predict_false(toep->flags & TPF_ABORT_SHUTDOWN))
		return;

#ifdef RATELIMIT
	if (__predict_false(inp->inp_flags2 & INP_RATE_LIMIT_CHANGED) &&
	    (update_tx_rate_limit(sc, toep, so->so_max_pacing_rate) == 0)) {
		inp->inp_flags2 &= ~INP_RATE_LIMIT_CHANGED;
	}
#endif

	/*
	 * This function doesn't resume by itself.  Someone else must clear the
	 * flag and call this function.
	 */
	if (__predict_false(toep->flags & TPF_TX_SUSPENDED)) {
		KASSERT(drop == 0,
		    ("%s: drop (%d) != 0 but tx is suspended", __func__, drop));
		return;
	}

	txsd = &toep->txsd[toep->txsd_pidx];
	for (;;) {
		tx_credits = min(toep->tx_credits, MAX_OFLD_TX_CREDITS);
		space = max_imm_tls_space(tx_credits);
		wr_len = sizeof(struct fw_tlstx_data_wr) +
		    sizeof(struct cpl_tx_tls_sfo) + key_size(toep);
		if (wr_len + CIPHER_BLOCK_SIZE + 1 > space)
			return;

		SOCKBUF_LOCK(sb);
		sowwakeup = drop;
		if (drop) {
			sbdrop_locked(sb, drop);
			MPASS(tls_ofld->sb_off >= drop);
			tls_ofld->sb_off -= drop;
			drop = 0;
		}

		/*
		 * Send a FIN if requested, but only if there's no
		 * more data to send.
		 */
		if (sbavail(sb) == 0 && toep->flags & TPF_SEND_FIN) {
			if (sowwakeup)
				sowwakeup_locked(so);
			else
				SOCKBUF_UNLOCK(sb);
			SOCKBUF_UNLOCK_ASSERT(sb);
			t4_close_conn(sc, toep);
			return;
		}

		if (sbavail(sb) < tls_ofld->sb_off + TLS_HEADER_LENGTH) {
			/*
			 * A full TLS header is not yet queued, stop
			 * for now until more data is added to the
			 * socket buffer.
			 */
			if (sowwakeup)
				sowwakeup_locked(so);
			else
				SOCKBUF_UNLOCK(sb);
			SOCKBUF_UNLOCK_ASSERT(sb);
			return;
		}

		/* Read the header of the next TLS record. */
		sndptr = sbsndmbuf(sb, tls_ofld->sb_off, &sndptroff);
		MPASS(!IS_AIOTX_MBUF(sndptr));
		m_copydata(sndptr, sndptroff, sizeof(thdr), (caddr_t)&thdr);
		tls_size = htons(thdr.length);
		plen = TLS_HEADER_LENGTH + tls_size;
		pdus = howmany(tls_size, tls_ofld->k_ctx.frag_size);
		iv_len = pdus * CIPHER_BLOCK_SIZE;

		if (sbavail(sb) < tls_ofld->sb_off + plen) {
			/*
			 * The full TLS record is not yet queued, stop
			 * for now until more data is added to the
			 * socket buffer.
			 */
			if (sowwakeup)
				sowwakeup_locked(so);
			else
				SOCKBUF_UNLOCK(sb);
			SOCKBUF_UNLOCK_ASSERT(sb);
			return;
		}

		/* Shove if there is no additional data pending. */
		shove = (sbavail(sb) == tls_ofld->sb_off + plen) &&
		    !(tp->t_flags & TF_MORETOCOME);

#if 0
		if (sbused(sb) > sb->sb_hiwat * 5 / 8 &&
		    toep->plen_nocompl + plen >= sb->sb_hiwat / 4)
			compl = 1;
		else
			compl = 0;
#endif

		if (sb->sb_flags & SB_AUTOSIZE &&
		    V_tcp_do_autosndbuf &&
		    sb->sb_hiwat < V_tcp_autosndbuf_max &&
		    sbused(sb) >= sb->sb_hiwat * 7 / 8) {
			int newsize = min(sb->sb_hiwat + V_tcp_autosndbuf_inc,
			    V_tcp_autosndbuf_max);

			if (!sbreserve_locked(sb, newsize, so, NULL))
				sb->sb_flags &= ~SB_AUTOSIZE;
			else
				sowwakeup = 1;	/* room available */
		}
		if (sowwakeup)
			sowwakeup_locked(so);
		else
			SOCKBUF_UNLOCK(sb);
		SOCKBUF_UNLOCK_ASSERT(sb);

		if (__predict_false(toep->flags & TPF_FIN_SENT))
			panic("%s: excess tx.", __func__);

		/* Determine whether to use immediate vs SGL. */
		imm_payload = false;
		imm_ivs = false;
		if (wr_len + iv_len <= space) {
			imm_ivs = true;
			wr_len += iv_len;
			if (wr_len + tls_size <= space) {
				wr_len += tls_size;
				imm_payload = true;
			}
		}

		/* Allocate space for IVs if needed. */
		if (!imm_ivs) {
			iv_buffer = malloc(iv_len, M_CXGBE, M_NOWAIT);
			if (iv_buffer == NULL) {
				/*
				 * XXX: How to restart this?
				 */
				if (sowwakeup)
					sowwakeup_locked(so);
				else
					SOCKBUF_UNLOCK(sb);
				SOCKBUF_UNLOCK_ASSERT(sb);
				return;
			}
		} else
			iv_buffer = NULL;

		/* Determine size of SGL. */
		nsegs = 0;
		max_nsegs_1mbuf = 0; /* max # of SGL segments in any one mbuf */
		if (!imm_payload) {
			nsegs = count_mbuf_segs(sndptr, sndptroff +
			    TLS_HEADER_LENGTH, tls_size, &max_nsegs_1mbuf);
			if (!imm_ivs) {
				int n = sglist_count(iv_buffer, iv_len);
				nsegs += n;
				if (n > max_nsegs_1mbuf)
					max_nsegs_1mbuf = n;
			}

			/* Account for SGL in work request length. */
			wr_len += sizeof(struct ulptx_sgl) +
			    ((3 * (nsegs - 1)) / 2 + ((nsegs - 1) & 1)) * 8;
		}

		wr = alloc_wrqe(roundup2(wr_len, 16), toep->ofld_txq);
		if (wr == NULL) {
			/* XXX: how will we recover from this? */
			toep->flags |= TPF_TX_SUSPENDED;
			return;
		}

#ifdef VERBOSE_TRACES
		CTR5(KTR_CXGBE, "%s: tid %d TLS record %d len %#x pdus %d",
		    __func__, toep->tid, thdr.type, tls_size, pdus);
#endif
		txwr = wrtod(wr);
		cpl = (struct cpl_tx_tls_sfo *)(txwr + 1);
		memset(txwr, 0, roundup2(wr_len, 16));
		credits = howmany(wr_len, 16);
		expn_size = tls_expansion_size(toep, tls_size, 0, NULL);
		write_tlstx_wr(txwr, toep, imm_payload ? tls_size : 0,
		    tls_size, expn_size, pdus, credits, shove, imm_ivs ? 1 : 0);
		write_tlstx_cpl(cpl, toep, &thdr, tls_size, pdus);
		tls_copy_tx_key(toep, cpl + 1);

		/* Generate random IVs */
		buf = (char *)(cpl + 1) + key_size(toep);
		if (imm_ivs) {
			MPASS(iv_buffer == NULL);
			iv_dst = buf;
			buf = (char *)iv_dst + iv_len;
		} else
			iv_dst = iv_buffer;
		arc4rand(iv_dst, iv_len, 0);

		if (imm_payload) {
			m_copydata(sndptr, sndptroff + TLS_HEADER_LENGTH,
			    tls_size, buf);
		} else {
			write_tlstx_sgl(buf, sndptr,
			    sndptroff + TLS_HEADER_LENGTH, tls_size, iv_buffer,
			    iv_len, nsegs, max_nsegs_1mbuf);
		}

		KASSERT(toep->tx_credits >= credits,
			("%s: not enough credits", __func__));

		toep->tx_credits -= credits;
#if 0
		toep->tx_nocompl += credits;
		toep->plen_nocompl += plen;
		if (toep->tx_credits <= toep->tx_total * 3 / 8 &&
		    toep->tx_nocompl >= toep->tx_total / 4)
			compl = 1;

		if (compl || toep->ulp_mode == ULP_MODE_RDMA) {
			txwr->op_to_immdlen |= htobe32(F_FW_WR_COMPL);
			toep->tx_nocompl = 0;
			toep->plen_nocompl = 0;
		}
#endif

		tp->snd_nxt += plen;
		tp->snd_max += plen;

		SOCKBUF_LOCK(sb);
		sbsndptr(sb, tls_ofld->sb_off, plen, &sndptroff);
		tls_ofld->sb_off += plen;
		SOCKBUF_UNLOCK(sb);

		toep->flags |= TPF_TX_DATA_SENT;
		if (toep->tx_credits < MIN_OFLD_TLSTX_CREDITS(toep))
			toep->flags |= TPF_TX_SUSPENDED;

		KASSERT(toep->txsd_avail > 0, ("%s: no txsd", __func__));
		txsd->plen = plen;
		txsd->tx_credits = credits;
		txsd->iv_buffer = iv_buffer;
		txsd++;
		if (__predict_false(++toep->txsd_pidx == toep->txsd_total)) {
			toep->txsd_pidx = 0;
			txsd = &toep->txsd[0];
		}
		toep->txsd_avail--;

		t4_l2t_send(sc, wr, toep->l2te);
	}
}
#endif	/* TCP_OFFLOAD */
