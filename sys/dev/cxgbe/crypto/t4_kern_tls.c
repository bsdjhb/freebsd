/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Chelsio Communications, Inc.
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

#include "opt_kern_tls.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#ifdef KERN_TLS
#include <sys/protosw.h>
#include <sys/sglist.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockbuf.h>
#include <sys/sockbuf_tls.h>
#endif
#include <sys/systm.h>
#ifdef KERN_TLS
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp_var.h>
#include <opencrypto/cryptodev.h>
#include <opencrypto/xform.h>

#include "common/common.h"
#include "common/t4_regs.h"
#include "common/t4_regs_values.h"
#include "common/t4_tcb.h"
#include "t4_l2t.h"
#include "t4_clip.h"
#include "t4_mp_ring.h"
#include "crypto/t4_crypto.h"

#define SALT_SIZE		4

#define GCM_TAG_SIZE			16
#define AEAD_EXPLICIT_DATA_SIZE		8
#define TLS_HEADER_LENGTH		5

#define	TLS_KEY_CONTEXT_SZ	roundup2(sizeof(struct tls_keyctx), 32)

struct tls_scmd {
	__be32 seqno_numivs;
	__be32 ivgen_hdrlen;
};

struct tls_key_req {
	/* FW_ULPTX_WR */
	__be32 wr_hi;
	__be32 wr_mid;
        __be32 ftid;
        __u8   reneg_to_write_rx;
        __u8   protocol;
        __be16 mfs;
	/* master command */
	__be32 cmd;
	__be32 len16;             /* command length */
	__be32 dlen;              /* data length in 32-byte units */
	__be32 kaddr;
	/* sub-command */
	__be32 sc_more;
	__be32 sc_len;
}__packed;

struct tls_keyctx {
	struct tx_keyctx_hdr {
		__u8   ctxlen;
		__u8   r2;
		__be16 dualck_to_txvalid;
		__u8   txsalt[4];
		__be64 r5;
	} txhdr;
        struct keys {
                __u8   edkey[32];
                __u8   ipad[64];
                __u8   opad[64];
        } keys;
};

#define S_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT 11
#define M_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT 0x1
#define V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT)
#define G_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT) & \
     M_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT)
#define F_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT \
    V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(1U)

#define S_TLS_KEYCTX_TX_WR_SALT_PRESENT 10
#define M_TLS_KEYCTX_TX_WR_SALT_PRESENT 0x1
#define V_TLS_KEYCTX_TX_WR_SALT_PRESENT(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_SALT_PRESENT)
#define G_TLS_KEYCTX_TX_WR_SALT_PRESENT(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_SALT_PRESENT) & \
     M_TLS_KEYCTX_TX_WR_SALT_PRESENT)
#define F_TLS_KEYCTX_TX_WR_SALT_PRESENT \
    V_TLS_KEYCTX_TX_WR_SALT_PRESENT(1U)

#define S_TLS_KEYCTX_TX_WR_TXCK_SIZE 6
#define M_TLS_KEYCTX_TX_WR_TXCK_SIZE 0xf
#define V_TLS_KEYCTX_TX_WR_TXCK_SIZE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXCK_SIZE)
#define G_TLS_KEYCTX_TX_WR_TXCK_SIZE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXCK_SIZE) & \
     M_TLS_KEYCTX_TX_WR_TXCK_SIZE)

#define S_TLS_KEYCTX_TX_WR_TXMK_SIZE 2
#define M_TLS_KEYCTX_TX_WR_TXMK_SIZE 0xf
#define V_TLS_KEYCTX_TX_WR_TXMK_SIZE(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXMK_SIZE)
#define G_TLS_KEYCTX_TX_WR_TXMK_SIZE(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXMK_SIZE) & \
     M_TLS_KEYCTX_TX_WR_TXMK_SIZE)

#define S_TLS_KEYCTX_TX_WR_TXVALID   0
#define M_TLS_KEYCTX_TX_WR_TXVALID   0x1
#define V_TLS_KEYCTX_TX_WR_TXVALID(x) \
    ((x) << S_TLS_KEYCTX_TX_WR_TXVALID)
#define G_TLS_KEYCTX_TX_WR_TXVALID(x) \
    (((x) >> S_TLS_KEYCTX_TX_WR_TXVALID) & M_TLS_KEYCTX_TX_WR_TXVALID)
#define F_TLS_KEYCTX_TX_WR_TXVALID   V_TLS_KEYCTX_TX_WR_TXVALID(1U)

/* Key Context Programming Operation type */
#define KEY_WRITE_RX			0x1
#define KEY_WRITE_TX			0x2
#define KEY_DELETE_RX			0x4
#define KEY_DELETE_TX			0x8

struct tlspcb {
	struct inpcb *inp;	/* backpointer to host stack's PCB */
	struct vnet *vnet;
	struct vi_info *vi;	/* virtual interface */
	struct sge_wrq *ctrlq;
	struct l2t_entry *l2te;	/* L2 table entry used by this connection */
	struct clip_entry *ce;	/* CLIP table entry used by this tid */
	int tid;		/* Connection identifier */

	bool inline_key;
	int tx_key_addr;
	struct tls_scmd scmd0;
	struct tls_scmd scmd0_short;

	struct tls_keyctx keyctx;

	unsigned char enc_mode;
	unsigned char auth_mode;
	unsigned char hmac_ctrl;
	unsigned char mac_first;
	unsigned char iv_size;

	unsigned int tx_key_info_size;
	unsigned int frag_size;
	unsigned int mac_secret_size;
	unsigned int cipher_secret_size;
	int proto_ver;

	bool open_pending;
};

static struct protosw *tcp_protosw, *tcp6_protosw;

static int sbtls_parse_pkt(struct t6_sbtls_cipher *cipher, struct mbuf *m,
    int *nsegsp, int *len16p);
static int sbtls_write_wr(struct t6_sbtls_cipher *cipher, struct sge_txq *txq,
    void *wr, struct mbuf *m, u_int nsegs, u_int available);

/* XXX: There are similar versions of these two in tom/t4_tls.c. */
static int
get_new_keyid(struct tlspcb *tlsp)
{
	struct adapter *sc = tlsp->vi->pi->adapter;
	vmem_addr_t addr;

	if (vmem_alloc(sc->key_map, TLS_KEY_CONTEXT_SZ, M_NOWAIT | M_FIRSTFIT,
	    &addr) != 0)
		return (-1);

	return (addr);
}

static void
free_keyid(struct tlspcb *tlsp, int keyid)
{
	struct adapter *sc = tlsp->vi->pi->adapter;

	CTR3(KTR_CXGBE, "%s: tid %d key addr %#x", __func__, tlsp->tid, keyid);
	vmem_free(sc->key_map, keyid, TLS_KEY_CONTEXT_SZ);
}

static struct tlspcb *
alloc_tlspcb(struct vi_info *vi, int flags)
{
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	struct tlspcb *tlsp;

	tlsp = malloc(sizeof(*tlsp), M_CXGBE, M_ZERO | flags);
	if (tlsp == NULL)
		return (NULL);

	tlsp->vi = vi;
	tlsp->ctrlq = &sc->sge.ctrlq[pi->port_id];
	tlsp->tid = -1;
	tlsp->tx_key_addr = -1;

	return (tlsp);
}

static void
free_tlspcb(struct tlspcb *tlsp)
{
	struct adapter *sc = tlsp->vi->pi->adapter;

	if (tlsp->l2te)
		t4_l2t_release(tlsp->l2te);
	if (tlsp->tid >= 0)
		release_tid(sc, tlsp->tid, tlsp->ctrlq);
	if (tlsp->ce)
		t4_release_lip(sc, tlsp->ce);
	if (tlsp->tx_key_addr >= 0)
		free_keyid(tlsp, tlsp->tx_key_addr);
	free(tlsp, M_CXGBE);
}

static void
init_sbtls_key_params(struct tlspcb *tlsp, struct tls_so_enable *en,
    struct sbtls_info *tls)
{
	int mac_key_size;

	if (en->tls_vminor == TLS_MINOR_VER_ONE)
		tlsp->proto_ver = SCMD_PROTO_VERSION_TLS_1_1;
	else
		tlsp->proto_ver = SCMD_PROTO_VERSION_TLS_1_2;
	tlsp->cipher_secret_size = en->key_size;
	tlsp->tx_key_info_size = sizeof(struct tx_keyctx_hdr) +
	    tlsp->cipher_secret_size;
	if (en->crypt_algorithm == CRYPTO_AES_NIST_GCM_16) {
		tlsp->auth_mode = SCMD_AUTH_MODE_GHASH;
		tlsp->enc_mode = SCMD_CIPH_MODE_AES_GCM;
		tlsp->iv_size = 4;
		tlsp->mac_first = 0;
		tlsp->hmac_ctrl = SCMD_HMAC_CTRL_NOP;
		tlsp->tx_key_info_size += GMAC_BLOCK_LEN;
	} else {
		switch (en->mac_algorthim) {
		case CRYPTO_SHA1_HMAC:
			mac_key_size = roundup2(SHA1_HASH_LEN, 16);
			tlsp->auth_mode = SCMD_AUTH_MODE_SHA1;
			break;
		case CRYPTO_SHA2_256_HMAC:
			mac_key_size = SHA2_256_HASH_LEN;
			tlsp->auth_mode = SCMD_AUTH_MODE_SHA256;
			break;
		case CRYPTO_SHA2_384_HMAC:
			mac_key_size = SHA2_512_HASH_LEN;
			tlsp->auth_mode = SCMD_AUTH_MODE_SHA512_384;
			break;
		case CRYPTO_SHA2_512_HMAC:
			mac_key_size = SHA2_512_HASH_LEN;
			tlsp->auth_mode = SCMD_AUTH_MODE_SHA512_512;
			break;
		}
		tlsp->enc_mode = SCMD_CIPH_MODE_AES_CBC;
		tlsp->mac_secret_size = en->hmac_key_len;
		tlsp->iv_size = 8; /* for CBC, iv is 16B, unit of 2B */
		tlsp->mac_first = 1;
		tlsp->tx_key_info_size += mac_key_size * 2;
	}

	tlsp->frag_size = tls->sb_params.sb_maxlen;
}

static int
sbtls_act_open_cpl_size(bool isipv6)
{

	if (isipv6)
		return (sizeof(struct cpl_t6_act_open_req6));
	else
		return (sizeof(struct cpl_t6_act_open_req));
}

static void
mk_sbtls_act_open_req(struct adapter *sc, struct vi_info *vi, struct inpcb *inp,
    struct tlspcb *tlsp, int atid, void *dst)
{
	struct tcpcb *tp = intotcpcb(inp);
	struct cpl_t6_act_open_req *cpl6;
	struct cpl_act_open_req *cpl;
	uint64_t options;
	int qid_atid;

	cpl6 = dst;
	cpl = (struct cpl_act_open_req *)cpl6;
	INIT_TP_WR(cpl6, 0);
	qid_atid = V_TID_QID(sc->sge.fwq.abs_id) | V_TID_TID(atid) |
	    V_TID_COOKIE(CPL_COOKIE_KERN_TLS);
	OPCODE_TID(cpl) = htobe32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
		qid_atid));
	inp_4tuple_get(inp, &cpl->local_ip, &cpl->local_port,
	    &cpl->peer_ip, &cpl->peer_port);

	options = F_TCAM_BYPASS | V_ULP_MODE(ULP_MODE_NONE);
	options |= V_SMAC_SEL(vi->smt_idx) | V_TX_CHAN(vi->pi->tx_chan);
	options |= F_NON_OFFLOAD;
	cpl->opt0 = htobe64(options);

	options = V_TX_QUEUE(sc->params.tp.tx_modq[vi->pi->tx_chan]);
	if (tp->t_flags & TF_REQ_TSTMP)
		options |= F_TSTAMPS_EN;
	cpl->opt2 = htobe32(options);
}

static void
mk_sbtls_act_open_req6(struct adapter *sc, struct vi_info *vi,
    struct inpcb *inp, struct tlspcb *tlsp, int atid, void *dst)
{
	struct tcpcb *tp = intotcpcb(inp);
	struct cpl_t6_act_open_req6 *cpl6;
	struct cpl_act_open_req6 *cpl;
	uint64_t options;
	int qid_atid;

	cpl6 = dst;
	cpl = (struct cpl_act_open_req6 *)cpl6;
	INIT_TP_WR(cpl6, 0);
	qid_atid = V_TID_QID(sc->sge.fwq.abs_id) | V_TID_TID(atid) |
	    V_TID_COOKIE(CPL_COOKIE_KERN_TLS);
	OPCODE_TID(cpl) = htobe32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6,
		qid_atid));
	cpl->local_port = inp->inp_lport;
	cpl->local_ip_hi = *(uint64_t *)&inp->in6p_laddr.s6_addr[0];
	cpl->local_ip_lo = *(uint64_t *)&inp->in6p_laddr.s6_addr[8];
	cpl->peer_port = inp->inp_fport;
	cpl->peer_ip_hi = *(uint64_t *)&inp->in6p_faddr.s6_addr[0];
	cpl->peer_ip_lo = *(uint64_t *)&inp->in6p_faddr.s6_addr[8];

	options = F_TCAM_BYPASS | V_ULP_MODE(ULP_MODE_NONE);
	options |= V_SMAC_SEL(vi->smt_idx) | V_TX_CHAN(vi->pi->tx_chan);
	options |= F_NON_OFFLOAD;
	cpl->opt0 = htobe64(options);

	options = V_TX_QUEUE(sc->params.tp.tx_modq[vi->pi->tx_chan]);
	if (tp->t_flags & TF_REQ_TSTMP)
		options |= F_TSTAMPS_EN;
	cpl->opt2 = htobe32(options);
}

static int
send_sbtls_act_open_req(struct adapter *sc, struct vi_info *vi,
    struct socket *so, struct tlspcb *tlsp, int atid)
{
	struct inpcb *inp;
	struct wrqe *wr;
	bool isipv6;

	inp = so->so_pcb;
	tlsp->vnet = so->so_vnet;
	isipv6 = (inp->inp_vflag & INP_IPV6) != 0;

	if (isipv6) {
		tlsp->ce = t4_hold_lip(sc, &inp->in6p_laddr, NULL);
		if (tlsp->ce == NULL)
			return (ENOENT);
	}

	/* XXX: Use start/commit? */
	wr = alloc_wrqe(sbtls_act_open_cpl_size(isipv6), tlsp->ctrlq);
	if (wr == NULL)
		return (ENOMEM);

	if (isipv6)
		mk_sbtls_act_open_req6(sc, vi, inp, tlsp, atid, wrtod(wr));
	else
		mk_sbtls_act_open_req(sc, vi, inp, tlsp, atid, wrtod(wr));

	tlsp->open_pending = true;
	t4_wrq_tx(sc, wr);
	return (0);
};

static int
sbtls_act_open_rpl(struct sge_iq *iq, const struct rss_header *rss,
    struct mbuf *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_act_open_rpl *cpl = (const void *)(rss + 1);
	u_int atid = G_TID_TID(G_AOPEN_ATID(be32toh(cpl->atid_status)));
	u_int status = G_AOPEN_STATUS(be32toh(cpl->atid_status));
	struct tlspcb *tlsp = lookup_atid(sc, atid);
	struct inpcb *inp = tlsp->inp;

	free_atid(sc, atid);
	if (status == 0)
		tlsp->tid = GET_TID(cpl);

	INP_WLOCK(inp);
	tlsp->open_pending = false;
	wakeup(tlsp);
	INP_WUNLOCK(inp);
	return (0);
}

/* SET_TCB_FIELD sent as a ULP command looks like this */
#define LEN__SET_TCB_FIELD_ULP (sizeof(struct ulp_txpkt) + \
    sizeof(struct ulptx_idata) + sizeof(struct cpl_set_tcb_field_core))

_Static_assert((LEN__SET_TCB_FIELD_ULP + sizeof(struct ulptx_idata)) % 16 == 0,
    "CPL_SET_TCB_FIELD ULP command not 16-byte aligned");

static void
write_set_tcb_field_ulp(struct tlspcb *tlsp, void *dst, struct sge_txq *txq,
    uint16_t word, uint64_t mask, uint64_t val)
{
	struct ulp_txpkt *txpkt;
	struct ulptx_idata *idata;
	struct cpl_set_tcb_field_core *cpl;

	/* ULP_TXPKT */
	txpkt = dst;
	txpkt->cmd_dest = htobe32(V_ULPTX_CMD(ULP_TX_PKT) |
	    V_ULP_TXPKT_DATAMODIFY(0) |
	    V_ULP_TXPKT_CHANNELID(tlsp->vi->pi->port_id) | V_ULP_TXPKT_DEST(0) |
	    V_ULP_TXPKT_FID(txq->eq.cntxt_id) | V_ULP_TXPKT_RO(1));
	txpkt->len = htobe32(howmany(LEN__SET_TCB_FIELD_ULP, 16));

	/* ULPTX_IDATA sub-command */
	idata = (struct ulptx_idata *)(txpkt + 1);
	idata->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	idata->len = htobe32(sizeof(*cpl));

	/* CPL_SET_TCB_FIELD */
	cpl = (struct cpl_set_tcb_field_core *)(idata + 1);
	OPCODE_TID(cpl) = htobe32(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tlsp->tid));
	cpl->reply_ctrl = htobe16(F_NO_REPLY);
	cpl->word_cookie = htobe16(V_WORD(word));
	cpl->mask = htobe64(mask);
	cpl->val = htobe64(val);

	/* ULPTX_NOOP */
	idata = (struct ulptx_idata *)(cpl + 1);
	idata->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_NOOP));
	idata->len = htobe32(0);
}

static int
sbtls_set_tcb_fields(struct tlspcb *tlsp, struct tcpcb *tp, struct sge_txq *txq)
{
	struct fw_ulptx_wr *wr;
	struct mbuf *m;
	char *dst;
	void *items[1];
	int error, len;

	len = sizeof(*wr) + 3 * roundup2(LEN__SET_TCB_FIELD_ULP, 16);
	if (tp->t_flags & TF_REQ_TSTMP)
		len += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
	m = alloc_wr_mbuf(len, M_NOWAIT);
	if (m == NULL)
		return (ENOMEM);

	/* FW_ULPTX_WR */
	wr = mtod(m, void *);
	wr->op_to_compl = htobe32(V_FW_WR_OP(FW_ULPTX_WR));
	wr->flowid_len16 = htobe32(F_FW_ULPTX_WR_DATA |
	    V_FW_WR_LEN16(len / 16));
	wr->cookie = 0;
	dst = (char *)(wr + 1);

        /* Clear TF_NON_OFFLOAD and set TF_CORE_BYPASS */
	write_set_tcb_field_ulp(tlsp, dst, txq, W_TCB_T_FLAGS,
	    V_TCB_T_FLAGS(V_TF_CORE_BYPASS(1) | V_TF_NON_OFFLOAD(1)),
	    V_TCB_T_FLAGS(V_TF_CORE_BYPASS(1)));
	dst += roundup2(LEN__SET_TCB_FIELD_ULP, 16);

	/* Clear the SND_UNA_RAW, SND_NXT_RAW, and SND_MAX_RAW offsets. */
	write_set_tcb_field_ulp(tlsp, dst, txq, W_TCB_SND_UNA_RAW,
	    V_TCB_SND_NXT_RAW(M_TCB_SND_NXT_RAW) |
	    V_TCB_SND_UNA_RAW(M_TCB_SND_UNA_RAW),
	    V_TCB_SND_NXT_RAW(0) | V_TCB_SND_UNA_RAW(0));
	dst += roundup2(LEN__SET_TCB_FIELD_ULP, 16);

	write_set_tcb_field_ulp(tlsp, dst, txq, W_TCB_SND_MAX_RAW,
	    V_TCB_SND_MAX_RAW(M_TCB_SND_MAX_RAW), V_TCB_SND_MAX_RAW(0));
	dst += roundup2(LEN__SET_TCB_FIELD_ULP, 16);

	if (tp->t_flags & TF_REQ_TSTMP) {
		write_set_tcb_field_ulp(tlsp, dst, txq, W_TCB_TIMESTAMP_OFFSET,
		    V_TCB_TIMESTAMP_OFFSET(M_TCB_TIMESTAMP_OFFSET),
		    V_TCB_TIMESTAMP_OFFSET(tp->ts_offset >> 28));
		dst += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
	}

	KASSERT(dst - (char *)wr == len, ("%s: length mismatch", __func__));

	items[0] = m;
	error = mp_ring_enqueue(txq->r, items, 1, 1);
	if (error)
		m_free(m);
	return (error);
}

static int
t6_sbtls_try(struct socket *so, struct tls_so_enable *en, int *errorp)
{
	struct t6_sbtls_cipher *cipher;
	struct sbtls_info *tls;
	struct mbuf *key_wr;
	struct tlspcb *tlsp;
	struct adapter *sc;
	struct vi_info *vi;
	struct ifnet *ifp;
	struct rtentry *rt;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct sge_txq *txq;
	int atid, error, keyid, len;

	/* Sanity check values in *en. */
	if (en->key_size != en->crypt_key_len)
		return (EINVAL);
	switch (en->crypt_algorithm) {
#ifdef notyet
	case CRYPTO_AES_CBC:
		/* XXX: Not sure if CBC uses a 4 byte IV for TLS? */
		if (en->iv_len != SALT_SIZE)
			return (EINVAL);
		switch (en->key_size) {
		case 128 / 8:
		case 192 / 8:
		case 256 / 8:
			break;
		default:
			return (EINVAL);
		}
		switch (en->mac_algorthim) {
		case CRYPTO_SHA1_HMAC:
		case CRYPTO_SHA2_256_HMAC:
		case CRYPTO_SHA2_384_HMAC:
		case CRYPTO_SHA2_512_HMAC:
			break;
		default:
			return (EPROTONOSUPPORT);
		}
		break;
#endif
	case CRYPTO_AES_NIST_GCM_16:
		if (en->iv_len != SALT_SIZE)
			return (EINVAL);
		switch (en->key_size) {
		case 128 / 8:
			if (en->mac_algorthim != CRYPTO_AES_128_NIST_GMAC)
				return (EINVAL);
			break;
		case 192 / 8:
			if (en->mac_algorthim != CRYPTO_AES_192_NIST_GMAC)
				return (EINVAL);
			break;
		case 256 / 8:
			if (en->mac_algorthim != CRYPTO_AES_256_NIST_GMAC)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
		break;
	default:
		return (EPROTONOSUPPORT);
	}

	/* Only TLS 1.1 and TLS 1.2 are currently supported. */
	if (en->tls_vmajor != TLS_MAJOR_VER_ONE ||
	    en->tls_vminor < TLS_MINOR_VER_ONE ||
	    en->tls_vminor > TLS_MINOR_VER_TWO)
		return (EPROTONOSUPPORT);

	/*
	 * Perform routing lookup to find ifnet.  Reject if it is not
	 * on a T6 or on a T6 that doesn't support TLS.  Also reject
	 * if it is not using the standard protocol switch (e.g. TOE).
	 */
	if (so->so_proto != tcp_protosw && so->so_proto != tcp6_protosw)
		return (EPROTONOSUPPORT);
	inp = so->so_pcb;
	INP_WLOCK_ASSERT(inp);
	rt = inp->inp_route.ro_rt;
	if (rt == NULL || rt->rt_ifp == NULL)
		return (ENXIO);

	tp = inp->inp_ppcb;
	if (tp->t_flags & TF_REQ_TSTMP) {
		if ((tp->ts_offset & 0xfffffff) != 0)
			return (EINVAL);
	}

	/* XXX: Gross */
	ifp = rt->rt_ifp;
	if (ifp->if_get_counter != cxgbe_get_counter)
		return (ENXIO);
	vi = ifp->if_softc;
	sc = vi->pi->adapter;

	if (!(sc->flags & KERN_TLS_OK) || !sc->tlst.enable)
		return (ENXIO);

	tlsp = alloc_tlspcb(vi, M_NOWAIT);
	if (tlsp == NULL)
		return (ENOMEM);

	key_wr = NULL;
	atid = alloc_atid(sc, tlsp);
	if (atid < 0) {
		error = ENOMEM;
		goto failed;
	}

	if (sc->tlst.inline_keys)
		keyid = -1;
	else
		keyid = get_new_keyid(tlsp);
	if (keyid < 0) {
		CTR2(KTR_CXGBE, "%s: atid %d using immediate key ctx", __func__,
		    atid);
		tlsp->inline_key = true;
	} else {
		tlsp->tx_key_addr = keyid;
		CTR3(KTR_CXGBE, "%s: atid %d allocated TX key addr %#x",
		    __func__,
		    atid, tlsp->tx_key_addr);
	}

	tlsp->inp = inp;
	error = send_sbtls_act_open_req(sc, vi, so, tlsp, atid);
	if (error)
		goto failed;

	/*
	 * Wait for reply to active open.
	 *
	 * XXX: What about rm lock?  Can't sleep while that is held.
	 *
	 * XXX: Probably need to recheck INP validity here and and in
	 * the try loop in sbtls_crypt_tls_enable().
	 */
	CTR2(KTR_CXGBE, "%s: atid %d sent CPL_ACT_OPEN_REQ", __func__,
	    atid);
	while (tlsp->open_pending) {
		/*
		 * XXX: PCATCH?  We would then have to discard the PCB
		 * when the completion CPL arrived.
		 */
		error = rw_sleep(tlsp, &inp->inp_lock, 0, "t6tlsop", 0);
	}

	atid = -1;
	if (tlsp->tid < 0) {
		error = ENOMEM;
		goto failed;
	}

	txq = &sc->sge.txq[vi->first_txq];
	if (inp->inp_flowtype != M_HASHTYPE_NONE)
		txq += ((inp->inp_flowid % (vi->ntxq - vi->rsrv_noflowq)) +
		    vi->rsrv_noflowq);

	error = sbtls_set_tcb_fields(tlsp, tp, txq);
	if (error)
		goto failed;

	/*
	 * Preallocate a work request mbuf to hold the work request
	 * that programs the transmit key.  The work request isn't
	 * populated until the setup_cipher callback since the keys
	 * aren't available yet.  However, if that callback fails the
	 * socket won't fall back to software encryption, so the
	 * allocation is done here where failure can be handled more
	 * gracefully.
	 */
	if (!tlsp->inline_key) {
		len = sizeof(struct tls_key_req) +
		    roundup2(sizeof(struct tls_keyctx), 32);
		key_wr = alloc_wr_mbuf(len, M_NOWAIT);
		if (key_wr == NULL) {
			error = ENOMEM;
			goto failed;
		}
	}

	tls = sbtls_init_sb_tls(so, en, sizeof(struct t6_sbtls_cipher));
	if (tls == NULL) {
		error = ENOMEM;
		goto failed;
	}
	cipher = tls->cipher;
	cipher->parse_pkt = sbtls_parse_pkt;
	cipher->write_tls_wr = sbtls_write_wr;
	cipher->sc = sc;
	cipher->tlsp = tlsp;
	cipher->txq = txq;
	cipher->key_wr = key_wr;
	cipher->using_timestamps = (tp->t_flags & TF_REQ_TSTMP) != 0;

	init_sbtls_key_params(tlsp, en, tls);

	/* The SCMD fields used when encrypting a full TLS record. */
	tlsp->scmd0.seqno_numivs = htobe32(V_SCMD_SEQ_NO_CTRL(3) |
	    V_SCMD_PROTO_VERSION(tlsp->proto_ver) |
	    V_SCMD_ENC_DEC_CTRL(SCMD_ENCDECCTRL_ENCRYPT) |
	    V_SCMD_CIPH_AUTH_SEQ_CTRL((tlsp->mac_first == 0)) |
	    V_SCMD_CIPH_MODE(tlsp->enc_mode) |
	    V_SCMD_AUTH_MODE(tlsp->auth_mode) |
	    V_SCMD_HMAC_CTRL(tlsp->hmac_ctrl) |
	    V_SCMD_IV_SIZE(tlsp->iv_size) | V_SCMD_NUM_IVS(1));

	tlsp->scmd0.ivgen_hdrlen = V_SCMD_IV_GEN_CTRL(0) |
	    V_SCMD_TLS_FRAG_ENABLE(0);
	if (tlsp->inline_key)
		tlsp->scmd0.ivgen_hdrlen |= V_SCMD_KEY_CTX_INLINE(1);
	tlsp->scmd0.ivgen_hdrlen = htobe32(tlsp->scmd0.ivgen_hdrlen);

	/*
	 * The SCMD fields used when encrypting a partial TLS record
	 * (no trailer and possibly a truncated payload).
	 */
	tlsp->scmd0_short.seqno_numivs = V_SCMD_SEQ_NO_CTRL(0) |
	    V_SCMD_PROTO_VERSION(SCMD_PROTO_VERSION_GENERIC) |
	    V_SCMD_ENC_DEC_CTRL(SCMD_ENCDECCTRL_ENCRYPT) |
	    V_SCMD_CIPH_AUTH_SEQ_CTRL((tlsp->mac_first == 0)) |
	    V_SCMD_AUTH_MODE(SCMD_AUTH_MODE_NOP) |
	    V_SCMD_HMAC_CTRL(SCMD_HMAC_CTRL_NOP) |
	    V_SCMD_IV_SIZE(AES_BLOCK_LEN / 2) | V_SCMD_NUM_IVS(0);
	if (tlsp->enc_mode == SCMD_CIPH_MODE_AES_GCM)
		tlsp->scmd0_short.seqno_numivs |=
		    V_SCMD_CIPH_MODE(SCMD_CIPH_MODE_AES_CTR);
	else
		tlsp->scmd0_short.seqno_numivs |=
		    V_SCMD_CIPH_MODE(tlsp->enc_mode);
	tlsp->scmd0_short.seqno_numivs =
	    htobe32(tlsp->scmd0_short.seqno_numivs);

	tlsp->scmd0_short.ivgen_hdrlen = V_SCMD_IV_GEN_CTRL(0) |
	    V_SCMD_TLS_FRAG_ENABLE(0) |
	    V_SCMD_AADIVDROP(1);
	if (tlsp->inline_key)
		tlsp->scmd0_short.ivgen_hdrlen |= V_SCMD_KEY_CTX_INLINE(1);

	/*
	 * XXX: This should move into sbtls_init_sb_tls().  It has to
	 * always be the same values regardless of the cipher backend,
	 * so doing it in the backends just duplicates a lot of code.
	 */
	if (en->crypt_algorithm == CRYPTO_AES_NIST_GCM_16) {
		tls->sb_params.sb_tls_hlen = TLS_HEADER_LENGTH +
		    AEAD_EXPLICIT_DATA_SIZE;
		tls->sb_params.sb_tls_tlen = GCM_TAG_SIZE;
#ifdef notyet
	} else {
		tls->sb_params.sb_tls_hlen = TLS_HEADER_LENGTH +
		    AES_BLOCK_LEN;
		/* XXX: Padding */
		tls->sb_params.sb_tls_tlen = tlsp->mac_secret_size;
		tls->sb_params.sb_tls_bs = AES_BLOCK_LEN;
#endif
	}
	tls->t_type = SBTLS_T_TYPE_CHELSIO;
	so->so_snd.sb_tls_flags |= SB_TLS_IFNET;
	return (0);

failed:
	if (key_wr != NULL)
		m_free(key_wr);
	if (atid >= 0)
		free_atid(sc, atid);
	free_tlspcb(tlsp);
	return (error);
}

/* XXX: Should share this with ccr(4) eventually. */
static void
init_sbtls_gmac_hash(const char *key, int klen, char *ghash)
{
	static char zeroes[GMAC_BLOCK_LEN];
	uint32_t keysched[4 * (RIJNDAEL_MAXNR + 1)];
	int rounds;

	rounds = rijndaelKeySetupEnc(keysched, key, klen);
	rijndaelEncrypt(keysched, rounds, zeroes, ghash);
}

static void
t6_sbtls_setup_cipher(struct sbtls_info *tls, int *error)
{
	struct t6_sbtls_cipher *cipher = tls->cipher;
	struct tlspcb *tlsp = cipher->tlsp;
	int keyid, kwrlen, kctxlen, len;
	struct tls_key_req *kwr;
	struct tls_keyctx *kctx;
	void *items[1], *key;
	struct tx_keyctx_hdr *khdr;
	unsigned int ck_size, mk_size;

	/* INP_WLOCK_ASSERT(inp); */

	/* Load keys into key context. */
	if (tls->sb_params.iv == NULL || tls->sb_params.crypt == NULL) {
		*error = EINVAL;
		return;
	}

	/*
	 * Store the salt and keys in the key context.  For
	 * connections with an inline key, this key context is passed
	 * as immediate data in each work request.  For connections
	 * storing the key in DDR, a work request is used to store a
	 * copy of the key context in DDR.
	 */
	kctx = &tlsp->keyctx;
	khdr = &kctx->txhdr;

	switch (tlsp->cipher_secret_size) {
	case 128 / 8:
		ck_size = CHCR_KEYCTX_CIPHER_KEY_SIZE_128;
		break;
	case 192 / 8:
		ck_size = CHCR_KEYCTX_CIPHER_KEY_SIZE_192;
		break;
	case 256 / 8:
		ck_size = CHCR_KEYCTX_CIPHER_KEY_SIZE_256;
		break;
	default:
		panic("bad key size");
	}
	if (tlsp->enc_mode == SCMD_CIPH_MODE_AES_GCM)
		mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_512;
	else {
		switch (tlsp->auth_mode) {
		case SCMD_AUTH_MODE_SHA1:
			mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_160;
			break;
		case SCMD_AUTH_MODE_SHA256:
			mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_256;
			break;
		case SCMD_AUTH_MODE_SHA512_384:
		case SCMD_AUTH_MODE_SHA512_512:
			mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_512;
			break;
		default:
			panic("bad auth mode");
		}
	}

	khdr->ctxlen = (tlsp->tx_key_info_size >> 4);
	khdr->dualck_to_txvalid = V_TLS_KEYCTX_TX_WR_SALT_PRESENT(1) |
	    V_TLS_KEYCTX_TX_WR_TXCK_SIZE(ck_size) |
	    V_TLS_KEYCTX_TX_WR_TXMK_SIZE(mk_size) |
	    V_TLS_KEYCTX_TX_WR_TXVALID(1);
	if (tlsp->enc_mode != SCMD_CIPH_MODE_AES_GCM)
		khdr->dualck_to_txvalid |= V_TLS_KEYCTX_TX_WR_TXOPAD_PRESENT(1);
	khdr->dualck_to_txvalid = htobe16(khdr->dualck_to_txvalid);
	memcpy(khdr->txsalt, tls->sb_params.iv, SALT_SIZE);
	key = kctx->keys.edkey;
	memcpy(key, tls->sb_params.crypt, tls->sb_params.crypt_key_len);
	if (tlsp->enc_mode == SCMD_CIPH_MODE_AES_GCM) {
		init_sbtls_gmac_hash(tls->sb_params.crypt,
		    tls->sb_params.crypt_key_len * 8,
		    (char *)key + tls->sb_params.crypt_key_len);
#ifdef notyet
	} else {
		/* Generate ipad and opad and append after key. */
		/*
		 * XXX: Probably want to share ccr_init_hmac_digest
		 * here rather than reimplementing.
		 */
#endif
	}

	if (tlsp->inline_key)
		return;

	keyid = tlsp->tx_key_addr;

	/* Populate key work request. */
	kwrlen = sizeof(*kwr);
	kctxlen = roundup2(sizeof(*kctx), 32);
	len = kwrlen + kctxlen;

	MPASS(cipher->key_wr->m_len == len);
	kwr = mtod(cipher->key_wr, void *);
	memset(kwr, 0, len);

	kwr->wr_hi = htobe32(V_FW_WR_OP(FW_ULPTX_WR) |
	    F_FW_WR_ATOMIC);
	kwr->wr_mid = htobe32(V_FW_WR_LEN16(DIV_ROUND_UP(len, 16)));
	kwr->protocol = tlsp->proto_ver;
	kwr->mfs = htons(tlsp->frag_size);
	kwr->reneg_to_write_rx = KEY_WRITE_TX;

	/* master command */
	kwr->cmd = htobe32(V_ULPTX_CMD(ULP_TX_MEM_WRITE) |
	    V_T5_ULP_MEMIO_ORDER(1) | V_T5_ULP_MEMIO_IMM(1));
	kwr->dlen = htobe32(V_ULP_MEMIO_DATA_LEN(kctxlen >> 5));
	kwr->len16 = htobe32((tlsp->tid << 8) |
	    DIV_ROUND_UP(len - sizeof(struct work_request_hdr), 16));
	kwr->kaddr = htobe32(V_ULP_MEMIO_ADDR(keyid >> 5));

	/* sub command */
	kwr->sc_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	kwr->sc_len = htobe32(kctxlen);

	kctx = (struct tls_keyctx *)(kwr + 1);
	memcpy(kctx, &tlsp->keyctx, sizeof(*kctx));

	/*
	 * Place the key work request in the transmit queue.  It
	 * should be sent to the NIC before any TLS packets using this
	 * session.
	 */
	items[0] = cipher->key_wr;
	*error = mp_ring_enqueue(cipher->txq->r, items, 1, 1);
	if (*error == 0) {
		cipher->key_wr = NULL;
		CTR2(KTR_CXGBE, "%s: tid %d sent key WR", __func__, tlsp->tid);
	}
}

static u_int
sbtls_base_wr_size(struct tlspcb *tlsp)
{
	u_int wr_len;

	wr_len = sizeof(struct fw_ulptx_wr);	// 16
	wr_len += sizeof(struct ulp_txpkt);	// 8
	wr_len += sizeof(struct ulptx_idata);	// 8
	wr_len += sizeof(struct cpl_tx_sec_pdu);// 32
	if (tlsp->inline_key)
		wr_len += tlsp->tx_key_info_size;
	else {
		wr_len += sizeof(struct ulptx_sc_memrd);// 8
		wr_len += sizeof(struct ulptx_idata);	// 8
	}
	wr_len += sizeof(struct cpl_tx_data);	// 16
	return (wr_len);
}

/* How many bytes of TCP payload to send for a given TLS record. */
static u_int
sbtls_tcp_payload_length(struct t6_sbtls_cipher *cipher, struct mbuf *m_tls)
{
	struct mbuf_ext_pgs *ext_pgs;
	struct tls_record_layer *hdr;
	u_int plen, mlen;

	MBUF_EXT_PGS_ASSERT(m_tls);
	ext_pgs = (void *)m_tls->m_ext.ext_buf;
	hdr = (void *)ext_pgs->hdr;
	plen = ntohs(hdr->tls_length);

	/*
	 * What range of the TLS record is the mbuf requesting to be
	 * sent.
	 */
	mlen = mtod(m_tls, vm_offset_t) + m_tls->m_len;

	/* Always send complete records. */
	if (mlen == ext_pgs->hdr_len + plen + ext_pgs->trail_len)
		return (mlen);

	/*
	 * If the host stack has asked to send part of the trailer,
	 * trim the length to avoid sending any of the trailer.  There
	 * is no way to send a partial trailer currently.
	 */
	if (mlen > ext_pgs->hdr_len + plen)
		mlen = ext_pgs->hdr_len + plen;

	/*
	 * TODO: For AES-CBC we will want to adjust the ciphertext
	 * length for the block size.
	 */

#ifdef VERBOSE_TRACES
	CTR4(KTR_CXGBE, "%s: tid %d short TLS record (%u vs %u)",
	    __func__, cipher->tlsp->tid, mlen, ext_pgs->hdr_len + plen +
	    ext_pgs->trail_len);
#endif
	return (mlen);
}

/*
 * For a "short" TLS record, determine the offset into the TLS record
 * payload to send.  This offset does not include the TLS header, but
 * a non-zero offset implies that a header will not be sent.
 */
static u_int
sbtls_payload_offset(struct tlspcb *tlsp, struct mbuf *m_tls)
{
	struct mbuf_ext_pgs *ext_pgs;
	struct tls_record_layer *hdr;
	u_int offset, plen;
#ifdef INVARIANTS
	u_int mlen;
#endif

	MBUF_EXT_PGS_ASSERT(m_tls);
	ext_pgs = (void *)m_tls->m_ext.ext_buf;
	hdr = (void *)ext_pgs->hdr;
	plen = ntohs(hdr->tls_length);
#ifdef INVARIANTS
	mlen = mtod(m_tls, vm_offset_t) + m_tls->m_len;
	MPASS(mlen < ext_pgs->hdr_len + plen + ext_pgs->trail_len);
#endif
	if (mtod(m_tls, vm_offset_t) <= ext_pgs->hdr_len)
		return (0);
	if (tlsp->enc_mode == SCMD_CIPH_MODE_AES_GCM) {
		/*
		 * Always send something.  This function is only called
		 * if we aren't sending the tag at all, but if the
		 * request starts in the tag then we are in an odd
		 * state where would effectively send nothing.  Cap
		 * the offset at the last byte of the record payload
		 * to send the last cipher block.
		 */
		offset = min(mtod(m_tls, vm_offset_t) - ext_pgs->hdr_len,
		    plen - 1);
		return (rounddown(offset, AES_BLOCK_LEN));
	}
	return (0);
}

static u_int
sbtls_sgl_size(u_int nsegs)
{
	u_int wr_len;

	/* First segment is part of ulptx_sgl. */
	nsegs--;

	wr_len = sizeof(struct ulptx_sgl);
	wr_len += 8 * ((3 * nsegs) / 2 + (nsegs & 1));
	return (wr_len);
}

static int
sbtls_wr_len(struct t6_sbtls_cipher *cipher, struct mbuf *m, struct mbuf *m_tls,
    int *nsegsp)
{
	struct mbuf_ext_pgs *ext_pgs;
	struct tls_record_layer *hdr;
	u_int imm_len, offset, plen, wr_len, tlen;

	MBUF_EXT_PGS_ASSERT(m_tls);
	ext_pgs = (void *)m_tls->m_ext.ext_buf;

	/*
	 * Determine the size of the TLS record payload to send
	 * excluding header and trailer.
	 */
	tlen = sbtls_tcp_payload_length(cipher, m_tls);
	if (tlen <= ext_pgs->hdr_len) {
		/*
		 * For requests that only want to send the TLS header,
		 * send a tunnelled packet as immediate data.
		 */
		wr_len = sizeof(struct fw_eth_tx_pkt_wr) +
		    sizeof(struct cpl_tx_pkt_core) +
		    roundup2(m->m_len + m_tls->m_len, 16);
		if (wr_len > SGE_MAX_WR_LEN) {
			CTR3(KTR_CXGBE,
		    "%s: tid %d TLS header-only packet too long (len %d)",
			    __func__, cipher->tlsp->tid, m->m_len +
			    m_tls->m_len);
		}

		/* This should always be the last TLS record in a chain. */
		MPASS(m_tls->m_next == NULL);

		/*
		 * XXX: Set a bogus 'nsegs' value to avoid tripping an
		 * assertion in mbuf_nsegs() in t4_sge.c.
		 */
		*nsegsp = 1;
		return (wr_len);
	}

	hdr = (void *)ext_pgs->hdr;
	plen = ext_pgs->hdr_len + ntohs(hdr->tls_length);
	if (tlen < plen) {
		plen = tlen;
		offset = sbtls_payload_offset(cipher->tlsp, m_tls);
	} else
		offset = 0;

	/* Calculate the size of the work request. */
	wr_len = sbtls_base_wr_size(cipher->tlsp);

	/*
	 * Full records and short records with an offset of 0 include
	 * the TLS header as immediate data.  Short records include a
	 * raw AES IV as immediate data.
	 */
	imm_len = 0;
	if (offset == 0)
		imm_len += ext_pgs->hdr_len;
	if (plen == tlen)
		imm_len += AES_BLOCK_LEN;
	wr_len += roundup2(imm_len, 16);

	/* TLS record payload via DSGL. */
	*nsegsp = sglist_count_ext_pgs(ext_pgs, ext_pgs->hdr_len + offset,
	    plen - (ext_pgs->hdr_len + offset));
	wr_len += sbtls_sgl_size(*nsegsp);

	wr_len = roundup2(wr_len, 16);
	return (wr_len);
}

/*
 * See if we have any TCP options requiring a dedicated options-only
 * packet.
 */
static int
sbtls_has_tcp_options(struct tcphdr *tcp)
{
	u_char *cp;
	int cnt, opt, optlen;

	cp = (u_char *)(tcp + 1);
	cnt = tcp->th_off * 4 - sizeof(struct tcphdr);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {
		case TCPOPT_NOP:
		case TCPOPT_TIMESTAMP:
			break;
		default:
			return (1);
		}
	}
	return (0);
}

/*
 * Find the TCP timestamp option.
 */
static void *
sbtls_find_tcp_timestamps(struct tcphdr *tcp)
{
	u_char *cp;
	int cnt, opt, optlen;

	cp = (u_char *)(tcp + 1);
	cnt = tcp->th_off * 4 - sizeof(struct tcphdr);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		if (opt == TCPOPT_TIMESTAMP && optlen == TCPOLEN_TIMESTAMP)
			return (cp + 2);
	}
	return (NULL);
}

static int
sbtls_parse_pkt(struct t6_sbtls_cipher *cipher, struct mbuf *m, int *nsegsp,
    int *len16p)
{
	struct ether_header *eh;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	struct mbuf *m_tls;
	int nsegs;
	u_int wr_len, tot_len;

	/*
	 * Locate headers in initial mbuf.
	 * XXX: This assumes all of the headers are in the initial mbuf.
	 * Could perhaps use m_advance() like parse_pkt() if that turns
	 * out to not be true.
	 */
	M_ASSERTPKTHDR(m);
	if (m->m_len <= sizeof(*eh) + sizeof(*ip)) {
		CTR2(KTR_CXGBE, "%s: tid %d header mbuf too short", __func__,
		    cipher->tlsp->tid);
		return (EINVAL);
	}
	eh = mtod(m, struct ether_header *);
	if (ntohs(eh->ether_type) != ETHERTYPE_IP &&
	    ntohs(eh->ether_type) != ETHERTYPE_IPV6) {
		CTR2(KTR_CXGBE, "%s: tid %d mbuf not ETHERTYPE_IP{,V6}",
		    __func__, cipher->tlsp->tid);
		return (EINVAL);
	}
	m->m_pkthdr.l2hlen = sizeof(*eh);

	/* XXX: Reject unsupported IP options? */
	if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		ip = (struct ip *)(eh + 1);
		if (ip->ip_p != IPPROTO_TCP) {
			CTR2(KTR_CXGBE, "%s: tid %d mbuf not IPPROTO_TCP",
			    __func__, cipher->tlsp->tid);
			return (EINVAL);
		}
		m->m_pkthdr.l3hlen = ip->ip_hl * 4;
	} else {
		ip6 = (struct ip6_hdr *)(eh + 1);
		if (ip6->ip6_nxt != IPPROTO_TCP) {
			CTR3(KTR_CXGBE, "%s: tid %d mbuf not IPPROTO_TCP (%u)",
			    __func__, cipher->tlsp->tid, ip6->ip6_nxt);
			return (EINVAL);
		}
		m->m_pkthdr.l3hlen = sizeof(struct ip6_hdr);
	}
	if (m->m_len < m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen +
	    sizeof(*tcp)) {
		CTR2(KTR_CXGBE, "%s: tid %d header mbuf too short (2)",
		    __func__, cipher->tlsp->tid);
		return (EINVAL);
	}
	tcp = (struct tcphdr *)((char *)(eh + 1) + m->m_pkthdr.l3hlen);
	m->m_pkthdr.l4hlen = tcp->th_off * 4;

	/* Bail if there is TCP payload before the TLS record. */
	if (m->m_len != m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen +
	    m->m_pkthdr.l4hlen) {
		CTR6(KTR_CXGBE,
		    "%s: tid %d header mbuf bad length (%d + %d + %d != %d)",
		    __func__, cipher->tlsp->tid, m->m_pkthdr.l2hlen,
		    m->m_pkthdr.l3hlen, m->m_pkthdr.l4hlen, m->m_len);
		return (EINVAL);
	}

	/* Assume all headers are in 'm' for now. */
	MPASS(m->m_next != NULL);
	MPASS(m->m_next->m_flags & M_NOMAP);

	tot_len = 0;

	/*
	 * Each of the remaining mbufs in the chain should reference a
	 * TLS record.
	 */
	*nsegsp = 0;
	for (m_tls = m->m_next; m_tls != NULL; m_tls = m_tls->m_next) {
		MPASS(m_tls->m_flags & M_NOMAP);

		wr_len = sbtls_wr_len(cipher, m, m_tls, &nsegs);
#ifdef VERBOSE_TRACES
		CTR4(KTR_CXGBE, "%s: tid %d wr_len %d nsegs %d", __func__,
		    cipher->tlsp->tid, wr_len, nsegs);
#endif
		if (wr_len > SGE_MAX_WR_LEN || nsegs > TX_SGL_SEGS)
			return (EFBIG);
		tot_len += roundup2(wr_len, EQ_ESIZE);

		/*
		 * Store 'nsegs' for the first TLS record in the
		 * header mbuf's metadata.
		 */
		if (*nsegsp == 0)
			*nsegsp = nsegs;
	}

	MPASS(tot_len != 0);

	/*
	 * See if we have any TCP options or a FIN requiring a
	 * dedicated packet.
	 *
	 * A FIN packet may need dummy padding bytes in case the FIN
	 * is attached to a "short" TLS record.  The extra bytes can
	 * only be a partial trailer, so allow for a trailer's worth
	 * of bytes.
	 */
	if ((tcp->th_flags & TH_FIN) != 0 || sbtls_has_tcp_options(tcp)) {
		int padding;

		if ((tcp->th_flags & TH_FIN) != 0) {
#if 0
			padding = ext_pgs->trail_len;
#else
			padding = GCM_TAG_SIZE;
#endif
		} else
			padding = 0;
		wr_len = sizeof(struct fw_eth_tx_pkt_wr) +
		    sizeof(struct cpl_tx_pkt_core) +
		    roundup2(m->m_len + padding, 16);
		if (wr_len > SGE_MAX_WR_LEN) {
			CTR3(KTR_CXGBE,
			    "%s: tid %d options-only packet too long (len %d)",
			    __func__, cipher->tlsp->tid, m->m_len);
			return (EINVAL);
		}
		tot_len += roundup2(wr_len, EQ_ESIZE);
	}

	/* Include room for a TP work request to program an L2T entry. */
	tot_len += EQ_ESIZE;

	/*
	 * Include room for a ULPTX work request including up to 5
	 * CPL_SET_TCB_FIELD commands before the first TLS work
	 * request.
	 */
	wr_len = sizeof(struct fw_ulptx_wr) +
	    5 * roundup2(LEN__SET_TCB_FIELD_ULP, 16);

	/*
	 * If timestamps are present, reserve 1 more command for
	 * setting the echoed timestamp.
	 */
	if (cipher->using_timestamps)
		wr_len += roundup2(LEN__SET_TCB_FIELD_ULP, 16);

	tot_len += roundup2(wr_len, EQ_ESIZE);

	*len16p = tot_len / 16;
#ifdef VERBOSE_TRACES
	CTR4(KTR_CXGBE, "%s: tid %d len16 %d nsegs %d", __func__,
	    cipher->tlsp->tid, *len16p, *nsegsp);
#endif
	return (0);
}

/*
 * If the SGL ends on an address that is not 16 byte aligned, this function will
 * add a 0 filled flit at the end.
 */
static void
write_gl_to_buf(struct sglist *gl, caddr_t to)
{
	struct sglist_seg *seg;
	__be64 *flitp;
	struct ulptx_sgl *usgl;
	int i, nflits, nsegs;

	KASSERT(((uintptr_t)to & 0xf) == 0,
	    ("%s: SGL must start at a 16 byte boundary: %p", __func__, to));

	nsegs = gl->sg_nseg;
	MPASS(nsegs > 0);

	nflits = (3 * (nsegs - 1)) / 2 + ((nsegs - 1) & 1) + 2;
	flitp = (__be64 *)to;
	seg = &gl->sg_segs[0];
	usgl = (void *)flitp;

	usgl->cmd_nsge = htobe32(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
	    V_ULPTX_NSGE(nsegs));
	usgl->len0 = htobe32(seg->ss_len);
	usgl->addr0 = htobe64(seg->ss_paddr);
	seg++;

	for (i = 0; i < nsegs - 1; i++, seg++) {
		usgl->sge[i / 2].len[i & 1] = htobe32(seg->ss_len);
		usgl->sge[i / 2].addr[i & 1] = htobe64(seg->ss_paddr);
	}
	if (i & 1)
		usgl->sge[i / 2].len[1] = htobe32(0);
	flitp += nflits;

	if (nflits & 1) {
		MPASS(((uintptr_t)flitp) & 0xf);
		*flitp++ = 0;
	}

	MPASS((((uintptr_t)flitp) & 0xf) == 0);
}

static inline void
copy_to_txd(struct sge_eq *eq, caddr_t from, caddr_t *to, int len)
{

	MPASS((uintptr_t)(*to) >= (uintptr_t)&eq->desc[0]);
	MPASS((uintptr_t)(*to) < (uintptr_t)&eq->desc[eq->sidx]);

	if (__predict_true((uintptr_t)(*to) + len <=
	    (uintptr_t)&eq->desc[eq->sidx])) {
		bcopy(from, *to, len);
		(*to) += len;
		if ((uintptr_t)(*to) == (uintptr_t)&eq->desc[eq->sidx])
			(*to) = (caddr_t)eq->desc;
	} else {
		int portion = (uintptr_t)&eq->desc[eq->sidx] - (uintptr_t)(*to);

		bcopy(from, *to, portion);
		from += portion;
		portion = len - portion;	/* remaining */
		bcopy(from, (void *)eq->desc, portion);
		(*to) = (caddr_t)eq->desc + portion;
	}
}

static int
sbtls_write_tcp_options(struct t6_sbtls_cipher *cipher, struct sge_txq *txq,
    void *dst, struct mbuf *m, u_int available, u_int pidx)
{
	struct tx_sdesc *txsd;
	struct fw_eth_tx_pkt_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	uint32_t ctrl;
	uint64_t ctrl1;
	int len16, ndesc, pktlen;
	struct ether_header *eh;
	struct ip *ip, newip;
	struct ip6_hdr *ip6, newip6;
	struct tcphdr *tcp, newtcp;
	caddr_t out;

	TXQ_LOCK_ASSERT_OWNED(txq);
	M_ASSERTPKTHDR(m);

	wr = dst;
	pktlen = m->m_len;
	ctrl = sizeof(struct cpl_tx_pkt_core) + pktlen;
	len16 = howmany(sizeof(struct fw_eth_tx_pkt_wr) + ctrl, 16);
	ndesc = howmany(len16, EQ_ESIZE / 16);
	MPASS(ndesc <= available);

	/* Firmware work request header */
	wr->op_immdlen = htobe32(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
	    V_FW_ETH_TX_PKT_WR_IMMDLEN(ctrl));

	ctrl = V_FW_WR_LEN16(len16);
	wr->equiq_to_len16 = htobe32(ctrl);
	wr->r3 = 0;

	cpl = (void *)(wr + 1);

	/* Checksum offload */
	ctrl1 = 0;
	txq->txcsum++;

	/* CPL header */
	cpl->ctrl0 = txq->cpl_ctrl0;
	cpl->pack = 0;
	cpl->len = htobe16(pktlen);
	cpl->ctrl1 = htobe64(ctrl1);

	out = (void *)(cpl + 1);

	/* Copy over Ethernet header. */
	eh = mtod(m, struct ether_header *);
	copy_to_txd(&txq->eq, (caddr_t)eh, &out, m->m_pkthdr.l2hlen);

	/* Fixup length in IP header and copy out. */
	if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		ip = (void *)((char *)eh + m->m_pkthdr.l2hlen);
		newip = *ip;
		newip.ip_len = htons(pktlen - m->m_pkthdr.l2hlen);
		copy_to_txd(&txq->eq, (caddr_t)&newip, &out, sizeof(newip));
		if (m->m_pkthdr.l3hlen > sizeof(*ip))
			copy_to_txd(&txq->eq, (caddr_t)(ip + 1), &out,
			    m->m_pkthdr.l3hlen - sizeof(*ip));
	} else {
		ip6 = (void *)((char *)eh + m->m_pkthdr.l2hlen);
		newip6 = *ip6;
		newip6.ip6_plen = htons(pktlen - m->m_pkthdr.l2hlen);
		copy_to_txd(&txq->eq, (caddr_t)&newip6, &out, sizeof(newip6));
		MPASS(m->m_pkthdr.l3hlen == sizeof(*ip6));
	}

	/* Clear PUSH and FIN in the TCP header if present. */
	tcp = (void *)((char *)eh + m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen);
	newtcp = *tcp;
	newtcp.th_flags &= ~(TH_PUSH | TH_FIN);
	copy_to_txd(&txq->eq, (caddr_t)&newtcp, &out, sizeof(newtcp));

	/* Copy rest of packet. */
	copy_to_txd(&txq->eq, (caddr_t)(tcp + 1), &out, pktlen -
	    (m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen + sizeof(*tcp)));
	txq->imm_wrs++;

	txq->txpkt_wrs++;

	txq->kern_tls_options++;

	txsd = &txq->sdesc[pidx];
	txsd->m = NULL;
	txsd->desc_used = ndesc;

	return (ndesc);
}

static void
sbtls_populate_tls_header(struct tlspcb *tlsp, struct mbuf_ext_pgs *ext_pgs,
    void *dst)
{
	struct tls_record_layer *hdr, *inhdr;
	u_int real_tls_hdr_len;

	inhdr = (void *)ext_pgs->hdr;
	real_tls_hdr_len = ext_pgs->hdr_len + ntohs(inhdr->tls_length) +
	    ext_pgs->trail_len - TLS_HEADER_LENGTH;

	hdr = dst;
	hdr->tls_type = inhdr->tls_type;
	hdr->tls_vmajor = inhdr->tls_vmajor;
	hdr->tls_vminor = inhdr->tls_vminor;
	hdr->tls_length = htons(real_tls_hdr_len);
	if (tlsp->enc_mode == SCMD_CIPH_MODE_AES_GCM)
		*(uint64_t *)(hdr + 1) = htobe64(ext_pgs->seqno);
#ifdef notyet
	else
		/* XXX: Have to generate and append IV here. */
		/*
		 * XXX: This is fraught with peril for retransmits as
		 * we need to always use the same IV for the same TLS
		 * record.  Probably for CBC the IV will need to be
		 * generated when the TLS record is created at the
		 * socket layer.
		 */
		XXX;
#endif
}

static int
sbtls_write_tunnel_packet(struct t6_sbtls_cipher *cipher, struct sge_txq *txq,
    void *dst, struct mbuf *m, struct mbuf *m_tls, u_int available,
    tcp_seq tcp_seqno, u_int pidx)
{
	struct tx_sdesc *txsd;
	struct fw_eth_tx_pkt_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	uint32_t ctrl;
	uint64_t ctrl1;
	int len16, ndesc, pktlen;
	struct ether_header *eh;
	struct ip *ip, newip;
	struct ip6_hdr *ip6, newip6;
	struct tcphdr *tcp, newtcp;
	struct mbuf_ext_pgs *ext_pgs;
	caddr_t out;

	TXQ_LOCK_ASSERT_OWNED(txq);
	M_ASSERTPKTHDR(m);

	/* Locate the template TLS header. */
	MBUF_EXT_PGS_ASSERT(m_tls);
	ext_pgs = (void *)m_tls->m_ext.ext_buf;

	/* This should always be the last TLS record in a chain. */
	MPASS(m_tls->m_next == NULL);

	wr = dst;
	pktlen = m->m_len + m_tls->m_len;
	ctrl = sizeof(struct cpl_tx_pkt_core) + pktlen;
	len16 = howmany(sizeof(struct fw_eth_tx_pkt_wr) + ctrl, 16);
	ndesc = howmany(len16, EQ_ESIZE / 16);
	MPASS(ndesc <= available);

	/* Firmware work request header */
	wr->op_immdlen = htobe32(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
	    V_FW_ETH_TX_PKT_WR_IMMDLEN(ctrl));

	ctrl = V_FW_WR_LEN16(len16);
	wr->equiq_to_len16 = htobe32(ctrl);
	wr->r3 = 0;

	cpl = (void *)(wr + 1);

	/* Checksum offload */
	ctrl1 = 0;
	txq->txcsum++;

	/* CPL header */
	cpl->ctrl0 = txq->cpl_ctrl0;
	cpl->pack = 0;
	cpl->len = htobe16(pktlen);
	cpl->ctrl1 = htobe64(ctrl1);

	out = (void *)(cpl + 1);

	/* Copy over Ethernet header. */
	eh = mtod(m, struct ether_header *);
	copy_to_txd(&txq->eq, (caddr_t)eh, &out, m->m_pkthdr.l2hlen);

	/* Fixup length in IP header and copy out. */
	if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		ip = (void *)((char *)eh + m->m_pkthdr.l2hlen);
		newip = *ip;
		newip.ip_len = htons(pktlen - m->m_pkthdr.l2hlen);
		copy_to_txd(&txq->eq, (caddr_t)&newip, &out, sizeof(newip));
		if (m->m_pkthdr.l3hlen > sizeof(*ip))
			copy_to_txd(&txq->eq, (caddr_t)(ip + 1), &out,
			    m->m_pkthdr.l3hlen - sizeof(*ip));
	} else {
		ip6 = (void *)((char *)eh + m->m_pkthdr.l2hlen);
		newip6 = *ip6;
		newip6.ip6_plen = htons(pktlen - m->m_pkthdr.l2hlen);
		copy_to_txd(&txq->eq, (caddr_t)&newip6, &out, sizeof(newip6));
		MPASS(m->m_pkthdr.l3hlen == sizeof(*ip6));
	}

	/* Set sequence number in TCP header. */
	tcp = (void *)((char *)eh + m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen);
	newtcp = *tcp;
	newtcp.th_seq = htonl(tcp_seqno + mtod(m_tls, vm_offset_t));
	copy_to_txd(&txq->eq, (caddr_t)&newtcp, &out, sizeof(newtcp));

	/* Copy rest of TCP header. */
	copy_to_txd(&txq->eq, (caddr_t)(tcp + 1), &out, m->m_len -
	    (m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen + sizeof(*tcp)));

	/* Populate the TLS header in the scratch space. */
	sbtls_populate_tls_header(cipher->tlsp, ext_pgs, txq->ss);

	/* Copy the subset of the TLS header requested. */
	copy_to_txd(&txq->eq, (char *)txq->ss + mtod(m_tls, vm_offset_t), &out,
	    m_tls->m_len);
	txq->imm_wrs++;

	txq->txpkt_wrs++;

#ifdef VERBOSE_TRACES
	CTR3(KTR_CXGBE, "%s: tid %d header-only TLS record %u",
	    __func__, cipher->tlsp->tid, (u_int)ext_pgs->seqno);
#endif
	txq->kern_tls_header++;

	txsd = &txq->sdesc[pidx];
	txsd->m = m;
	txsd->desc_used = ndesc;

	return (ndesc);
}

_Static_assert(sizeof(struct cpl_set_tcb_field) <= EQ_ESIZE,
    "CPL_SET_TCB_FIELD must be smaller than a single TX descriptor");
_Static_assert(W_TCB_SND_UNA_RAW == W_TCB_SND_NXT_RAW,
    "SND_NXT_RAW and SND_UNA_RAW are in different words");

static int
sbtls_write_tls_wr(struct t6_sbtls_cipher *cipher, struct sge_txq *txq,
    void *dst, struct mbuf *m, struct tcphdr *tcp, struct mbuf *m_tls,
    u_int nsegs, u_int available, tcp_seq tcp_seqno, uint32_t *tsopt,
    u_int pidx, bool set_l2t_idx)
{
	struct sge_eq *eq = &txq->eq;
	struct tx_sdesc *txsd;
	struct tlspcb *tlsp;
	struct fw_ulptx_wr *wr;
	struct ulp_txpkt *txpkt;
	struct ulptx_sc_memrd *memrd;
	struct ulptx_idata *idata;
	struct cpl_tx_sec_pdu *sec_pdu;
	struct cpl_tx_data *tx_data;
	struct mbuf_ext_pgs *ext_pgs;
	struct tls_record_layer *hdr;
	char *iv, *out;
	u_int aad_start, aad_stop;
	u_int auth_start, auth_stop, auth_insert;
	u_int cipher_start, cipher_stop, iv_offset;
	u_int imm_len, mss, ndesc, offset, plen, tlen, twr_len, wr_len;
	u_int tx_max, fields;
	bool first_wr, last_wr, using_scratch;

	ndesc = 0;
	tlsp = cipher->tlsp;
	MPASS(cipher->txq == txq);

	first_wr = (cipher->prev_seq == 0 && cipher->prev_ack == 0 &&
	    cipher->prev_win == 0);

	/*
	 * Use the per-txq scratch pad if near the end of the ring to
	 * simplify handling of wrap-around.  This uses a simple but
	 * not quite perfect test of using the scratch buffer if we
	 * can't fit a maximal work request in without wrapping.
	 */
	using_scratch = (eq->sidx - pidx < SGE_MAX_WR_LEN / EQ_ESIZE);

	/* Locate the template TLS header. */
	MBUF_EXT_PGS_ASSERT(m_tls);
	ext_pgs = (void *)m_tls->m_ext.ext_buf;
	hdr = (void *)ext_pgs->hdr;
	plen = ext_pgs->hdr_len + ntohs(hdr->tls_length);

	/* Determine how much of the TLS record to send. */
	tlen = sbtls_tcp_payload_length(cipher, m_tls);
	if (tlen <= ext_pgs->hdr_len) {
		/*
		 * For requests that only want to send the TLS header,
		 * send a tunnelled packet as immediate data.
		 */
		return (sbtls_write_tunnel_packet(cipher, txq, dst, m, m_tls,
		    available, tcp_seqno, pidx));
	}
	if (tlen < plen) {
		plen = tlen;
		offset = sbtls_payload_offset(cipher->tlsp, m_tls);
#ifdef VERBOSE_TRACES
		CTR4(KTR_CXGBE, "%s: tid %d short TLS record %u with offset %u",
		    __func__, cipher->tlsp->tid, (u_int)ext_pgs->seqno, offset);
#endif
	} else
		offset = 0;

	/*
	 * This is the last work request for a given TLS mbuf chain if
	 * it is the last mbuf in the chain and FIN is not set.  If
	 * FIN is set, then sbtls_write_tcp_fin() will write out the
	 * last work request.
	 */
	last_wr = m_tls->m_next == NULL && (tcp->th_flags & TH_FIN) == 0;

	/*
	 * The host stack may ask us to not send part of the start of
	 * a TLS record.  (For example, the stack might have
	 * previously sent a "short" TLS record and might later send
	 * down an mbuf that requests to send the remainder of the TLS
	 * record.)  The crypto engine must process a TLS record from
	 * the beginning if computing a GCM tag or HMAC, so we always
	 * send the TLS record from the beginning as input to the
	 * crypto engine and via CPL_TX_DATA to TP.  However, TP will
	 * drop individual packets after they have been chopped up
	 * into MSS-sized chunks if the entire sequence range of those
	 * packets is less than SND_UNA.  SND_UNA is computed as
	 * TX_MAX - SND_UNA_RAW.  Thus, use the offset stored in
	 * m_data to set TX_MAX to the first byte in the TCP sequence
	 * space the host actually wants us to send and set
	 * SND_UNA_RAW to 0.
	 *
	 * If the host sends us back to back requests that span the
	 * trailer of a single TLS record (first request ends "in" the
	 * trailer and second request starts at the next byte but
	 * still "in" the trailer), the initial bytes of the trailer
	 * that the first request drops will not be retransmitted.  If
	 * the host uses the same requests when retransmitting the
	 * connection will hang.  To handle this, always transmit the
	 * full trailer for a request that begins "in" the trailer
	 * (the second request in the example above).  This should
	 * also help to avoid retransmits for the common case.
	 */
	tx_max = tcp_seqno + min(mtod(m_tls, vm_offset_t),
	    ext_pgs->hdr_len + ntohs(hdr->tls_length));

	/*
	 * Update TCB fields.  Reserve space for the FW_ULPTX_WR header
	 * but don't populate it until we know how many field updates
	 * are required.
	 */
	if (using_scratch)
		wr = (void *)txq->ss;
	else
		wr = dst;
	out = (void *)(wr + 1);
	fields = 0;
	if (set_l2t_idx) {
		KASSERT(nsegs != 0,
		    ("trying to set L2T_IX for subsequent TLS WR"));
#ifdef VERBOSE_TRACES
		CTR3(KTR_CXGBE, "%s: tid %d set L2T_IX to %d", __func__,
		    tlsp->tid, tlsp->l2te->idx);
#endif
		write_set_tcb_field_ulp(tlsp, out, txq, W_TCB_L2T_IX,
		    V_TCB_L2T_IX(M_TCB_L2T_IX), V_TCB_L2T_IX(tlsp->l2te->idx));
		out += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
		fields++;
	}		
	if (tsopt != NULL && cipher->prev_tsecr != ntohl(tsopt[1])) {
		KASSERT(nsegs != 0,
		    ("trying to set T_RTSEQ_RECENT for subsequent TLS WR"));
#ifdef VERBOSE_TRACES
		CTR2(KTR_CXGBE, "%s: tid %d wrote updated T_RTSEQ_RECENT",
		    __func__, cipher->tlsp->tid);
#endif
		write_set_tcb_field_ulp(tlsp, out, txq, W_TCB_T_RTSEQ_RECENT,
		    V_TCB_T_RTSEQ_RECENT(M_TCB_T_RTSEQ_RECENT),
		    V_TCB_T_RTSEQ_RECENT(ntohl(tsopt[1])));
		out += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
		fields++;

		cipher->prev_tsecr = ntohl(tsopt[1]);
	}

	if (first_wr || cipher->prev_seq != tx_max) {
		KASSERT(nsegs != 0,
		    ("trying to set TX_MAX for subsequent TLS WR"));
#ifdef VERBOSE_TRACES
		CTR4(KTR_CXGBE,
		    "%s: tid %d setting TX_MAX to %u (tcp_seqno %u)",
		    __func__, tlsp->tid, tx_max, tcp_seqno);
#endif
		write_set_tcb_field_ulp(tlsp, out, txq, W_TCB_TX_MAX,
		    V_TCB_TX_MAX(M_TCB_TX_MAX), V_TCB_TX_MAX(tx_max));
		out += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
		fields++;
	}

	/*
	 * If there is data to drop at the beginning of this TLS
	 * record or if this is a retransmit,
	 * reset SND_UNA_RAW to 0 so that SND_UNA == TX_MAX.
	 */
	if (cipher->prev_seq != tx_max || mtod(m_tls, vm_offset_t) != 0) {
		KASSERT(nsegs != 0,
		    ("trying to clear SND_UNA_RAW for subsequent TLS WR"));
#ifdef VERBOSE_TRACES
		CTR2(KTR_CXGBE, "%s: tid %d clearing SND_UNA_RAW", __func__,
		    tlsp->tid);
#endif
		write_set_tcb_field_ulp(tlsp, out, txq, W_TCB_SND_UNA_RAW,
		    V_TCB_SND_UNA_RAW(M_TCB_SND_UNA_RAW),
		    V_TCB_SND_UNA_RAW(0));
		out += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
		fields++;
	}

	/*
	 * Store the expected sequence number of the next byte after
	 * this record.
	 */
	cipher->prev_seq = tcp_seqno + tlen;

	if (first_wr || cipher->prev_ack != ntohl(tcp->th_ack)) {
		KASSERT(nsegs != 0,
		    ("trying to set RCV_NXT for subsequent TLS WR"));
		write_set_tcb_field_ulp(tlsp, out, txq, W_TCB_RCV_NXT,
		    V_TCB_RCV_NXT(M_TCB_RCV_NXT),
		    V_TCB_RCV_NXT(ntohl(tcp->th_ack)));
		out += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
		fields++;

		cipher->prev_ack = ntohl(tcp->th_ack);
	}

	if (first_wr || cipher->prev_win != ntohs(tcp->th_win)) {
		KASSERT(nsegs != 0,
		    ("trying to set RCV_WND for subsequent TLS WR"));
		write_set_tcb_field_ulp(tlsp, out, txq, W_TCB_RCV_WND,
		    V_TCB_RCV_WND(M_TCB_RCV_WND),
		    V_TCB_RCV_WND(ntohs(tcp->th_win)));
		out += roundup2(LEN__SET_TCB_FIELD_ULP, 16);
		fields++;

		cipher->prev_win = ntohs(tcp->th_win);
	}

	/* Recalculate 'nsegs' if cached value is not available. */
	if (nsegs == 0)
		nsegs = sglist_count_ext_pgs(ext_pgs, ext_pgs->hdr_len +
		    offset, plen - (ext_pgs->hdr_len + offset));

	/* Calculate the size of the TLS work request. */
	twr_len = sbtls_base_wr_size(cipher->tlsp);

	imm_len = 0;
	if (offset == 0)
		imm_len += ext_pgs->hdr_len;
	if (plen == tlen)
		imm_len += AES_BLOCK_LEN;
	twr_len += roundup2(imm_len, 16);
	twr_len += sbtls_sgl_size(nsegs);

	/*
	 * If any field updates were required, determine if they can
	 * be included in the TLS work request.  If not, use the
	 * FW_ULPTX_WR work request header at 'wr' as a dedicated work
	 * request for the field updates and start a new work request
	 * for the TLS work request afterward.
	 */
	if (fields != 0) {
		wr_len = fields * roundup2(LEN__SET_TCB_FIELD_ULP, 16);
		if (twr_len + wr_len <= SGE_MAX_WR_LEN &&
		    cipher->sc->tlst.combo_wrs) {
			wr_len += twr_len;
			txpkt = (void *)out;
		} else {
			wr_len += sizeof(*wr);
			wr->op_to_compl = htobe32(V_FW_WR_OP(FW_ULPTX_WR));
			wr->flowid_len16 = htobe32(F_FW_ULPTX_WR_DATA |
			    V_FW_WR_LEN16(wr_len / 16));
			wr->cookie = 0;

			/*
			 * If we were using scratch space, copy the
			 * field updates work request to the ring.
			 */
			if (using_scratch) {
				out = dst;
				copy_to_txd(eq, txq->ss, &out, wr_len);
			}

			ndesc = howmany(wr_len, EQ_ESIZE);
			MPASS(ndesc <= available);

			txq->raw_wrs++;
			txsd = &txq->sdesc[pidx];
			txsd->m = NULL;
			txsd->desc_used = ndesc;
			IDXINCR(pidx, ndesc, eq->sidx);
			dst = &eq->desc[pidx];

			/*
			 * Determine if we should use scratch space
			 * for the TLS work request based on the
			 * available space after advancing pidx for
			 * the field updates work request.
			 */
			wr_len = twr_len;
			using_scratch = (eq->sidx - pidx <
			    howmany(wr_len, EQ_ESIZE));
			if (using_scratch)
				wr = (void *)txq->ss;
			else
				wr = dst;
			txpkt = (void *)(wr + 1);
		}
	} else {
		wr_len = twr_len;
		txpkt = (void *)out;
	}

	wr_len = roundup2(wr_len, 16);
	MPASS(ndesc + howmany(wr_len, EQ_ESIZE) <= available);

	/* FW_ULPTX_WR */
	wr->op_to_compl = htobe32(V_FW_WR_OP(FW_ULPTX_WR));
	wr->flowid_len16 = htobe32(F_FW_ULPTX_WR_DATA |
	    V_FW_WR_LEN16(wr_len / 16));
	wr->cookie = 0;

	/* ULP_TXPKT */
	txpkt->cmd_dest = htobe32(V_ULPTX_CMD(ULP_TX_PKT) |
	    V_ULP_TXPKT_DATAMODIFY(0) |
	    V_ULP_TXPKT_CHANNELID(tlsp->vi->pi->port_id) | V_ULP_TXPKT_DEST(0) |
	    V_ULP_TXPKT_FID(txq->eq.cntxt_id) | V_ULP_TXPKT_RO(1));
	txpkt->len = htobe32(howmany(twr_len - sizeof(*wr), 16));

	/* ULPTX_IDATA sub-command */
	idata = (void *)(txpkt + 1);
	idata->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM) |
	    V_ULP_TX_SC_MORE(1));
	idata->len = sizeof(struct cpl_tx_sec_pdu);

	/*
	 * The key context, CPL_TX_DATA, and immediate data are part
	 * of this ULPTX_IDATA when using an inline key.  When reading
	 * the key from memory, the CPL_TX_DATA and immediate data are
	 * part of a separate ULPTX_IDATA.
	 */
	if (tlsp->inline_key)
		idata->len += tlsp->tx_key_info_size +
		    sizeof(struct cpl_tx_data) + imm_len;
	idata->len = htobe32(idata->len);

	/* CPL_TX_SEC_PDU */
	sec_pdu = (void *)(idata + 1);

	/*
	 * For short records, AAD is counted as header data in SCMD0,
	 * the IV is next followed by a cipher region for the payload.
	 */
	if (plen == tlen) {
		aad_start = 0;
		aad_stop = 0;
		iv_offset = 1;
		auth_start = 0;
		auth_stop = 0;
		auth_insert = 0;
		cipher_start = AES_BLOCK_LEN + 1;
		cipher_stop = 0;

		sec_pdu->pldlen = htobe32(16 + plen -
		    (ext_pgs->hdr_len + offset));

		/* These two flits are actually a CPL_TLS_TX_SCMD_FMT. */
		sec_pdu->seqno_numivs = tlsp->scmd0_short.seqno_numivs;
		sec_pdu->ivgen_hdrlen = htobe32(
		    tlsp->scmd0_short.ivgen_hdrlen |
		    V_SCMD_HDR_LEN(offset == 0 ? ext_pgs->hdr_len : 0));

		txq->kern_tls_short++;
	} else {
		/*
		 * AAD is TLS header.  IV is after AAD.  The cipher region
		 * starts after the IV.  See comments in ccr_authenc() and
		 * ccr_gmac() in t4_crypto.c regarding cipher and auth
		 * start/stop values.
		 */
		aad_start = 1;
		aad_stop = TLS_HEADER_LENGTH;
		iv_offset = TLS_HEADER_LENGTH + 1;
		cipher_start = ext_pgs->hdr_len + 1;
		if (tlsp->enc_mode == SCMD_CIPH_MODE_AES_GCM) {
			cipher_stop = 0;
			auth_start = cipher_start;
			auth_stop = 0;
			auth_insert = 0;
		} else {
			/* XXX: This might not be quite right due to padding. */
			cipher_stop = 0;
			auth_start = cipher_start;
			auth_stop = cipher_stop;
			auth_insert = 0;
		}

		sec_pdu->pldlen = htobe32(plen);

		/* These two flits are actually a CPL_TLS_TX_SCMD_FMT. */
		sec_pdu->seqno_numivs = tlsp->scmd0.seqno_numivs;
		sec_pdu->ivgen_hdrlen = tlsp->scmd0.ivgen_hdrlen;

		if (mtod(m_tls, vm_offset_t) == 0)
			txq->kern_tls_full++;
		else
			txq->kern_tls_partial++;
	}
	sec_pdu->op_ivinsrtofst = htobe32(
	    V_CPL_TX_SEC_PDU_OPCODE(CPL_TX_SEC_PDU) |
	    V_CPL_TX_SEC_PDU_CPLLEN(2) | V_CPL_TX_SEC_PDU_PLACEHOLDER(0) |
	    V_CPL_TX_SEC_PDU_IVINSRTOFST(iv_offset));
	sec_pdu->aadstart_cipherstop_hi = htobe32(
	    V_CPL_TX_SEC_PDU_AADSTART(aad_start) |
	    V_CPL_TX_SEC_PDU_AADSTOP(aad_stop) |
	    V_CPL_TX_SEC_PDU_CIPHERSTART(cipher_start) |
	    V_CPL_TX_SEC_PDU_CIPHERSTOP_HI(cipher_stop >> 4));
	sec_pdu->cipherstop_lo_authinsert = htobe32(
	    V_CPL_TX_SEC_PDU_CIPHERSTOP_LO(cipher_stop & 0xf) |
	    V_CPL_TX_SEC_PDU_AUTHSTART(auth_start) |
	    V_CPL_TX_SEC_PDU_AUTHSTOP(auth_stop) |
	    V_CPL_TX_SEC_PDU_AUTHINSERT(auth_insert));

	/* XXX: Ok to reuse TLS sequence number? */
	sec_pdu->scmd1 = htobe64(ext_pgs->seqno);

	/* Key context */
	out = (void *)(sec_pdu + 1);
	if (tlsp->inline_key) {
		memcpy(out, &tlsp->keyctx, tlsp->tx_key_info_size);
		out += tlsp->tx_key_info_size;
	} else {
		/* ULPTX_SC_MEMRD to read key context. */
		memrd = (void *)out;
		memrd->cmd_to_len = htobe32(V_ULPTX_CMD(ULP_TX_SC_MEMRD) |
		    V_ULP_TX_SC_MORE(1) |
		    V_ULPTX_LEN16(tlsp->tx_key_info_size >> 4));
		memrd->addr = htobe32(tlsp->tx_key_addr >> 5);

		/* ULPTX_IDATA for CPL_TX_DATA and TLS header. */
		idata = (void *)(memrd + 1);
		idata->cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM) |
		    V_ULP_TX_SC_MORE(1));
		idata->len = htobe32(sizeof(struct cpl_tx_data) + imm_len);

		out = (void *)(idata + 1);
	}

	/* CPL_TX_DATA */
	tx_data = (void *)out;
	OPCODE_TID(tx_data) = htonl(MK_OPCODE_TID(CPL_TX_DATA, tlsp->tid));
	if (m->m_pkthdr.csum_flags & CSUM_TSO) {
		mss = m->m_pkthdr.tso_segsz;
		cipher->prev_mss = mss;
	} else if (cipher->prev_mss != 0)
		mss = cipher->prev_mss;
	else
		mss = tlsp->vi->ifp->if_mtu -
		    (m->m_pkthdr.l3hlen + m->m_pkthdr.l4hlen);
	if (offset == 0) {
		tx_data->len = htobe32(V_TX_DATA_MSS(mss) | V_TX_LENGTH(tlen));
		tx_data->rsvd = htobe32(tcp_seqno);
	} else {
		tx_data->len = htobe32(V_TX_DATA_MSS(mss) |
		    V_TX_LENGTH(tlen - (ext_pgs->hdr_len + offset)));
		tx_data->rsvd = htobe32(tcp_seqno + ext_pgs->hdr_len + offset);
	}
	tx_data->flags = htobe32(F_TX_BYPASS);
	if (last_wr && tcp->th_flags & TH_PUSH)
		tx_data->flags |= htobe32(F_TX_PUSH | F_TX_SHOVE);

	/* Populate the TLS header */
	out = (void *)(tx_data + 1);
	if (offset == 0) {
		sbtls_populate_tls_header(tlsp, ext_pgs, out);
		out += ext_pgs->hdr_len;
	}

	/* AES IV for a short record. */
	if (plen == tlen) {
		iv = out;
		if (tlsp->enc_mode == SCMD_CIPH_MODE_AES_GCM) {
			memcpy(iv, tlsp->keyctx.txhdr.txsalt, SALT_SIZE);
			*(uint64_t *)(iv + 4) = htobe64(ext_pgs->seqno);
			*(uint32_t *)(iv + 12) = htobe32(2 +
			    offset / AES_BLOCK_LEN);
		}
#ifdef notyet
		else
			XXX;
#endif
		out += AES_BLOCK_LEN;
	}

	/* Skip over padding to a 16-byte boundary. */
	if (imm_len % 16 != 0)
		out += 16 - (imm_len % 16);

	/* SGL for record payload */
	sglist_reset(txq->gl);
	if (sglist_append_ext_pgs(txq->gl, ext_pgs, ext_pgs->hdr_len + offset,
	    plen - (ext_pgs->hdr_len + offset)) != 0) {
#ifdef INVARIANTS
		panic("%s: failed to append sglist", __func__);
#endif
	}
	write_gl_to_buf(txq->gl, out);

	if (using_scratch) {
		out = dst;
		copy_to_txd(eq, txq->ss, &out, wr_len);
	}

	ndesc += howmany(wr_len, EQ_ESIZE);
	MPASS(ndesc <= available);
	txq->tls_wrs++;

	txq->kern_tls_records++;
	txq->kern_tls_octets += tlen - mtod(m_tls, vm_offset_t);
	if (mtod(m_tls, vm_offset_t) != 0) {
		if (offset == 0)
			txq->kern_tls_waste += mtod(m_tls, vm_offset_t);
		else
			txq->kern_tls_waste += mtod(m_tls, vm_offset_t) -
			    (ext_pgs->hdr_len + offset);
	}

	txsd = &txq->sdesc[pidx];
	if (last_wr)
		txsd->m = m;
	else
		txsd->m = NULL;
	txsd->desc_used = howmany(wr_len, EQ_ESIZE);

	return (ndesc);
}

static int
sbtls_write_tcp_fin(struct t6_sbtls_cipher *cipher, struct sge_txq *txq,
    void *dst, struct mbuf *m, u_int available, tcp_seq tcp_seqno,
    u_int padding, u_int pidx)
{
	struct tx_sdesc *txsd;
	struct fw_eth_tx_pkt_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	uint32_t ctrl;
	uint64_t ctrl1;
	int len16, ndesc, pktlen;
	struct ether_header *eh;
	struct ip *ip, newip;
	struct ip6_hdr *ip6, newip6;
	struct tcphdr *tcp, newtcp;
	caddr_t out;
	static char padding_bytes[GCM_TAG_SIZE];

	TXQ_LOCK_ASSERT_OWNED(txq);
	M_ASSERTPKTHDR(m);

	wr = dst;
	pktlen = m->m_len + padding;
	ctrl = sizeof(struct cpl_tx_pkt_core) + pktlen;
	len16 = howmany(sizeof(struct fw_eth_tx_pkt_wr) + ctrl, 16);
	ndesc = howmany(len16, EQ_ESIZE / 16);
	MPASS(ndesc <= available);

	/* Firmware work request header */
	wr->op_immdlen = htobe32(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
	    V_FW_ETH_TX_PKT_WR_IMMDLEN(ctrl));

	ctrl = V_FW_WR_LEN16(len16);
	wr->equiq_to_len16 = htobe32(ctrl);
	wr->r3 = 0;

	cpl = (void *)(wr + 1);

	/* Checksum offload */
	ctrl1 = 0;
	txq->txcsum++;

	/* CPL header */
	cpl->ctrl0 = txq->cpl_ctrl0;
	cpl->pack = 0;
	cpl->len = htobe16(pktlen);
	cpl->ctrl1 = htobe64(ctrl1);

	out = (void *)(cpl + 1);

	/* Copy over Ethernet header. */
	eh = mtod(m, struct ether_header *);
	copy_to_txd(&txq->eq, (caddr_t)eh, &out, m->m_pkthdr.l2hlen);

	/* Fixup length in IP header and copy out. */
	if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
		ip = (void *)((char *)eh + m->m_pkthdr.l2hlen);
		newip = *ip;
		newip.ip_len = htons(pktlen - m->m_pkthdr.l2hlen);
		copy_to_txd(&txq->eq, (caddr_t)&newip, &out, sizeof(newip));
		if (m->m_pkthdr.l3hlen > sizeof(*ip))
			copy_to_txd(&txq->eq, (caddr_t)(ip + 1), &out,
			    m->m_pkthdr.l3hlen - sizeof(*ip));
	} else {
		ip6 = (void *)((char *)eh + m->m_pkthdr.l2hlen);
		newip6 = *ip6;
		newip6.ip6_plen = htons(pktlen - m->m_pkthdr.l2hlen);
		copy_to_txd(&txq->eq, (caddr_t)&newip6, &out, sizeof(newip6));
		MPASS(m->m_pkthdr.l3hlen == sizeof(*ip6));
	}

	/* Set sequence number in TCP header. */
	tcp = (void *)((char *)eh + m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen);
	newtcp = *tcp;
	newtcp.th_seq = htonl(tcp_seqno);
	copy_to_txd(&txq->eq, (caddr_t)&newtcp, &out, sizeof(newtcp));

	/* Copy rest of packet. */
	copy_to_txd(&txq->eq, (caddr_t)(tcp + 1), &out, m->m_len -
	    (m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen + sizeof(*tcp)));

	/* Append padding bytes. */
	KASSERT(padding <= sizeof(padding_bytes),
	    ("padding too long: %u vs %zu", padding, sizeof(padding_bytes)));
	copy_to_txd(&txq->eq, padding_bytes, &out, padding);

	txq->imm_wrs++;

	txq->txpkt_wrs++;

	if (padding != 0)
		txq->kern_tls_fin_short++;
	else
		txq->kern_tls_fin++;

	txsd = &txq->sdesc[pidx];
	txsd->m = m;
	txsd->desc_used = ndesc;

	return (ndesc);
}

static int
sbtls_write_wr(struct t6_sbtls_cipher *cipher, struct sge_txq *txq, void *dst,
    struct mbuf *m, u_int nsegs, u_int available)
{
	struct sge_eq *eq = &txq->eq;
	struct tx_sdesc *txsd;
	struct tlspcb *tlsp;
	struct tcphdr *tcp;
	struct mbuf *m_tls;
	struct ether_header *eh;
	tcp_seq tcp_seqno, fin_seqno;
	u_int ndesc, pidx, totdesc;
	bool set_l2t_idx;
	void *tsopt;

	totdesc = 0;
	eh = mtod(m, struct ether_header *);
	tcp = (struct tcphdr *)((char *)eh + m->m_pkthdr.l2hlen +
	    m->m_pkthdr.l3hlen);
	pidx = eq->pidx;
	tlsp = cipher->tlsp;
	fin_seqno = 0;

	/*
	 * If this TLS record has a FIN, then we will send any
	 * requested options as part of the FIN packet.
	 */
	if ((tcp->th_flags & TH_FIN) == 0 && sbtls_has_tcp_options(tcp)) {
		ndesc = sbtls_write_tcp_options(cipher, txq, dst, m, available,
		    pidx);
		totdesc += ndesc;
		IDXINCR(pidx, ndesc, eq->sidx);
		dst = &eq->desc[pidx];
#ifdef VERBOSE_TRACES
		CTR2(KTR_CXGBE, "%s: tid %d wrote TCP options packet", __func__,
		    tlsp->tid);
#endif
	}

	/*
	 * Allocate a new L2T entry if necessary.  This may write out
	 * a work request to the txq.
	 */
	set_l2t_idx = false;
	if (tlsp->l2te == NULL ||
	    memcmp(tlsp->l2te->dmac, eh->ether_dhost, ETHER_ADDR_LEN) != 0) {
		set_l2t_idx = true;
		if (tlsp->l2te)
			t4_l2t_release(tlsp->l2te);
		tlsp->l2te = t4_l2t_alloc_tls(cipher->sc, txq, dst, &ndesc,
		    0, tlsp->vi->pi->lport, eh->ether_dhost);
		if (tlsp->l2te == NULL)
			CXGBE_UNIMPLEMENTED("failed to allocate TLS L2TE");
		if (ndesc != 0) {
			MPASS(ndesc <= available - totdesc);

			txq->raw_wrs++;
			txsd = &txq->sdesc[pidx];
			txsd->m = NULL;
			txsd->desc_used = ndesc;
			totdesc += ndesc;
			IDXINCR(pidx, ndesc, eq->sidx);
			dst = &eq->desc[pidx];
		}
	}

	/*
	 * Iterate over each TLS record constructing a work request
	 * for that record.
	 */
	for (m_tls = m->m_next; m_tls != NULL; m_tls = m_tls->m_next) {
		MPASS(m_tls->m_flags & M_NOMAP);

		/*
		 * Determine the initial TCP sequence number for this
		 * record.
		 */
		tsopt = NULL;
		if (m_tls == m->m_next) {
			tcp_seqno = ntohl(tcp->th_seq) -
			    mtod(m_tls, vm_offset_t);
			if (cipher->using_timestamps)
				tsopt = sbtls_find_tcp_timestamps(tcp);
		} else {
			MPASS(mtod(m_tls, vm_offset_t) == 0);
			tcp_seqno = cipher->prev_seq;
		}

		ndesc = sbtls_write_tls_wr(cipher, txq, dst, m, tcp, m_tls,
		    nsegs, available - totdesc, tcp_seqno, tsopt, pidx,
		    set_l2t_idx);
		totdesc += ndesc;
		IDXINCR(pidx, ndesc, eq->sidx);
		dst = &eq->desc[pidx];

		/*
		 * The value of nsegs from the header mbuf's metadata
		 * is only valid for the first TLS record.
		 */
		nsegs = 0;

		/* Only need to set the L2T index once. */
		set_l2t_idx = false;

		/*
		 * Compute the sequence number of a FIN following this
		 * mbuf.  This could be conditional on m_tls->m_next
		 * being NULL, but the extra branch is probably more
		 * work than just doing the math always.
		 */
		fin_seqno = tcp_seqno + m_tls->m_len;
	}

	if (tcp->th_flags & TH_FIN) {
		/*
		 * If the TCP header for this chain has FIN sent, then
		 * explicitly send a packet that has FIN set.  This
		 * will also have PUSH set if requested.  This assumes
		 * we sent at least one TLS record work request and
		 * uses the TCP sequence number after that reqeust as
		 * the seqeuence number for the FIN packet.  If the
		 * last TLS record work request was for a short
		 * request, then we need to send dummy bytes for the
		 * partial TLS trailer.  In that case, fin_seqno will
		 * be the sequence number of the FIN itself and
		 * fin_seqno - cipher->prev_seq gives the number of
		 * dummy bytes required.
		 */
		ndesc = sbtls_write_tcp_fin(cipher, txq, dst, m, available,
		    cipher->prev_seq, fin_seqno - cipher->prev_seq, pidx);
		totdesc += ndesc;
	}

	MPASS(totdesc <= available);
	return (totdesc);
}

static void
t6_sbtls_clean_cipher(struct sbtls_info *tls, void *cipher_arg)
{
	struct t6_sbtls_cipher *cipher;
	struct adapter *sc;
	struct tlspcb *tlsp;

	cipher = cipher_arg;
	sc = cipher->sc;
	tlsp = cipher->tlsp;

	CTR2(KTR_CXGBE, "%s: tid %d", __func__, tlsp->tid);

	explicit_bzero(&tlsp->keyctx, sizeof(&tlsp->keyctx));

	if (cipher->key_wr != NULL)
		m_free(cipher->key_wr);
	free_tlspcb(tlsp);
}

struct sbtls_crypto_backend t6tls_backend = {
	.name = "Chelsio T6",
	.prio = 30,
	.api_version = SBTLS_API_VERSION,
	.try = t6_sbtls_try,
	.setup_cipher = t6_sbtls_setup_cipher,
	.clean_cipher = t6_sbtls_clean_cipher
};

static void
t6_sbtls_proto_init(void *dummy __unused)
{

	tcp_protosw = pffindproto(PF_INET, IPPROTO_TCP, SOCK_STREAM);
	tcp6_protosw = pffindproto(PF_INET6, IPPROTO_TCP, SOCK_STREAM);
}
SYSINIT(t6_sbtls, SI_SUB_PROTO_END, SI_ORDER_ANY, t6_sbtls_proto_init, NULL);

static int
t6_sbtls_mod_load(void)
{
	int error;

	error = sbtls_crypto_backend_register(&t6tls_backend);
	if (error)
		return (error);
	t4_register_shared_cpl_handler(CPL_ACT_OPEN_RPL, sbtls_act_open_rpl,
	    CPL_COOKIE_KERN_TLS);
	return (error);
}

static int
t6_sbtls_mod_unload(void)
{
	int error;

	error = sbtls_crypto_backend_deregister(&t6tls_backend);
	if (error)
		return (error);
	t4_register_shared_cpl_handler(CPL_ACT_OPEN_RPL, NULL,
	    CPL_COOKIE_KERN_TLS);
	return (error);
}
#endif

static int
t6_sbtls_modevent(module_t mod, int cmd, void *arg)
{
	int error;

#ifdef KERN_TLS
	switch (cmd) {
	case MOD_LOAD:
		error = t6_sbtls_mod_load();
		break;
	case MOD_UNLOAD:
		error = t6_sbtls_mod_unload();
		break;
	default:
		error = EOPNOTSUPP;
	}
#else
	printf("t4_kern_tls: compiled without KERN_TLS support.\n");
	error = EOPNOTSUPP;
#endif
	return (error);
}

static moduledata_t t6_sbtls_moddata = {
	"t6_sbtls",
	t6_sbtls_modevent,
	0
};

MODULE_VERSION(t6_sbtls, 1);
MODULE_DEPEND(t6_sbtls, t6nex, 1, 1, 1);
DECLARE_MODULE(t6_sbtls, t6_sbtls_moddata, SI_SUB_EXEC, SI_ORDER_ANY);
