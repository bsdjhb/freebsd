/*-
 * Copyright (c) 2017 Chelsio Communications, Inc.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/module.h>
#include <sys/sglist.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/xform.h>

#include "cryptodev_if.h"

#include "common/common.h"
#include "t4_crypto.h"

/*
 * Requests consist of:
 *
 * +-------------------------------+
 * | struct fw_crypto_lookaside_wr |
 * +-------------------------------+
 * | struct ulp_txpkt              |
 * +-------------------------------+
 * | struct ulptx_idata            |
 * +-------------------------------+
 * | struct cpl_tx_sec_pdu         |
 * +-------------------------------+
 * | struct cpl_tls_tx_scmd_fmt    |
 * +-------------------------------+
 * | key context                   |
 * +-------------------------------+ -
 * | struct cpl_rx_phys_dsgl       |  \
 * +-------------------------------+  +---- Destination buffer for
 * | PHYS_DSGL entries             |  /     non-hash-only requests
 * +-------------------------------+ -
 * | 16 dummy bytes                |  ----- Only for hash-only requests
 * +-------------------------------+
 * | IV                            |  ----- If immediate IV
 * +-------------------------------+
 * | Payload                       |  ----- If immediate Payload
 * +-------------------------------+ -
 * | struct ulptx_sgl              |  \
 * +-------------------------------+  +---- If payload via SGL
 * | SGL entries                   |  /
 * +-------------------------------+ -
 *
 * Note that the key context must be padded to ensure 16-byte alignment.
 * For HMAC requests, the key consists of the partial hash of the IPAD
 * followed by the partial hash of the OPAD.
 *
 * Replies consist of:
 *
 * +-------------------------------+
 * | struct cpl_fw6_pld            |
 * +-------------------------------+
 * | hash digest                   |  ----- Only for hash-only requests
 * +-------------------------------+
 * 
 * A 32-bit big-endian error status word is supplied in the last 4
 * bytes of data[0] in the CPL_FW6_PLD message.  bit 0 indicates a
 * "MAC" error and bit 1 indicates a "PAD" error.
 *
 * The 64-bit 'cookie' field from the fw_crypto_lookaside_wr message
 * in the request is returned in data[1] of the CPL_FW6_PLD message.
 *
 * For block cipher replies, the updated IV is supplied in data[2] and
 * data[3] of the CPL_FW6_PLD message.
 *
 * For hash replies, the hash digest is supplied immediately following
 * the CPL_FW6_PLD message.
 */

/*
 * The documentation for CPL_RX_PHYS_DSGL claims a maximum of 32
 * SG entries.
 */
#define	MAX_RX_PHYS_DSGL_SGE	32

static MALLOC_DEFINE(M_CCR, "ccr", "Chelsio T6 crypto");

struct ccr_session_hmac {
	struct auth_hash *auth_hash;
	int hash_len;
	unsigned int partial_digest_len;
	unsigned int auth_mode;
	unsigned int mk_size;
	char ipad[CHCR_HASH_MAX_BLOCK_SIZE_128];
	char opad[CHCR_HASH_MAX_BLOCK_SIZE_128];
};

struct ccr_session_blkcipher {
	unsigned int cipher_mode;
	unsigned int key_len;
	unsigned int iv_len;
	__be32 key_ctx_hdr; 
	char enckey[CHCR_AES_MAX_KEY_LEN];
	char deckey[CHCR_AES_MAX_KEY_LEN];
};

struct ccr_session {
	bool active;
	int pending;
	enum { HMAC, BLKCIPHER, AUTHENC } mode;
	struct ccr_session_hmac hmac;
	struct ccr_session_blkcipher blkcipher;
};

struct ccr_softc {
	struct adapter *adapter;
	device_t dev;
	uint32_t cid;
	int tx_channel_id;
	struct ccr_session *sessions;
	int nsessions;
	struct mtx lock;
	bool detaching;
	struct sge_wrq *ofld_txq;
	struct sge_ofld_rxq *ofld_rxq;
	struct sglist *sg;
};

/*
 * Crypto requests involve two kind of scatter/gather lists.
 *
 * Non-hash-only requests require a PHYS_DSGL that describes the
 * location to store the results of the encryption or decryption
 * operation.  This SGL uses a different format (PHYS_DSGL) and should
 * exclude the crd_skip bytes at the start of the data.
 *
 * The input payload may either be supplied inline as immediate data,
 * or via a standard ULP_TX SGL.  This SGL may include the crd_skip
 * bytes if they cover an IV needed by the crypto engine.  Otherwise,
 * this SGL should exclude the crd_skip bytes.
 */
static int
ccr_populage_sglist(struct sglist *sg, struct cryptop *crp)
{
	int error;

	sglist_reset(sg);
	if (crp->crp_flags & CRYPTO_F_IMBUF)
		error = sglist_append_mbuf(sg, (struct mbuf *)crp->crp_buf);
	else if (crp->crp_flags & CRYPTO_F_IOV)
		error = sglist_append_uio(sg, (struct uio *)crp->crp_buf);
	else
		error = sglist_append(sg, crp->crp_buf, crp->crp_ilen);
	if (error == 0) {
		for (unsigned i = 0; i < sg->sg_nseg; i++) {
			if (sg->sg_segs[i].ss_len >= 65536) {
				/* XXX */
				printf("CCR: segment too big %#zx\n",
				    sg->sg_segs[i].ss_len);
				error = EFBIG;
				break;
			}
		}
	}
	return (error);
}

static int
ccr_count_sgl(struct sglist *sg, struct cryptodesc *crd, bool honor_skip)
{
	struct sglist_seg *seg;
	size_t seglen;
	int len, nsegs, skip;

	if (honor_skip) {
		skip = crd->crd_skip;
		len = crd->crd_len;
	} else {
		skip = 0;
		len = crd->crd_skip + crd->crd_len;
	}
	MPASS(len != 0);
	seg = &sg->sg_segs[0];
	while (skip >= seg->ss_len) {
		skip -= seg->ss_len;
		seg++;
		KASSERT(seg - sg->sg_segs < sg->sg_nseg,
		    ("crd_skip too long"));
	}
	seglen = seg->ss_len - skip;
	if (seglen >= len)
		return (1);
	nsegs = 1;
	len -= seglen;
	seg++;
	for (;;) {
		KASSERT(seg - sg->sg_segs < sg->sg_nseg,
		    ("crd_len + crd_skip too long"));
		seglen = seg->ss_len;
		nsegs++;
		if (seglen >= len)
			return (nsegs);
		len -= seglen;
		seg++;
	}
}

/* These functions deal with PHYS_DSGL for the reply buffer. */
static inline int
ccr_phys_dsgl_len(int nsegs)
{
	int len;

	len = (nsegs / 8) * sizeof(struct phys_sge_pairs);
	if ((nsegs % 8) != 0) {
		len += sizeof(uint16_t) * 8;
		len += roundup2(nsegs % 8, 2) * sizeof(uint64_t);
	}
	return (len);
}

static void
ccr_write_phys_dsgl(struct ccr_softc *sc, void *dst, struct cryptodesc *crd,
    int nsegs)
{
	struct sglist *sg;
	struct cpl_rx_phys_dsgl *cpl;
	struct phys_sge_pairs *sgl;
	int len, skip;
	size_t seglen;
	u_int i, j;

	sg = sc->sg;
	cpl = dst;
	cpl->op_to_tid = htobe32(V_CPL_RX_PHYS_DSGL_OPCODE(CPL_RX_PHYS_DSGL) |
	    V_CPL_RX_PHYS_DSGL_ISRDMA(0));
	cpl->pcirlxorder_to_noofsgentr = htobe32(
	    V_CPL_RX_PHYS_DSGL_PCIRLXORDER(0) |
	    V_CPL_RX_PHYS_DSGL_PCINOSNOOP(0) |
	    V_CPL_RX_PHYS_DSGL_PCITPHNTENB(0) | V_CPL_RX_PHYS_DSGL_DCAID(0) |
	    V_CPL_RX_PHYS_DSGL_NOOFSGENTR(nsegs));
	cpl->rss_hdr_int.opcode = CPL_RX_PHYS_ADDR;
	cpl->rss_hdr_int.qid = htobe16(sc->ofld_rxq->iq.abs_id);
	cpl->rss_hdr_int.hash_val = 0;
	sgl = (struct phys_sge_pairs *)(cpl + 1);
	skip = crd->crd_skip;
	len = crd->crd_len;
	j = 0;
	for (i = 0; i < sg->sg_nseg; i++) {
		seglen = sg->sg_segs[i].ss_len;
		if (skip >= seglen) {
			skip -= seglen;
			continue;
		}
		sgl->addr[j] = htobe64(sg->sg_segs[i].ss_paddr + skip);
		if (skip > 0) {
			seglen -= skip;
			skip = 0;
		}
		if (seglen >= len) {
			sgl->len[j] = htobe16(len);
			break;
		}
		sgl->len[j] = htobe16(seglen);
		len -= seglen;
		j++;
		if (j == 8) {
			sgl++;
			j = 0;
		}
	}
}

/* These functions deal with the ULPTX_SGL for input payload. */
static inline int
ccr_ulptx_sgl_len(int nsegs)
{
	u_int n;

	nsegs--; /* first segment is part of ulptx_sgl */
	n = sizeof(struct ulptx_sgl) + 8 * ((3 * nsegs) / 2 + (nsegs & 1));
	return (roundup2(n, 16));
}

static void
ccr_write_ulptx_sgl(struct ccr_softc *sc, int skip, int len, void *dst,
    int nsegs)
{
	struct ulptx_sgl *usgl;
	struct sglist *sg;
	struct sglist_seg *seg;
	size_t seglen;
	int i;

	sg = sc->sg;
	seg = &sg->sg_segs[0];
	usgl = dst;
	usgl->cmd_nsge = htobe32(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
	    V_ULPTX_NSGE(nsegs));
	while (skip >= seg->ss_len) {
		skip -= seg->ss_len;
		seg++;
	}
	seglen = seg->ss_len - skip;
	if (seglen > len)
		seglen = len;
	usgl->len0 = htobe32(seglen);
	usgl->addr0 = htobe64(seg->ss_paddr + skip);
	len -= seglen;
	seg++;
	for (i = 0; len != 0; i++) {
		seglen = seg->ss_len;
		if (seglen > len)
			seglen = len;
		usgl->sge[i / 2].len[i & 1] = htobe32(seglen);
		usgl->sge[i / 2].addr[i & 1] = htobe64(seg->ss_paddr);
		len -= seglen;
		seg++;
	}
}

static void
ccr_populate_wreq(struct ccr_softc *sc, struct chcr_wr *crwr, u_int kctx_len,
    u_int wr_len, uint32_t sid, u_int imm_len, u_int sgl_len, u_int hash_size,
    u_int iv_loc, struct cryptop *crp)
{
	u_int cctx_size;
	
	cctx_size = sizeof(struct _key_ctx) + kctx_len;
	crwr->wreq.op_to_cctx_size = htobe32(
	    V_FW_CRYPTO_LOOKASIDE_WR_OPCODE(FW_CRYPTO_LOOKASIDE_WR) |
	    V_FW_CRYPTO_LOOKASIDE_WR_COMPL(0) |
	    V_FW_CRYPTO_LOOKASIDE_WR_IMM_LEN(imm_len) |
	    V_FW_CRYPTO_LOOKASIDE_WR_CCTX_LOC(1) |
	    V_FW_CRYPTO_LOOKASIDE_WR_CCTX_SIZE(cctx_size >> 4));
	crwr->wreq.len16_pkd = htobe32(
	    V_FW_CRYPTO_LOOKASIDE_WR_LEN16(wr_len / 16));
	crwr->wreq.session_id = htobe32(sid);
	crwr->wreq.rx_chid_to_rx_q_id = htobe32(
	    V_FW_CRYPTO_LOOKASIDE_WR_RX_CHID(sc->tx_channel_id) |
	    V_FW_CRYPTO_LOOKASIDE_WR_LCB(0) |
	    V_FW_CRYPTO_LOOKASIDE_WR_PHASH(0) |
	    V_FW_CRYPTO_LOOKASIDE_WR_IV(iv_loc) |
	    V_FW_CRYPTO_LOOKASIDE_WR_FQIDX(0) |
	    V_FW_CRYPTO_LOOKASIDE_WR_TX_CH(0) |
	    V_FW_CRYPTO_LOOKASIDE_WR_RX_Q_ID(sc->ofld_rxq->iq.abs_id));
	crwr->wreq.key_addr = 0;
	crwr->wreq.pld_size_hash_size = htobe32(
	    V_FW_CRYPTO_LOOKASIDE_WR_PLD_SIZE(sgl_len) |
	    V_FW_CRYPTO_LOOKASIDE_WR_HASH_SIZE(hash_size));
	crwr->wreq.cookie = htobe64((uintptr_t)crp);

	crwr->ulptx.cmd_dest = htobe32(V_ULPTX_CMD(ULP_TX_PKT) |
	    V_ULP_TXPKT_DATAMODIFY(0) |
	    V_ULP_TXPKT_CHANNELID(sc->tx_channel_id) | V_ULP_TXPKT_DEST(0) |
	    V_ULP_TXPKT_FID(0) | V_ULP_TXPKT_RO(1));
	crwr->ulptx.len = htobe32(
	    ((wr_len - sizeof(struct fw_crypto_lookaside_wr)) / 16));

	crwr->sc_imm.cmd_more = htobe32(V_ULPTX_CMD(ULP_TX_SC_IMM) |
	    V_ULP_TX_SC_MORE(imm_len != 0 ? 0 : 1));
	crwr->sc_imm.len = htobe32(wr_len - offsetof(struct chcr_wr, sec_cpl) -
	    sgl_len);
}

#if 1
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>

static void
dump_payload(struct ccr_softc *sc, const void *dst, int sgl_nsegs)
{
	const struct ulptx_sgl *usgl;
	uint64_t addr;
	uint32_t len;
	int i;

	usgl = dst;
	device_printf(sc->dev, "payload:\n");
	for (i = 0; i < sgl_nsegs; i++) {
		if (i == 0) {
			addr = usgl->addr0;
			len = usgl->len0;
		} else {
			addr = usgl->sge[(i - 1) / 2].addr[(i - 1) & 1];
			addr = usgl->sge[(i - 1) / 2].addr[(i - 1) & 1];
		}
		addr = be64toh(addr);
		len = be32toh(len);
		printf("SGL[%d]: (%#lx:%#x)\n", i, addr, len);
		hexdump((void *)PHYS_TO_DMAP(addr), len, NULL, HD_OMIT_CHARS |
		    HD_OMIT_COUNT);
	}
}
#endif

static int
ccr_hmac(struct ccr_softc *sc, uint32_t sid, struct ccr_session *s,
    struct cryptop *crp)
{
	struct chcr_wr *crwr;
	struct wrqe *wr;
	struct auth_hash *axf;
	struct cryptodesc *crd;
	char *dst;
	u_int hash_size_in_response, kctx_flits, kctx_len, transhdr_len, wr_len;
	u_int imm_len, iopad_size;
	int sgl_nsegs, sgl_len;

	axf = s->hmac.auth_hash;
	crd = crp->crp_desc;
	if (crd->crd_len <= CRYPTO_MAX_IMM_TX_PKT_LEN) {
		imm_len = crd->crd_len;
		sgl_nsegs = 0;
		sgl_len = 0;
	} else {
		imm_len = 0;
		sgl_nsegs = ccr_count_sgl(sc->sg, crd, true);
		sgl_len = ccr_ulptx_sgl_len(sgl_nsegs);
	}

	/* PADs must be 128-bit aligned. */
	iopad_size = roundup2(s->hmac.partial_digest_len, 16);

	/*
	 * The 'key' part of the context includes the partial hash
	 * (IPAD) followed by the OPAD.
	 */
	kctx_len = iopad_size * 2;
	hash_size_in_response = axf->hashsize;
	transhdr_len = HASH_TRANSHDR_SIZE(kctx_len);
	wr_len = roundup2(transhdr_len, 16) + roundup2(imm_len, 16) + sgl_len;
	wr = alloc_wrqe(wr_len, sc->ofld_txq);
	if (wr == NULL)
		return (ENOMEM);
	crwr = wrtod(wr);
	memset(crwr, 0, transhdr_len);

	ccr_populate_wreq(sc, crwr, kctx_len, wr_len, sid, imm_len, sgl_len,
	    hash_size_in_response, IV_NOP, crp);

	/* XXX: Hardcodes SGE loopback channel of 0. */
	crwr->sec_cpl.op_ivinsrtofst = htobe32(
	    V_CPL_TX_SEC_PDU_OPCODE(CPL_TX_SEC_PDU) |
	    V_CPL_TX_SEC_PDU_RXCHID(sc->tx_channel_id) |
	    V_CPL_TX_SEC_PDU_ACKFOLLOWS(0) | V_CPL_TX_SEC_PDU_ULPTXLPBK(1) |
	    V_CPL_TX_SEC_PDU_CPLLEN(2) | V_CPL_TX_SEC_PDU_PLACEHOLDER(0) |
	    V_CPL_TX_SEC_PDU_IVINSRTOFST(0));

	crwr->sec_cpl.pldlen = htobe32(crd->crd_len);

	crwr->sec_cpl.cipherstop_lo_authinsert = htobe32(
	    V_CPL_TX_SEC_PDU_AUTHSTART(1) | V_CPL_TX_SEC_PDU_AUTHSTOP(0));

	/* These two flits are actually a CPL_TLS_TX_SCMD_FMT. */
	crwr->sec_cpl.seqno_numivs = htobe32(
	    V_SCMD_SEQ_NO_CTRL(0) |
	    V_SCMD_PROTO_VERSION(CHCR_SCMD_PROTO_VERSION_GENERIC) |
	    V_SCMD_CIPH_MODE(CHCR_SCMD_CIPHER_MODE_NOP) |
	    V_SCMD_AUTH_MODE(s->hmac.auth_mode) |
	    V_SCMD_HMAC_CTRL(CHCR_SCMD_HMAC_CTRL_NO_TRUNC));
	/* XXX: Set V_SCMD_KEY_CTX_INLINE? */
	crwr->sec_cpl.ivgen_hdrlen = htobe32(
	    V_SCMD_LAST_FRAG(0) | V_SCMD_MORE_FRAGS(0) | V_SCMD_MAC_ONLY(1));

	memcpy(crwr->key_ctx.key, s->hmac.ipad, s->hmac.partial_digest_len);
	memcpy(crwr->key_ctx.key + iopad_size, s->hmac.opad,
	    s->hmac.partial_digest_len);

	/* XXX: F_KEY_CONTEXT_SALT_PRESENT set, but 'salt' not set. */
	kctx_flits = (sizeof(struct _key_ctx) + kctx_len) / 16;
	crwr->key_ctx.ctx_hdr = htobe32(V_KEY_CONTEXT_CTX_LEN(kctx_flits) |
	    V_KEY_CONTEXT_OPAD_PRESENT(1) | V_KEY_CONTEXT_SALT_PRESENT(1) |
	    V_KEY_CONTEXT_CK_SIZE(CHCR_KEYCTX_NO_KEY) |
	    V_KEY_CONTEXT_MK_SIZE(s->hmac.mk_size) | V_KEY_CONTEXT_VALID(1));

	dst = (char *)(crwr + 1) + kctx_len + DUMMY_BYTES;
	if (imm_len != 0)
		crypto_copydata(crp->crp_flags, crp->crp_buf, crd->crd_skip,
		    crd->crd_len, dst);
	else
		ccr_write_ulptx_sgl(sc, crd->crd_skip, crd->crd_len, dst,
		    sgl_nsegs);

#if 0
	device_printf(sc->dev, "submitting HMAC request:\n");
	hexdump(crwr, wr_len, NULL, HD_OMIT_CHARS | HD_OMIT_COUNT);
	if (imm_len == 0)
		dump_payload(sc, dst, sgl_nsegs);
#endif

	/* XXX: TODO backpressure */
	t4_wrq_tx(sc->adapter, wr);

	return (0);
}

static int
ccr_hmac_done(struct ccr_softc *sc, struct ccr_session *s, struct cryptop *crp,
    const struct cpl_fw6_pld *cpl, int error)
{
	struct cryptodesc *crd;

	crd = crp->crp_desc;
	if (error == 0) {
#if 0
		hexdump(cpl + 1, s->hmac.hash_len, NULL, HD_OMIT_COUNT |
		    HD_OMIT_CHARS);
#endif
		crypto_copyback(crp->crp_flags, crp->crp_buf, crd->crd_inject,
		    s->hmac.hash_len, (c_caddr_t)(cpl + 1));
	}

	return (error);
}

static int
ccr_blkcipher(struct ccr_softc *sc, uint32_t sid, struct ccr_session *s,
    struct cryptop *crp)
{
	char iv[CHCR_MAX_CRYPTO_IV_LEN];
	struct chcr_wr *crwr;
	struct wrqe *wr;
	struct cryptodesc *crd;
	char *dst;
	u_int iv_loc, kctx_len, key_half, op_type, transhdr_len, wr_len;
	u_int imm_len;
	int dsgl_nsegs, dsgl_len;
	int sgl_nsegs, sgl_len;

	crd = crp->crp_desc;

	if ((crd->crd_len % AES_BLOCK_LEN) != 0 || s->blkcipher.key_len == 0)
		return (EINVAL);

	iv_loc = IV_NOP;
	if (crd->crd_flags & CRD_F_ENCRYPT) {
		op_type = CHCR_ENCRYPT_OP;
		if (crd->crd_flags & CRD_F_IV_EXPLICIT)
			memcpy(iv, crd->crd_iv, s->blkcipher.iv_len);
		else
			arc4rand(iv, s->blkcipher.iv_len, 0);
		iv_loc = IV_IMMEDIATE;		
		if ((crd->crd_flags & CRD_F_IV_PRESENT) == 0)
			crypto_copyback(crp->crp_flags, crp->crp_buf,
			    crd->crd_inject, s->blkcipher.iv_len, iv);
	} else {
		op_type = CHCR_DECRYPT_OP;
		if (crd->crd_flags & CRD_F_IV_EXPLICIT) {
			memcpy(iv, crd->crd_iv, s->blkcipher.iv_len);
			iv_loc = IV_IMMEDIATE;
		} else
			iv_loc = IV_DSGL;
	}

	dsgl_nsegs = ccr_count_sgl(sc->sg, crd, true);
	dsgl_len = ccr_phys_dsgl_len(dsgl_nsegs);

	if (crd->crd_len + s->blkcipher.iv_len <= CRYPTO_MAX_IMM_TX_PKT_LEN) {
		imm_len = crd->crd_len;
		if (iv_loc == IV_DSGL) {
			crypto_copydata(crp->crp_flags, crp->crp_buf,
			    crd->crd_inject, s->blkcipher.iv_len, iv);
			iv_loc = IV_IMMEDIATE;
		}
		sgl_nsegs = 0;
		sgl_len = 0;
	} else {
		imm_len = 0;
		if (iv_loc == IV_DSGL)
			sgl_nsegs = ccr_count_sgl(sc->sg, crd, false);
		else
			sgl_nsegs = dsgl_nsegs;
		sgl_len = ccr_ulptx_sgl_len(sgl_nsegs);
	}

	/* The 'key' must be 128-bit aligned. */
	kctx_len = roundup2(s->blkcipher.key_len, 16);

	transhdr_len = CIPHER_TRANSHDR_SIZE(kctx_len, dsgl_len);
	wr_len = roundup2(transhdr_len, 16) + roundup2(imm_len, 16) + sgl_len;
	if (iv_loc == IV_IMMEDIATE)
		wr_len += s->blkcipher.iv_len;
	wr = alloc_wrqe(wr_len, sc->ofld_txq);
	if (wr == NULL)
		return (ENOMEM);
	crwr = wrtod(wr);
	memset(crwr, 0, transhdr_len);

	ccr_populate_wreq(sc, crwr, kctx_len, wr_len, sid, imm_len, sgl_len, 0,
	    iv_loc, crp);

	/* XXX: Hardcodes SGE loopback channel of 0. */
	crwr->sec_cpl.op_ivinsrtofst = htobe32(
	    V_CPL_TX_SEC_PDU_OPCODE(CPL_TX_SEC_PDU) |
	    V_CPL_TX_SEC_PDU_RXCHID(sc->tx_channel_id) |
	    V_CPL_TX_SEC_PDU_ACKFOLLOWS(0) | V_CPL_TX_SEC_PDU_ULPTXLPBK(1) |
	    V_CPL_TX_SEC_PDU_CPLLEN(2) | V_CPL_TX_SEC_PDU_PLACEHOLDER(0) |
	    V_CPL_TX_SEC_PDU_IVINSRTOFST(1));

	crwr->sec_cpl.pldlen = htobe32(s->blkcipher.iv_len + crd->crd_len);

	crwr->sec_cpl.aadstart_cipherstop_hi = htobe32(
	    V_CPL_TX_SEC_PDU_CIPHERSTART(s->blkcipher.iv_len + 1) |
	    V_CPL_TX_SEC_PDU_CIPHERSTOP_HI(0));
	crwr->sec_cpl.cipherstop_lo_authinsert = htobe32(
	    V_CPL_TX_SEC_PDU_CIPHERSTOP_LO(0));

	/* These two flits are actually a CPL_TLS_TX_SCMD_FMT. */
	/* XXX: NumIvs set to 0? */
	crwr->sec_cpl.seqno_numivs = htobe32(
	    V_SCMD_SEQ_NO_CTRL(0) |
	    V_SCMD_PROTO_VERSION(CHCR_SCMD_PROTO_VERSION_GENERIC) |
	    V_SCMD_ENC_DEC_CTRL(op_type) |
	    V_SCMD_CIPH_MODE(s->blkcipher.cipher_mode) |
	    V_SCMD_AUTH_MODE(CHCR_SCMD_AUTH_MODE_NOP) |
	    V_SCMD_HMAC_CTRL(CHCR_SCMD_HMAC_CTRL_NOP) |
	    V_SCMD_IV_SIZE(s->blkcipher.iv_len / 2) |
	    V_SCMD_NUM_IVS(0));
	/* XXX: Set V_SCMD_IV_GEN_CTRL? */
	/* XXX: Set V_SCMD_KEY_CTX_INLINE? */
	crwr->sec_cpl.ivgen_hdrlen = htobe32(
	    V_SCMD_IV_GEN_CTRL(0) |
	    V_SCMD_MORE_FRAGS(0) | V_SCMD_LAST_FRAG(0) | V_SCMD_MAC_ONLY(0) |
	    V_SCMD_AADIVDROP(1) | V_SCMD_HDR_LEN(dsgl_len));

	crwr->key_ctx.ctx_hdr = s->blkcipher.key_ctx_hdr;
	switch (crd->crd_alg) {
	case CRYPTO_AES_CBC:
		if (crd->crd_flags & CRD_F_ENCRYPT)
			memcpy(crwr->key_ctx.key, s->blkcipher.enckey,
			    s->blkcipher.key_len);
		else
			memcpy(crwr->key_ctx.key, s->blkcipher.deckey,
			    s->blkcipher.key_len);
		break;
	case CRYPTO_AES_ICM:
		memcpy(crwr->key_ctx.key, s->blkcipher.enckey,
		    s->blkcipher.key_len);
		break;
	case CRYPTO_AES_XTS:
		key_half = s->blkcipher.key_len / 2;
		memcpy(crwr->key_ctx.key, s->blkcipher.enckey + key_half,
		    key_half);
		if (crd->crd_flags & CRD_F_ENCRYPT)
			memcpy(crwr->key_ctx.key + key_half,
			    s->blkcipher.enckey, key_half);
		else
			memcpy(crwr->key_ctx.key + key_half,
			    s->blkcipher.deckey, key_half);
		break;
	}

	dst = (char *)(crwr + 1) + kctx_len;
	ccr_write_phys_dsgl(sc, dst, crd, dsgl_nsegs);
	dst += sizeof(struct cpl_rx_phys_dsgl) + dsgl_len;
	if (iv_loc == IV_IMMEDIATE) {
		memcpy(dst, iv, s->blkcipher.iv_len);
		dst += s->blkcipher.iv_len;
	}
	if (imm_len != 0)
		crypto_copydata(crp->crp_flags, crp->crp_buf, crd->crd_skip,
		    crd->crd_len, dst);
	else if (iv_loc == IV_IMMEDIATE)
		ccr_write_ulptx_sgl(sc, crd->crd_skip, crd->crd_len, dst,
		    sgl_nsegs);
	else
		ccr_write_ulptx_sgl(sc, 0, crd->crd_skip + crd->crd_len, dst,
		    sgl_nsegs);

#if 0
	device_printf(sc->dev, "submitting BLKCIPHER request:\n");
	hexdump(crwr, wr_len, NULL, HD_OMIT_CHARS | HD_OMIT_COUNT);
	if (imm_len == 0)
		dump_payload(sc, dst, sgl_nsegs);
#endif

	/* XXX: TODO backpressure */
	t4_wrq_tx(sc->adapter, wr);

	return (0);
}

static int
ccr_blkcipher_done(struct ccr_softc *sc, struct ccr_session *s,
    struct cryptop *crp, const struct cpl_fw6_pld *cpl, int error)
{

	/*
	 * The updated IV to permit chained requests is at
	 * cpl->data[2], but OCF doesn't permit chained requests.
	 */
	return (error);
}

static int
ccr_authenc(struct ccr_softc *sc, uint32_t sid, struct ccr_session *s,
    struct cryptop *crp, struct cryptodesc *crda, struct cryptodesc *crde)
{
	char iv[CHCR_MAX_CRYPTO_IV_LEN];
	struct chcr_wr *crwr;
	struct wrqe *wr;
	char *dst;
	u_int iv_loc, kctx_len, key_half, op_type, transhdr_len, wr_len;
	u_int imm_len, iopad_size, tot_len;
	u_int cipher_start, cipher_stop, auth_start, auth_stop;
	int dsgl_nsegs, dsgl_len;
	int sgl_nsegs, sgl_len;

	if ((crde->crd_len % AES_BLOCK_LEN) != 0 || s->blkcipher.key_len == 0)
		return (EINVAL);

	/*
	 * For now, the IV is always stored first with an empty AAD
	 * region and the hash and cipher regions are applied to the
	 * payload after the IV (which may also include a copy of the
	 * IV).  Eventually we should optimize the case of an IPSec
	 * request and make use of the AAD region for the auth-only
	 * data before the IV.
	 */
	iv_loc = IV_IMMEDIATE;
	if (crde->crd_flags & CRD_F_ENCRYPT) {
		op_type = CHCR_ENCRYPT_OP;
		if (crde->crd_flags & CRD_F_IV_EXPLICIT)
			memcpy(iv, crde->crd_iv, s->blkcipher.iv_len);
		else
			arc4rand(iv, s->blkcipher.iv_len, 0);
		if ((crde->crd_flags & CRD_F_IV_PRESENT) == 0)
			crypto_copyback(crp->crp_flags, crp->crp_buf,
			    crde->crd_inject, s->blkcipher.iv_len, iv);
	} else {
		op_type = CHCR_DECRYPT_OP;
		if (crde->crd_flags & CRD_F_IV_EXPLICIT)
			memcpy(iv, crde->crd_iv, s->blkcipher.iv_len);
		else
			crypto_copydata(crp->crp_flags, crp->crp_buf,
			    crde->crd_inject, s->blkcipher.iv_len, iv);
	}

	dsgl_nsegs = ccr_count_sgl(sc->sg, crde, true);
	dsgl_len = ccr_phys_dsgl_len(dsgl_nsegs);

	tot_len = max(crda->crd_len + crda->crd_skip,
	    crde->crd_len + crde->crd_skip);
	if (tot_len + s->blkcipher.iv_len <= CRYPTO_MAX_IMM_TX_PKT_LEN) {
		imm_len = tot_len;
		sgl_nsegs = 0;
		sgl_len = 0;
	} else {
		imm_len = 0;
		sgl_nsegs = sc->sg->sg_nseg;
		sgl_len = ccr_ulptx_sgl_len(sgl_nsegs);
		tot_len = sglist_length(sc->sg);
	}

	cipher_start = s->blkcipher.iv_len + crde->crd_skip + 1;
	cipher_stop = tot_len - (crde->crd_skip + crde->crd_len);
	auth_start = s->blkcipher.iv_len + crda->crd_skip + 1;
	auth_stop = tot_len - (crda->crd_skip + crda->crd_len);

	/* PADs must be 128-bit aligned. */
	iopad_size = roundup2(s->hmac.partial_digest_len, 16);

	/*
	 * The 'key' part of the key context consists of the key followed
	 * by the IPAD and OPAD.
	 */
	kctx_len = roundup2(s->blkcipher.key_len, 16) + iopad_size * 2;

	transhdr_len = CIPHER_TRANSHDR_SIZE(kctx_len, dsgl_len);
	wr_len = roundup2(transhdr_len, 16) + roundup2(imm_len, 16) + sgl_len;
	if (iv_loc == IV_IMMEDIATE)
		wr_len += s->blkcipher.iv_len;
	wr = alloc_wrqe(wr_len, sc->ofld_txq);
	if (wr == NULL)
		return (ENOMEM);
	crwr = wrtod(wr);
	memset(crwr, 0, transhdr_len);

	ccr_populate_wreq(sc, crwr, kctx_len, wr_len, sid, imm_len, sgl_len, 0,
	    iv_loc, crp);

	/* XXX: Hardcodes SGE loopback channel of 0. */
	crwr->sec_cpl.op_ivinsrtofst = htobe32(
	    V_CPL_TX_SEC_PDU_OPCODE(CPL_TX_SEC_PDU) |
	    V_CPL_TX_SEC_PDU_RXCHID(sc->tx_channel_id) |
	    V_CPL_TX_SEC_PDU_ACKFOLLOWS(0) | V_CPL_TX_SEC_PDU_ULPTXLPBK(1) |
	    V_CPL_TX_SEC_PDU_CPLLEN(2) | V_CPL_TX_SEC_PDU_PLACEHOLDER(0) |
	    V_CPL_TX_SEC_PDU_IVINSRTOFST(1));

	crwr->sec_cpl.pldlen = htobe32(s->blkcipher.iv_len + tot_len);

	crwr->sec_cpl.aadstart_cipherstop_hi = htobe32(
	    V_CPL_TX_SEC_PDU_CIPHERSTART(cipher_start) |
	    V_CPL_TX_SEC_PDU_CIPHERSTOP_HI(cipher_stop >> 4));
	crwr->sec_cpl.cipherstop_lo_authinsert = htobe32(
	    V_CPL_TX_SEC_PDU_CIPHERSTOP_LO(cipher_stop & 0xf) |
	    V_CPL_TX_SEC_PDU_AUTHSTART(auth_start) |
	    V_CPL_TX_SEC_PDU_AUTHSTOP(auth_stop));

	/* These two flits are actually a CPL_TLS_TX_SCMD_FMT. */
	/* XXX: NumIvs set to 0? */
	crwr->sec_cpl.seqno_numivs = htobe32(
	    V_SCMD_SEQ_NO_CTRL(0) |
	    V_SCMD_PROTO_VERSION(CHCR_SCMD_PROTO_VERSION_GENERIC) |
	    V_SCMD_ENC_DEC_CTRL(op_type) |
	    V_SCMD_CIPH_MODE(s->blkcipher.cipher_mode) |
	    V_SCMD_AUTH_MODE(s->hmac.auth_mode) |
	    V_SCMD_HMAC_CTRL(CHCR_SCMD_HMAC_CTRL_NO_TRUNC) |
	    V_SCMD_IV_SIZE(s->blkcipher.iv_len / 2) |
	    V_SCMD_NUM_IVS(0));
	/* XXX: Set V_SCMD_IV_GEN_CTRL? */
	/* XXX: Set V_SCMD_KEY_CTX_INLINE? */
	crwr->sec_cpl.ivgen_hdrlen = htobe32(
	    V_SCMD_IV_GEN_CTRL(0) |
	    V_SCMD_MORE_FRAGS(0) | V_SCMD_LAST_FRAG(0) | V_SCMD_MAC_ONLY(0) |
	    V_SCMD_AADIVDROP(1) | V_SCMD_HDR_LEN(dsgl_len));

	crwr->key_ctx.ctx_hdr = s->blkcipher.key_ctx_hdr;
	switch (crde->crd_alg) {
	case CRYPTO_AES_CBC:
		if (crde->crd_flags & CRD_F_ENCRYPT)
			memcpy(crwr->key_ctx.key, s->blkcipher.enckey,
			    s->blkcipher.key_len);
		else
			memcpy(crwr->key_ctx.key, s->blkcipher.deckey,
			    s->blkcipher.key_len);
		break;
	case CRYPTO_AES_ICM:
		memcpy(crwr->key_ctx.key, s->blkcipher.enckey,
		    s->blkcipher.key_len);
		break;
	case CRYPTO_AES_XTS:
		key_half = s->blkcipher.key_len / 2;
		memcpy(crwr->key_ctx.key, s->blkcipher.enckey + key_half,
		    key_half);
		if (crde->crd_flags & CRD_F_ENCRYPT)
			memcpy(crwr->key_ctx.key + key_half,
			    s->blkcipher.enckey, key_half);
		else
			memcpy(crwr->key_ctx.key + key_half,
			    s->blkcipher.deckey, key_half);
		break;
	}

	memcpy(crwr->key_ctx.key + s->blkcipher.key_len, s->hmac.ipad,
	    s->hmac.partial_digest_len);
	memcpy(crwr->key_ctx.key + s->blkcipher.key_len + iopad_size,
	    s->hmac.opad, s->hmac.partial_digest_len);

	dst = (char *)(crwr + 1) + kctx_len;
	ccr_write_phys_dsgl(sc, dst, crde, dsgl_nsegs);
	dst += sizeof(struct cpl_rx_phys_dsgl) + dsgl_len;
	if (iv_loc == IV_IMMEDIATE) {
		memcpy(dst, iv, s->blkcipher.iv_len);
		dst += s->blkcipher.iv_len;
	}
	if (imm_len != 0)
		crypto_copydata(crp->crp_flags, crp->crp_buf, 0, tot_len, dst);
	else
		ccr_write_ulptx_sgl(sc, 0, tot_len, dst, sgl_nsegs);

#if 1
	device_printf(sc->dev, "submitting AUTHENC request:\n");
	hexdump(crwr, wr_len, NULL, HD_OMIT_CHARS | HD_OMIT_COUNT);
	if (imm_len == 0)
		dump_payload(sc, dst, sgl_nsegs);
#endif

	/* XXX: TODO backpressure */
	t4_wrq_tx(sc->adapter, wr);

	return (0);
}

static int
ccr_authenc_done(struct ccr_softc *sc, struct ccr_session *s,
    struct cryptop *crp, const struct cpl_fw6_pld *cpl, int error)
{
	struct cryptodesc *crd;

	/*
	 * If OCF generated chained cipher requests the updated
	 * IV would need to be extracted.  As it is, just handle
	 * the hash.
	 */
	crd = crp->crp_desc;
	if (crd->crd_flags & CRD_F_ENCRYPT)
		crd = crd->crd_next;
	if (error == 0) {
#if 1
		hexdump(cpl + 1, s->hmac.hash_len, NULL, HD_OMIT_COUNT |
		    HD_OMIT_CHARS);
#endif
		crypto_copyback(crp->crp_flags, crp->crp_buf, crd->crd_inject,
		    s->hmac.hash_len, (c_caddr_t)(cpl + 1));
	}

	return (error);
}

static void
ccr_identify(driver_t *driver, device_t parent)
{
	struct adapter *sc;

	sc = device_get_softc(parent);
	if (sc->cryptocaps & FW_CAPS_CONFIG_CRYPTO_LOOKASIDE &&
	    device_find_child(parent, "ccr", -1) == NULL)
		device_add_child(parent, "ccr", -1);
}

static int
ccr_probe(device_t dev)
{

	device_set_desc(dev, "Chelsio Crypto Accelerator");
	return (BUS_PROBE_DEFAULT);
}

static int
ccr_attach(device_t dev)
{
	struct ccr_softc *sc;
	int32_t cid;

	/*
	 * TODO: Crypto requests will panic if the parent device isn't
	 * initialized so that the offload queues are up and running.
	 * Need to figure out how to handle that correctly, maybe just
	 * reject requests if the adapter isn't fully initialized?
	 */
	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->adapter = device_get_softc(device_get_parent(dev));
	if (sc->adapter->sge.nofldrxq == 0) {
		device_printf(dev,
		    "parent device does not have offload queues\n");
		return (ENXIO);
	}
	sc->ofld_txq = &sc->adapter->sge.ofld_txq[0];
	sc->ofld_rxq = &sc->adapter->sge.ofld_rxq[0];
	cid = crypto_get_driverid(dev, CRYPTOCAP_F_HARDWARE);
	if (cid < 0) {
		device_printf(dev, "could not get crypto driver id\n");
		return (ENXIO);
	}
	sc->cid = cid;
	sc->adapter->ccr_softc = sc;

	/* XXX: TODO? */
	sc->tx_channel_id = 0;

	mtx_init(&sc->lock, "ccr", NULL, MTX_DEF);
	sc->sg = sglist_alloc(MAX_RX_PHYS_DSGL_SGE, M_WAITOK);

#ifdef notyet
	/* Not even swcrypto handles this, so maybe not worth doing? */
	crypto_register(cid, CRYPTO_SHA1, 0, 0);
#endif
	crypto_register(cid, CRYPTO_SHA1_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_256_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_384_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_512_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_AES_CBC, 0, 0);
	crypto_register(cid, CRYPTO_AES_ICM, 0, 0);
#ifdef notyet
	crypto_register(cid, CRYPTO_AES_NIST_GMAC, 0, 0);
	crypto_register(cid, CRYPTO_AES_NIST_GCM_16, 0, 0);
#endif
	crypto_register(cid, CRYPTO_AES_XTS, 0, 0);
	return (0);
}

static int
ccr_detach(device_t dev)
{
	struct ccr_softc *sc;
	int i;

	sc = device_get_softc(dev);

	mtx_lock(&sc->lock);
	for (i = 0; i < sc->nsessions; i++) {
		if (sc->sessions[i].pending != 0) {
			mtx_unlock(&sc->lock);
			return (EBUSY);
		}
	}
	sc->detaching = true;
	mtx_unlock(&sc->lock);

	crypto_unregister_all(sc->cid);
	free(sc->sessions, M_CCR);
	mtx_destroy(&sc->lock);
	sglist_free(sc->sg);
	sc->adapter->ccr_softc = NULL;
	return (0);
}

static void
ccr_copy_partial_hash(void *dst, int cri_alg, union authctx *auth_ctx)
{
	uint32_t *u32;
	uint64_t *u64;
	u_int i;

	u32 = (uint32_t *)dst;
	u64 = (uint64_t *)dst;
	switch (cri_alg) {
	case CRYPTO_SHA1_HMAC:
		for (i = 0; i < SHA1_HASH_LEN / 4; i++)
			u32[i] = htobe32(auth_ctx->sha1ctx.h.b32[i]);
		break;
	case CRYPTO_SHA2_256_HMAC:
		for (i = 0; i < SHA2_256_HASH_LEN / 4; i++)
			u32[i] = htobe32(auth_ctx->sha256ctx.state[i]);
		break;
	case CRYPTO_SHA2_384_HMAC:
		for (i = 0; i < SHA2_512_HASH_LEN / 8; i++)
			u64[i] = htobe64(auth_ctx->sha384ctx.state[i]);
		break;
	case CRYPTO_SHA2_512_HMAC:
		for (i = 0; i < SHA2_512_HASH_LEN / 8; i++)
			u64[i] = htobe64(auth_ctx->sha512ctx.state[i]);
		break;
	}
}

static void
ccr_init_hmac_digest(struct ccr_session *s, int cri_alg, char *key,
    int klen)
{
	union authctx auth_ctx;
	struct auth_hash *axf;
	u_int i;

	/*
	 * If the key is larger than the block size, use the digest of
	 * the key as the key instead.
	 */
	axf = s->hmac.auth_hash;
	klen /= 8;
	if (klen > axf->blocksize) {
		axf->Init(&auth_ctx);
		axf->Update(&auth_ctx, key, klen);
		axf->Final(s->hmac.ipad, &auth_ctx);
		klen = axf->hashsize;
	} else
		memcpy(s->hmac.ipad, key, klen);

	memset(s->hmac.ipad + klen, 0, axf->blocksize);
	memcpy(s->hmac.opad, s->hmac.ipad, axf->blocksize);

	for (i = 0; i < axf->blocksize; i++) {
		s->hmac.ipad[i] ^= HMAC_IPAD_VAL;
		s->hmac.opad[i] ^= HMAC_OPAD_VAL;
	}

	/*
	 * Hash the raw ipad and opad and store the partial result in
	 * the same buffer.
	 */
	axf->Init(&auth_ctx);
	axf->Update(&auth_ctx, s->hmac.ipad, axf->blocksize);
	ccr_copy_partial_hash(s->hmac.ipad, cri_alg, &auth_ctx);

	axf->Init(&auth_ctx);
	axf->Update(&auth_ctx, s->hmac.opad, axf->blocksize);
	ccr_copy_partial_hash(s->hmac.opad, cri_alg, &auth_ctx);
}

static int
ccr_aes_check_keylen(int alg, int klen)
{

	switch (klen) {
	case 128:
	case 192:
		if (alg == CRYPTO_AES_XTS)
			return (EINVAL);
		break;
	case 256:
		break;
	case 512:
		if (alg != CRYPTO_AES_XTS)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

/*
 * Borrowed from cesa_prep_aes_key().  We should perhaps have a public
 * function to generate this instead.
 *
 * NB: The crypto engine wants the words in the decryption key in reverse
 * order.
 */
static void
ccr_aes_getdeckey(void *dec_key, const void *enc_key, unsigned int kbits)
{
	uint32_t ek[4 * (RIJNDAEL_MAXNR + 1)];
	uint32_t *dkey;
	int i;

	rijndaelKeySetupEnc(ek, enc_key, kbits);
	dkey = dec_key;
	dkey += (kbits / 8) / 4;

	switch (kbits) {
	case 128:
		for (i = 0; i < 4; i++)
			*--dkey = htobe32(ek[4 * 10 + i]);
		break;
	case 192:
		for (i = 0; i < 4; i++)
			*--dkey = htobe32(ek[4 * 12 + i]);
		for (i = 0; i < 2; i++)
			*--dkey = htobe32(ek[4 * 11 + 2 + i]);
		break;
	case 256:
		for (i = 0; i < 4; i++)
			*--dkey = htobe32(ek[4 * 14 + i]);
		for (i = 0; i < 4; i++)
			*--dkey = htobe32(ek[4 * 13 + i]);
		break;
	}
	MPASS(dkey == dec_key);
}

static void
ccr_aes_setkey(struct ccr_session *s, int alg, const void *key, int klen)
{
	unsigned int ck_size, iopad_size, kctx_flits, kctx_len, kbits, mk_size;

	if (alg == CRYPTO_AES_XTS)
		kbits = klen / 2;
	else
		kbits = klen;
	switch (kbits) {
	case 128:
		ck_size = CHCR_KEYCTX_CIPHER_KEY_SIZE_128;
		break;
	case 192:
		ck_size = CHCR_KEYCTX_CIPHER_KEY_SIZE_192;
		break;
	case 256:
		ck_size = CHCR_KEYCTX_CIPHER_KEY_SIZE_256;
		break;
	default:
		panic("should not get here");
	}

	s->blkcipher.key_len = klen / 8;
	memcpy(s->blkcipher.enckey, key, s->blkcipher.key_len);
	if (alg != CRYPTO_AES_ICM)
		ccr_aes_getdeckey(s->blkcipher.deckey, key, kbits);

	kctx_len = roundup2(s->blkcipher.key_len, 16);
	mk_size = CHCR_KEYCTX_NO_KEY;
	if (s->mode == AUTHENC) {
		mk_size = s->hmac.mk_size;
		iopad_size = roundup2(s->hmac.partial_digest_len, 16);
		kctx_len += iopad_size * 2;
	}
	kctx_flits = (sizeof(struct _key_ctx) + kctx_len) / 16;
	s->blkcipher.key_ctx_hdr = htobe32(V_KEY_CONTEXT_CTX_LEN(kctx_flits) |
	    V_KEY_CONTEXT_DUAL_CK(alg == CRYPTO_AES_XTS) |
	    V_KEY_CONTEXT_SALT_PRESENT(1) | V_KEY_CONTEXT_CK_SIZE(ck_size) |
	    V_KEY_CONTEXT_MK_SIZE(mk_size) | V_KEY_CONTEXT_VALID(1));
}

static int
ccr_newsession(device_t dev, uint32_t *sidp, struct cryptoini *cri)
{
	struct ccr_softc *sc;
	struct ccr_session *s;
	struct auth_hash *auth_hash;
	struct cryptoini *c, *hash, *cipher;
	unsigned int auth_mode, cipher_mode, iv_len, mk_size;
	unsigned int partial_digest_len;
	int error, i, sess;

	if (sidp == NULL || cri == NULL)
		return (EINVAL);

	cipher = NULL;
	hash = NULL;
	auth_hash = NULL;
	auth_mode = CHCR_SCMD_AUTH_MODE_NOP;
	cipher_mode = CHCR_SCMD_CIPHER_MODE_NOP;
	iv_len = 0;
	mk_size = 0;
	partial_digest_len = 0;
	for (c = cri; c != NULL; c = c->cri_next) {
		switch (c->cri_alg) {
		case CRYPTO_SHA1_HMAC:
		case CRYPTO_SHA2_256_HMAC:
		case CRYPTO_SHA2_384_HMAC:
		case CRYPTO_SHA2_512_HMAC:
			if (hash)
				return (EINVAL);
			hash = c;
			switch (c->cri_alg) {
			case CRYPTO_SHA1_HMAC:
				auth_hash = &auth_hash_hmac_sha1;
				auth_mode = CHCR_SCMD_AUTH_MODE_SHA1;
				mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_160;
				partial_digest_len = SHA1_HASH_LEN;
				break;
			case CRYPTO_SHA2_256_HMAC:
				auth_hash = &auth_hash_hmac_sha2_256;
				auth_mode = CHCR_SCMD_AUTH_MODE_SHA256;
				mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_256;
				partial_digest_len = SHA2_256_HASH_LEN;
				break;
			case CRYPTO_SHA2_384_HMAC:
				auth_hash = &auth_hash_hmac_sha2_384;
				auth_mode = CHCR_SCMD_AUTH_MODE_SHA512_384;
				mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_512;
				partial_digest_len = SHA2_512_HASH_LEN;
				break;
			case CRYPTO_SHA2_512_HMAC:
				auth_hash = &auth_hash_hmac_sha2_512;
				auth_mode = CHCR_SCMD_AUTH_MODE_SHA512_512;
				mk_size = CHCR_KEYCTX_MAC_KEY_SIZE_512;
				partial_digest_len = SHA2_512_HASH_LEN;
				break;
			}
			break;
		case CRYPTO_AES_CBC:
		case CRYPTO_AES_ICM:
		case CRYPTO_AES_XTS:
			if (cipher)
				return (EINVAL);
			cipher = c;
			switch (c->cri_alg) {
			case CRYPTO_AES_CBC:
				cipher_mode = CHCR_SCMD_CIPHER_MODE_AES_CBC;
				iv_len = AES_BLOCK_LEN;
				break;
			case CRYPTO_AES_ICM:
				cipher_mode = CHCR_SCMD_CIPHER_MODE_AES_CTR;
				iv_len = AES_BLOCK_LEN;
				break;
			case CRYPTO_AES_XTS:
				cipher_mode = CHCR_SCMD_CIPHER_MODE_AES_XTS;
				iv_len = AES_BLOCK_LEN;
				break;
			}
			if (c->cri_key != NULL) {
				error = ccr_aes_check_keylen(c->cri_alg,
				    c->cri_klen);
				if (error)
					return (error);
			}
			break;
		default:
			return (EINVAL);
		}
	}
	if (hash == NULL && cipher == NULL)
		return (EINVAL);
	if (hash != NULL && hash->cri_key == NULL)
		return (EINVAL);

	sc = device_get_softc(dev);
	mtx_lock(&sc->lock);
	if (sc->detaching) {
		mtx_unlock(&sc->lock);
		return (ENXIO);
	}
	sess = -1;
	for (i = 0; i < sc->nsessions; i++) {
		if (!sc->sessions[i].active && sc->sessions[i].pending == 0) {
			sess = i;
			break;
		}
	}
	if (sess == -1) {
		s = malloc(sizeof(*s) * (sc->nsessions + 1), M_CCR,
		    M_NOWAIT | M_ZERO);
		if (s == NULL) {
			mtx_unlock(&sc->lock);
			return (ENOMEM);
		}
		if (sc->sessions != NULL)
			memcpy(s, sc->sessions, sizeof(*s) * sc->nsessions);
		sess = sc->nsessions;
		free(sc->sessions, M_CCR);
		sc->sessions = s;
		sc->nsessions++;
	}

	s = &sc->sessions[sess];

	if (hash != NULL && cipher != NULL)
		s->mode = AUTHENC;
	else if (hash != NULL)
		s->mode = HMAC;
	else {
		MPASS(cipher != NULL);
		s->mode = BLKCIPHER;
	}
	if (hash != NULL) {
		s->hmac.auth_hash = auth_hash;
		s->hmac.auth_mode = auth_mode;
		s->hmac.mk_size = mk_size;
		s->hmac.partial_digest_len = partial_digest_len;
		if (hash->cri_mlen == 0)
			s->hmac.hash_len = auth_hash->hashsize;
		else
			s->hmac.hash_len = hash->cri_mlen;
		ccr_init_hmac_digest(s, hash->cri_alg, hash->cri_key,
		    hash->cri_klen);
	}
	if (cipher != NULL) {
		s->blkcipher.cipher_mode = cipher_mode;
		s->blkcipher.iv_len = iv_len;
		if (cipher->cri_key != NULL)
			ccr_aes_setkey(s, cipher->cri_alg, cipher->cri_key,
			    cipher->cri_klen);
	}

	s->active = true;
	mtx_unlock(&sc->lock);

	*sidp = sess;
	return (0);
}

static int
ccr_freesession(device_t dev, uint64_t tid)
{
	struct ccr_softc *sc;
	uint32_t sid;
	int error;

	sc = device_get_softc(dev);
	sid = CRYPTO_SESID2LID(tid);
	mtx_lock(&sc->lock);
	if (sid >= sc->nsessions || !sc->sessions[sid].active)
		error = EINVAL;
	else {
		if (sc->sessions[sid].pending != 0)
			device_printf(dev,
			    "session %d freed with %d pending requests\n", sid,
			    sc->sessions[sid].pending);
		sc->sessions[sid].active = false;
		error = 0;
	}
	mtx_unlock(&sc->lock);
	return (error);
}

static int
ccr_process(device_t dev, struct cryptop *crp, int hint)
{
	struct ccr_softc *sc;
	struct ccr_session *s;
	struct cryptodesc *crd, *crda, *crde;
	uint32_t sid;
	int error;

	if (crp == NULL || crp->crp_callback == NULL)
		return (EINVAL);

	crd = crp->crp_desc;
	if (crd->crd_next != NULL)
		return (EINVAL);

	sid = CRYPTO_SESID2LID(crp->crp_sid);
	sc = device_get_softc(dev);
	mtx_lock(&sc->lock);
	if (sid >= sc->nsessions || !sc->sessions[sid].active) {
		mtx_unlock(&sc->lock);
		return (EINVAL);
	}

	error = ccr_populage_sglist(sc->sg, crp);
	if (error) {
		mtx_unlock(&sc->lock);
		return (error);
	}

	s = &sc->sessions[sid];
	switch (s->mode) {
	case HMAC:
		if (crd->crd_flags & CRD_F_KEY_EXPLICIT)
			ccr_init_hmac_digest(s, crd->crd_alg, crd->crd_key,
			    crd->crd_klen);
		error = ccr_hmac(sc, sid, s, crp);
		break;
	case BLKCIPHER:
		if (crd->crd_flags & CRD_F_KEY_EXPLICIT) {
			error = ccr_aes_check_keylen(crd->crd_alg,
			    crd->crd_klen);
			if (error)
				break;
			ccr_aes_setkey(s, crd->crd_alg, crd->crd_key,
			    crd->crd_klen);
		}
		error = ccr_blkcipher(sc, sid, s, crp);
		break;
	case AUTHENC:
		error = 0;
		switch (crd->crd_alg) {
		case CRYPTO_AES_CBC:
		case CRYPTO_AES_ICM:
		case CRYPTO_AES_XTS:
			/* Only encrypt-then-authenticate supported. */
			if (!(crd->crd_flags & CRD_F_ENCRYPT)) {
				error = EINVAL;
				break;
			}
			crde = crd;
			crda = crd->crd_next;
			break;
		default:
			crda = crd;
			crde = crd->crd_next;
			if (crde->crd_flags & CRD_F_ENCRYPT) {
				error = EINVAL;
				break;
			}
			break;
		}
		if (error)
			break;
		if (crda->crd_flags & CRD_F_KEY_EXPLICIT)
			ccr_init_hmac_digest(s, crda->crd_alg, crda->crd_key,
			    crda->crd_klen);
		if (crde->crd_flags & CRD_F_KEY_EXPLICIT) {
			error = ccr_aes_check_keylen(crde->crd_alg,
			    crde->crd_klen);
			if (error)
				break;
			ccr_aes_setkey(s, crde->crd_alg, crde->crd_key,
			    crde->crd_klen);
		}
		error = ccr_authenc(sc, sid, s, crp, crda, crde);
		break;
	}

	if (error == 0)
		s->pending++;
	mtx_unlock(&sc->lock);

	return (error);
}

static int
do_cpl6_fw_pld(struct sge_iq *iq, const struct rss_header *rss,
    struct mbuf *m)
{
	struct ccr_softc *sc = iq->adapter->ccr_softc;
	struct ccr_session *s;
	const struct cpl_fw6_pld *cpl;
	struct cryptop *crp;
	uint32_t sid, status;
	int error;

	if (m != NULL)
		cpl = mtod(m, const void *);
	else
		cpl = (const void *)(rss + 1);

#if 0
	device_printf(sc->dev, "CPL6_FW_PLD:\n");
	hexdump(cpl, sizeof(*cpl), NULL, HD_OMIT_COUNT | HD_OMIT_CHARS);
#endif

	crp = (struct cryptop *)be64toh(cpl->data[1]);
	sid = CRYPTO_SESID2LID(crp->crp_sid);
	status = be64toh(cpl->data[0]);
	if (CHK_MAC_ERR_BIT(status) || CHK_PAD_ERR_BIT(status))
		error = EBADMSG;
	else
		error = 0;

	mtx_lock(&sc->lock);
	MPASS(sid < sc->nsessions);
	s = &sc->sessions[sid];
	s->pending--;

	switch (s->mode) {
	case HMAC:
		error = ccr_hmac_done(sc, s, crp, cpl, error);
		break;
	case BLKCIPHER:
		error = ccr_blkcipher_done(sc, s, crp, cpl, error);
		break;
	case AUTHENC:
		error = ccr_authenc_done(sc, s, crp, cpl, error);
		break;
	}

	mtx_unlock(&sc->lock);
	crp->crp_etype = error;
	crypto_done(crp);
	return (0);
}

static int
ccr_modevent(module_t mod, int cmd, void *arg)
{

	switch (cmd) {
	case MOD_LOAD:
		t4_register_cpl_handler(CPL_FW6_PLD, do_cpl6_fw_pld);
		return (0);
	case MOD_UNLOAD:
		t4_register_cpl_handler(CPL_FW6_PLD, NULL);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static device_method_t ccr_methods[] = {
	DEVMETHOD(device_identify,	ccr_identify),
	DEVMETHOD(device_probe,		ccr_probe),
	DEVMETHOD(device_attach,	ccr_attach),
	DEVMETHOD(device_detach,	ccr_detach),

	DEVMETHOD(cryptodev_newsession,	ccr_newsession),
	DEVMETHOD(cryptodev_freesession, ccr_freesession),
	DEVMETHOD(cryptodev_process,	ccr_process),

	DEVMETHOD_END
};

static driver_t ccr_driver = {
	"ccr",
	ccr_methods,
	sizeof(struct ccr_softc)
};

static devclass_t ccr_devclass;

DRIVER_MODULE(ccr, t6nex, ccr_driver, ccr_devclass, ccr_modevent, NULL);
MODULE_VERSION(ccr, 1);
MODULE_DEPEND(ccr, crypto, 1, 1, 1);
MODULE_DEPEND(ccr, t6nex, 1, 1, 1);
