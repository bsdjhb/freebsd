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
 * | keys                          |
 * +-------------------------------+
 * | struct cpl_rx_phys_dsgl       |
 * +-------------------------------+
 * | SGL entries                   |
 * +-------------------------------+
 *
 * Replies consist of:
 *
 * +-------------------------------+
 * | struct cpl_fw6_pld            |
 * +-------------------------------+
 * 
 * A 32-bit big-endian error status word is supplied in the last 4
 * bytes of data[0] in the CPL_FW6_PLD message.  bit 0 indicates a
 * "MAC" error and bit 1 indicates a "PAD" error.
 *
 * The 64-bit 'cookie' field from the fw_crypto_lookaside_wr message
 * in the request is returned in data[1] of the CPL_FW6_PLD message.
 *
 * For block cipher replies, the updated IV is supplied in data[2] of
 * the CPL_FW6_PLD message.
 *
 * For non-HMAC hash replies, the hash digest is supplied immediately
 * following the CPL_FW6_PLD message.
 */

static MALLOC_DEFINE(M_CCR, "ccr", "Chelsio T6 crypto");

struct ccr_session_hmac {
	struct auth_hash *auth_hash;
	int hash_len;
	unsigned int auth_mode;
	char digest[CHCR_HASH_MAX_DIGEST_SIZE];
	char ipad[CHCR_HASH_MAX_BLOCK_SIZE_128];
	char opad[CHCR_HASH_MAX_BLOCK_SIZE_128];
};
	
struct ccr_session {
	bool active;
	int pending;
	union {
		struct ccr_session_hmac hmac;
	};
};

struct ccr_softc {
	struct adapter *adapter;
	device_t dev;
	uint32_t cid;
	struct ccr_session *sessions;
	int nsessions;
	struct mtx lock;
	bool detaching;
	struct sge_ofld_txq *ofld_txq;
};

static int
ccr_hmac(struct ccr_softc *sc, struct ccr_session *s, struct cryptop *crp)
{
	struct chcr_wr *crwr;
	struct wrqe *wr;
	u_int hash_size_in_response, kctx_len, transhdr_len, wr_len;

	/* Key context must be 128-bit aligned. */
	kctx_len = sizeof(struct _key_ctx) +
	    roundup2(s->hmac.auth_hash->hashsize, 16) * 2;
	hash_size_in_response = s->hmac.auth_hash->hashsize;
	transhdr_len = HASH_TRANSHDR_SIZE(kctx_len);
	wr = alloc_wrqe(transhdr_len, sc->ofld_txq);
	if (wr == NULL)
		return (ENOMEM);
	memset(wr, 0, transhdr_len);
	crwr = wrtod(wr);

	/* XXX: Hardcodes SGE loopback channel of 0. */
	/* XXX: Not sure if crd_inject is IV offset? */
	crwr->sec_cpl.op_ivinsrtofst = htobe32(
	    CPL_TX_SEC_PDU_OPCODE_V(CPL_TX_SEC_PDU) |
	    CPL_TX_SEC_PDU_RXCHID_V(0) | CPL_TX_SEC_PDU_ACKFOLLOWS_V(0) |
	    CPL_TX_SEC_PDU_ULPTXLPBK_V(1) | CPL_TX_SEC_PDU_CPLLEN_V(2) |
	    CPL_TX_SEC_PDU_PLACEHOLDER_V(0) | CPL_TX_SEC_PDU_IVINSRTOFST_V(0));

	/* XXX: Compute size of either immediate data or SG data. */
	crwr->sec_cpl.pldlen = htobe32(/* XXX */);

	crwr->sec_cpl.cipherstop_lo_authinsert = htobe32(
	    CPL_TX_SEC_PDU_AUTHSTART_V(0) | CPL_TX_SEC_PDU_AUTHSTOP_V(1));

	/* These two flits are actually a CPL_TLX_TX_SCMD_FMT. */
	crwr->sec_cpl.seqno_numivs = htobe32(
	    SCMD_SEQ_NO_CTRL_V(0) |
	    SCMD_PROTO_VERSION_V(CHCR_SCMD_PROTO_VERSION_GENERIC) |
		SCMD_CIPH_MODE_V(CHCR_SCMD_CIPHER_MODE_NOP) |
		SCMD_AUTH_MODE_V(s->hmac.auth_mode) /* | TODO */);
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

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->adapter = device_get_softc(device_get_parent(dev));
	if (sc->adapter->sge.nofldrxq == 0) {
		device_printf(dev,
		    "parent device does not have offload queues\n");
		return (ENXIO);
	}
	sc->ofld_txq = &sc->sge.ofld_txq[0];
	cid = crypto_get_driverid(dev, CRYPTOCAP_F_HARDWARE);
	if (cid < 0) {
		device_printf(dev, "could not get crypto driver id\n");
		return (ENXIO);
	}
	sc->cid = cid;

	mtx_init(&sc->lock, "ccr", NULL, MTX_DEF);

#ifdef notyet
	/* Not even swcrypto handles this, so maybe not worth doing? */
	crypto_register(cid, CRYPTO_SHA1, 0, 0);
#endif
	crypto_register(cid, CRYPTO_SHA1_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_256_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_384_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_512_HMAC, 0, 0);
#ifdef notyet
	crypto_register(cid, CRYPTO_AES_CBC, 0, 0);
	crypto_register(cid, CRYPTO_AES_ICM, 0, 0);
	crypto_register(cid, CRYPTO_AES_NIST_GMAC, 0, 0);
	crypto_register(cid, CRYPTO_AES_NIST_GCM_16, 0, 0);
	crypto_register(cid, CRYPTO_AES_XTS, 0, 0);
#endif
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
	return (0);
}

static void
ccr_copy_partial_hash(void *dst, int cri_alg, union authctx *auth_ctx)
{
	uint32_t *u32;
	uint64_t *u64;

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
		for (i = 0; i < SHA2_384_HASH_LEN / 8; i++)
			u64[i] = htobe64(auth_ctx->sha384ctx.state[i]);
		break;
	case CRYPTO_SHA2_512_HMAC:
		for (i = 0; i < SHA2_512_HASH_LEN / 8; i++)
			u64[i] = htobe64(auth_ctx->sha384ctx.state[i]);
		break;
	}
}

static void
ccr_init_hmac_digest(struct ccr_session *s, int cri_alg, char *key,
    int klen)
{
	union authctx auth_ctx;
	struct auth_hash *axf;
	uint32_t *u32;
	uint64_t *u64;
	int i;

	axf = s->hmac.auth_hash;
	if (key == NULL) {
		/*
		 * XXX: Not sure this is correct.  If HMAC always
		 * requires a key we should instead error if we get
		 * a request to process an op without an explicit
		 * key.
		 */
		axf->Init(&auth_ctx);
		ccr_copy_partial_hash(s->hmac.digest, cri_alg, &auth_ctx);
		return;
	}

	/*
	 * If the key is larger than the block size, use the digest of
	 * the key as the key instead.
	 */
	if (klen > axf->blocksize) {
		axf->Init(&auth_ctx);
		axf->Update(&auth_ctx, key, klen);
		axf->Final(&auth_ctx, s->hmac.ipad);
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
	axf->Init(&authctx);
	axf->Update(&authctx, s->hmac.ipad, axf->blocksize);
	ccr_copy_partial_hash(s->hmac.ipad, cri_alg, &auth_ctx);

	axf->Init(&authctx);
	axf->Update(&authctx, s->hmac.opad, axf->blocksize);
	ccr_copy_partial_hash(s->hmac.opad, cri_alg, &auth_ctx);

	memcpy(s->hmac.digest, s->hmac.ipad, axf->hashsize);
}

static int
ccr_newsession(device_t dev, uint32_t *sidp, struct cryptoini *cri)
{
	struct ccr_softc *sc;
	struct ccr_session *s;
	struct auth_hash *auth_hash;
	struct cryptoini *c, *hash;
	unsigned int auth_mode;
	int i, sess;

	if (sidp == NULL || cri == NULL)
		return (EINVAL);

	hash = NULL;
	auth_hash = NULL;
	auth_mode = CHCR_SCMD_AUTH_MODE_NOP;
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
				break;
			case CRYPTO_SHA2_256_HMAC:
				auth_hash = &auth_hash_hmac_sha2_256;
				auth_mode = CHCR_SCMD_AUTH_MODE_SHA256;
				break;
			case CRYPTO_SHA2_384_HMAC:
				auth_hash = &auth_hash_hmac_sha2_384;
				auth_mode = CHCR_SCMD_AUTH_MODE_SHA512_384;
				break;
			case CRYPTO_SHA2_512_HMAC:
				auth_hash = &auth_hash_hmac_sha2_512;
				auth_mode = CHCR_SCMD_AUTH_MODE_SHA512_512;
				break;
			}
			break;
		default:
			return (EINVAL);
		}
	}
	if (hash == NULL)
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

	/* XXX: Assumes hash-only for now. */
	MPASS(hash != NULL);
	s->hmac.auth_hash = auth_hash;
	s->hmac.auth_mode = auth_mode;
	if (hash->cri_mlen == 0)
		s->hmac.hash_len = auth_hash->hashsize;
	else
		s->hmac.hash_len = hash->cri_mlen;
	ccr_init_hmac_digest(s, hash->cri_alg, hash->cri_key, hash->cri_klen);

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
	struct cryptodesc *crd;
	int error;

	if (crp == NULL || crp->crp_callback == NULL)
		return (EINVAL);

	crd = crp->crp_desc;
	if (crd->crd_next != NULL)
		return (EINVAL);

	sc = device_get_softc(dev);
	mtx_lock(&sc->lock);
	if (sid >= sc->nsessions || !sc->sessions[sid].active) {
		mtx_unlock(&sc->lock);
		return (EINVAL);
	}

	s = &sc->sessions[sid];
	if (crd->crd_flags & CRD_F_KEY_EXPLICIT)
		ccr_init_hmac_digest(s, crd->crd_alg, crd->crd_key,
		    crd->crd_klen);
	error = ccr_hmac(sc, s, crp);
	mtx_unlock(&sc->lock);
	
	return (error);
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

DRIVER_MODULE(ccr, t6nex, ccr_driver, ccr_devclass, NULL, NULL);
MODULE_VERSION(ccr, 1);
MODULE_DEPEND(ccr, crypto, 1, 1, 1);
