/*-
 * Copyright (c) 2016 Chelsio Communications, Inc.
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

#include "cryptodev_if.h"

#include "common/common.h"

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

struct ccr_session {
	bool active;
	int pending;
};

struct ccr_softc {
	struct adapter *adapter;
	device_t dev;
	uint32_t cid;
	struct ccr_session *sessions;
	int nsessions;
	struct mtx lock;
	bool detaching;
};

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
	sc->adapter = device_get_softc(device_get_parent(dev));
	if (sc->adapter->sge.nofldrxq == 0) {
		device_printf(dev,
		    "parent device does not have offload queues\n");
		return (ENXIO);
	}
	sc->dev = dev;
	cid = crypto_get_driverid(dev, CRYPTOCAP_F_HARDWARE);
	if (cid < 0) {
		device_printf(dev, "could not get crypto driver id\n");
		return (ENXIO);
	}
	sc->cid = cid;

	mtx_init(&sc->lock, "ccr", NULL, MTX_DEF);

	crypto_register(cid, CRYPTO_SHA1, 0, 0);
#ifdef notyet
	crypto_register(cid, CRYPTO_SHA1_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_256_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_384_HMAC, 0, 0);
	crypto_register(cid, CRYPTO_SHA2_512_HMAC, 0, 0);
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

static int
ccr_newsession(device_t dev, uint32_t *sidp, struct cryptoini *cri)
{
	struct ccr_softc *sc;
	struct ccr_session *s;
	struct cryptoini *c, *hash;
	int i, sess;

	if (sidp == NULL || cri == NULL)
		return (EINVAL);

	hash = NULL;
	for (c = cri; c != NULL; c = c->cri_next) {
		switch (c->cri_alg) {
		case CRYPTO_SHA1:
			if (hash)
				return (EINVAL);
			hash = c;

			/* Honor cri_mlen? */
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

	/* Init SHA1 digest H[] array? */

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

	
	return (ENXIO);
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
