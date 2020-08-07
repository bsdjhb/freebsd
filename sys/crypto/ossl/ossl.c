/*
 * Copyright (c) 2020 Netflix, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

/*
 * A driver for the OpenCrypto framework which uses assembly routines
 * from OpenSSL.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>

#include <opencrypto/cryptodev.h>

#include "cryptodev_if.h"

struct ossl_softc {
	int32_t sc_cid;
};

struct ossl_session {
};

static void
ossl_identify(driver_t *driver, device_t parent)
{

	if (device_find_child(parent, "ossl", -1) == NULL)
		BUS_ADD_CHILD(parent, 10, "ossl", -1);
}

static int
ossl_probe(device_t dev)
{

	device_set_desc(dev, "OpenSSL crypto");
	return (BUS_PROBE_DEFAULT);
}

static int
ossl_attach(device_t dev)
{
	struct ossl_softc *sc;

	sc = device_get_softc(dev);

	sc->sc_cid = crypto_get_driverid(dev, sizeof(struct ossl_session),
	    CRYPTOCAP_F_SOFTWARE | CRYPTOCAP_F_SYNC |
	    CRYPTOCAP_F_ACCEL_SOFTWARE);
	if (sc->sc_cid < 0) {
		device_printf(dev, "failed to allocate crypto driver id\n");
		return (ENXIO);
	}

	return (0);
}

static int
ossl_detach(device_t dev)
{
	struct ossl_softc *sc;

	sc = device_get_softc(dev);

	crypto_unregister_all(sc->sc_cid);

	return (0);
}

static int
ossl_probesession(device_t dev, const struct crypto_session_params *csp)
{

	if ((csp->csp_flags & ~(CSP_F_SEPARATE_OUTPUT | CSP_F_SEPARATE_AAD)) !=
	    0)
		return (EINVAL);
	switch (csp->csp_mode) {
	default:
		return (EINVAL);
	}

	return (CRYPTODEV_PROBE_ACCEL_SOFTWARE);
}

static int
ossl_newsession(device_t dev, crypto_session_t cses,
    const struct crypto_session_params *csp)
{
	struct ossl_session *s;

	s = crypto_get_driver_session(cses);

	return (ENXIO);
}

static int
ossl_process(device_t dev, struct cryptop *crp, int hint)
{

	crp->crp_etype = ENXIO;
	crypto_done(crp);
	return (0);
}

static device_method_t ossl_methods[] = {
	DEVMETHOD(device_identify,	ossl_identify),
	DEVMETHOD(device_probe,		ossl_probe),
	DEVMETHOD(device_attach,	ossl_attach),
	DEVMETHOD(device_detach,	ossl_detach),

	DEVMETHOD(cryptodev_probesession, ossl_probesession),
	DEVMETHOD(cryptodev_newsession,	ossl_newsession),
	DEVMETHOD(cryptodev_process,	ossl_process),

	DEVMETHOD_END
};

static driver_t ossl_driver = {
	"ossl",
	ossl_methods,
	sizeof(struct ossl_softc)
};

static devclass_t ossl_devclass;

DRIVER_MODULE(ossl, nexus, ossl_driver, ossl_devclass, NULL, NULL);
MODULE_VERSION(ossl, 1);
MODULE_DEPEND(ossl, crypto, 1, 1, 1);
