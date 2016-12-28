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
#include <sys/module.h>

#include "common/common.h"

struct ccr_softc {
	struct adapter *adapter;
	device_t dev;
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

	sc = device_get_softc(dev);
	sc->adapter = device_get_softc(device_get_parent(dev));
	sc->dev = dev;
	return (0);
}

static int
ccr_detach(device_t dev)
{

	return (0);
}

static device_method_t ccr_methods[] = {
	DEVMETHOD(device_identify,	ccr_identify),
	DEVMETHOD(device_probe,		ccr_probe),
	DEVMETHOD(device_attach,	ccr_attach),
	DEVMETHOD(device_detach,	ccr_detach),

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
