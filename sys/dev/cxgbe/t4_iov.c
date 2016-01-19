/*-
 * Copyright (c) 2015-2016 Chelsio Communications, Inc.
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

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <dev/pci/pcivar.h>

struct t4iov_softc {
	device_t sc_dev;
	bool sc_attached;
};

struct {
	uint16_t device;
	char *desc;
} t4iov_pciids[] = {
	{0x4000, "Chelsio T440-dbg"},
	{0x4001, "Chelsio T420-CR"},
	{0x4002, "Chelsio T422-CR"},
	{0x4003, "Chelsio T440-CR"},
	{0x4004, "Chelsio T420-BCH"},
	{0x4005, "Chelsio T440-BCH"},
	{0x4006, "Chelsio T440-CH"},
	{0x4007, "Chelsio T420-SO"},
	{0x4008, "Chelsio T420-CX"},
	{0x4009, "Chelsio T420-BT"},
	{0x400a, "Chelsio T404-BT"},
	{0x400e, "Chelsio T440-LP-CR"},
}, t5iov_pciids[] = {
	{0x5000, "Chelsio T580-dbg"},
	{0x5001,  "Chelsio T520-CR"},		/* 2 x 10G */
	{0x5002,  "Chelsio T522-CR"},		/* 2 x 10G, 2 X 1G */
	{0x5003,  "Chelsio T540-CR"},		/* 4 x 10G */
	{0x5007,  "Chelsio T520-SO"},		/* 2 x 10G, nomem */
	{0x5009,  "Chelsio T520-BT"},		/* 2 x 10GBaseT */
	{0x500a,  "Chelsio T504-BT"},		/* 4 x 1G */
	{0x500d,  "Chelsio T580-CR"},		/* 2 x 40G */
	{0x500e,  "Chelsio T540-LP-CR"},	/* 4 x 10G */
	{0x5010,  "Chelsio T580-LP-CR"},	/* 2 x 40G */
	{0x5011,  "Chelsio T520-LL-CR"},	/* 2 x 10G */
	{0x5012,  "Chelsio T560-CR"},		/* 1 x 40G, 2 x 10G */
	{0x5014,  "Chelsio T580-LP-SO-CR"},	/* 2 x 40G, nomem */
	{0x5015,  "Chelsio T502-BT"},		/* 2 x 1G */
#ifdef notyet
	{0x5004,  "Chelsio T520-BCH"},
	{0x5005,  "Chelsio T540-BCH"},
	{0x5006,  "Chelsio T540-CH"},
	{0x5008,  "Chelsio T520-CX"},
	{0x500b,  "Chelsio B520-SR"},
	{0x500c,  "Chelsio B504-BT"},
	{0x500f,  "Chelsio Amsterdam"},
	{0x5013,  "Chelsio T580-CHR"},
#endif
};

static int
t4iov_probe(device_t dev)
{

	/*
	 * TODO: Need to fail probing if there is not an active port
	 * for this function.
	 */
	for (i = 0; i < nitems(t4_pciids); i++) {
		if (d == t4_pciids[i].device) {
			device_set_desc(dev, t4_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}
	return (ENXIO);
}

static int
t5iov_probe(device_t dev)
{

	/*
	 * TODO: Need to fail probing if there is not an active port
	 * for this function.
	 */
	for (i = 0; i < nitems(t5_pciids); i++) {
		if (d == t5_pciids[i].device) {
			device_set_desc(dev, t5_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}
	return (ENXIO);
}

static int
t4iov_attach(device_t dev)
{
	struct t4iov_softc *sc;
	device_t main;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;

	main = pci_find_dbsf(pci_get_domain(dev), pci_get_bus(dev),
	    pci_get_slot(dev), 4);
	if (CHELSIO_T4_IS_PARENT_READY(main) == 0)
		return (t4iov_attach_child);
	return (0);
}

static int
t4iov_attach_child(device_t dev)
{
	struct t4iov_softc *sc;

	sc = device_get_softc(dev);
	MPASS(!sc->sc_attached);

	sc->sc_attached = true;
	return (0);
}

static int
t4iov_detach_child(device_t dev)
{
	struct t4iov_softc *sc;

	sc = device_get_softc(dev);
	MPASS(sc->sc_attached);

	sc->sc_attached = false;
	return (0);
}

static int
t4iov_detach(device_t dev)
{

	if (sc->sc_attached)
		return (t4iov_detach_child(dev));
	return (0);
}

static int
t4iov_init_iov(device_t dev, uint16_t num_vfs, const struct nvlist *config)
{

	return (ENXIO);
}

static void
t4iov_uninit_iov(device_t dev)
{
}

static int
t4iov_add_vf(device_t dev, uint16_t vfnum, const struct nvlist *config)
{

	return (ENXIO);
}

static device_method_t t4iov_methods[] = {
	DEVMETHOD(device_probe,		t4iov_probe),
	DEVMETHOD(device_attach,	t4iov_attach),
	DEVMETHOD(device_detach,	t4iov_detach),

	DEVMETHOD(pci_init_iov,		t4iov_init_iov),
	DEVMETHOD(pci_uninit_iov,	t4iov_uninit_iov),
	DEVMETHOD(pci_add_vf,		t4iov_add_vf),

	DEVMETHOD_END
};

static driver_t t4iov_driver = {
	"t4iov",
	t4iov_methods,
	sizeof(struct t4iov_softc)
};

static device_method_t t5iov_methods[] = {
	DEVMETHOD(device_probe,		t5iov_probe),
	DEVMETHOD(device_attach,	t4iov_attach),
	DEVMETHOD(device_detach,	t4iov_detach),

	DEVMETHOD(pci_init_iov,		t4iov_init_iov),
	DEVMETHOD(pci_uninit_iov,	t4iov_uninit_iov),
	DEVMETHOD(pci_add_vf,		t4iov_add_vf),

	DEVMETHOD_END
};

static driver_t t5iov_driver = {
	"t5iov",
	t5iov_methods,
	sizeof(struct t4iov_softc)
};

static devclass_t t4iov_devclass, t5iov_devclass;

DRIVER_MODULE(t4iov, pci, t4iov_driver, t4iov_devclass, 0, 0);
MODULE_VERSION(t4iov, 1);
DRIVER_MODULE(t5iov, pci, t5iov_driver, t5iov_devclass, 0, 0);
MODULE_VERSION(t5iov, 1);

