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

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <dev/pci/pcivar.h>

struct t4vf_softc {
};

struct {
	uint16_t device;
	char *desc;
} t4vf_pciids[] = {
	{0x4800, "Chelsio T440-dbg VF"},
	{0x4801, "Chelsio T420-CR VF"},
	{0x4802, "Chelsio T422-CR VF"},
	{0x4803, "Chelsio T440-CR VF"},
	{0x4804, "Chelsio T420-BCH VF"},
	{0x4805, "Chelsio T440-BCH VF"},
	{0x4806, "Chelsio T440-CH VF"},
	{0x4807, "Chelsio T420-SO VF"},
	{0x4808, "Chelsio T420-CX VF"},
	{0x4809, "Chelsio T420-BT VF"},
	{0x480a, "Chelsio T404-BT VF"},
	{0x480e, "Chelsio T440-LP-CR VF"},
}, t5vf_pciids[] = {
	{0x5800, "Chelsio T580-dbg VF"},
	{0x5801,  "Chelsio T520-CR VF"},	/* 2 x 10G */
	{0x5802,  "Chelsio T522-CR VF"},	/* 2 x 10G, 2 X 1G */
	{0x5803,  "Chelsio T540-CR VF"},	/* 4 x 10G */
	{0x5807,  "Chelsio T520-SO VF"},	/* 2 x 10G, nomem */
	{0x5809,  "Chelsio T520-BT VF"},	/* 2 x 10GBaseT */
	{0x580a,  "Chelsio T504-BT VF"},	/* 4 x 1G */
	{0x580d,  "Chelsio T580-CR VF"},	/* 2 x 40G */
	{0x580e,  "Chelsio T540-LP-CR VF"},	/* 4 x 10G */
	{0x5810,  "Chelsio T580-LP-CR VF"},	/* 2 x 40G */
	{0x5811,  "Chelsio T520-LL-CR VF"},	/* 2 x 10G */
	{0x5812,  "Chelsio T560-CR VF"},	/* 1 x 40G, 2 x 10G */
	{0x5814,  "Chelsio T580-LP-SO-CR VF"},	/* 2 x 40G, nomem */
	{0x5815,  "Chelsio T502-BT VF"},	/* 2 x 1G */
#ifdef notyet
	{0x5804,  "Chelsio T520-BCH VF"},
	{0x5805,  "Chelsio T540-BCH VF"},
	{0x5806,  "Chelsio T540-CH VF"},
	{0x5808,  "Chelsio T520-CX VF"},
	{0x580b,  "Chelsio B520-SR VF"},
	{0x580c,  "Chelsio B504-BT VF"},
	{0x580f,  "Chelsio Amsterdam VF"},
	{0x5813,  "Chelsio T580-CHR VF"},
#endif
};

static int
t4vf_probe(device_t dev)
{
	uint16_t d; 
	size_t i;

	d = pci_get_device(dev);
	for (i = 0; i < nitems(t4vf_pciids); i++) {
		if (d == t4vf_pciids[i].device) {
			device_set_desc(dev, t4vf_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}
	return (ENXIO);
}

static int
t5vf_probe(device_t dev)
{
	uint16_t d; 
	size_t i;

	d = pci_get_device(dev);
	for (i = 0; i < nitems(t5vf_pciids); i++) {
		if (d == t5vf_pciids[i].device) {
			device_set_desc(dev, t5vf_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}
	return (ENXIO);
}

static int
t4vf_attach(device_t dev)
{

	return (ENXIO);
}

static int
t4vf_detach(device_t dev)
{

	return (ENXIO);
}

static device_method_t t4vf_methods[] = {
	DEVMETHOD(device_probe,		t4vf_probe),
	DEVMETHOD(device_attach,	t4vf_attach),
	DEVMETHOD(device_detach,	t4vf_detach),

	DEVMETHOD_END
};

static driver_t t4vf_driver = {
	"t4vf",
	t4vf_methods,
	sizeof(struct t4vf_softc)
};

static device_method_t t5vf_methods[] = {
	DEVMETHOD(device_probe,		t5vf_probe),
	DEVMETHOD(device_attach,	t4vf_attach),
	DEVMETHOD(device_detach,	t4vf_detach),

	DEVMETHOD_END
};

static driver_t t5vf_driver = {
	"t5vf",
	t5vf_methods,
	sizeof(struct t4vf_softc)
};

static devclass_t t4vf_devclass, t5vf_devclass;

DRIVER_MODULE(t4vf, pci, t4vf_driver, t4vf_devclass, 0, 0);
MODULE_VERSION(t4vf, 1);
MODULE_DEPEND(t4vf, t4nex, 1, 1, 1);

DRIVER_MODULE(t5vf, pci, t5vf_driver, t5vf_devclass, 0, 0);
MODULE_VERSION(t5vf, 1);
MODULE_DEPEND(t5vf, t5nex, 1, 1, 1);
