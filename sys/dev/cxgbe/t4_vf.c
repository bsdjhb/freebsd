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
#if defined(__i386__) || defined(__amd64__)
#include <vm/vm.h>
#include <vm/pmap.h>
#endif

#include "common/common.h"
#include "common/t4_regs.h"

/*
 * Some notes:
 *
 * The Virtual Interfaces are connected to an internal switch on the chip
 * which allows VIs attached to the same port to talk to each other even when
 * the port link is down.  As a result, we might want to always report a
 * VF's link as being "up".
 *
 * XXX: Add a TUNABLE and possible per-device sysctl for this?
 */

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
get_params__pre_init(struct adapter *sc)
{
	int rc;
	uint32_t param[3], val[3];

	param[0] = FW_PARAM_DEV(FWREV);
	param[1] = FW_PARAM_DEV(TPREV);
	param[2] = FW_PARAM_DEV(CCLK);
	rc = -t4vf_query_params(sc, nitems(param), param, val);
	if (rc != 0) {
		device_printf(sc->dev,
		    "failed to query parameters (pre_init): %d.\n", rc);
		return (rc);
	}

	sc->params.fw_vers = val[0];
	sc->params.tp_vers = val[1];
	sc->params.vpd.cclk = val[2];
	return (0);
}

static int
get_params__post_init(struct adapter *sc)
{
	int rc;

	rc = -t4vf_get_sge_params(sc);
	if (rc != 0) {
		device_printf(sc->dev,
		    "unable to retrieve adapter SGE parameters: %d\n", rc);
		return (rc);
	}
	rc = -t4vf_get_rss_glb_config(sc);
	if (rc != 0) {
		device_printf(sc->dev,
		    "unable to retrieve adapter RSS parameters: %d\n", rc);
		return (rc);
	}
	if (sc->params.rss.mode != FW_RSS_GLB_CONFIG_CMD_MODE_BASICVIRTUAL) {
		device_printf(sc->dev,
		    "unable to operate with global RSS mode %d\n",
		    sc->params.rss.mode);
		return (EINVAL);
	}

	rc = t4_read_chip_settings(sc);
	if (rc != 0)
		return (rc);

	/*
	 * Grab our Virtual Interface resource allocation, extract the
	 * features that we're interested in and do a bit of sanity testing on
	 * what we discover.
	 */
	rc = -t4vf_get_vfres(sc);
	if (rc != 0) {
		device_printf(sc->dev,
		    "unable to get virtual interface resources: %d\n", rc);
		return (rc);
	}

	/*
	 * Check for various parameter sanity issues.
	 */
	if (sc->params.vfres.pmask == 0) {
		device_printf(sc->dev, "no port access configured/usable!\n");
		return (EINVAL);
	}
	if (sc->params.vfres.nvi == 0) {
		device_printf(sc->dev,
		    "no virtual interfaces configured/usable!\n");
		return (EINVAL);
	}

	return (0);
}

static int
set_params__post_init(struct adapter *sc)
{
	uint32_t param, val;

	/* ask for encapsulated CPLs */
	param = FW_PARAM_PFVF(CPLFW4MSG_ENCAP);
	val = 1;
	(void)t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);

	return (0);
}

static int
t4vf_attach(device_t dev)
{
	struct adapter *sc;
	uint32_t val;
	int rc;

	sc = device_get_softc(dev);
	sc->dev = dev;
	pci_enable_busmaster(dev);
#if 0
	/* XXX: Not sure?  The Linux driver doesn't do this on the PF or VF. */
	pci_set_max_read_req(dev, 4096);
#endif

	sc->flags |= IS_VF;

	snprintf(sc->lockname, sizeof(sc->lockname), "%s",
	    device_get_nameunit(dev));
	mtx_init(&sc->sc_lock, sc->lockname, 0, MTX_DEF);

	mtx_init(&sc->sfl_lock, "starving freelists", 0, MTX_DEF);
	TAILQ_INIT(&sc->sfl);
	callout_init_mtx(&sc->sfl_callout, &sc->sfl_lock, 0);

	mtx_init(&sc->regwin_lock, "register and memory window", 0, MTX_DEF);

	rc = t4_map_bars_0_and_4(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = -t4vf_prep_adapter(sc);
	if (rc != 0)
		goto done;

	/*
	 * Note the PF is the parent of this VF.  The mbox is only
	 * used for logging mbox messages, so set it to the VF ID.
	 */
	val = t4_read_reg(sc, VF_PL_REG(A_PL_VF_WHOAMI));
	sc->pf = G_SOURCEPF(val);
	sc->mbox = G_VFID(val);

	memset(sc->chan_map, 0xff, sizeof(sc->chan_map));

#if defined(__i386__)
	if ((cpu_feature & CPUID_CX8) == 0) {
		device_printf(dev, "64 bit atomics not available.\n");
		rc = ENOTSUP;
		goto done;
	}
#endif

	/* XXX: Somewhere we have to setup the MBDATA base? */

	/*
	 * Some environments do not properly handle PCIE FLRs -- e.g. in Linux
	 * 2.6.31 and later we can't call pci_reset_function() in order to
	 * issue an FLR because of a self- deadlock on the device semaphore.
	 * Meanwhile, the OS infrastructure doesn't issue FLRs in all the
	 * cases where they're needed -- for instance, some versions of KVM
	 * fail to reset "Assigned Devices" when the VM reboots.  Therefore we
	 * use the firmware based reset in order to reset any per function
	 * state.
	 */
	device_printf(dev, "PF %d mbox %d flags %#x\n", sc->pf, sc->mbox,
	    sc->flags);
	rc = -t4vf_fw_reset(sc);
	if (rc != 0) {
		device_printf(dev, "FW reset failed: %d\n", rc);
		goto done;
	}
	sc->flags |= FW_OK;

	/*
	 * Grab basic operational parameters.  These will predominantly have
	 * been set up by the Physical Function Driver or will be hard coded
	 * into the adapter.  We just have to live with them ...  Note that
	 * we _must_ get our VPD parameters before our SGE parameters because
	 * we need to know the adapter's core clock from the VPD in order to
	 * properly decode the SGE Timer Values.
	 */
	rc = get_params__pre_init(sc);
	if (rc != 0)
		goto done; /* error message displayed already */
	rc = get_params__post_init(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = set_params__post_init(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = t4_map_bar_2(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = t4_create_dma_tag(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	/*
	 * The number of "ports" which we support is equal to the number of
	 * Virtual Interfaces with which we've been provisioned.
	 */
	sc->params.nports = imin(sc->params.vfres.nvi, MAX_NPORTS);

	/*
	 * We may have been provisioned with more VIs than the number of
	 * ports we're allowed to access (our Port Access Rights Mask).
	 * Just use a single VI for each port.
	 */
	sc->params.nports = imin(sc->params.nports,
	    bitcount32(sc->params.vfres.pmask));
		
#ifdef notyet
	/*
	 * XXX: The Linux VF driver will lower nports if it thinks there
	 * are too few resources in vfres (niqflint, nethctrl, neq).
	 */
#endif

	device_printf(dev,
	    "PCIe gen%d x%d, %d ports, %d %s interrupt%s, %d eq, %d iq\n",
	    sc->params.pci.speed, sc->params.pci.width, sc->params.nports,
	    sc->intr_count, sc->intr_type == INTR_MSIX ? "MSI-X" :
	    (sc->intr_type == INTR_MSI ? "MSI" : "INTx"),
	    sc->intr_count > 1 ? "s" : "", sc->sge.neq, sc->sge.niq);



done:
	if (rc != 0)
		t4_detach_common(dev);
#if 0
	else
		t4_sysctls(sc);
#endif

	return (rc);
}

static device_method_t t4vf_methods[] = {
	DEVMETHOD(device_probe,		t4vf_probe),
	DEVMETHOD(device_attach,	t4vf_attach),
	DEVMETHOD(device_detach,	t4_detach_common),

	DEVMETHOD_END
};

static driver_t t4vf_driver = {
	"t4vf",
	t4vf_methods,
	sizeof(struct adapter)
};

static device_method_t t5vf_methods[] = {
	DEVMETHOD(device_probe,		t5vf_probe),
	DEVMETHOD(device_attach,	t4vf_attach),
	DEVMETHOD(device_detach,	t4_detach_common),

	DEVMETHOD_END
};

static driver_t t5vf_driver = {
	"t5vf",
	t5vf_methods,
	sizeof(struct adapter)
};

static devclass_t t4vf_devclass, t5vf_devclass;

DRIVER_MODULE(t4vf, pci, t4vf_driver, t4vf_devclass, 0, 0);
MODULE_VERSION(t4vf, 1);
MODULE_DEPEND(t4vf, t4nex, 1, 1, 1);

DRIVER_MODULE(t5vf, pci, t5vf_driver, t5vf_devclass, 0, 0);
MODULE_VERSION(t5vf, 1);
MODULE_DEPEND(t5vf, t5nex, 1, 1, 1);
