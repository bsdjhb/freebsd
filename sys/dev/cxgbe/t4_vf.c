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
#include "common/t4vf_defs.h"

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
map_bars_0_and_4(struct adapter *sc)
{
	sc->regs_rid = PCIR_BAR(0);
	sc->regs_res = bus_alloc_resource_any(sc->dev, SYS_RES_MEMORY,
	    &sc->regs_rid, RF_ACTIVE);
	if (sc->regs_res == NULL) {
		device_printf(sc->dev, "cannot map registers.\n");
		return (ENXIO);
	}
	sc->bt = rman_get_bustag(sc->regs_res);
	sc->bh = rman_get_bushandle(sc->regs_res);
	sc->mmio_len = rman_get_size(sc->regs_res);
	setbit(&sc->doorbells, DOORBELL_KDB);

	sc->msix_rid = PCIR_BAR(4);
	sc->msix_res = bus_alloc_resource_any(sc->dev, SYS_RES_MEMORY,
	    &sc->msix_rid, RF_ACTIVE);
	if (sc->msix_res == NULL) {
		device_printf(sc->dev, "cannot map MSI-X BAR.\n");
		return (ENXIO);
	}

	return (0);
}

static int
map_bar_2(struct adapter *sc)
{

	/*
	 * T4: only iWARP driver uses the userspace doorbells.  There is no need
	 * to map it if RDMA is disabled.
	 */
	if (is_t4(sc) && sc->rdmacaps == 0)
		return (0);

	sc->udbs_rid = PCIR_BAR(2);
	sc->udbs_res = bus_alloc_resource_any(sc->dev, SYS_RES_MEMORY,
	    &sc->udbs_rid, RF_ACTIVE);
	if (sc->udbs_res == NULL) {
		device_printf(sc->dev, "cannot map doorbell BAR.\n");
		return (ENXIO);
	}
	sc->udbs_base = rman_get_virtual(sc->udbs_res);

	if (is_t5(sc)) {
		setbit(&sc->doorbells, DOORBELL_UDB);
#if defined(__i386__) || defined(__amd64__)
		if (t5_write_combine) {
			int rc;

			/*
			 * Enable write combining on BAR2.  This is the
			 * userspace doorbell BAR and is split into 128B
			 * (UDBS_SEG_SIZE) doorbell regions, each associated
			 * with an egress queue.  The first 64B has the doorbell
			 * and the second 64B can be used to submit a tx work
			 * request with an implicit doorbell.
			 */

			rc = pmap_change_attr((vm_offset_t)sc->udbs_base,
			    rman_get_size(sc->udbs_res), PAT_WRITE_COMBINING);
			if (rc == 0) {
				clrbit(&sc->doorbells, DOORBELL_UDB);
				setbit(&sc->doorbells, DOORBELL_WCWR);
				setbit(&sc->doorbells, DOORBELL_UDBWC);
			} else {
				device_printf(sc->dev,
				    "couldn't enable write combining: %d\n",
				    rc);
			}

			t4_write_reg(sc, A_SGE_STAT_CFG,
			    V_STATSOURCE_T5(7) | V_STATMODE(0));
		}
#endif
	}

	return (0);
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

	rc = map_bars_0_and_4(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = -t4vf_prep_adapter(sc);
	if (rc != 0)
		goto done;

	/*
	 * XXX: Not sure if we need the PF?  The mbox should only be used
	 * for logging, so set it to the VF ID.
	 */
	val = t4_read_reg(sc, VF_PL_REG(A_PL_VF_WHOAMI));
	sc->pf = G_SOURCEPF(val);
	sc->mbox = G_VFID(val);

	/* XXX: Somewhere we have to setup the MBDATA base. */

	/* XXX: adap_init0 start */
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
	rc = -t4vf_fw_reset(sc);
	if (rc != 0) {
		device_printf(dev, "FW reset failed: %d\n", rc);
		goto done;
	}

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
	rc = -t4vf_get_sge_params(sc);
	if (rc != 0) {
		device_printf(dev,
		    "unable to retrieve adapter SGE parameters: %d\n", rc);
		goto done;
	}
	rc = -t4vf_get_rss_glb_config(sc);
	if (rc != 0) {
		device_printf(dev,
		    "unable to retrieve adapter RSS parameters: %d\n", rc);
		goto done;
	}
	if (sc->params.rss.mode != FW_RSS_GLB_CONFIG_CMD_MODE_BASICVIRTUAL) {
		device_printf(dev,
		    "unable to operate with global RSS mode %d\n",
		    sc->params.rss.mode);
		rc = EINVAL;
		goto done;
	}
#ifdef notyet
	err = t4vf_sge_init(adapter);
	if (err) {
		dev_err(adapter->pdev_dev, "unable to use adapter parameters:"
			" err=%d\n", err);
		return err;
	}

	/* If we're running on newer firmware, let it know that we're
	 * prepared to deal with encapsulated CPL messages.  Older
	 * firmware won't understand this and we'll just get
	 * unencapsulated messages ...
	 */
	param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
		V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_CPLFW4MSG_ENCAP);
	val = 1;
	(void) t4vf_set_params(adapter, 1, &param, &val);

	/*
	 * Retrieve our RX interrupt holdoff timer values and counter
	 * threshold values from the SGE parameters.
	 */
	s->timer_val[0] = core_ticks_to_us(adapter,
		G_TIMERVALUE0(sge_params->sge_timer_value_0_and_1));
	s->timer_val[1] = core_ticks_to_us(adapter,
		G_TIMERVALUE1(sge_params->sge_timer_value_0_and_1));
	s->timer_val[2] = core_ticks_to_us(adapter,
		G_TIMERVALUE2(sge_params->sge_timer_value_2_and_3));
	s->timer_val[3] = core_ticks_to_us(adapter,
		G_TIMERVALUE3(sge_params->sge_timer_value_2_and_3));
	s->timer_val[4] = core_ticks_to_us(adapter,
		G_TIMERVALUE4(sge_params->sge_timer_value_4_and_5));
	s->timer_val[5] = core_ticks_to_us(adapter,
		G_TIMERVALUE5(sge_params->sge_timer_value_4_and_5));

	s->counter_val[0] = G_THRESHOLD_0(sge_params->sge_ingress_rx_threshold);
	s->counter_val[1] = G_THRESHOLD_1(sge_params->sge_ingress_rx_threshold);
	s->counter_val[2] = G_THRESHOLD_2(sge_params->sge_ingress_rx_threshold);
	s->counter_val[3] = G_THRESHOLD_3(sge_params->sge_ingress_rx_threshold);

	/*
	 * Grab our Virtual Interface resource allocation, extract the
	 * features that we're interested in and do a bit of sanity testing on
	 * what we discover.
	 */
	err = t4vf_get_vfres(adapter);
	if (err) {
		dev_err(adapter->pdev_dev, "unable to get virtual interface"
			" resources: err=%d\n", err);
		return err;
	}

	/*
	 * Check for various parameter sanity issues.
	 */
	if (adapter->params.vfres.pmask == 0) {
		dev_err(adapter->pdev_dev, "no port access configured\n"
			"usable!\n");
		return -EINVAL;
	}
	if (adapter->params.vfres.nvi == 0) {
		dev_err(adapter->pdev_dev, "no virtual interfaces configured/"
			"usable!\n");
		return -EINVAL;
	}

	/*
	 * Initialize nports and max_ethqsets now that we have our Virtual
	 * Function Resources.
	 */
	size_nports_qsets(adapter);

	adapter->flags |= FW_OK;
#endif

	/* XXX: adap_init0 end */
#if 0
	/* XXX: Not sure yet. */
	memset(sc->chan_map, 0xff, sizeof(sc->chan_map));
	sc->an_handler = an_not_handled;
	for (i = 0; i < nitems(sc->cpl_handler); i++)
		sc->cpl_handler[i] = cpl_not_handled;
	for (i = 0; i < nitems(sc->fw_msg_handler); i++)
		sc->fw_msg_handler[i] = fw_msg_not_handled;
	t4_init_sge_cpl_handlers(sc);
#endif

done:
	mtx_destroy(&sc->regwin_lock);
	mtx_destroy(&sc->sfl_lock);
	mtx_destroy(&sc->sc_lock);

	return (rc);
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
	sizeof(struct adapter)
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
	sizeof(struct adapter)
};

static devclass_t t4vf_devclass, t5vf_devclass;

DRIVER_MODULE(t4vf, pci, t4vf_driver, t4vf_devclass, 0, 0);
MODULE_VERSION(t4vf, 1);
MODULE_DEPEND(t4vf, t4nex, 1, 1, 1);

DRIVER_MODULE(t5vf, pci, t5vf_driver, t5vf_devclass, 0, 0);
MODULE_VERSION(t5vf, 1);
MODULE_DEPEND(t5vf, t5nex, 1, 1, 1);
