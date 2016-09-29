/*-
 * Copyright (c) 2011 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: Navdeep Parhar <np@FreeBSD.org>
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

#include "opt_ddb.h"
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_rss.h"

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/priv.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/pciio.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pci_private.h>
#include <sys/firmware.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_vlan_var.h>
#ifdef RSS
#include <net/rss_config.h>
#endif
#if defined(__i386__) || defined(__amd64__)
#include <vm/vm.h>
#include <vm/pmap.h>
#endif
#ifdef DDB
#include <ddb/ddb.h>
#include <ddb/db_lex.h>
#endif

#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_regs_values.h"
#include "t4_ioctl.h"
#include "t4_l2t.h"
#include "t4_mp_ring.h"
#include "t4_if.h"

/* T4 bus driver interface */
static int t4_probe(device_t);
static int t4_attach(device_t);
static int t4_detach(device_t);
static int t4_ready(device_t);
static int t4_read_port_device(device_t, int, device_t *);
static device_method_t t4_methods[] = {
	DEVMETHOD(device_probe,		t4_probe),
	DEVMETHOD(device_attach,	t4_attach),
	DEVMETHOD(device_detach,	t4_detach),

	DEVMETHOD(t4_is_main_ready,	t4_ready),
	DEVMETHOD(t4_read_port_device,	t4_read_port_device),

	DEVMETHOD_END
};
static driver_t t4_driver = {
	"t4nex",
	t4_methods,
	sizeof(struct adapter)
};


/* T4 port (cxgbe) interface */
static driver_t cxgbe_driver = {
	"cxgbe",
	cxgbe_methods,
	sizeof(struct port_info)
};

/* T4 VI (vcxgbe) interface */
static int vcxgbe_probe(device_t);
static int vcxgbe_attach(device_t);
static int vcxgbe_detach(device_t);
static device_method_t vcxgbe_methods[] = {
	DEVMETHOD(device_probe,		vcxgbe_probe),
	DEVMETHOD(device_attach,	vcxgbe_attach),
	DEVMETHOD(device_detach,	vcxgbe_detach),
	{ 0, 0 }
};
static driver_t vcxgbe_driver = {
	"vcxgbe",
	vcxgbe_methods,
	sizeof(struct vi_info)
};

static d_ioctl_t t4_ioctl;

static struct cdevsw t4_cdevsw = {
       .d_version = D_VERSION,
       .d_ioctl = t4_ioctl,
       .d_name = "t4nex",
};

/* T5 bus driver interface */
static int t5_probe(device_t);
static device_method_t t5_methods[] = {
	DEVMETHOD(device_probe,		t5_probe),
	DEVMETHOD(device_attach,	t4_attach),
	DEVMETHOD(device_detach,	t4_detach),

	DEVMETHOD(t4_is_main_ready,	t4_ready),
	DEVMETHOD(t4_read_port_device,	t4_read_port_device),

	DEVMETHOD_END
};
static driver_t t5_driver = {
	"t5nex",
	t5_methods,
	sizeof(struct adapter)
};


/* T5 port (cxl) interface */
static driver_t cxl_driver = {
	"cxl",
	cxgbe_methods,
	sizeof(struct port_info)
};

/* T5 VI (vcxl) interface */
static driver_t vcxl_driver = {
	"vcxl",
	vcxgbe_methods,
	sizeof(struct vi_info)
};

/* T6 bus driver interface */
static int t6_probe(device_t);
static device_method_t t6_methods[] = {
	DEVMETHOD(device_probe,		t6_probe),
	DEVMETHOD(device_attach,	t4_attach),
	DEVMETHOD(device_detach,	t4_detach),

	DEVMETHOD(t4_is_main_ready,	t4_ready),
	DEVMETHOD(t4_read_port_device,	t4_read_port_device),

	DEVMETHOD_END
};
static driver_t t6_driver = {
	"t6nex",
	t6_methods,
	sizeof(struct adapter)
};


/* T6 port (cc) interface */
static driver_t cc_driver = {
	"cc",
	cxgbe_methods,
	sizeof(struct port_info)
};

/* T6 VI (vcc) interface */
static driver_t vcc_driver = {
	"vcc",
	vcxgbe_methods,
	sizeof(struct vi_info)
};

/*
 * Tunables specific to the PF drivers.
 */

/* Reserve transmit queue 0 for non-flowid packets. */
static int t4_rsrv_noflowq = 0;
TUNABLE_INT("hw.cxgbe.rsrv_noflowq", &t4_rsrv_noflowq);

/*
 * Configuration file.
 */
#define DEFAULT_CF	"default"
#define FLASH_CF	"flash"
#define UWIRE_CF	"uwire"
#define FPGA_CF		"fpga"
static char t4_cfg_file[32] = DEFAULT_CF;
TUNABLE_STR("hw.cxgbe.config_file", t4_cfg_file, sizeof(t4_cfg_file));

/*
 * PAUSE settings (bit 0, 1 = rx_pause, tx_pause respectively).
 * rx_pause = 1 to heed incoming PAUSE frames, 0 to ignore them.
 * tx_pause = 1 to emit PAUSE frames when the rx FIFO reaches its high water
 *            mark or when signalled to do so, 0 to never emit PAUSE.
 */
static int t4_pause_settings = PAUSE_TX | PAUSE_RX;
TUNABLE_INT("hw.cxgbe.pause_settings", &t4_pause_settings);

/*
 * Firmware auto-install by driver during attach (0, 1, 2 = prohibited, allowed,
 * encouraged respectively).
 */
static unsigned int t4_fw_install = 1;
TUNABLE_INT("hw.cxgbe.fw_install", &t4_fw_install);

/*
 * ASIC features that will be used.  Disable the ones you don't want so that the
 * chip resources aren't wasted on features that will not be used.
 */
static int t4_nbmcaps_allowed = 0;
TUNABLE_INT("hw.cxgbe.nbmcaps_allowed", &t4_nbmcaps_allowed);

static int t4_linkcaps_allowed = 0;	/* No DCBX, PPP, etc. by default */
TUNABLE_INT("hw.cxgbe.linkcaps_allowed", &t4_linkcaps_allowed);

static int t4_switchcaps_allowed = FW_CAPS_CONFIG_SWITCH_INGRESS |
    FW_CAPS_CONFIG_SWITCH_EGRESS;
TUNABLE_INT("hw.cxgbe.switchcaps_allowed", &t4_switchcaps_allowed);

static int t4_niccaps_allowed = FW_CAPS_CONFIG_NIC;
TUNABLE_INT("hw.cxgbe.niccaps_allowed", &t4_niccaps_allowed);

static int t4_toecaps_allowed = -1;
TUNABLE_INT("hw.cxgbe.toecaps_allowed", &t4_toecaps_allowed);

static int t4_rdmacaps_allowed = -1;
TUNABLE_INT("hw.cxgbe.rdmacaps_allowed", &t4_rdmacaps_allowed);

static int t4_cryptocaps_allowed = 0;
TUNABLE_INT("hw.cxgbe.cryptocaps_allowed", &t4_cryptocaps_allowed);

static int t4_iscsicaps_allowed = -1;
TUNABLE_INT("hw.cxgbe.iscsicaps_allowed", &t4_iscsicaps_allowed);

static int t4_fcoecaps_allowed = 0;
TUNABLE_INT("hw.cxgbe.fcoecaps_allowed", &t4_fcoecaps_allowed);

static int t5_write_combine = 0;
TUNABLE_INT("hw.cxl.write_combine", &t5_write_combine);

static int t4_num_vis = 1;
TUNABLE_INT("hw.cxgbe.num_vis", &t4_num_vis);

/* Functions used by extra VIs to obtain unique MAC addresses for each VI. */
static int vi_mac_funcs[] = {
	FW_VI_FUNC_OFLD,
	FW_VI_FUNC_IWARP,
	FW_VI_FUNC_OPENISCSI,
	FW_VI_FUNC_OPENFCOE,
	FW_VI_FUNC_FOISCSI,
	FW_VI_FUNC_FOFCOE,
};

struct intrs_and_queues {
	uint16_t intr_type;	/* INTx, MSI, or MSI-X */
	uint16_t nirq;		/* Total # of vectors */
	uint16_t intr_flags_10g;/* Interrupt flags for each 10G port */
	uint16_t intr_flags_1g;	/* Interrupt flags for each 1G port */
	uint16_t ntxq10g;	/* # of NIC txq's for each 10G port */
	uint16_t nrxq10g;	/* # of NIC rxq's for each 10G port */
	uint16_t ntxq1g;	/* # of NIC txq's for each 1G port */
	uint16_t nrxq1g;	/* # of NIC rxq's for each 1G port */
	uint16_t rsrv_noflowq;	/* Flag whether to reserve queue 0 */
	uint16_t nofldtxq10g;	/* # of TOE txq's for each 10G port */
	uint16_t nofldrxq10g;	/* # of TOE rxq's for each 10G port */
	uint16_t nofldtxq1g;	/* # of TOE txq's for each 1G port */
	uint16_t nofldrxq1g;	/* # of TOE rxq's for each 1G port */

	/* The vcxgbe/vcxl interfaces use these and not the ones above. */
	uint16_t ntxq_vi;	/* # of NIC txq's */
	uint16_t nrxq_vi;	/* # of NIC rxq's */
	uint16_t nofldtxq_vi;	/* # of TOE txq's */
	uint16_t nofldrxq_vi;	/* # of TOE rxq's */
	uint16_t nnmtxq_vi;	/* # of netmap txq's */
	uint16_t nnmrxq_vi;	/* # of netmap rxq's */
};

struct filter_entry {
        uint32_t valid:1;	/* filter allocated and valid */
        uint32_t locked:1;	/* filter is administratively locked */
        uint32_t pending:1;	/* filter action is pending firmware reply */
	uint32_t smtidx:8;	/* Source MAC Table index for smac */
	struct l2t_entry *l2t;	/* Layer Two Table entry for dmac */

        struct t4_filter_specification fs;
};

static void setup_memwin(struct adapter *);
static void position_memwin(struct adapter *, int, uint32_t);
static int rw_via_memwin(struct adapter *, int, uint32_t, uint32_t *, int, int);
static inline int read_via_memwin(struct adapter *, int, uint32_t, uint32_t *,
    int);
static inline int write_via_memwin(struct adapter *, int, uint32_t,
    const uint32_t *, int);
static int validate_mem_range(struct adapter *, uint32_t, int);
static int fwmtype_to_hwmtype(int);
static int validate_mt_off_len(struct adapter *, int, uint32_t, int,
    uint32_t *);
static int fixup_devlog_params(struct adapter *);
static int cfg_itype_and_nqueues(struct adapter *, int, int, int,
    struct intrs_and_queues *);
static int prep_firmware(struct adapter *);
static int partition_resources(struct adapter *, const struct firmware *,
    const char *);
static int get_params__pre_init(struct adapter *);
static int get_params__post_init(struct adapter *);
static int set_params__post_init(struct adapter *);
static void t4_set_desc(struct adapter *);
static void get_regs(struct adapter *, struct t4_regdump *, uint8_t *);
static uint32_t fconf_iconf_to_mode(uint32_t, uint32_t);
static uint32_t mode_to_fconf(uint32_t);
static uint32_t mode_to_iconf(uint32_t);
static int check_fspec_against_fconf_iconf(struct adapter *,
    struct t4_filter_specification *);
static int get_filter_mode(struct adapter *, uint32_t *);
static int set_filter_mode(struct adapter *, uint32_t);
static inline uint64_t get_filter_hits(struct adapter *, uint32_t);
static int get_filter(struct adapter *, struct t4_filter *);
static int set_filter(struct adapter *, struct t4_filter *);
static int del_filter(struct adapter *, struct t4_filter *);
static void clear_filter(struct filter_entry *);
static int set_filter_wr(struct adapter *, int);
static int del_filter_wr(struct adapter *, int);
static int t4_filter_rpl(struct sge_iq *, const struct rss_header *,
    struct mbuf *);
static int get_sge_context(struct adapter *, struct t4_sge_context *);
static int load_fw(struct adapter *, struct t4_data *);
static int load_cfg(struct adapter *, struct t4_data *);
static int read_card_mem(struct adapter *, int, struct t4_mem_range *);
static int read_i2c(struct adapter *, struct t4_i2c_data *);
static int notify_siblings(device_t, int);

struct {
	uint16_t device;
	char *desc;
} t4_pciids[] = {
	{0xa000, "Chelsio Terminator 4 FPGA"},
	{0x4400, "Chelsio T440-dbg"},
	{0x4401, "Chelsio T420-CR"},
	{0x4402, "Chelsio T422-CR"},
	{0x4403, "Chelsio T440-CR"},
	{0x4404, "Chelsio T420-BCH"},
	{0x4405, "Chelsio T440-BCH"},
	{0x4406, "Chelsio T440-CH"},
	{0x4407, "Chelsio T420-SO"},
	{0x4408, "Chelsio T420-CX"},
	{0x4409, "Chelsio T420-BT"},
	{0x440a, "Chelsio T404-BT"},
	{0x440e, "Chelsio T440-LP-CR"},
}, t5_pciids[] = {
	{0xb000, "Chelsio Terminator 5 FPGA"},
	{0x5400, "Chelsio T580-dbg"},
	{0x5401,  "Chelsio T520-CR"},		/* 2 x 10G */
	{0x5402,  "Chelsio T522-CR"},		/* 2 x 10G, 2 X 1G */
	{0x5403,  "Chelsio T540-CR"},		/* 4 x 10G */
	{0x5407,  "Chelsio T520-SO"},		/* 2 x 10G, nomem */
	{0x5409,  "Chelsio T520-BT"},		/* 2 x 10GBaseT */
	{0x540a,  "Chelsio T504-BT"},		/* 4 x 1G */
	{0x540d,  "Chelsio T580-CR"},		/* 2 x 40G */
	{0x540e,  "Chelsio T540-LP-CR"},	/* 4 x 10G */
	{0x5410,  "Chelsio T580-LP-CR"},	/* 2 x 40G */
	{0x5411,  "Chelsio T520-LL-CR"},	/* 2 x 10G */
	{0x5412,  "Chelsio T560-CR"},		/* 1 x 40G, 2 x 10G */
	{0x5414,  "Chelsio T580-LP-SO-CR"},	/* 2 x 40G, nomem */
	{0x5415,  "Chelsio T502-BT"},		/* 2 x 1G */
#ifdef notyet
	{0x5404,  "Chelsio T520-BCH"},
	{0x5405,  "Chelsio T540-BCH"},
	{0x5406,  "Chelsio T540-CH"},
	{0x5408,  "Chelsio T520-CX"},
	{0x540b,  "Chelsio B520-SR"},
	{0x540c,  "Chelsio B504-BT"},
	{0x540f,  "Chelsio Amsterdam"},
	{0x5413,  "Chelsio T580-CHR"},
#endif
}, t6_pciids[] = {
	{0xc006, "Chelsio Terminator 6 FPGA"},	/* T6 PE10K6 FPGA (PF0) */
	{0x6401, "Chelsio T6225-CR"},		/* 2 x 10/25G */
	{0x6402, "Chelsio T6225-SO-CR"},	/* 2 x 10/25G, nomem */
	{0x6407, "Chelsio T62100-LP-CR"},	/* 2 x 40/50/100G */
	{0x6408, "Chelsio T62100-SO-CR"},	/* 2 x 40/50/100G, nomem */
	{0x640d, "Chelsio T62100-CR"},		/* 2 x 40/50/100G */
	{0x6410, "Chelsio T62100-DBG"},		/* 2 x 40/50/100G, debug */
};

static int
t4_probe(device_t dev)
{
	int i;
	uint16_t v = pci_get_vendor(dev);
	uint16_t d = pci_get_device(dev);
	uint8_t f = pci_get_function(dev);

	if (v != PCI_VENDOR_ID_CHELSIO)
		return (ENXIO);

	/* Attach only to PF0 of the FPGA */
	if (d == 0xa000 && f != 0)
		return (ENXIO);

	for (i = 0; i < nitems(t4_pciids); i++) {
		if (d == t4_pciids[i].device) {
			device_set_desc(dev, t4_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}

	return (ENXIO);
}

static int
t5_probe(device_t dev)
{
	int i;
	uint16_t v = pci_get_vendor(dev);
	uint16_t d = pci_get_device(dev);
	uint8_t f = pci_get_function(dev);

	if (v != PCI_VENDOR_ID_CHELSIO)
		return (ENXIO);

	/* Attach only to PF0 of the FPGA */
	if (d == 0xb000 && f != 0)
		return (ENXIO);

	for (i = 0; i < nitems(t5_pciids); i++) {
		if (d == t5_pciids[i].device) {
			device_set_desc(dev, t5_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}

	return (ENXIO);
}

static int
t6_probe(device_t dev)
{
	int i;
	uint16_t v = pci_get_vendor(dev);
	uint16_t d = pci_get_device(dev);

	if (v != PCI_VENDOR_ID_CHELSIO)
		return (ENXIO);

	for (i = 0; i < nitems(t6_pciids); i++) {
		if (d == t6_pciids[i].device) {
			device_set_desc(dev, t6_pciids[i].desc);
			return (BUS_PROBE_DEFAULT);
		}
	}

	return (ENXIO);
}

static void
t5_attribute_workaround(device_t dev)
{
	device_t root_port;
	uint32_t v;

	/*
	 * The T5 chips do not properly echo the No Snoop and Relaxed
	 * Ordering attributes when replying to a TLP from a Root
	 * Port.  As a workaround, find the parent Root Port and
	 * disable No Snoop and Relaxed Ordering.  Note that this
	 * affects all devices under this root port.
	 */
	root_port = pci_find_pcie_root_port(dev);
	if (root_port == NULL) {
		device_printf(dev, "Unable to find parent root port\n");
		return;
	}

	v = pcie_adjust_config(root_port, PCIER_DEVICE_CTL,
	    PCIEM_CTL_RELAXED_ORD_ENABLE | PCIEM_CTL_NOSNOOP_ENABLE, 0, 2);
	if ((v & (PCIEM_CTL_RELAXED_ORD_ENABLE | PCIEM_CTL_NOSNOOP_ENABLE)) !=
	    0)
		device_printf(dev, "Disabled No Snoop/Relaxed Ordering on %s\n",
		    device_get_nameunit(root_port));
}

static int
t4_attach(device_t dev)
{
	struct adapter *sc;
	int rc = 0, i, j, n10g, n1g, rqidx, tqidx;
	struct make_dev_args mda;
	struct intrs_and_queues iaq;
	struct sge *s;
	uint8_t *buf;
#ifdef TCP_OFFLOAD
	int ofld_rqidx, ofld_tqidx;
#endif
#ifdef DEV_NETMAP
	int nm_rqidx, nm_tqidx;
#endif
	int num_vis;

	sc = device_get_softc(dev);
	sc->dev = dev;
	TUNABLE_INT_FETCH("hw.cxgbe.dflags", &sc->debug_flags);

	if ((pci_get_device(dev) & 0xff00) == 0x5400)
		t5_attribute_workaround(dev);
	pci_enable_busmaster(dev);
	if (pci_find_cap(dev, PCIY_EXPRESS, &i) == 0) {
		uint32_t v;

		pci_set_max_read_req(dev, 4096);
		v = pci_read_config(dev, i + PCIER_DEVICE_CTL, 2);
		v |= PCIEM_CTL_RELAXED_ORD_ENABLE;
		pci_write_config(dev, i + PCIER_DEVICE_CTL, v, 2);

		sc->params.pci.mps = 128 << ((v & PCIEM_CTL_MAX_PAYLOAD) >> 5);
	}

	sc->sge_gts_reg = MYPF_REG(A_SGE_PF_GTS);
	sc->sge_kdoorbell_reg = MYPF_REG(A_SGE_PF_KDOORBELL);
	sc->traceq = -1;
	mtx_init(&sc->ifp_lock, sc->ifp_lockname, 0, MTX_DEF);
	snprintf(sc->ifp_lockname, sizeof(sc->ifp_lockname), "%s tracer",
	    device_get_nameunit(dev));

	snprintf(sc->lockname, sizeof(sc->lockname), "%s",
	    device_get_nameunit(dev));
	mtx_init(&sc->sc_lock, sc->lockname, 0, MTX_DEF);
	t4_add_adapter(sc);

	mtx_init(&sc->sfl_lock, "starving freelists", 0, MTX_DEF);
	TAILQ_INIT(&sc->sfl);
	callout_init_mtx(&sc->sfl_callout, &sc->sfl_lock, 0);

	mtx_init(&sc->reg_lock, "indirect register access", 0, MTX_DEF);

	rc = t4_map_bars_0_and_4(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	memset(sc->chan_map, 0xff, sizeof(sc->chan_map));

	/* Prepare the adapter for operation. */
	buf = malloc(PAGE_SIZE, M_CXGBE, M_ZERO | M_WAITOK);
	rc = -t4_prep_adapter(sc, buf);
	free(buf, M_CXGBE);
	if (rc != 0) {
		device_printf(dev, "failed to prepare adapter: %d.\n", rc);
		goto done;
	}

	/*
	 * This is the real PF# to which we're attaching.  Works from within PCI
	 * passthrough environments too, where pci_get_function() could return a
	 * different PF# depending on the passthrough configuration.  We need to
	 * use the real PF# in all our communication with the firmware.
	 */
	j = t4_read_reg(sc, A_PL_WHOAMI);
	sc->pf = chip_id(sc) <= CHELSIO_T5 ? G_SOURCEPF(j) : G_T6_SOURCEPF(j);
	sc->mbox = sc->pf;

	t4_init_devnames(sc);
	if (sc->names == NULL) {
		rc = ENOTSUP;
		goto done; /* error message displayed already */
	}

	/*
	 * Do this really early, with the memory windows set up even before the
	 * character device.  The userland tool's register i/o and mem read
	 * will work even in "recovery mode".
	 */
	setup_memwin(sc);
	if (t4_init_devlog_params(sc, 0) == 0)
		fixup_devlog_params(sc);
	make_dev_args_init(&mda);
	mda.mda_devsw = &t4_cdevsw;
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_WHEEL;
	mda.mda_mode = 0600;
	mda.mda_si_drv1 = sc;
	rc = make_dev_s(&mda, &sc->cdev, "%s", device_get_nameunit(dev));
	if (rc != 0)
		device_printf(dev, "failed to create nexus char device: %d.\n",
		    rc);

	/* Go no further if recovery mode has been requested. */
	if (TUNABLE_INT_FETCH("hw.cxgbe.sos", &i) && i != 0) {
		device_printf(dev, "recovery mode.\n");
		goto done;
	}

#if defined(__i386__)
	if ((cpu_feature & CPUID_CX8) == 0) {
		device_printf(dev, "64 bit atomics not available.\n");
		rc = ENOTSUP;
		goto done;
	}
#endif

	/* Prepare the firmware for operation */
	rc = prep_firmware(sc);
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
	 * Number of VIs to create per-port.  The first VI is the "main" regular
	 * VI for the port.  The rest are additional virtual interfaces on the
	 * same physical port.  Note that the main VI does not have native
	 * netmap support but the extra VIs do.
	 *
	 * Limit the number of VIs per port to the number of available
	 * MAC addresses per port.
	 */
	if (t4_num_vis >= 1)
		num_vis = t4_num_vis;
	else
		num_vis = 1;
	if (num_vis > nitems(vi_mac_funcs)) {
		num_vis = nitems(vi_mac_funcs);
		device_printf(dev, "Number of VIs limited to %d\n", num_vis);
	}

	/*
	 * First pass over all the ports - allocate VIs and initialize some
	 * basic parameters like mac address, port type, etc.  We also figure
	 * out whether a port is 10G or 1G and use that information when
	 * calculating how many interrupts to attempt to allocate.
	 */
	n10g = n1g = 0;
	for_each_port(sc, i) {
		struct port_info *pi;

		pi = malloc(sizeof(*pi), M_CXGBE, M_ZERO | M_WAITOK);
		sc->port[i] = pi;

		/* These must be set before t4_port_init */
		pi->adapter = sc;
		pi->port_id = i;
		/*
		 * XXX: vi[0] is special so we can't delay this allocation until
		 * pi->nvi's final value is known.
		 */
		pi->vi = malloc(sizeof(struct vi_info) * num_vis, M_CXGBE,
		    M_ZERO | M_WAITOK);

		/*
		 * Allocate the "main" VI and initialize parameters
		 * like mac addr.
		 */
		rc = -t4_port_init(sc, sc->mbox, sc->pf, 0, i);
		if (rc != 0) {
			device_printf(dev, "unable to initialize port %d: %d\n",
			    i, rc);
			free(pi->vi, M_CXGBE);
			free(pi, M_CXGBE);
			sc->port[i] = NULL;
			goto done;
		}

		pi->link_cfg.requested_fc &= ~(PAUSE_TX | PAUSE_RX);
		pi->link_cfg.requested_fc |= t4_pause_settings;
		pi->link_cfg.fc &= ~(PAUSE_TX | PAUSE_RX);
		pi->link_cfg.fc |= t4_pause_settings;

		rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan, &pi->link_cfg);
		if (rc != 0) {
			device_printf(dev, "port %d l1cfg failed: %d\n", i, rc);
			free(pi->vi, M_CXGBE);
			free(pi, M_CXGBE);
			sc->port[i] = NULL;
			goto done;
		}

		snprintf(pi->lockname, sizeof(pi->lockname), "%sp%d",
		    device_get_nameunit(dev), i);
		mtx_init(&pi->pi_lock, pi->lockname, 0, MTX_DEF);
		sc->chan_map[pi->tx_chan] = i;

		pi->tc = malloc(sizeof(struct tx_sched_class) *
		    sc->chip_params->nsched_cls, M_CXGBE, M_ZERO | M_WAITOK);

		if (port_top_speed(pi) >= 10) {
			n10g++;
		} else {
			n1g++;
		}

		pi->linkdnrc = -1;

		pi->dev = device_add_child(dev, sc->names->ifnet_name, -1);
		if (pi->dev == NULL) {
			device_printf(dev,
			    "failed to add device for port %d.\n", i);
			rc = ENXIO;
			goto done;
		}
		pi->vi[0].dev = pi->dev;
		device_set_softc(pi->dev, pi);
	}

	/*
	 * Interrupt type, # of interrupts, # of rx/tx queues, etc.
	 */
	rc = cfg_itype_and_nqueues(sc, n10g, n1g, num_vis, &iaq);
	if (rc != 0)
		goto done; /* error message displayed already */
	if (iaq.nrxq_vi + iaq.nofldrxq_vi + iaq.nnmrxq_vi == 0)
		num_vis = 1;

	sc->intr_type = iaq.intr_type;
	sc->intr_count = iaq.nirq;

	s = &sc->sge;
	s->nrxq = n10g * iaq.nrxq10g + n1g * iaq.nrxq1g;
	s->ntxq = n10g * iaq.ntxq10g + n1g * iaq.ntxq1g;
	if (num_vis > 1) {
		s->nrxq += (n10g + n1g) * (num_vis - 1) * iaq.nrxq_vi;
		s->ntxq += (n10g + n1g) * (num_vis - 1) * iaq.ntxq_vi;
	}
	s->neq = s->ntxq + s->nrxq;	/* the free list in an rxq is an eq */
	s->neq += sc->params.nports + 1;/* ctrl queues: 1 per port + 1 mgmt */
	s->niq = s->nrxq + 1;		/* 1 extra for firmware event queue */
#ifdef TCP_OFFLOAD
	if (is_offload(sc)) {
		s->nofldrxq = n10g * iaq.nofldrxq10g + n1g * iaq.nofldrxq1g;
		s->nofldtxq = n10g * iaq.nofldtxq10g + n1g * iaq.nofldtxq1g;
		if (num_vis > 1) {
			s->nofldrxq += (n10g + n1g) * (num_vis - 1) *
			    iaq.nofldrxq_vi;
			s->nofldtxq += (n10g + n1g) * (num_vis - 1) *
			    iaq.nofldtxq_vi;
		}
		s->neq += s->nofldtxq + s->nofldrxq;
		s->niq += s->nofldrxq;

		s->ofld_rxq = malloc(s->nofldrxq * sizeof(struct sge_ofld_rxq),
		    M_CXGBE, M_ZERO | M_WAITOK);
		s->ofld_txq = malloc(s->nofldtxq * sizeof(struct sge_wrq),
		    M_CXGBE, M_ZERO | M_WAITOK);
	}
#endif
#ifdef DEV_NETMAP
	if (num_vis > 1) {
		s->nnmrxq = (n10g + n1g) * (num_vis - 1) * iaq.nnmrxq_vi;
		s->nnmtxq = (n10g + n1g) * (num_vis - 1) * iaq.nnmtxq_vi;
	}
	s->neq += s->nnmtxq + s->nnmrxq;
	s->niq += s->nnmrxq;

	s->nm_rxq = malloc(s->nnmrxq * sizeof(struct sge_nm_rxq),
	    M_CXGBE, M_ZERO | M_WAITOK);
	s->nm_txq = malloc(s->nnmtxq * sizeof(struct sge_nm_txq),
	    M_CXGBE, M_ZERO | M_WAITOK);
#endif

	s->ctrlq = malloc(sc->params.nports * sizeof(struct sge_wrq), M_CXGBE,
	    M_ZERO | M_WAITOK);
	s->rxq = malloc(s->nrxq * sizeof(struct sge_rxq), M_CXGBE,
	    M_ZERO | M_WAITOK);
	s->txq = malloc(s->ntxq * sizeof(struct sge_txq), M_CXGBE,
	    M_ZERO | M_WAITOK);
	s->iqmap = malloc(s->niq * sizeof(struct sge_iq *), M_CXGBE,
	    M_ZERO | M_WAITOK);
	s->eqmap = malloc(s->neq * sizeof(struct sge_eq *), M_CXGBE,
	    M_ZERO | M_WAITOK);

	sc->irq = malloc(sc->intr_count * sizeof(struct irq), M_CXGBE,
	    M_ZERO | M_WAITOK);

	t4_init_l2t(sc, M_WAITOK);

	/*
	 * Second pass over the ports.  This time we know the number of rx and
	 * tx queues that each port should get.
	 */
	rqidx = tqidx = 0;
#ifdef TCP_OFFLOAD
	ofld_rqidx = ofld_tqidx = 0;
#endif
#ifdef DEV_NETMAP
	nm_rqidx = nm_tqidx = 0;
#endif
	for_each_port(sc, i) {
		struct port_info *pi = sc->port[i];
		struct vi_info *vi;

		if (pi == NULL)
			continue;

		pi->nvi = num_vis;
		for_each_vi(pi, j, vi) {
			vi->pi = pi;
			vi->qsize_rxq = t4_qsize_rxq;
			vi->qsize_txq = t4_qsize_txq;

			vi->first_rxq = rqidx;
			vi->first_txq = tqidx;
			if (port_top_speed(pi) >= 10) {
				vi->tmr_idx = t4_tmr_idx_10g;
				vi->pktc_idx = t4_pktc_idx_10g;
				vi->flags |= iaq.intr_flags_10g & INTR_RXQ;
				vi->nrxq = j == 0 ? iaq.nrxq10g : iaq.nrxq_vi;
				vi->ntxq = j == 0 ? iaq.ntxq10g : iaq.ntxq_vi;
			} else {
				vi->tmr_idx = t4_tmr_idx_1g;
				vi->pktc_idx = t4_pktc_idx_1g;
				vi->flags |= iaq.intr_flags_1g & INTR_RXQ;
				vi->nrxq = j == 0 ? iaq.nrxq1g : iaq.nrxq_vi;
				vi->ntxq = j == 0 ? iaq.ntxq1g : iaq.ntxq_vi;
			}
			rqidx += vi->nrxq;
			tqidx += vi->ntxq;

			if (j == 0 && vi->ntxq > 1)
				vi->rsrv_noflowq = iaq.rsrv_noflowq ? 1 : 0;
			else
				vi->rsrv_noflowq = 0;

#ifdef TCP_OFFLOAD
			vi->first_ofld_rxq = ofld_rqidx;
			vi->first_ofld_txq = ofld_tqidx;
			if (port_top_speed(pi) >= 10) {
				vi->flags |= iaq.intr_flags_10g & INTR_OFLD_RXQ;
				vi->nofldrxq = j == 0 ? iaq.nofldrxq10g :
				    iaq.nofldrxq_vi;
				vi->nofldtxq = j == 0 ? iaq.nofldtxq10g :
				    iaq.nofldtxq_vi;
			} else {
				vi->flags |= iaq.intr_flags_1g & INTR_OFLD_RXQ;
				vi->nofldrxq = j == 0 ? iaq.nofldrxq1g :
				    iaq.nofldrxq_vi;
				vi->nofldtxq = j == 0 ? iaq.nofldtxq1g :
				    iaq.nofldtxq_vi;
			}
			ofld_rqidx += vi->nofldrxq;
			ofld_tqidx += vi->nofldtxq;
#endif
#ifdef DEV_NETMAP
			if (j > 0) {
				vi->first_nm_rxq = nm_rqidx;
				vi->first_nm_txq = nm_tqidx;
				vi->nnmrxq = iaq.nnmrxq_vi;
				vi->nnmtxq = iaq.nnmtxq_vi;
				nm_rqidx += vi->nnmrxq;
				nm_tqidx += vi->nnmtxq;
			}
#endif
		}
	}

	rc = t4_setup_intr_handlers(sc);
	if (rc != 0) {
		device_printf(dev,
		    "failed to setup interrupt handlers: %d\n", rc);
		goto done;
	}

	rc = bus_generic_attach(dev);
	if (rc != 0) {
		device_printf(dev,
		    "failed to attach all child ports: %d\n", rc);
		goto done;
	}

	device_printf(dev,
	    "PCIe gen%d x%d, %d ports, %d %s interrupt%s, %d eq, %d iq\n",
	    sc->params.pci.speed, sc->params.pci.width, sc->params.nports,
	    sc->intr_count, sc->intr_type == INTR_MSIX ? "MSI-X" :
	    (sc->intr_type == INTR_MSI ? "MSI" : "INTx"),
	    sc->intr_count > 1 ? "s" : "", sc->sge.neq, sc->sge.niq);

	t4_set_desc(sc);

	notify_siblings(dev, 0);

done:
	if (rc != 0 && sc->cdev) {
		/* cdev was created and so cxgbetool works; recover that way. */
		device_printf(dev,
		    "error during attach, adapter is now in recovery mode.\n");
		rc = 0;
	}

	if (rc != 0)
		t4_detach_common(dev);
	else
		t4_sysctls(sc);

	return (rc);
}

static int
t4_ready(device_t dev)
{
	struct adapter *sc;

	sc = device_get_softc(dev);
	if (sc->flags & FW_OK)
		return (0);
	return (ENXIO);
}

static int
t4_read_port_device(device_t dev, int port, device_t *child)
{
	struct adapter *sc;
	struct port_info *pi;

	sc = device_get_softc(dev);
	if (port < 0 || port >= MAX_NPORTS)
		return (EINVAL);
	pi = sc->port[port];
	if (pi == NULL || pi->dev == NULL)
		return (ENXIO);
	*child = pi->dev;
	return (0);
}

static int
notify_siblings(device_t dev, int detaching)
{
	device_t sibling;
	int error, i;

	error = 0;
	for (i = 0; i < PCI_FUNCMAX; i++) {
		if (i == pci_get_function(dev))
			continue;
		sibling = pci_find_dbsf(pci_get_domain(dev), pci_get_bus(dev),
		    pci_get_slot(dev), i);
		if (sibling == NULL || !device_is_attached(sibling))
			continue;
		if (detaching)
			error = T4_DETACH_CHILD(sibling);
		else
			(void)T4_ATTACH_CHILD(sibling);
		if (error)
			break;
	}
	return (error);
}

/*
 * Idempotent
 */
static int
t4_detach(device_t dev)
{
	struct adapter *sc;
	int rc;

	sc = device_get_softc(dev);

	rc = notify_siblings(dev, 1);
	if (rc) {
		device_printf(dev,
		    "failed to detach sibling devices: %d\n", rc);
		return (rc);
	}

	return (t4_detach_common(dev));
}

static int
vcxgbe_probe(device_t dev)
{
	char buf[128];
	struct vi_info *vi = device_get_softc(dev);

	snprintf(buf, sizeof(buf), "port %d vi %td", vi->pi->port_id,
	    vi - vi->pi->vi);
	device_set_desc_copy(dev, buf);

	return (BUS_PROBE_DEFAULT);
}

static int
vcxgbe_attach(device_t dev)
{
	struct vi_info *vi;
	struct port_info *pi;
	struct adapter *sc;
	int func, index, rc;
	u32 param, val;

	vi = device_get_softc(dev);
	pi = vi->pi;
	sc = pi->adapter;

	index = vi - pi->vi;
	KASSERT(index < nitems(vi_mac_funcs),
	    ("%s: VI %s doesn't have a MAC func", __func__,
	    device_get_nameunit(dev)));
	func = vi_mac_funcs[index];
	rc = t4_alloc_vi_func(sc, sc->mbox, pi->tx_chan, sc->pf, 0, 1,
	    vi->hw_addr, &vi->rss_size, func, 0);
	if (rc < 0) {
		device_printf(dev, "Failed to allocate virtual interface "
		    "for port %d: %d\n", pi->port_id, -rc);
		return (-rc);
	}
	vi->viid = rc;
	if (chip_id(sc) <= CHELSIO_T5)
		vi->smt_idx = (rc & 0x7f) << 1;
	else
		vi->smt_idx = (rc & 0x7f);

	param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_RSSINFO) |
	    V_FW_PARAMS_PARAM_YZ(vi->viid);
	rc = t4_query_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
	if (rc)
		vi->rss_base = 0xffff;
	else {
		/* MPASS((val >> 16) == rss_size); */
		vi->rss_base = val & 0xffff;
	}

	rc = cxgbe_vi_attach(dev, vi);
	if (rc) {
		t4_free_vi(sc, sc->mbox, sc->pf, 0, vi->viid);
		return (rc);
	}
	return (0);
}

static int
vcxgbe_detach(device_t dev)
{
	struct vi_info *vi;
	struct adapter *sc;

	vi = device_get_softc(dev);
	sc = vi->pi->adapter;

	doom_vi(sc, vi);

	cxgbe_vi_detach(vi);
	t4_free_vi(sc, sc->mbox, sc->pf, 0, vi->viid);

	end_synchronized_op(sc, 0);

	return (0);
}

struct memwin_init {
	uint32_t base;
	uint32_t aperture;
};

static const struct memwin_init t4_memwin[NUM_MEMWIN] = {
	{ MEMWIN0_BASE, MEMWIN0_APERTURE },
	{ MEMWIN1_BASE, MEMWIN1_APERTURE },
	{ MEMWIN2_BASE_T4, MEMWIN2_APERTURE_T4 }
};

static const struct memwin_init t5_memwin[NUM_MEMWIN] = {
	{ MEMWIN0_BASE, MEMWIN0_APERTURE },
	{ MEMWIN1_BASE, MEMWIN1_APERTURE },
	{ MEMWIN2_BASE_T5, MEMWIN2_APERTURE_T5 },
};

static void
setup_memwin(struct adapter *sc)
{
	const struct memwin_init *mw_init;
	struct memwin *mw;
	int i;
	uint32_t bar0;

	if (is_t4(sc)) {
		/*
		 * Read low 32b of bar0 indirectly via the hardware backdoor
		 * mechanism.  Works from within PCI passthrough environments
		 * too, where rman_get_start() can return a different value.  We
		 * need to program the T4 memory window decoders with the actual
		 * addresses that will be coming across the PCIe link.
		 */
		bar0 = t4_hw_pci_read_cfg4(sc, PCIR_BAR(0));
		bar0 &= (uint32_t) PCIM_BAR_MEM_BASE;

		mw_init = &t4_memwin[0];
	} else {
		/* T5+ use the relative offset inside the PCIe BAR */
		bar0 = 0;

		mw_init = &t5_memwin[0];
	}

	for (i = 0, mw = &sc->memwin[0]; i < NUM_MEMWIN; i++, mw_init++, mw++) {
		rw_init(&mw->mw_lock, "memory window access");
		mw->mw_base = mw_init->base;
		mw->mw_aperture = mw_init->aperture;
		mw->mw_curpos = 0;
		t4_write_reg(sc,
		    PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, i),
		    (mw->mw_base + bar0) | V_BIR(0) |
		    V_WINDOW(ilog2(mw->mw_aperture) - 10));
		rw_wlock(&mw->mw_lock);
		position_memwin(sc, i, 0);
		rw_wunlock(&mw->mw_lock);
	}

	/* flush */
	t4_read_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 2));
}

/*
 * Positions the memory window at the given address in the card's address space.
 * There are some alignment requirements and the actual position may be at an
 * address prior to the requested address.  mw->mw_curpos always has the actual
 * position of the window.
 */
static void
position_memwin(struct adapter *sc, int idx, uint32_t addr)
{
	struct memwin *mw;
	uint32_t pf;
	uint32_t reg;

	MPASS(idx >= 0 && idx < NUM_MEMWIN);
	mw = &sc->memwin[idx];
	rw_assert(&mw->mw_lock, RA_WLOCKED);

	if (is_t4(sc)) {
		pf = 0;
		mw->mw_curpos = addr & ~0xf;	/* start must be 16B aligned */
	} else {
		pf = V_PFNUM(sc->pf);
		mw->mw_curpos = addr & ~0x7f;	/* start must be 128B aligned */
	}
	reg = PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, idx);
	t4_write_reg(sc, reg, mw->mw_curpos | pf);
	t4_read_reg(sc, reg);	/* flush */
}

static int
rw_via_memwin(struct adapter *sc, int idx, uint32_t addr, uint32_t *val,
    int len, int rw)
{
	struct memwin *mw;
	uint32_t mw_end, v;

	MPASS(idx >= 0 && idx < NUM_MEMWIN);

	/* Memory can only be accessed in naturally aligned 4 byte units */
	if (addr & 3 || len & 3 || len <= 0)
		return (EINVAL);

	mw = &sc->memwin[idx];
	while (len > 0) {
		rw_rlock(&mw->mw_lock);
		mw_end = mw->mw_curpos + mw->mw_aperture;
		if (addr >= mw_end || addr < mw->mw_curpos) {
			/* Will need to reposition the window */
			if (!rw_try_upgrade(&mw->mw_lock)) {
				rw_runlock(&mw->mw_lock);
				rw_wlock(&mw->mw_lock);
			}
			rw_assert(&mw->mw_lock, RA_WLOCKED);
			position_memwin(sc, idx, addr);
			rw_downgrade(&mw->mw_lock);
			mw_end = mw->mw_curpos + mw->mw_aperture;
		}
		rw_assert(&mw->mw_lock, RA_RLOCKED);
		while (addr < mw_end && len > 0) {
			if (rw == 0) {
				v = t4_read_reg(sc, mw->mw_base + addr -
				    mw->mw_curpos);
				*val++ = le32toh(v);
			} else {
				v = *val++;
				t4_write_reg(sc, mw->mw_base + addr -
				    mw->mw_curpos, htole32(v));
			}
			addr += 4;
			len -= 4;
		}
		rw_runlock(&mw->mw_lock);
	}

	return (0);
}

static inline int
read_via_memwin(struct adapter *sc, int idx, uint32_t addr, uint32_t *val,
    int len)
{

	return (rw_via_memwin(sc, idx, addr, val, len, 0));
}

static inline int
write_via_memwin(struct adapter *sc, int idx, uint32_t addr,
    const uint32_t *val, int len)
{

	return (rw_via_memwin(sc, idx, addr, (void *)(uintptr_t)val, len, 1));
}

static int
t4_range_cmp(const void *a, const void *b)
{
	return ((const struct t4_range *)a)->start -
	       ((const struct t4_range *)b)->start;
}

/*
 * Verify that the memory range specified by the addr/len pair is valid within
 * the card's address space.
 */
static int
validate_mem_range(struct adapter *sc, uint32_t addr, int len)
{
	struct t4_range mem_ranges[4], *r, *next;
	uint32_t em, addr_len;
	int i, n, remaining;

	/* Memory can only be accessed in naturally aligned 4 byte units */
	if (addr & 3 || len & 3 || len <= 0)
		return (EINVAL);

	/* Enabled memories */
	em = t4_read_reg(sc, A_MA_TARGET_MEM_ENABLE);

	r = &mem_ranges[0];
	n = 0;
	bzero(r, sizeof(mem_ranges));
	if (em & F_EDRAM0_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EDRAM0_BAR);
		r->size = G_EDRAM0_SIZE(addr_len) << 20;
		if (r->size > 0) {
			r->start = G_EDRAM0_BASE(addr_len) << 20;
			if (addr >= r->start &&
			    addr + len <= r->start + r->size)
				return (0);
			r++;
			n++;
		}
	}
	if (em & F_EDRAM1_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EDRAM1_BAR);
		r->size = G_EDRAM1_SIZE(addr_len) << 20;
		if (r->size > 0) {
			r->start = G_EDRAM1_BASE(addr_len) << 20;
			if (addr >= r->start &&
			    addr + len <= r->start + r->size)
				return (0);
			r++;
			n++;
		}
	}
	if (em & F_EXT_MEM_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY_BAR);
		r->size = G_EXT_MEM_SIZE(addr_len) << 20;
		if (r->size > 0) {
			r->start = G_EXT_MEM_BASE(addr_len) << 20;
			if (addr >= r->start &&
			    addr + len <= r->start + r->size)
				return (0);
			r++;
			n++;
		}
	}
	if (is_t5(sc) && em & F_EXT_MEM1_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY1_BAR);
		r->size = G_EXT_MEM1_SIZE(addr_len) << 20;
		if (r->size > 0) {
			r->start = G_EXT_MEM1_BASE(addr_len) << 20;
			if (addr >= r->start &&
			    addr + len <= r->start + r->size)
				return (0);
			r++;
			n++;
		}
	}
	MPASS(n <= nitems(mem_ranges));

	if (n > 1) {
		/* Sort and merge the ranges. */
		qsort(mem_ranges, n, sizeof(struct t4_range), t4_range_cmp);

		/* Start from index 0 and examine the next n - 1 entries. */
		r = &mem_ranges[0];
		for (remaining = n - 1; remaining > 0; remaining--, r++) {

			MPASS(r->size > 0);	/* r is a valid entry. */
			next = r + 1;
			MPASS(next->size > 0);	/* and so is the next one. */

			while (r->start + r->size >= next->start) {
				/* Merge the next one into the current entry. */
				r->size = max(r->start + r->size,
				    next->start + next->size) - r->start;
				n--;	/* One fewer entry in total. */
				if (--remaining == 0)
					goto done;	/* short circuit */
				next++;
			}
			if (next != r + 1) {
				/*
				 * Some entries were merged into r and next
				 * points to the first valid entry that couldn't
				 * be merged.
				 */
				MPASS(next->size > 0);	/* must be valid */
				memcpy(r + 1, next, remaining * sizeof(*r));
#ifdef INVARIANTS
				/*
				 * This so that the foo->size assertion in the
				 * next iteration of the loop do the right
				 * thing for entries that were pulled up and are
				 * no longer valid.
				 */
				MPASS(n < nitems(mem_ranges));
				bzero(&mem_ranges[n], (nitems(mem_ranges) - n) *
				    sizeof(struct t4_range));
#endif
			}
		}
done:
		/* Done merging the ranges. */
		MPASS(n > 0);
		r = &mem_ranges[0];
		for (i = 0; i < n; i++, r++) {
			if (addr >= r->start &&
			    addr + len <= r->start + r->size)
				return (0);
		}
	}

	return (EFAULT);
}

static int
fwmtype_to_hwmtype(int mtype)
{

	switch (mtype) {
	case FW_MEMTYPE_EDC0:
		return (MEM_EDC0);
	case FW_MEMTYPE_EDC1:
		return (MEM_EDC1);
	case FW_MEMTYPE_EXTMEM:
		return (MEM_MC0);
	case FW_MEMTYPE_EXTMEM1:
		return (MEM_MC1);
	default:
		panic("%s: cannot translate fw mtype %d.", __func__, mtype);
	}
}

/*
 * Verify that the memory range specified by the memtype/offset/len pair is
 * valid and lies entirely within the memtype specified.  The global address of
 * the start of the range is returned in addr.
 */
static int
validate_mt_off_len(struct adapter *sc, int mtype, uint32_t off, int len,
    uint32_t *addr)
{
	uint32_t em, addr_len, maddr;

	/* Memory can only be accessed in naturally aligned 4 byte units */
	if (off & 3 || len & 3 || len == 0)
		return (EINVAL);

	em = t4_read_reg(sc, A_MA_TARGET_MEM_ENABLE);
	switch (fwmtype_to_hwmtype(mtype)) {
	case MEM_EDC0:
		if (!(em & F_EDRAM0_ENABLE))
			return (EINVAL);
		addr_len = t4_read_reg(sc, A_MA_EDRAM0_BAR);
		maddr = G_EDRAM0_BASE(addr_len) << 20;
		break;
	case MEM_EDC1:
		if (!(em & F_EDRAM1_ENABLE))
			return (EINVAL);
		addr_len = t4_read_reg(sc, A_MA_EDRAM1_BAR);
		maddr = G_EDRAM1_BASE(addr_len) << 20;
		break;
	case MEM_MC:
		if (!(em & F_EXT_MEM_ENABLE))
			return (EINVAL);
		addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY_BAR);
		maddr = G_EXT_MEM_BASE(addr_len) << 20;
		break;
	case MEM_MC1:
		if (!is_t5(sc) || !(em & F_EXT_MEM1_ENABLE))
			return (EINVAL);
		addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY1_BAR);
		maddr = G_EXT_MEM1_BASE(addr_len) << 20;
		break;
	default:
		return (EINVAL);
	}

	*addr = maddr + off;	/* global address */
	return (validate_mem_range(sc, *addr, len));
}

static int
fixup_devlog_params(struct adapter *sc)
{
	struct devlog_params *dparams = &sc->params.devlog;
	int rc;

	rc = validate_mt_off_len(sc, dparams->memtype, dparams->start,
	    dparams->size, &dparams->addr);

	return (rc);
}

static int
cfg_itype_and_nqueues(struct adapter *sc, int n10g, int n1g, int num_vis,
    struct intrs_and_queues *iaq)
{
	int rc, itype, navail, nrxq10g, nrxq1g, n;
	int nofldrxq10g = 0, nofldrxq1g = 0;

	bzero(iaq, sizeof(*iaq));

	iaq->ntxq10g = t4_ntxq10g;
	iaq->ntxq1g = t4_ntxq1g;
	iaq->ntxq_vi = t4_ntxq_vi;
	iaq->nrxq10g = nrxq10g = t4_nrxq10g;
	iaq->nrxq1g = nrxq1g = t4_nrxq1g;
	iaq->nrxq_vi = t4_nrxq_vi;
	iaq->rsrv_noflowq = t4_rsrv_noflowq;
#ifdef TCP_OFFLOAD
	if (is_offload(sc)) {
		iaq->nofldtxq10g = t4_nofldtxq10g;
		iaq->nofldtxq1g = t4_nofldtxq1g;
		iaq->nofldtxq_vi = t4_nofldtxq_vi;
		iaq->nofldrxq10g = nofldrxq10g = t4_nofldrxq10g;
		iaq->nofldrxq1g = nofldrxq1g = t4_nofldrxq1g;
		iaq->nofldrxq_vi = t4_nofldrxq_vi;
	}
#endif
#ifdef DEV_NETMAP
	iaq->nnmtxq_vi = t4_nnmtxq_vi;
	iaq->nnmrxq_vi = t4_nnmrxq_vi;
#endif

	for (itype = INTR_MSIX; itype; itype >>= 1) {

		if ((itype & t4_intr_types) == 0)
			continue;	/* not allowed */

		if (itype == INTR_MSIX)
			navail = pci_msix_count(sc->dev);
		else if (itype == INTR_MSI)
			navail = pci_msi_count(sc->dev);
		else
			navail = 1;
restart:
		if (navail == 0)
			continue;

		iaq->intr_type = itype;
		iaq->intr_flags_10g = 0;
		iaq->intr_flags_1g = 0;

		/*
		 * Best option: an interrupt vector for errors, one for the
		 * firmware event queue, and one for every rxq (NIC and TOE) of
		 * every VI.  The VIs that support netmap use the same
		 * interrupts for the NIC rx queues and the netmap rx queues
		 * because only one set of queues is active at a time.
		 */
		iaq->nirq = T4_EXTRA_INTR;
		iaq->nirq += n10g * (nrxq10g + nofldrxq10g);
		iaq->nirq += n1g * (nrxq1g + nofldrxq1g);
		iaq->nirq += (n10g + n1g) * (num_vis - 1) *
		    max(iaq->nrxq_vi, iaq->nnmrxq_vi);	/* See comment above. */
		iaq->nirq += (n10g + n1g) * (num_vis - 1) * iaq->nofldrxq_vi;
		if (iaq->nirq <= navail &&
		    (itype != INTR_MSI || powerof2(iaq->nirq))) {
			iaq->intr_flags_10g = INTR_ALL;
			iaq->intr_flags_1g = INTR_ALL;
			goto allocate;
		}

		/* Disable the VIs (and netmap) if there aren't enough intrs */
		if (num_vis > 1) {
			device_printf(sc->dev, "virtual interfaces disabled "
			    "because num_vis=%u with current settings "
			    "(nrxq10g=%u, nrxq1g=%u, nofldrxq10g=%u, "
			    "nofldrxq1g=%u, nrxq_vi=%u nofldrxq_vi=%u, "
			    "nnmrxq_vi=%u) would need %u interrupts but "
			    "only %u are available.\n", num_vis, nrxq10g,
			    nrxq1g, nofldrxq10g, nofldrxq1g, iaq->nrxq_vi,
			    iaq->nofldrxq_vi, iaq->nnmrxq_vi, iaq->nirq,
			    navail);
			num_vis = 1;
			iaq->ntxq_vi = iaq->nrxq_vi = 0;
			iaq->nofldtxq_vi = iaq->nofldrxq_vi = 0;
			iaq->nnmtxq_vi = iaq->nnmrxq_vi = 0;
			goto restart;
		}

		/*
		 * Second best option: a vector for errors, one for the firmware
		 * event queue, and vectors for either all the NIC rx queues or
		 * all the TOE rx queues.  The queues that don't get vectors
		 * will forward their interrupts to those that do.
		 */
		iaq->nirq = T4_EXTRA_INTR;
		if (nrxq10g >= nofldrxq10g) {
			iaq->intr_flags_10g = INTR_RXQ;
			iaq->nirq += n10g * nrxq10g;
		} else {
			iaq->intr_flags_10g = INTR_OFLD_RXQ;
			iaq->nirq += n10g * nofldrxq10g;
		}
		if (nrxq1g >= nofldrxq1g) {
			iaq->intr_flags_1g = INTR_RXQ;
			iaq->nirq += n1g * nrxq1g;
		} else {
			iaq->intr_flags_1g = INTR_OFLD_RXQ;
			iaq->nirq += n1g * nofldrxq1g;
		}
		if (iaq->nirq <= navail &&
		    (itype != INTR_MSI || powerof2(iaq->nirq)))
			goto allocate;

		/*
		 * Next best option: an interrupt vector for errors, one for the
		 * firmware event queue, and at least one per main-VI.  At this
		 * point we know we'll have to downsize nrxq and/or nofldrxq to
		 * fit what's available to us.
		 */
		iaq->nirq = T4_EXTRA_INTR;
		iaq->nirq += n10g + n1g;
		if (iaq->nirq <= navail) {
			int leftover = navail - iaq->nirq;

			if (n10g > 0) {
				int target = max(nrxq10g, nofldrxq10g);

				iaq->intr_flags_10g = nrxq10g >= nofldrxq10g ?
				    INTR_RXQ : INTR_OFLD_RXQ;

				n = 1;
				while (n < target && leftover >= n10g) {
					leftover -= n10g;
					iaq->nirq += n10g;
					n++;
				}
				iaq->nrxq10g = min(n, nrxq10g);
#ifdef TCP_OFFLOAD
				iaq->nofldrxq10g = min(n, nofldrxq10g);
#endif
			}

			if (n1g > 0) {
				int target = max(nrxq1g, nofldrxq1g);

				iaq->intr_flags_1g = nrxq1g >= nofldrxq1g ?
				    INTR_RXQ : INTR_OFLD_RXQ;

				n = 1;
				while (n < target && leftover >= n1g) {
					leftover -= n1g;
					iaq->nirq += n1g;
					n++;
				}
				iaq->nrxq1g = min(n, nrxq1g);
#ifdef TCP_OFFLOAD
				iaq->nofldrxq1g = min(n, nofldrxq1g);
#endif
			}

			if (itype != INTR_MSI || powerof2(iaq->nirq))
				goto allocate;
		}

		/*
		 * Least desirable option: one interrupt vector for everything.
		 */
		iaq->nirq = iaq->nrxq10g = iaq->nrxq1g = 1;
		iaq->intr_flags_10g = iaq->intr_flags_1g = 0;
#ifdef TCP_OFFLOAD
		if (is_offload(sc))
			iaq->nofldrxq10g = iaq->nofldrxq1g = 1;
#endif
allocate:
		navail = iaq->nirq;
		rc = 0;
		if (itype == INTR_MSIX)
			rc = pci_alloc_msix(sc->dev, &navail);
		else if (itype == INTR_MSI)
			rc = pci_alloc_msi(sc->dev, &navail);

		if (rc == 0) {
			if (navail == iaq->nirq)
				return (0);

			/*
			 * Didn't get the number requested.  Use whatever number
			 * the kernel is willing to allocate (it's in navail).
			 */
			device_printf(sc->dev, "fewer vectors than requested, "
			    "type=%d, req=%d, rcvd=%d; will downshift req.\n",
			    itype, iaq->nirq, navail);
			pci_release_msi(sc->dev);
			goto restart;
		}

		device_printf(sc->dev,
		    "failed to allocate vectors:%d, type=%d, req=%d, rcvd=%d\n",
		    itype, rc, iaq->nirq, navail);
	}

	device_printf(sc->dev,
	    "failed to find a usable interrupt type.  "
	    "allowed=%d, msi-x=%d, msi=%d, intx=1", t4_intr_types,
	    pci_msix_count(sc->dev), pci_msi_count(sc->dev));

	return (ENXIO);
}

#define FW_VERSION(chip) ( \
    V_FW_HDR_FW_VER_MAJOR(chip##FW_VERSION_MAJOR) | \
    V_FW_HDR_FW_VER_MINOR(chip##FW_VERSION_MINOR) | \
    V_FW_HDR_FW_VER_MICRO(chip##FW_VERSION_MICRO) | \
    V_FW_HDR_FW_VER_BUILD(chip##FW_VERSION_BUILD))
#define FW_INTFVER(chip, intf) (chip##FW_HDR_INTFVER_##intf)

struct fw_info {
	uint8_t chip;
	char *kld_name;
	char *fw_mod_name;
	struct fw_hdr fw_hdr;	/* XXX: waste of space, need a sparse struct */
} fw_info[] = {
	{
		.chip = CHELSIO_T4,
		.kld_name = "t4fw_cfg",
		.fw_mod_name = "t4fw",
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T4,
			.fw_ver = htobe32_const(FW_VERSION(T4)),
			.intfver_nic = FW_INTFVER(T4, NIC),
			.intfver_vnic = FW_INTFVER(T4, VNIC),
			.intfver_ofld = FW_INTFVER(T4, OFLD),
			.intfver_ri = FW_INTFVER(T4, RI),
			.intfver_iscsipdu = FW_INTFVER(T4, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T4, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T4, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T4, FCOE),
		},
	}, {
		.chip = CHELSIO_T5,
		.kld_name = "t5fw_cfg",
		.fw_mod_name = "t5fw",
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T5,
			.fw_ver = htobe32_const(FW_VERSION(T5)),
			.intfver_nic = FW_INTFVER(T5, NIC),
			.intfver_vnic = FW_INTFVER(T5, VNIC),
			.intfver_ofld = FW_INTFVER(T5, OFLD),
			.intfver_ri = FW_INTFVER(T5, RI),
			.intfver_iscsipdu = FW_INTFVER(T5, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T5, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T5, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T5, FCOE),
		},
	}, {
		.chip = CHELSIO_T6,
		.kld_name = "t6fw_cfg",
		.fw_mod_name = "t6fw",
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T6,
			.fw_ver = htobe32_const(FW_VERSION(T6)),
			.intfver_nic = FW_INTFVER(T6, NIC),
			.intfver_vnic = FW_INTFVER(T6, VNIC),
			.intfver_ofld = FW_INTFVER(T6, OFLD),
			.intfver_ri = FW_INTFVER(T6, RI),
			.intfver_iscsipdu = FW_INTFVER(T6, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T6, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T6, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T6, FCOE),
		},
	}
};

static struct fw_info *
find_fw_info(int chip)
{
	int i;

	for (i = 0; i < nitems(fw_info); i++) {
		if (fw_info[i].chip == chip)
			return (&fw_info[i]);
	}
	return (NULL);
}

/*
 * Is the given firmware API compatible with the one the driver was compiled
 * with?
 */
static int
fw_compatible(const struct fw_hdr *hdr1, const struct fw_hdr *hdr2)
{

	/* short circuit if it's the exact same firmware version */
	if (hdr1->chip == hdr2->chip && hdr1->fw_ver == hdr2->fw_ver)
		return (1);

	/*
	 * XXX: Is this too conservative?  Perhaps I should limit this to the
	 * features that are supported in the driver.
	 */
#define SAME_INTF(x) (hdr1->intfver_##x == hdr2->intfver_##x)
	if (hdr1->chip == hdr2->chip && SAME_INTF(nic) && SAME_INTF(vnic) &&
	    SAME_INTF(ofld) && SAME_INTF(ri) && SAME_INTF(iscsipdu) &&
	    SAME_INTF(iscsi) && SAME_INTF(fcoepdu) && SAME_INTF(fcoe))
		return (1);
#undef SAME_INTF

	return (0);
}

/*
 * The firmware in the KLD is usable, but should it be installed?  This routine
 * explains itself in detail if it indicates the KLD firmware should be
 * installed.
 */
static int
should_install_kld_fw(struct adapter *sc, int card_fw_usable, int k, int c)
{
	const char *reason;

	if (!card_fw_usable) {
		reason = "incompatible or unusable";
		goto install;
	}

	if (k > c) {
		reason = "older than the version bundled with this driver";
		goto install;
	}

	if (t4_fw_install == 2 && k != c) {
		reason = "different than the version bundled with this driver";
		goto install;
	}

	return (0);

install:
	if (t4_fw_install == 0) {
		device_printf(sc->dev, "firmware on card (%u.%u.%u.%u) is %s, "
		    "but the driver is prohibited from installing a different "
		    "firmware on the card.\n",
		    G_FW_HDR_FW_VER_MAJOR(c), G_FW_HDR_FW_VER_MINOR(c),
		    G_FW_HDR_FW_VER_MICRO(c), G_FW_HDR_FW_VER_BUILD(c), reason);

		return (0);
	}

	device_printf(sc->dev, "firmware on card (%u.%u.%u.%u) is %s, "
	    "installing firmware %u.%u.%u.%u on card.\n",
	    G_FW_HDR_FW_VER_MAJOR(c), G_FW_HDR_FW_VER_MINOR(c),
	    G_FW_HDR_FW_VER_MICRO(c), G_FW_HDR_FW_VER_BUILD(c), reason,
	    G_FW_HDR_FW_VER_MAJOR(k), G_FW_HDR_FW_VER_MINOR(k),
	    G_FW_HDR_FW_VER_MICRO(k), G_FW_HDR_FW_VER_BUILD(k));

	return (1);
}
/*
 * Establish contact with the firmware and determine if we are the master driver
 * or not, and whether we are responsible for chip initialization.
 */
static int
prep_firmware(struct adapter *sc)
{
	const struct firmware *fw = NULL, *default_cfg;
	int rc, pf, card_fw_usable, kld_fw_usable, need_fw_reset = 1;
	enum dev_state state;
	struct fw_info *fw_info;
	struct fw_hdr *card_fw;		/* fw on the card */
	const struct fw_hdr *kld_fw;	/* fw in the KLD */
	const struct fw_hdr *drv_fw;	/* fw header the driver was compiled
					   against */

	/* Contact firmware. */
	rc = t4_fw_hello(sc, sc->mbox, sc->mbox, MASTER_MAY, &state);
	if (rc < 0 || state == DEV_STATE_ERR) {
		rc = -rc;
		device_printf(sc->dev,
		    "failed to connect to the firmware: %d, %d.\n", rc, state);
		return (rc);
	}
	pf = rc;
	if (pf == sc->mbox)
		sc->flags |= MASTER_PF;
	else if (state == DEV_STATE_UNINIT) {
		/*
		 * We didn't get to be the master so we definitely won't be
		 * configuring the chip.  It's a bug if someone else hasn't
		 * configured it already.
		 */
		device_printf(sc->dev, "couldn't be master(%d), "
		    "device not already initialized either(%d).\n", rc, state);
		return (EDOOFUS);
	}

	/* This is the firmware whose headers the driver was compiled against */
	fw_info = find_fw_info(chip_id(sc));
	if (fw_info == NULL) {
		device_printf(sc->dev,
		    "unable to look up firmware information for chip %d.\n",
		    chip_id(sc));
		return (EINVAL);
	}
	drv_fw = &fw_info->fw_hdr;

	/*
	 * The firmware KLD contains many modules.  The KLD name is also the
	 * name of the module that contains the default config file.
	 */
	default_cfg = firmware_get(fw_info->kld_name);

	/* Read the header of the firmware on the card */
	card_fw = malloc(sizeof(*card_fw), M_CXGBE, M_ZERO | M_WAITOK);
	rc = -t4_read_flash(sc, FLASH_FW_START,
	    sizeof (*card_fw) / sizeof (uint32_t), (uint32_t *)card_fw, 1);
	if (rc == 0)
		card_fw_usable = fw_compatible(drv_fw, (const void*)card_fw);
	else {
		device_printf(sc->dev,
		    "Unable to read card's firmware header: %d\n", rc);
		card_fw_usable = 0;
	}

	/* This is the firmware in the KLD */
	fw = firmware_get(fw_info->fw_mod_name);
	if (fw != NULL) {
		kld_fw = (const void *)fw->data;
		kld_fw_usable = fw_compatible(drv_fw, kld_fw);
	} else {
		kld_fw = NULL;
		kld_fw_usable = 0;
	}

	if (card_fw_usable && card_fw->fw_ver == drv_fw->fw_ver &&
	    (!kld_fw_usable || kld_fw->fw_ver == drv_fw->fw_ver)) {
		/*
		 * Common case: the firmware on the card is an exact match and
		 * the KLD is an exact match too, or the KLD is
		 * absent/incompatible.  Note that t4_fw_install = 2 is ignored
		 * here -- use cxgbetool loadfw if you want to reinstall the
		 * same firmware as the one on the card.
		 */
	} else if (kld_fw_usable && state == DEV_STATE_UNINIT &&
	    should_install_kld_fw(sc, card_fw_usable, be32toh(kld_fw->fw_ver),
	    be32toh(card_fw->fw_ver))) {

		rc = -t4_fw_upgrade(sc, sc->mbox, fw->data, fw->datasize, 0);
		if (rc != 0) {
			device_printf(sc->dev,
			    "failed to install firmware: %d\n", rc);
			goto done;
		}

		/* Installed successfully, update the cached header too. */
		memcpy(card_fw, kld_fw, sizeof(*card_fw));
		card_fw_usable = 1;
		need_fw_reset = 0;	/* already reset as part of load_fw */
	}

	if (!card_fw_usable) {
		uint32_t d, c, k;

		d = ntohl(drv_fw->fw_ver);
		c = ntohl(card_fw->fw_ver);
		k = kld_fw ? ntohl(kld_fw->fw_ver) : 0;

		device_printf(sc->dev, "Cannot find a usable firmware: "
		    "fw_install %d, chip state %d, "
		    "driver compiled with %d.%d.%d.%d, "
		    "card has %d.%d.%d.%d, KLD has %d.%d.%d.%d\n",
		    t4_fw_install, state,
		    G_FW_HDR_FW_VER_MAJOR(d), G_FW_HDR_FW_VER_MINOR(d),
		    G_FW_HDR_FW_VER_MICRO(d), G_FW_HDR_FW_VER_BUILD(d),
		    G_FW_HDR_FW_VER_MAJOR(c), G_FW_HDR_FW_VER_MINOR(c),
		    G_FW_HDR_FW_VER_MICRO(c), G_FW_HDR_FW_VER_BUILD(c),
		    G_FW_HDR_FW_VER_MAJOR(k), G_FW_HDR_FW_VER_MINOR(k),
		    G_FW_HDR_FW_VER_MICRO(k), G_FW_HDR_FW_VER_BUILD(k));
		rc = EINVAL;
		goto done;
	}

	/* Reset device */
	if (need_fw_reset &&
	    (rc = -t4_fw_reset(sc, sc->mbox, F_PIORSTMODE | F_PIORST)) != 0) {
		device_printf(sc->dev, "firmware reset failed: %d.\n", rc);
		if (rc != ETIMEDOUT && rc != EIO)
			t4_fw_bye(sc, sc->mbox);
		goto done;
	}
	sc->flags |= FW_OK;

	rc = get_params__pre_init(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	/* Partition adapter resources as specified in the config file. */
	if (state == DEV_STATE_UNINIT) {

		KASSERT(sc->flags & MASTER_PF,
		    ("%s: trying to change chip settings when not master.",
		    __func__));

		rc = partition_resources(sc, default_cfg, fw_info->kld_name);
		if (rc != 0)
			goto done;	/* error message displayed already */

		t4_tweak_chip_settings(sc);

		/* get basic stuff going */
		rc = -t4_fw_initialize(sc, sc->mbox);
		if (rc != 0) {
			device_printf(sc->dev, "fw init failed: %d.\n", rc);
			goto done;
		}
	} else {
		snprintf(sc->cfg_file, sizeof(sc->cfg_file), "pf%d", pf);
		sc->cfcsum = 0;
	}

done:
	free(card_fw, M_CXGBE);
	if (fw != NULL)
		firmware_put(fw, FIRMWARE_UNLOAD);
	if (default_cfg != NULL)
		firmware_put(default_cfg, FIRMWARE_UNLOAD);

	return (rc);
}

#define FW_PARAM_DEV(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param))
#define FW_PARAM_PFVF(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param))

/*
 * Partition chip resources for use between various PFs, VFs, etc.
 */
static int
partition_resources(struct adapter *sc, const struct firmware *default_cfg,
    const char *name_prefix)
{
	const struct firmware *cfg = NULL;
	int rc = 0;
	struct fw_caps_config_cmd caps;
	uint32_t mtype, moff, finicsum, cfcsum;

	/*
	 * Figure out what configuration file to use.  Pick the default config
	 * file for the card if the user hasn't specified one explicitly.
	 */
	snprintf(sc->cfg_file, sizeof(sc->cfg_file), "%s", t4_cfg_file);
	if (strncmp(t4_cfg_file, DEFAULT_CF, sizeof(t4_cfg_file)) == 0) {
		/* Card specific overrides go here. */
		if (pci_get_device(sc->dev) == 0x440a)
			snprintf(sc->cfg_file, sizeof(sc->cfg_file), UWIRE_CF);
		if (is_fpga(sc))
			snprintf(sc->cfg_file, sizeof(sc->cfg_file), FPGA_CF);
	}

	/*
	 * We need to load another module if the profile is anything except
	 * "default" or "flash".
	 */
	if (strncmp(sc->cfg_file, DEFAULT_CF, sizeof(sc->cfg_file)) != 0 &&
	    strncmp(sc->cfg_file, FLASH_CF, sizeof(sc->cfg_file)) != 0) {
		char s[32];

		snprintf(s, sizeof(s), "%s_%s", name_prefix, sc->cfg_file);
		cfg = firmware_get(s);
		if (cfg == NULL) {
			if (default_cfg != NULL) {
				device_printf(sc->dev,
				    "unable to load module \"%s\" for "
				    "configuration profile \"%s\", will use "
				    "the default config file instead.\n",
				    s, sc->cfg_file);
				snprintf(sc->cfg_file, sizeof(sc->cfg_file),
				    "%s", DEFAULT_CF);
			} else {
				device_printf(sc->dev,
				    "unable to load module \"%s\" for "
				    "configuration profile \"%s\", will use "
				    "the config file on the card's flash "
				    "instead.\n", s, sc->cfg_file);
				snprintf(sc->cfg_file, sizeof(sc->cfg_file),
				    "%s", FLASH_CF);
			}
		}
	}

	if (strncmp(sc->cfg_file, DEFAULT_CF, sizeof(sc->cfg_file)) == 0 &&
	    default_cfg == NULL) {
		device_printf(sc->dev,
		    "default config file not available, will use the config "
		    "file on the card's flash instead.\n");
		snprintf(sc->cfg_file, sizeof(sc->cfg_file), "%s", FLASH_CF);
	}

	if (strncmp(sc->cfg_file, FLASH_CF, sizeof(sc->cfg_file)) != 0) {
		u_int cflen;
		const uint32_t *cfdata;
		uint32_t param, val, addr;

		KASSERT(cfg != NULL || default_cfg != NULL,
		    ("%s: no config to upload", __func__));

		/*
		 * Ask the firmware where it wants us to upload the config file.
		 */
		param = FW_PARAM_DEV(CF);
		rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
		if (rc != 0) {
			/* No support for config file?  Shouldn't happen. */
			device_printf(sc->dev,
			    "failed to query config file location: %d.\n", rc);
			goto done;
		}
		mtype = G_FW_PARAMS_PARAM_Y(val);
		moff = G_FW_PARAMS_PARAM_Z(val) << 16;

		/*
		 * XXX: sheer laziness.  We deliberately added 4 bytes of
		 * useless stuffing/comments at the end of the config file so
		 * it's ok to simply throw away the last remaining bytes when
		 * the config file is not an exact multiple of 4.  This also
		 * helps with the validate_mt_off_len check.
		 */
		if (cfg != NULL) {
			cflen = cfg->datasize & ~3;
			cfdata = cfg->data;
		} else {
			cflen = default_cfg->datasize & ~3;
			cfdata = default_cfg->data;
		}

		if (cflen > FLASH_CFG_MAX_SIZE) {
			device_printf(sc->dev,
			    "config file too long (%d, max allowed is %d).  "
			    "Will try to use the config on the card, if any.\n",
			    cflen, FLASH_CFG_MAX_SIZE);
			goto use_config_on_flash;
		}

		rc = validate_mt_off_len(sc, mtype, moff, cflen, &addr);
		if (rc != 0) {
			device_printf(sc->dev,
			    "%s: addr (%d/0x%x) or len %d is not valid: %d.  "
			    "Will try to use the config on the card, if any.\n",
			    __func__, mtype, moff, cflen, rc);
			goto use_config_on_flash;
		}
		write_via_memwin(sc, 2, addr, cfdata, cflen);
	} else {
use_config_on_flash:
		mtype = FW_MEMTYPE_FLASH;
		moff = t4_flash_cfg_addr(sc);
	}

	bzero(&caps, sizeof(caps));
	caps.op_to_write = htobe32(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_READ);
	caps.cfvalid_to_len16 = htobe32(F_FW_CAPS_CONFIG_CMD_CFVALID |
	    V_FW_CAPS_CONFIG_CMD_MEMTYPE_CF(mtype) |
	    V_FW_CAPS_CONFIG_CMD_MEMADDR64K_CF(moff >> 16) | FW_LEN16(caps));
	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof(caps), &caps);
	if (rc != 0) {
		device_printf(sc->dev,
		    "failed to pre-process config file: %d "
		    "(mtype %d, moff 0x%x).\n", rc, mtype, moff);
		goto done;
	}

	finicsum = be32toh(caps.finicsum);
	cfcsum = be32toh(caps.cfcsum);
	if (finicsum != cfcsum) {
		device_printf(sc->dev,
		    "WARNING: config file checksum mismatch: %08x %08x\n",
		    finicsum, cfcsum);
	}
	sc->cfcsum = cfcsum;

#define LIMIT_CAPS(x) do { \
	caps.x &= htobe16(t4_##x##_allowed); \
} while (0)

	/*
	 * Let the firmware know what features will (not) be used so it can tune
	 * things accordingly.
	 */
	LIMIT_CAPS(nbmcaps);
	LIMIT_CAPS(linkcaps);
	LIMIT_CAPS(switchcaps);
	LIMIT_CAPS(niccaps);
	LIMIT_CAPS(toecaps);
	LIMIT_CAPS(rdmacaps);
	LIMIT_CAPS(cryptocaps);
	LIMIT_CAPS(iscsicaps);
	LIMIT_CAPS(fcoecaps);
#undef LIMIT_CAPS

	caps.op_to_write = htobe32(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
	caps.cfvalid_to_len16 = htobe32(FW_LEN16(caps));
	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof(caps), NULL);
	if (rc != 0) {
		device_printf(sc->dev,
		    "failed to process config file: %d.\n", rc);
	}
done:
	if (cfg != NULL)
		firmware_put(cfg, FIRMWARE_UNLOAD);
	return (rc);
}

/*
 * Retrieve parameters that are needed (or nice to have) very early.
 */
static int
get_params__pre_init(struct adapter *sc)
{
	int rc;
	uint32_t param[2], val[2];

	t4_get_version_info(sc);

	snprintf(sc->fw_version, sizeof(sc->fw_version), "%u.%u.%u.%u",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.fw_vers));

	snprintf(sc->bs_version, sizeof(sc->bs_version), "%u.%u.%u.%u",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.bs_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.bs_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.bs_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.bs_vers));

	snprintf(sc->tp_version, sizeof(sc->tp_version), "%u.%u.%u.%u",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.tp_vers));

	snprintf(sc->er_version, sizeof(sc->er_version), "%u.%u.%u.%u",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.er_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.er_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.er_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.er_vers));

	param[0] = FW_PARAM_DEV(PORTVEC);
	param[1] = FW_PARAM_DEV(CCLK);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 2, param, val);
	if (rc != 0) {
		device_printf(sc->dev,
		    "failed to query parameters (pre_init): %d.\n", rc);
		return (rc);
	}

	sc->params.portvec = val[0];
	sc->params.nports = bitcount32(val[0]);
	sc->params.vpd.cclk = val[1];

	/* Read device log parameters. */
	rc = -t4_init_devlog_params(sc, 1);
	if (rc == 0)
		fixup_devlog_params(sc);
	else {
		device_printf(sc->dev,
		    "failed to get devlog parameters: %d.\n", rc);
		rc = 0;	/* devlog isn't critical for device operation */
	}

	return (rc);
}

/*
 * Retrieve various parameters that are of interest to the driver.  The device
 * has been initialized by the firmware at this point.
 */
static int
get_params__post_init(struct adapter *sc)
{
	int rc;
	uint32_t param[7], val[7];
	struct fw_caps_config_cmd caps;

	param[0] = FW_PARAM_PFVF(IQFLINT_START);
	param[1] = FW_PARAM_PFVF(EQ_START);
	param[2] = FW_PARAM_PFVF(FILTER_START);
	param[3] = FW_PARAM_PFVF(FILTER_END);
	param[4] = FW_PARAM_PFVF(L2T_START);
	param[5] = FW_PARAM_PFVF(L2T_END);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 6, param, val);
	if (rc != 0) {
		device_printf(sc->dev,
		    "failed to query parameters (post_init): %d.\n", rc);
		return (rc);
	}

	sc->sge.iq_start = val[0];
	sc->sge.eq_start = val[1];
	sc->tids.ftid_base = val[2];
	sc->tids.nftids = val[3] - val[2] + 1;
	sc->params.ftid_min = val[2];
	sc->params.ftid_max = val[3];
	sc->vres.l2t.start = val[4];
	sc->vres.l2t.size = val[5] - val[4] + 1;
	KASSERT(sc->vres.l2t.size <= L2T_SIZE,
	    ("%s: L2 table size (%u) larger than expected (%u)",
	    __func__, sc->vres.l2t.size, L2T_SIZE));

	/* get capabilites */
	bzero(&caps, sizeof(caps));
	caps.op_to_write = htobe32(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_READ);
	caps.cfvalid_to_len16 = htobe32(FW_LEN16(caps));
	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof(caps), &caps);
	if (rc != 0) {
		device_printf(sc->dev,
		    "failed to get card capabilities: %d.\n", rc);
		return (rc);
	}

#define READ_CAPS(x) do { \
	sc->x = htobe16(caps.x); \
} while (0)
	READ_CAPS(nbmcaps);
	READ_CAPS(linkcaps);
	READ_CAPS(switchcaps);
	READ_CAPS(niccaps);
	READ_CAPS(toecaps);
	READ_CAPS(rdmacaps);
	READ_CAPS(cryptocaps);
	READ_CAPS(iscsicaps);
	READ_CAPS(fcoecaps);

	if (sc->niccaps & FW_CAPS_CONFIG_NIC_ETHOFLD) {
		param[0] = FW_PARAM_PFVF(ETHOFLD_START);
		param[1] = FW_PARAM_PFVF(ETHOFLD_END);
		param[2] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
		rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 3, param, val);
		if (rc != 0) {
			device_printf(sc->dev,
			    "failed to query NIC parameters: %d.\n", rc);
			return (rc);
		}
		sc->tids.etid_base = val[0];
		sc->params.etid_min = val[0];
		sc->tids.netids = val[1] - val[0] + 1;
		sc->params.netids = sc->tids.netids;
		sc->params.eo_wr_cred = val[2];
		sc->params.ethoffload = 1;
	}

	if (sc->toecaps) {
		/* query offload-related parameters */
		param[0] = FW_PARAM_DEV(NTID);
		param[1] = FW_PARAM_PFVF(SERVER_START);
		param[2] = FW_PARAM_PFVF(SERVER_END);
		param[3] = FW_PARAM_PFVF(TDDP_START);
		param[4] = FW_PARAM_PFVF(TDDP_END);
		param[5] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
		rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 6, param, val);
		if (rc != 0) {
			device_printf(sc->dev,
			    "failed to query TOE parameters: %d.\n", rc);
			return (rc);
		}
		sc->tids.ntids = val[0];
		sc->tids.natids = min(sc->tids.ntids / 2, MAX_ATIDS);
		sc->tids.stid_base = val[1];
		sc->tids.nstids = val[2] - val[1] + 1;
		sc->vres.ddp.start = val[3];
		sc->vres.ddp.size = val[4] - val[3] + 1;
		sc->params.ofldq_wr_cred = val[5];
		sc->params.offload = 1;
	}
	if (sc->rdmacaps) {
		param[0] = FW_PARAM_PFVF(STAG_START);
		param[1] = FW_PARAM_PFVF(STAG_END);
		param[2] = FW_PARAM_PFVF(RQ_START);
		param[3] = FW_PARAM_PFVF(RQ_END);
		param[4] = FW_PARAM_PFVF(PBL_START);
		param[5] = FW_PARAM_PFVF(PBL_END);
		rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 6, param, val);
		if (rc != 0) {
			device_printf(sc->dev,
			    "failed to query RDMA parameters(1): %d.\n", rc);
			return (rc);
		}
		sc->vres.stag.start = val[0];
		sc->vres.stag.size = val[1] - val[0] + 1;
		sc->vres.rq.start = val[2];
		sc->vres.rq.size = val[3] - val[2] + 1;
		sc->vres.pbl.start = val[4];
		sc->vres.pbl.size = val[5] - val[4] + 1;

		param[0] = FW_PARAM_PFVF(SQRQ_START);
		param[1] = FW_PARAM_PFVF(SQRQ_END);
		param[2] = FW_PARAM_PFVF(CQ_START);
		param[3] = FW_PARAM_PFVF(CQ_END);
		param[4] = FW_PARAM_PFVF(OCQ_START);
		param[5] = FW_PARAM_PFVF(OCQ_END);
		rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 6, param, val);
		if (rc != 0) {
			device_printf(sc->dev,
			    "failed to query RDMA parameters(2): %d.\n", rc);
			return (rc);
		}
		sc->vres.qp.start = val[0];
		sc->vres.qp.size = val[1] - val[0] + 1;
		sc->vres.cq.start = val[2];
		sc->vres.cq.size = val[3] - val[2] + 1;
		sc->vres.ocq.start = val[4];
		sc->vres.ocq.size = val[5] - val[4] + 1;
	}
	if (sc->iscsicaps) {
		param[0] = FW_PARAM_PFVF(ISCSI_START);
		param[1] = FW_PARAM_PFVF(ISCSI_END);
		rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 2, param, val);
		if (rc != 0) {
			device_printf(sc->dev,
			    "failed to query iSCSI parameters: %d.\n", rc);
			return (rc);
		}
		sc->vres.iscsi.start = val[0];
		sc->vres.iscsi.size = val[1] - val[0] + 1;
	}

	t4_init_sge_params(sc);

	/*
	 * We've got the params we wanted to query via the firmware.  Now grab
	 * some others directly from the chip.
	 */
	rc = t4_read_chip_settings(sc);

	return (rc);
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

#undef FW_PARAM_PFVF
#undef FW_PARAM_DEV

static void
t4_set_desc(struct adapter *sc)
{
	char buf[128];
	struct adapter_params *p = &sc->params;

	snprintf(buf, sizeof(buf), "Chelsio %s", p->vpd.id);

	device_set_desc_copy(sc->dev, buf);
}

static void
get_regs(struct adapter *sc, struct t4_regdump *regs, uint8_t *buf)
{

	regs->version = chip_id(sc) | chip_rev(sc) << 10;
	t4_get_regs(sc, buf, regs->len);
}

static void
t4_clr_vi_stats(struct adapter *sc, unsigned int viid)
{
	int reg;

	t4_write_reg(sc, A_PL_INDIR_CMD, V_PL_AUTOINC(1) |
	    V_PL_VFID(G_FW_VIID_VIN(viid)) |
	    V_PL_ADDR(VF_MPS_REG(A_MPS_VF_STAT_TX_VF_BCAST_BYTES_L)));
	for (reg = A_MPS_VF_STAT_TX_VF_BCAST_BYTES_L;
	     reg <= A_MPS_VF_STAT_RX_VF_ERR_FRAMES_H; reg += 4)
		t4_write_reg(sc, A_PL_INDIR_DATA, 0);
}

static uint32_t
fconf_iconf_to_mode(uint32_t fconf, uint32_t iconf)
{
	uint32_t mode;

	mode = T4_FILTER_IPv4 | T4_FILTER_IPv6 | T4_FILTER_IP_SADDR |
	    T4_FILTER_IP_DADDR | T4_FILTER_IP_SPORT | T4_FILTER_IP_DPORT;

	if (fconf & F_FRAGMENTATION)
		mode |= T4_FILTER_IP_FRAGMENT;

	if (fconf & F_MPSHITTYPE)
		mode |= T4_FILTER_MPS_HIT_TYPE;

	if (fconf & F_MACMATCH)
		mode |= T4_FILTER_MAC_IDX;

	if (fconf & F_ETHERTYPE)
		mode |= T4_FILTER_ETH_TYPE;

	if (fconf & F_PROTOCOL)
		mode |= T4_FILTER_IP_PROTO;

	if (fconf & F_TOS)
		mode |= T4_FILTER_IP_TOS;

	if (fconf & F_VLAN)
		mode |= T4_FILTER_VLAN;

	if (fconf & F_VNIC_ID) {
		mode |= T4_FILTER_VNIC;
		if (iconf & F_VNIC)
			mode |= T4_FILTER_IC_VNIC;
	}

	if (fconf & F_PORT)
		mode |= T4_FILTER_PORT;

	if (fconf & F_FCOE)
		mode |= T4_FILTER_FCoE;

	return (mode);
}

static uint32_t
mode_to_fconf(uint32_t mode)
{
	uint32_t fconf = 0;

	if (mode & T4_FILTER_IP_FRAGMENT)
		fconf |= F_FRAGMENTATION;

	if (mode & T4_FILTER_MPS_HIT_TYPE)
		fconf |= F_MPSHITTYPE;

	if (mode & T4_FILTER_MAC_IDX)
		fconf |= F_MACMATCH;

	if (mode & T4_FILTER_ETH_TYPE)
		fconf |= F_ETHERTYPE;

	if (mode & T4_FILTER_IP_PROTO)
		fconf |= F_PROTOCOL;

	if (mode & T4_FILTER_IP_TOS)
		fconf |= F_TOS;

	if (mode & T4_FILTER_VLAN)
		fconf |= F_VLAN;

	if (mode & T4_FILTER_VNIC)
		fconf |= F_VNIC_ID;

	if (mode & T4_FILTER_PORT)
		fconf |= F_PORT;

	if (mode & T4_FILTER_FCoE)
		fconf |= F_FCOE;

	return (fconf);
}

static uint32_t
mode_to_iconf(uint32_t mode)
{

	if (mode & T4_FILTER_IC_VNIC)
		return (F_VNIC);
	return (0);
}

static int check_fspec_against_fconf_iconf(struct adapter *sc,
    struct t4_filter_specification *fs)
{
	struct tp_params *tpp = &sc->params.tp;
	uint32_t fconf = 0;

	if (fs->val.frag || fs->mask.frag)
		fconf |= F_FRAGMENTATION;

	if (fs->val.matchtype || fs->mask.matchtype)
		fconf |= F_MPSHITTYPE;

	if (fs->val.macidx || fs->mask.macidx)
		fconf |= F_MACMATCH;

	if (fs->val.ethtype || fs->mask.ethtype)
		fconf |= F_ETHERTYPE;

	if (fs->val.proto || fs->mask.proto)
		fconf |= F_PROTOCOL;

	if (fs->val.tos || fs->mask.tos)
		fconf |= F_TOS;

	if (fs->val.vlan_vld || fs->mask.vlan_vld)
		fconf |= F_VLAN;

	if (fs->val.ovlan_vld || fs->mask.ovlan_vld) {
		fconf |= F_VNIC_ID;
		if (tpp->ingress_config & F_VNIC)
			return (EINVAL);
	}

	if (fs->val.pfvf_vld || fs->mask.pfvf_vld) {
		fconf |= F_VNIC_ID;
		if ((tpp->ingress_config & F_VNIC) == 0)
			return (EINVAL);
	}

	if (fs->val.iport || fs->mask.iport)
		fconf |= F_PORT;

	if (fs->val.fcoe || fs->mask.fcoe)
		fconf |= F_FCOE;

	if ((tpp->vlan_pri_map | fconf) != tpp->vlan_pri_map)
		return (E2BIG);

	return (0);
}

static int
get_filter_mode(struct adapter *sc, uint32_t *mode)
{
	struct tp_params *tpp = &sc->params.tp;

	/*
	 * We trust the cached values of the relevant TP registers.  This means
	 * things work reliably only if writes to those registers are always via
	 * t4_set_filter_mode.
	 */
	*mode = fconf_iconf_to_mode(tpp->vlan_pri_map, tpp->ingress_config);

	return (0);
}

static int
set_filter_mode(struct adapter *sc, uint32_t mode)
{
	struct tp_params *tpp = &sc->params.tp;
	uint32_t fconf, iconf;
	int rc;

	iconf = mode_to_iconf(mode);
	if ((iconf ^ tpp->ingress_config) & F_VNIC) {
		/*
		 * For now we just complain if A_TP_INGRESS_CONFIG is not
		 * already set to the correct value for the requested filter
		 * mode.  It's not clear if it's safe to write to this register
		 * on the fly.  (And we trust the cached value of the register).
		 */
		return (EBUSY);
	}

	fconf = mode_to_fconf(mode);

	rc = begin_synchronized_op(sc, NULL, HOLD_LOCK | SLEEP_OK | INTR_OK,
	    "t4setfm");
	if (rc)
		return (rc);

	if (sc->tids.ftids_in_use > 0) {
		rc = EBUSY;
		goto done;
	}

#ifdef TCP_OFFLOAD
	if (uld_active(sc, ULD_TOM)) {
		rc = EBUSY;
		goto done;
	}
#endif

	rc = -t4_set_filter_mode(sc, fconf);
done:
	end_synchronized_op(sc, LOCK_HELD);
	return (rc);
}

static inline uint64_t
get_filter_hits(struct adapter *sc, uint32_t fid)
{
	uint32_t tcb_addr;

	tcb_addr = t4_read_reg(sc, A_TP_CMM_TCB_BASE) +
	    (fid + sc->tids.ftid_base) * TCB_SIZE;

	if (is_t4(sc)) {
		uint64_t hits;

		read_via_memwin(sc, 0, tcb_addr + 16, (uint32_t *)&hits, 8);
		return (be64toh(hits));
	} else {
		uint32_t hits;

		read_via_memwin(sc, 0, tcb_addr + 24, &hits, 4);
		return (be32toh(hits));
	}
}

static int
get_filter(struct adapter *sc, struct t4_filter *t)
{
	int i, rc, nfilters = sc->tids.nftids;
	struct filter_entry *f;

	rc = begin_synchronized_op(sc, NULL, HOLD_LOCK | SLEEP_OK | INTR_OK,
	    "t4getf");
	if (rc)
		return (rc);

	if (sc->tids.ftids_in_use == 0 || sc->tids.ftid_tab == NULL ||
	    t->idx >= nfilters) {
		t->idx = 0xffffffff;
		goto done;
	}

	f = &sc->tids.ftid_tab[t->idx];
	for (i = t->idx; i < nfilters; i++, f++) {
		if (f->valid) {
			t->idx = i;
			t->l2tidx = f->l2t ? f->l2t->idx : 0;
			t->smtidx = f->smtidx;
			if (f->fs.hitcnts)
				t->hits = get_filter_hits(sc, t->idx);
			else
				t->hits = UINT64_MAX;
			t->fs = f->fs;

			goto done;
		}
	}

	t->idx = 0xffffffff;
done:
	end_synchronized_op(sc, LOCK_HELD);
	return (0);
}

static int
set_filter(struct adapter *sc, struct t4_filter *t)
{
	unsigned int nfilters, nports;
	struct filter_entry *f;
	int i, rc;

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4setf");
	if (rc)
		return (rc);

	nfilters = sc->tids.nftids;
	nports = sc->params.nports;

	if (nfilters == 0) {
		rc = ENOTSUP;
		goto done;
	}

	if (t->idx >= nfilters) {
		rc = EINVAL;
		goto done;
	}

	/* Validate against the global filter mode and ingress config */
	rc = check_fspec_against_fconf_iconf(sc, &t->fs);
	if (rc != 0)
		goto done;

	if (t->fs.action == FILTER_SWITCH && t->fs.eport >= nports) {
		rc = EINVAL;
		goto done;
	}

	if (t->fs.val.iport >= nports) {
		rc = EINVAL;
		goto done;
	}

	/* Can't specify an iq if not steering to it */
	if (!t->fs.dirsteer && t->fs.iq) {
		rc = EINVAL;
		goto done;
	}

	/* IPv6 filter idx must be 4 aligned */
	if (t->fs.type == 1 &&
	    ((t->idx & 0x3) || t->idx + 4 >= nfilters)) {
		rc = EINVAL;
		goto done;
	}

	if (!(sc->flags & FULL_INIT_DONE) &&
	    ((rc = adapter_full_init(sc)) != 0))
		goto done;

	if (sc->tids.ftid_tab == NULL) {
		KASSERT(sc->tids.ftids_in_use == 0,
		    ("%s: no memory allocated but filters_in_use > 0",
		    __func__));

		sc->tids.ftid_tab = malloc(sizeof (struct filter_entry) *
		    nfilters, M_CXGBE, M_NOWAIT | M_ZERO);
		if (sc->tids.ftid_tab == NULL) {
			rc = ENOMEM;
			goto done;
		}
		mtx_init(&sc->tids.ftid_lock, "T4 filters", 0, MTX_DEF);
	}

	for (i = 0; i < 4; i++) {
		f = &sc->tids.ftid_tab[t->idx + i];

		if (f->pending || f->valid) {
			rc = EBUSY;
			goto done;
		}
		if (f->locked) {
			rc = EPERM;
			goto done;
		}

		if (t->fs.type == 0)
			break;
	}

	f = &sc->tids.ftid_tab[t->idx];
	f->fs = t->fs;

	rc = set_filter_wr(sc, t->idx);
done:
	end_synchronized_op(sc, 0);

	if (rc == 0) {
		mtx_lock(&sc->tids.ftid_lock);
		for (;;) {
			if (f->pending == 0) {
				rc = f->valid ? 0 : EIO;
				break;
			}

			if (mtx_sleep(&sc->tids.ftid_tab, &sc->tids.ftid_lock,
			    PCATCH, "t4setfw", 0)) {
				rc = EINPROGRESS;
				break;
			}
		}
		mtx_unlock(&sc->tids.ftid_lock);
	}
	return (rc);
}

static int
del_filter(struct adapter *sc, struct t4_filter *t)
{
	unsigned int nfilters;
	struct filter_entry *f;
	int rc;

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4delf");
	if (rc)
		return (rc);

	nfilters = sc->tids.nftids;

	if (nfilters == 0) {
		rc = ENOTSUP;
		goto done;
	}

	if (sc->tids.ftid_tab == NULL || sc->tids.ftids_in_use == 0 ||
	    t->idx >= nfilters) {
		rc = EINVAL;
		goto done;
	}

	if (!(sc->flags & FULL_INIT_DONE)) {
		rc = EAGAIN;
		goto done;
	}

	f = &sc->tids.ftid_tab[t->idx];

	if (f->pending) {
		rc = EBUSY;
		goto done;
	}
	if (f->locked) {
		rc = EPERM;
		goto done;
	}

	if (f->valid) {
		t->fs = f->fs;	/* extra info for the caller */
		rc = del_filter_wr(sc, t->idx);
	}

done:
	end_synchronized_op(sc, 0);

	if (rc == 0) {
		mtx_lock(&sc->tids.ftid_lock);
		for (;;) {
			if (f->pending == 0) {
				rc = f->valid ? EIO : 0;
				break;
			}

			if (mtx_sleep(&sc->tids.ftid_tab, &sc->tids.ftid_lock,
			    PCATCH, "t4delfw", 0)) {
				rc = EINPROGRESS;
				break;
			}
		}
		mtx_unlock(&sc->tids.ftid_lock);
	}

	return (rc);
}

static void
clear_filter(struct filter_entry *f)
{
	if (f->l2t)
		t4_l2t_release(f->l2t);

	bzero(f, sizeof (*f));
}

static int
set_filter_wr(struct adapter *sc, int fidx)
{
	struct filter_entry *f = &sc->tids.ftid_tab[fidx];
	struct fw_filter_wr *fwr;
	unsigned int ftid, vnic_vld, vnic_vld_mask;
	struct wrq_cookie cookie;

	ASSERT_SYNCHRONIZED_OP(sc);

	if (f->fs.newdmac || f->fs.newvlan) {
		/* This filter needs an L2T entry; allocate one. */
		f->l2t = t4_l2t_alloc_switching(sc->l2t);
		if (f->l2t == NULL)
			return (EAGAIN);
		if (t4_l2t_set_switching(sc, f->l2t, f->fs.vlan, f->fs.eport,
		    f->fs.dmac)) {
			t4_l2t_release(f->l2t);
			f->l2t = NULL;
			return (ENOMEM);
		}
	}

	/* Already validated against fconf, iconf */
	MPASS((f->fs.val.pfvf_vld & f->fs.val.ovlan_vld) == 0);
	MPASS((f->fs.mask.pfvf_vld & f->fs.mask.ovlan_vld) == 0);
	if (f->fs.val.pfvf_vld || f->fs.val.ovlan_vld)
		vnic_vld = 1;
	else
		vnic_vld = 0;
	if (f->fs.mask.pfvf_vld || f->fs.mask.ovlan_vld)
		vnic_vld_mask = 1;
	else
		vnic_vld_mask = 0;

	ftid = sc->tids.ftid_base + fidx;

	fwr = start_wrq_wr(&sc->sge.mgmtq, howmany(sizeof(*fwr), 16), &cookie);
	if (fwr == NULL)
		return (ENOMEM);
	bzero(fwr, sizeof(*fwr));

	fwr->op_pkd = htobe32(V_FW_WR_OP(FW_FILTER_WR));
	fwr->len16_pkd = htobe32(FW_LEN16(*fwr));
	fwr->tid_to_iq =
	    htobe32(V_FW_FILTER_WR_TID(ftid) |
		V_FW_FILTER_WR_RQTYPE(f->fs.type) |
		V_FW_FILTER_WR_NOREPLY(0) |
		V_FW_FILTER_WR_IQ(f->fs.iq));
	fwr->del_filter_to_l2tix =
	    htobe32(V_FW_FILTER_WR_RPTTID(f->fs.rpttid) |
		V_FW_FILTER_WR_DROP(f->fs.action == FILTER_DROP) |
		V_FW_FILTER_WR_DIRSTEER(f->fs.dirsteer) |
		V_FW_FILTER_WR_MASKHASH(f->fs.maskhash) |
		V_FW_FILTER_WR_DIRSTEERHASH(f->fs.dirsteerhash) |
		V_FW_FILTER_WR_LPBK(f->fs.action == FILTER_SWITCH) |
		V_FW_FILTER_WR_DMAC(f->fs.newdmac) |
		V_FW_FILTER_WR_SMAC(f->fs.newsmac) |
		V_FW_FILTER_WR_INSVLAN(f->fs.newvlan == VLAN_INSERT ||
		    f->fs.newvlan == VLAN_REWRITE) |
		V_FW_FILTER_WR_RMVLAN(f->fs.newvlan == VLAN_REMOVE ||
		    f->fs.newvlan == VLAN_REWRITE) |
		V_FW_FILTER_WR_HITCNTS(f->fs.hitcnts) |
		V_FW_FILTER_WR_TXCHAN(f->fs.eport) |
		V_FW_FILTER_WR_PRIO(f->fs.prio) |
		V_FW_FILTER_WR_L2TIX(f->l2t ? f->l2t->idx : 0));
	fwr->ethtype = htobe16(f->fs.val.ethtype);
	fwr->ethtypem = htobe16(f->fs.mask.ethtype);
	fwr->frag_to_ovlan_vldm =
	    (V_FW_FILTER_WR_FRAG(f->fs.val.frag) |
		V_FW_FILTER_WR_FRAGM(f->fs.mask.frag) |
		V_FW_FILTER_WR_IVLAN_VLD(f->fs.val.vlan_vld) |
		V_FW_FILTER_WR_OVLAN_VLD(vnic_vld) |
		V_FW_FILTER_WR_IVLAN_VLDM(f->fs.mask.vlan_vld) |
		V_FW_FILTER_WR_OVLAN_VLDM(vnic_vld_mask));
	fwr->smac_sel = 0;
	fwr->rx_chan_rx_rpl_iq = htobe16(V_FW_FILTER_WR_RX_CHAN(0) |
	    V_FW_FILTER_WR_RX_RPL_IQ(sc->sge.fwq.abs_id));
	fwr->maci_to_matchtypem =
	    htobe32(V_FW_FILTER_WR_MACI(f->fs.val.macidx) |
		V_FW_FILTER_WR_MACIM(f->fs.mask.macidx) |
		V_FW_FILTER_WR_FCOE(f->fs.val.fcoe) |
		V_FW_FILTER_WR_FCOEM(f->fs.mask.fcoe) |
		V_FW_FILTER_WR_PORT(f->fs.val.iport) |
		V_FW_FILTER_WR_PORTM(f->fs.mask.iport) |
		V_FW_FILTER_WR_MATCHTYPE(f->fs.val.matchtype) |
		V_FW_FILTER_WR_MATCHTYPEM(f->fs.mask.matchtype));
	fwr->ptcl = f->fs.val.proto;
	fwr->ptclm = f->fs.mask.proto;
	fwr->ttyp = f->fs.val.tos;
	fwr->ttypm = f->fs.mask.tos;
	fwr->ivlan = htobe16(f->fs.val.vlan);
	fwr->ivlanm = htobe16(f->fs.mask.vlan);
	fwr->ovlan = htobe16(f->fs.val.vnic);
	fwr->ovlanm = htobe16(f->fs.mask.vnic);
	bcopy(f->fs.val.dip, fwr->lip, sizeof (fwr->lip));
	bcopy(f->fs.mask.dip, fwr->lipm, sizeof (fwr->lipm));
	bcopy(f->fs.val.sip, fwr->fip, sizeof (fwr->fip));
	bcopy(f->fs.mask.sip, fwr->fipm, sizeof (fwr->fipm));
	fwr->lp = htobe16(f->fs.val.dport);
	fwr->lpm = htobe16(f->fs.mask.dport);
	fwr->fp = htobe16(f->fs.val.sport);
	fwr->fpm = htobe16(f->fs.mask.sport);
	if (f->fs.newsmac)
		bcopy(f->fs.smac, fwr->sma, sizeof (fwr->sma));

	f->pending = 1;
	sc->tids.ftids_in_use++;

	commit_wrq_wr(&sc->sge.mgmtq, fwr, &cookie);
	return (0);
}

static int
del_filter_wr(struct adapter *sc, int fidx)
{
	struct filter_entry *f = &sc->tids.ftid_tab[fidx];
	struct fw_filter_wr *fwr;
	unsigned int ftid;
	struct wrq_cookie cookie;

	ftid = sc->tids.ftid_base + fidx;

	fwr = start_wrq_wr(&sc->sge.mgmtq, howmany(sizeof(*fwr), 16), &cookie);
	if (fwr == NULL)
		return (ENOMEM);
	bzero(fwr, sizeof (*fwr));

	t4_mk_filtdelwr(ftid, fwr, sc->sge.fwq.abs_id);

	f->pending = 1;
	commit_wrq_wr(&sc->sge.mgmtq, fwr, &cookie);
	return (0);
}

static int
t4_filter_rpl(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_set_tcb_rpl *rpl = (const void *)(rss + 1);
	unsigned int idx = GET_TID(rpl);
	unsigned int rc;
	struct filter_entry *f;

	KASSERT(m == NULL, ("%s: payload with opcode %02x", __func__,
	    rss->opcode));
	MPASS(iq == &sc->sge.fwq);
	MPASS(is_ftid(sc, idx));

	idx -= sc->tids.ftid_base;
	f = &sc->tids.ftid_tab[idx];
	rc = G_COOKIE(rpl->cookie);

	mtx_lock(&sc->tids.ftid_lock);
	if (rc == FW_FILTER_WR_FLT_ADDED) {
		KASSERT(f->pending, ("%s: filter[%u] isn't pending.",
		    __func__, idx));
		f->smtidx = (be64toh(rpl->oldval) >> 24) & 0xff;
		f->pending = 0;  /* asynchronous setup completed */
		f->valid = 1;
	} else {
		if (rc != FW_FILTER_WR_FLT_DELETED) {
			/* Add or delete failed, display an error */
			log(LOG_ERR,
			    "filter %u setup failed with error %u\n",
			    idx, rc);
		}

		clear_filter(f);
		sc->tids.ftids_in_use--;
	}
	wakeup(&sc->tids.ftid_tab);
	mtx_unlock(&sc->tids.ftid_lock);

	return (0);
}

static int
set_tcb_rpl(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{

	MPASS(iq->set_tcb_rpl != NULL);
	return (iq->set_tcb_rpl(iq, rss, m));
}

static int
l2t_write_rpl(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{

	MPASS(iq->l2t_write_rpl != NULL);
	return (iq->l2t_write_rpl(iq, rss, m));
}

static int
get_sge_context(struct adapter *sc, struct t4_sge_context *cntxt)
{
	int rc;

	if (cntxt->cid > M_CTXTQID)
		return (EINVAL);

	if (cntxt->mem_id != CTXT_EGRESS && cntxt->mem_id != CTXT_INGRESS &&
	    cntxt->mem_id != CTXT_FLM && cntxt->mem_id != CTXT_CNM)
		return (EINVAL);

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4ctxt");
	if (rc)
		return (rc);

	if (sc->flags & FW_OK) {
		rc = -t4_sge_ctxt_rd(sc, sc->mbox, cntxt->cid, cntxt->mem_id,
		    &cntxt->data[0]);
		if (rc == 0)
			goto done;
	}

	/*
	 * Read via firmware failed or wasn't even attempted.  Read directly via
	 * the backdoor.
	 */
	rc = -t4_sge_ctxt_rd_bd(sc, cntxt->cid, cntxt->mem_id, &cntxt->data[0]);
done:
	end_synchronized_op(sc, 0);
	return (rc);
}

static int
load_fw(struct adapter *sc, struct t4_data *fw)
{
	int rc;
	uint8_t *fw_data;

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4ldfw");
	if (rc)
		return (rc);

	if (sc->flags & FULL_INIT_DONE) {
		rc = EBUSY;
		goto done;
	}

	fw_data = malloc(fw->len, M_CXGBE, M_WAITOK);
	if (fw_data == NULL) {
		rc = ENOMEM;
		goto done;
	}

	rc = copyin(fw->data, fw_data, fw->len);
	if (rc == 0)
		rc = -t4_load_fw(sc, fw_data, fw->len);

	free(fw_data, M_CXGBE);
done:
	end_synchronized_op(sc, 0);
	return (rc);
}

static int
load_cfg(struct adapter *sc, struct t4_data *cfg)
{
	int rc;
	uint8_t *cfg_data = NULL;

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4ldcf");
	if (rc)
		return (rc);

	if (cfg->len == 0) {
		/* clear */
		rc = -t4_load_cfg(sc, NULL, 0);
		goto done;
	}

	cfg_data = malloc(cfg->len, M_CXGBE, M_WAITOK);
	if (cfg_data == NULL) {
		rc = ENOMEM;
		goto done;
	}

	rc = copyin(cfg->data, cfg_data, cfg->len);
	if (rc == 0)
		rc = -t4_load_cfg(sc, cfg_data, cfg->len);

	free(cfg_data, M_CXGBE);
done:
	end_synchronized_op(sc, 0);
	return (rc);
}

#define MAX_READ_BUF_SIZE (128 * 1024)
static int
read_card_mem(struct adapter *sc, int win, struct t4_mem_range *mr)
{
	uint32_t addr, remaining, n;
	uint32_t *buf;
	int rc;
	uint8_t *dst;

	rc = validate_mem_range(sc, mr->addr, mr->len);
	if (rc != 0)
		return (rc);

	buf = malloc(min(mr->len, MAX_READ_BUF_SIZE), M_CXGBE, M_WAITOK);
	addr = mr->addr;
	remaining = mr->len;
	dst = (void *)mr->data;

	while (remaining) {
		n = min(remaining, MAX_READ_BUF_SIZE);
		read_via_memwin(sc, 2, addr, buf, n);

		rc = copyout(buf, dst, n);
		if (rc != 0)
			break;

		dst += n;
		remaining -= n;
		addr += n;
	}

	free(buf, M_CXGBE);
	return (rc);
}
#undef MAX_READ_BUF_SIZE

static int
read_i2c(struct adapter *sc, struct t4_i2c_data *i2cd)
{
	int rc;

	if (i2cd->len == 0 || i2cd->port_id >= sc->params.nports)
		return (EINVAL);

	if (i2cd->len > sizeof(i2cd->data))
		return (EFBIG);

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4i2crd");
	if (rc)
		return (rc);
	rc = -t4_i2c_rd(sc, sc->mbox, i2cd->port_id, i2cd->dev_addr,
	    i2cd->offset, i2cd->len, &i2cd->data[0]);
	end_synchronized_op(sc, 0);

	return (rc);
}

static int
t4_ioctl(struct cdev *dev, unsigned long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int rc;
	struct adapter *sc = dev->si_drv1;

	rc = priv_check(td, PRIV_DRIVER);
	if (rc != 0)
		return (rc);

	switch (cmd) {
	case CHELSIO_T4_GETREG: {
		struct t4_reg *edata = (struct t4_reg *)data;

		if ((edata->addr & 0x3) != 0 || edata->addr >= sc->mmio_len)
			return (EFAULT);

		if (edata->size == 4)
			edata->val = t4_read_reg(sc, edata->addr);
		else if (edata->size == 8)
			edata->val = t4_read_reg64(sc, edata->addr);
		else
			return (EINVAL);

		break;
	}
	case CHELSIO_T4_SETREG: {
		struct t4_reg *edata = (struct t4_reg *)data;

		if ((edata->addr & 0x3) != 0 || edata->addr >= sc->mmio_len)
			return (EFAULT);

		if (edata->size == 4) {
			if (edata->val & 0xffffffff00000000)
				return (EINVAL);
			t4_write_reg(sc, edata->addr, (uint32_t) edata->val);
		} else if (edata->size == 8)
			t4_write_reg64(sc, edata->addr, edata->val);
		else
			return (EINVAL);
		break;
	}
	case CHELSIO_T4_REGDUMP: {
		struct t4_regdump *regs = (struct t4_regdump *)data;
		int reglen = t4_get_regs_len(sc);
		uint8_t *buf;

		if (regs->len < reglen) {
			regs->len = reglen; /* hint to the caller */
			return (ENOBUFS);
		}

		regs->len = reglen;
		buf = malloc(reglen, M_CXGBE, M_WAITOK | M_ZERO);
		get_regs(sc, regs, buf);
		rc = copyout(buf, regs->data, reglen);
		free(buf, M_CXGBE);
		break;
	}
	case CHELSIO_T4_GET_FILTER_MODE:
		rc = get_filter_mode(sc, (uint32_t *)data);
		break;
	case CHELSIO_T4_SET_FILTER_MODE:
		rc = set_filter_mode(sc, *(uint32_t *)data);
		break;
	case CHELSIO_T4_GET_FILTER:
		rc = get_filter(sc, (struct t4_filter *)data);
		break;
	case CHELSIO_T4_SET_FILTER:
		rc = set_filter(sc, (struct t4_filter *)data);
		break;
	case CHELSIO_T4_DEL_FILTER:
		rc = del_filter(sc, (struct t4_filter *)data);
		break;
	case CHELSIO_T4_GET_SGE_CONTEXT:
		rc = get_sge_context(sc, (struct t4_sge_context *)data);
		break;
	case CHELSIO_T4_LOAD_FW:
		rc = load_fw(sc, (struct t4_data *)data);
		break;
	case CHELSIO_T4_GET_MEM:
		rc = read_card_mem(sc, 2, (struct t4_mem_range *)data);
		break;
	case CHELSIO_T4_GET_I2C:
		rc = read_i2c(sc, (struct t4_i2c_data *)data);
		break;
	case CHELSIO_T4_CLEAR_STATS: {
		int i, v;
		u_int port_id = *(uint32_t *)data;
		struct port_info *pi;
		struct vi_info *vi;

		if (port_id >= sc->params.nports)
			return (EINVAL);
		pi = sc->port[port_id];
		if (pi == NULL)
			return (EIO);

		/* MAC stats */
		t4_clr_port_stats(sc, pi->tx_chan);
		pi->tx_parse_error = 0;
		mtx_lock(&sc->reg_lock);
		for_each_vi(pi, v, vi) {
			if (vi->flags & VI_INIT_DONE)
				t4_clr_vi_stats(sc, vi->viid);
		}
		mtx_unlock(&sc->reg_lock);

		/*
		 * Since this command accepts a port, clear stats for
		 * all VIs on this port.
		 */
		for_each_vi(pi, v, vi) {
			if (vi->flags & VI_INIT_DONE) {
				struct sge_rxq *rxq;
				struct sge_txq *txq;
				struct sge_wrq *wrq;

				for_each_rxq(vi, i, rxq) {
#if defined(INET) || defined(INET6)
					rxq->lro.lro_queued = 0;
					rxq->lro.lro_flushed = 0;
#endif
					rxq->rxcsum = 0;
					rxq->vlan_extraction = 0;
				}

				for_each_txq(vi, i, txq) {
					txq->txcsum = 0;
					txq->tso_wrs = 0;
					txq->vlan_insertion = 0;
					txq->imm_wrs = 0;
					txq->sgl_wrs = 0;
					txq->txpkt_wrs = 0;
					txq->txpkts0_wrs = 0;
					txq->txpkts1_wrs = 0;
					txq->txpkts0_pkts = 0;
					txq->txpkts1_pkts = 0;
					mp_ring_reset_stats(txq->r);
				}

#ifdef TCP_OFFLOAD
				/* nothing to clear for each ofld_rxq */

				for_each_ofld_txq(vi, i, wrq) {
					wrq->tx_wrs_direct = 0;
					wrq->tx_wrs_copied = 0;
				}
#endif

				if (IS_MAIN_VI(vi)) {
					wrq = &sc->sge.ctrlq[pi->port_id];
					wrq->tx_wrs_direct = 0;
					wrq->tx_wrs_copied = 0;
				}
			}
		}
		break;
	}
	case CHELSIO_T4_SCHED_CLASS:
		rc = t4_set_sched_class(sc, (struct t4_sched_params *)data);
		break;
	case CHELSIO_T4_SCHED_QUEUE:
		rc = t4_set_sched_queue(sc, (struct t4_sched_queue *)data);
		break;
	case CHELSIO_T4_GET_TRACER:
		rc = t4_get_tracer(sc, (struct t4_tracer *)data);
		break;
	case CHELSIO_T4_SET_TRACER:
		rc = t4_set_tracer(sc, (struct t4_tracer *)data);
		break;
	case CHELSIO_T4_LOAD_CFG:
		rc = load_cfg(sc, (struct t4_data *)data);
		break;
	default:
		rc = ENOTTY;
	}

	return (rc);
}

#ifdef DDB
static void
t4_dump_tcb(struct adapter *sc, int tid)
{
	uint32_t base, i, j, off, pf, reg, save, tcb_addr, win_pos;

	reg = PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 2);
	save = t4_read_reg(sc, reg);
	base = sc->memwin[2].mw_base;

	/* Dump TCB for the tid */
	tcb_addr = t4_read_reg(sc, A_TP_CMM_TCB_BASE);
	tcb_addr += tid * TCB_SIZE;

	if (is_t4(sc)) {
		pf = 0;
		win_pos = tcb_addr & ~0xf;	/* start must be 16B aligned */
	} else {
		pf = V_PFNUM(sc->pf);
		win_pos = tcb_addr & ~0x7f;	/* start must be 128B aligned */
	}
	t4_write_reg(sc, reg, win_pos | pf);
	t4_read_reg(sc, reg);

	off = tcb_addr - win_pos;
	for (i = 0; i < 4; i++) {
		uint32_t buf[8];
		for (j = 0; j < 8; j++, off += 4)
			buf[j] = htonl(t4_read_reg(sc, base + off));

		db_printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",
		    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6],
		    buf[7]);
	}

	t4_write_reg(sc, reg, save);
	t4_read_reg(sc, reg);
}

static void
t4_dump_devlog(struct adapter *sc)
{
	struct devlog_params *dparams = &sc->params.devlog;
	struct fw_devlog_e e;
	int i, first, j, m, nentries, rc;
	uint64_t ftstamp = UINT64_MAX;

	if (dparams->start == 0) {
		db_printf("devlog params not valid\n");
		return;
	}

	nentries = dparams->size / sizeof(struct fw_devlog_e);
	m = fwmtype_to_hwmtype(dparams->memtype);

	/* Find the first entry. */
	first = -1;
	for (i = 0; i < nentries && !db_pager_quit; i++) {
		rc = -t4_mem_read(sc, m, dparams->start + i * sizeof(e),
		    sizeof(e), (void *)&e);
		if (rc != 0)
			break;

		if (e.timestamp == 0)
			break;

		e.timestamp = be64toh(e.timestamp);
		if (e.timestamp < ftstamp) {
			ftstamp = e.timestamp;
			first = i;
		}
	}

	if (first == -1)
		return;

	i = first;
	do {
		rc = -t4_mem_read(sc, m, dparams->start + i * sizeof(e),
		    sizeof(e), (void *)&e);
		if (rc != 0)
			return;

		if (e.timestamp == 0)
			return;

		e.timestamp = be64toh(e.timestamp);
		e.seqno = be32toh(e.seqno);
		for (j = 0; j < 8; j++)
			e.params[j] = be32toh(e.params[j]);

		db_printf("%10d  %15ju  %8s  %8s  ",
		    e.seqno, e.timestamp,
		    (e.level < nitems(devlog_level_strings) ?
			devlog_level_strings[e.level] : "UNKNOWN"),
		    (e.facility < nitems(devlog_facility_strings) ?
			devlog_facility_strings[e.facility] : "UNKNOWN"));
		db_printf(e.fmt, e.params[0], e.params[1], e.params[2],
		    e.params[3], e.params[4], e.params[5], e.params[6],
		    e.params[7]);

		if (++i == nentries)
			i = 0;
	} while (i != first && !db_pager_quit);
}

static struct command_table db_t4_table = LIST_HEAD_INITIALIZER(db_t4_table);
_DB_SET(_show, t4, NULL, db_show_table, 0, &db_t4_table);

DB_FUNC(devlog, db_show_devlog, db_t4_table, CS_OWN, NULL)
{
	device_t dev;
	int t;
	bool valid;

	valid = false;
	t = db_read_token();
	if (t == tIDENT) {
		dev = device_lookup_by_name(db_tok_string);
		valid = true;
	}
	db_skip_to_eol();
	if (!valid) {
		db_printf("usage: show t4 devlog <nexus>\n");
		return;
	}

	if (dev == NULL) {
		db_printf("device not found\n");
		return;
	}

	t4_dump_devlog(device_get_softc(dev));
}

DB_FUNC(tcb, db_show_t4tcb, db_t4_table, CS_OWN, NULL)
{
	device_t dev;
	int radix, tid, t;
	bool valid;

	valid = false;
	radix = db_radix;
	db_radix = 10;
	t = db_read_token();
	if (t == tIDENT) {
		dev = device_lookup_by_name(db_tok_string);
		t = db_read_token();
		if (t == tNUMBER) {
			tid = db_tok_number;
			valid = true;
		}
	}	
	db_radix = radix;
	db_skip_to_eol();
	if (!valid) {
		db_printf("usage: show t4 tcb <nexus> <tid>\n");
		return;
	}

	if (dev == NULL) {
		db_printf("device not found\n");
		return;
	}
	if (tid < 0) {
		db_printf("invalid tid\n");
		return;
	}

	t4_dump_tcb(device_get_softc(dev), tid);
}
#endif

static devclass_t t4_devclass, t5_devclass, t6_devclass;
static devclass_t cxgbe_devclass, cxl_devclass, cc_devclass;
static devclass_t vcxgbe_devclass, vcxl_devclass, vcc_devclass;

DRIVER_MODULE(t4nex, pci, t4_driver, t4_devclass, 0, 0);
MODULE_VERSION(t4nex, 1);
MODULE_DEPEND(t4nex, firmware, 1, 1, 1);
#ifdef DEV_NETMAP
MODULE_DEPEND(t4nex, netmap, 1, 1, 1);
#endif /* DEV_NETMAP */
MODULE_DEPEND(t4nex, t4_common, 1, 1, 1);

DRIVER_MODULE(t5nex, pci, t5_driver, t5_devclass, 0, 0);
MODULE_VERSION(t5nex, 1);
MODULE_DEPEND(t5nex, firmware, 1, 1, 1);
#ifdef DEV_NETMAP
MODULE_DEPEND(t5nex, netmap, 1, 1, 1);
#endif /* DEV_NETMAP */
MODULE_DEPEND(t5nex, t4_common, 1, 1, 1);

DRIVER_MODULE(t6nex, pci, t6_driver, t6_devclass, 0, 0);
MODULE_VERSION(t6nex, 1);
MODULE_DEPEND(t6nex, firmware, 1, 1, 1);
#ifdef DEV_NETMAP
MODULE_DEPEND(t6nex, netmap, 1, 1, 1);
#endif /* DEV_NETMAP */
MODULE_DEPEND(t6nex, t4_common, 1, 1, 1);

DRIVER_MODULE(cxgbe, t4nex, cxgbe_driver, cxgbe_devclass, 0, 0);
MODULE_VERSION(cxgbe, 1);

DRIVER_MODULE(cxl, t5nex, cxl_driver, cxl_devclass, 0, 0);
MODULE_VERSION(cxl, 1);

DRIVER_MODULE(cc, t6nex, cc_driver, cc_devclass, 0, 0);
MODULE_VERSION(cc, 1);

DRIVER_MODULE(vcxgbe, cxgbe, vcxgbe_driver, vcxgbe_devclass, 0, 0);
MODULE_VERSION(vcxgbe, 1);

DRIVER_MODULE(vcxl, cxl, vcxl_driver, vcxl_devclass, 0, 0);
MODULE_VERSION(vcxl, 1);

DRIVER_MODULE(vcc, cc, vcc_driver, vcc_devclass, 0, 0);
MODULE_VERSION(vcc, 1);
