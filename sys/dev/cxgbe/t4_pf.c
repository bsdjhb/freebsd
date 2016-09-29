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

/*
 * Number of queues for tx and rx; 10G and 1G; offload, netmap, and VI.
 */
#define NTXQ_VI 1
static int t4_ntxq_vi = -1;
TUNABLE_INT("hw.cxgbe.ntxq_vi", &t4_ntxq_vi);

#define NRXQ_VI 1
static int t4_nrxq_vi = -1;
TUNABLE_INT("hw.cxgbe.nrxq_vi", &t4_nrxq_vi);

static int t4_rsrv_noflowq = 0;
TUNABLE_INT("hw.cxgbe.rsrv_noflowq", &t4_rsrv_noflowq);

#ifdef TCP_OFFLOAD
#define NOFLDTXQ_10G 8
static int t4_nofldtxq10g = -1;
TUNABLE_INT("hw.cxgbe.nofldtxq10g", &t4_nofldtxq10g);

#define NOFLDRXQ_10G 2
static int t4_nofldrxq10g = -1;
TUNABLE_INT("hw.cxgbe.nofldrxq10g", &t4_nofldrxq10g);

#define NOFLDTXQ_1G 2
static int t4_nofldtxq1g = -1;
TUNABLE_INT("hw.cxgbe.nofldtxq1g", &t4_nofldtxq1g);

#define NOFLDRXQ_1G 1
static int t4_nofldrxq1g = -1;
TUNABLE_INT("hw.cxgbe.nofldrxq1g", &t4_nofldrxq1g);

#define NOFLDTXQ_VI 1
static int t4_nofldtxq_vi = -1;
TUNABLE_INT("hw.cxgbe.nofldtxq_vi", &t4_nofldtxq_vi);

#define NOFLDRXQ_VI 1
static int t4_nofldrxq_vi = -1;
TUNABLE_INT("hw.cxgbe.nofldrxq_vi", &t4_nofldrxq_vi);
#endif

#ifdef DEV_NETMAP
#define NNMTXQ_VI 2
static int t4_nnmtxq_vi = -1;
TUNABLE_INT("hw.cxgbe.nnmtxq_vi", &t4_nnmtxq_vi);

#define NNMRXQ_VI 2
static int t4_nnmrxq_vi = -1;
TUNABLE_INT("hw.cxgbe.nnmrxq_vi", &t4_nnmrxq_vi);
#endif

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
static void t4_sysctls(struct adapter *);
static int sysctl_temperature(SYSCTL_HANDLER_ARGS);
#ifdef SBUF_DRAIN
static int sysctl_cctrl(SYSCTL_HANDLER_ARGS);
static int sysctl_cim_ibq_obq(SYSCTL_HANDLER_ARGS);
static int sysctl_cim_la(SYSCTL_HANDLER_ARGS);
static int sysctl_cim_la_t6(SYSCTL_HANDLER_ARGS);
static int sysctl_cim_ma_la(SYSCTL_HANDLER_ARGS);
static int sysctl_cim_pif_la(SYSCTL_HANDLER_ARGS);
static int sysctl_cim_qcfg(SYSCTL_HANDLER_ARGS);
static int sysctl_cpl_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_ddp_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_devlog(SYSCTL_HANDLER_ARGS);
static int sysctl_fcoe_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_hw_sched(SYSCTL_HANDLER_ARGS);
static int sysctl_lb_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_meminfo(SYSCTL_HANDLER_ARGS);
static int sysctl_mps_tcam(SYSCTL_HANDLER_ARGS);
static int sysctl_mps_tcam_t6(SYSCTL_HANDLER_ARGS);
static int sysctl_path_mtus(SYSCTL_HANDLER_ARGS);
static int sysctl_pm_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_rdma_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_tcp_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_tids(SYSCTL_HANDLER_ARGS);
static int sysctl_tp_err_stats(SYSCTL_HANDLER_ARGS);
static int sysctl_tp_la_mask(SYSCTL_HANDLER_ARGS);
static int sysctl_tp_la(SYSCTL_HANDLER_ARGS);
static int sysctl_tx_rate(SYSCTL_HANDLER_ARGS);
static int sysctl_ulprx_la(SYSCTL_HANDLER_ARGS);
static int sysctl_wcwr_stats(SYSCTL_HANDLER_ARGS);
#endif
#ifdef TCP_OFFLOAD
static int sysctl_tp_tick(SYSCTL_HANDLER_ARGS);
static int sysctl_tp_dack_timer(SYSCTL_HANDLER_ARGS);
static int sysctl_tp_timer(SYSCTL_HANDLER_ARGS);
#endif
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
	sc->set_tcb_rpl = t4_filter_rpl;
	sc->l2t_write_rpl = do_l2t_write_rpl;
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
	sc->fwq_intr_idx = sc->intr_count > 1 ? 1 : 0;

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

	rc = t4_detach_common(dev);
	if (rc)
		return (rc);

	if (sc->l2t)
		t4_free_l2t(sc->l2t);

	return (0);
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

/*
 * Should match fw_caps_config_<foo> enums in t4fw_interface.h
 */
static char *caps_decoder[] = {
	"\20\001IPMI\002NCSI",				/* 0: NBM */
	"\20\001PPP\002QFC\003DCBX",			/* 1: link */
	"\20\001INGRESS\002EGRESS",			/* 2: switch */
	"\20\001NIC\002VM\003IDS\004UM\005UM_ISGL"	/* 3: NIC */
	    "\006HASHFILTER\007ETHOFLD",
	"\20\001TOE",					/* 4: TOE */
	"\20\001RDDP\002RDMAC",				/* 5: RDMA */
	"\20\001INITIATOR_PDU\002TARGET_PDU"		/* 6: iSCSI */
	    "\003INITIATOR_CNXOFLD\004TARGET_CNXOFLD"
	    "\005INITIATOR_SSNOFLD\006TARGET_SSNOFLD"
	    "\007T10DIF"
	    "\010INITIATOR_CMDOFLD\011TARGET_CMDOFLD",
	"\20\001LOOKASIDE\002TLSKEYS",			/* 7: Crypto */
	"\20\001INITIATOR\002TARGET\003CTRL_OFLD"	/* 8: FCoE */
		    "\004PO_INITIATOR\005PO_TARGET",
};

static void
t4_sysctls(struct adapter *sc)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *children, *c0;

	t4_sysctls_common(sc);

	ctx = device_get_sysctl_ctx(sc->dev);

	/*
	 * dev.t4nex.X.
	 */
	oid = device_get_sysctl_tree(sc->dev);
	c0 = children = SYSCTL_CHILDREN(oid);

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "hw_revision", CTLFLAG_RD,
	    NULL, chip_rev(sc), "chip hardware revision");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "sn",
	    CTLFLAG_RD, sc->params.vpd.sn, 0, "serial number");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "pn",
	    CTLFLAG_RD, sc->params.vpd.pn, 0, "part number");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "ec",
	    CTLFLAG_RD, sc->params.vpd.ec, 0, "engineering change");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "na",
	    CTLFLAG_RD, sc->params.vpd.na, 0, "network address");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "er_version", CTLFLAG_RD,
	    sc->er_version, 0, "expansion ROM version");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "bs_version", CTLFLAG_RD,
	    sc->bs_version, 0, "bootstrap firmware version");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, "scfg_version", CTLFLAG_RD,
	    NULL, sc->params.scfg_vers, "serial config version");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, "vpd_version", CTLFLAG_RD,
	    NULL, sc->params.vpd_vers, "VPD version");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "cf",
	    CTLFLAG_RD, sc->cfg_file, 0, "configuration file");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, "cfcsum", CTLFLAG_RD, NULL,
	    sc->cfcsum, "config file checksum");

#define SYSCTL_CAP(name, n, text) \
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, #name, \
	    CTLTYPE_STRING | CTLFLAG_RD, caps_decoder[n], sc->name, \
	    sysctl_bitfield, "A", "available " text " capabilities")

	SYSCTL_CAP(nbmcaps, 0, "NBM");
	SYSCTL_CAP(linkcaps, 1, "link");
	SYSCTL_CAP(switchcaps, 2, "switch");
	SYSCTL_CAP(niccaps, 3, "NIC");
	SYSCTL_CAP(toecaps, 4, "TCP offload");
	SYSCTL_CAP(rdmacaps, 5, "RDMA");
	SYSCTL_CAP(iscsicaps, 6, "iSCSI");
	SYSCTL_CAP(cryptocaps, 7, "crypto");
	SYSCTL_CAP(fcoecaps, 8, "FCoE");
#undef SYSCTL_CAP

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "nfilters", CTLFLAG_RD,
	    NULL, sc->tids.nftids, "number of filters");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "temperature", CTLTYPE_INT |
	    CTLFLAG_RD, sc, 0, sysctl_temperature, "I",
	    "chip temperature (in Celsius)");

#ifdef SBUF_DRAIN
	/*
	 * dev.t4nex.X.misc.  Marked CTLFLAG_SKIP to avoid information overload.
	 */
	oid = SYSCTL_ADD_NODE(ctx, c0, OID_AUTO, "misc",
	    CTLFLAG_RD | CTLFLAG_SKIP, NULL,
	    "logs and miscellaneous information");
	children = SYSCTL_CHILDREN(oid);

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cctrl",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_cctrl, "A", "congestion control");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_ibq_tp0",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_cim_ibq_obq, "A", "CIM IBQ 0 (TP0)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_ibq_tp1",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 1,
	    sysctl_cim_ibq_obq, "A", "CIM IBQ 1 (TP1)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_ibq_ulp",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 2,
	    sysctl_cim_ibq_obq, "A", "CIM IBQ 2 (ULP)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_ibq_sge0",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 3,
	    sysctl_cim_ibq_obq, "A", "CIM IBQ 3 (SGE0)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_ibq_sge1",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 4,
	    sysctl_cim_ibq_obq, "A", "CIM IBQ 4 (SGE1)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_ibq_ncsi",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 5,
	    sysctl_cim_ibq_obq, "A", "CIM IBQ 5 (NCSI)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_la",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    chip_id(sc) <= CHELSIO_T5 ? sysctl_cim_la : sysctl_cim_la_t6,
	    "A", "CIM logic analyzer");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_ma_la",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_cim_ma_la, "A", "CIM MA logic analyzer");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_ulp0",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0 + CIM_NUM_IBQ,
	    sysctl_cim_ibq_obq, "A", "CIM OBQ 0 (ULP0)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_ulp1",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 1 + CIM_NUM_IBQ,
	    sysctl_cim_ibq_obq, "A", "CIM OBQ 1 (ULP1)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_ulp2",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 2 + CIM_NUM_IBQ,
	    sysctl_cim_ibq_obq, "A", "CIM OBQ 2 (ULP2)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_ulp3",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 3 + CIM_NUM_IBQ,
	    sysctl_cim_ibq_obq, "A", "CIM OBQ 3 (ULP3)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_sge",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 4 + CIM_NUM_IBQ,
	    sysctl_cim_ibq_obq, "A", "CIM OBQ 4 (SGE)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_ncsi",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 5 + CIM_NUM_IBQ,
	    sysctl_cim_ibq_obq, "A", "CIM OBQ 5 (NCSI)");

	if (chip_id(sc) > CHELSIO_T4) {
		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_sge0_rx",
		    CTLTYPE_STRING | CTLFLAG_RD, sc, 6 + CIM_NUM_IBQ,
		    sysctl_cim_ibq_obq, "A", "CIM OBQ 6 (SGE0-RX)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_obq_sge1_rx",
		    CTLTYPE_STRING | CTLFLAG_RD, sc, 7 + CIM_NUM_IBQ,
		    sysctl_cim_ibq_obq, "A", "CIM OBQ 7 (SGE1-RX)");
	}

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_pif_la",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_cim_pif_la, "A", "CIM PIF logic analyzer");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cim_qcfg",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_cim_qcfg, "A", "CIM queue configuration");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "cpl_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_cpl_stats, "A", "CPL statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "ddp_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_ddp_stats, "A", "non-TCP DDP statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "devlog",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_devlog, "A", "firmware's device log");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "fcoe_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_fcoe_stats, "A", "FCoE statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "hw_sched",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_hw_sched, "A", "hardware scheduler ");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "l2t",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_l2t, "A", "hardware L2 table");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "lb_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_lb_stats, "A", "loopback statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "meminfo",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_meminfo, "A", "memory regions");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "mps_tcam",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    chip_id(sc) <= CHELSIO_T5 ? sysctl_mps_tcam : sysctl_mps_tcam_t6,
	    "A", "MPS TCAM entries");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "path_mtus",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_path_mtus, "A", "path MTUs");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "pm_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_pm_stats, "A", "PM statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rdma_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_rdma_stats, "A", "RDMA statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tcp_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_tcp_stats, "A", "TCP statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tids",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_tids, "A", "TID information");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tp_err_stats",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_tp_err_stats, "A", "TP error statistics");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tp_la_mask",
	    CTLTYPE_INT | CTLFLAG_RW, sc, 0, sysctl_tp_la_mask, "I",
	    "TP logic analyzer event capture mask");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tp_la",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_tp_la, "A", "TP logic analyzer");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tx_rate",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_tx_rate, "A", "Tx rate");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "ulprx_la",
	    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
	    sysctl_ulprx_la, "A", "ULPRX logic analyzer");

	if (chip_id(sc) >= CHELSIO_T5) {
		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "wcwr_stats",
		    CTLTYPE_STRING | CTLFLAG_RD, sc, 0,
		    sysctl_wcwr_stats, "A", "write combined work requests");
	}
#endif

#ifdef TCP_OFFLOAD
	if (is_offload(sc)) {
		/*
		 * dev.t4nex.X.toe.
		 */
		oid = SYSCTL_ADD_NODE(ctx, c0, OID_AUTO, "toe", CTLFLAG_RD,
		    NULL, "TOE parameters");
		children = SYSCTL_CHILDREN(oid);

		sc->tt.sndbuf = 256 * 1024;
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "sndbuf", CTLFLAG_RW,
		    &sc->tt.sndbuf, 0, "max hardware send buffer size");

		sc->tt.ddp = 0;
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "ddp", CTLFLAG_RW,
		    &sc->tt.ddp, 0, "DDP allowed");

		sc->tt.rx_coalesce = 1;
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "rx_coalesce",
		    CTLFLAG_RW, &sc->tt.rx_coalesce, 0, "receive coalescing");

		sc->tt.tx_align = 1;
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "tx_align",
		    CTLFLAG_RW, &sc->tt.tx_align, 0, "chop and align payload");

		sc->tt.tx_zcopy = 0;
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "tx_zcopy",
		    CTLFLAG_RW, &sc->tt.tx_zcopy, 0,
		    "Enable zero-copy aio_write(2)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "timer_tick",
		    CTLTYPE_STRING | CTLFLAG_RD, sc, 0, sysctl_tp_tick, "A",
		    "TP timer tick (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "timestamp_tick",
		    CTLTYPE_STRING | CTLFLAG_RD, sc, 1, sysctl_tp_tick, "A",
		    "TCP timestamp tick (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "dack_tick",
		    CTLTYPE_STRING | CTLFLAG_RD, sc, 2, sysctl_tp_tick, "A",
		    "DACK tick (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "dack_timer",
		    CTLTYPE_UINT | CTLFLAG_RD, sc, 0, sysctl_tp_dack_timer,
		    "IU", "DACK timer (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rexmt_min",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_RXT_MIN,
		    sysctl_tp_timer, "LU", "Retransmit min (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rexmt_max",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_RXT_MAX,
		    sysctl_tp_timer, "LU", "Retransmit max (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "persist_min",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_PERS_MIN,
		    sysctl_tp_timer, "LU", "Persist timer min (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "persist_max",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_PERS_MAX,
		    sysctl_tp_timer, "LU", "Persist timer max (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "keepalive_idle",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_KEEP_IDLE,
		    sysctl_tp_timer, "LU", "Keepidle idle timer (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "keepalive_intvl",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_KEEP_INTVL,
		    sysctl_tp_timer, "LU", "Keepidle interval (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "initial_srtt",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_INIT_SRTT,
		    sysctl_tp_timer, "LU", "Initial SRTT (us)");

		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "finwait2_timer",
		    CTLTYPE_ULONG | CTLFLAG_RD, sc, A_TP_FINWAIT2_TIMER,
		    sysctl_tp_timer, "LU", "FINWAIT2 timer (us)");
	}
#endif
}

static int
sysctl_temperature(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	int rc, t;
	uint32_t param, val;

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4temp");
	if (rc)
		return (rc);
	param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DIAG) |
	    V_FW_PARAMS_PARAM_Y(FW_PARAM_DEV_DIAG_TMP);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
	end_synchronized_op(sc, 0);
	if (rc)
		return (rc);

	/* unknown is returned as 0 but we display -1 in that case */
	t = val == 0 ? -1 : val;

	rc = sysctl_handle_int(oidp, &t, 0, req);
	return (rc);
}

#ifdef SBUF_DRAIN
static int
sysctl_cctrl(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i;
	uint16_t incr[NMTUS][NCCTRL_WIN];
	static const char *dec_fac[] = {
		"0.5", "0.5625", "0.625", "0.6875", "0.75", "0.8125", "0.875",
		"0.9375"
	};

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	t4_read_cong_tbl(sc, incr);

	for (i = 0; i < NCCTRL_WIN; ++i) {
		sbuf_printf(sb, "%2d: %4u %4u %4u %4u %4u %4u %4u %4u\n", i,
		    incr[0][i], incr[1][i], incr[2][i], incr[3][i], incr[4][i],
		    incr[5][i], incr[6][i], incr[7][i]);
		sbuf_printf(sb, "%8u %4u %4u %4u %4u %4u %4u %4u %5u %s\n",
		    incr[8][i], incr[9][i], incr[10][i], incr[11][i],
		    incr[12][i], incr[13][i], incr[14][i], incr[15][i],
		    sc->params.a_wnd[i], dec_fac[sc->params.b_wnd[i]]);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static const char *qname[CIM_NUM_IBQ + CIM_NUM_OBQ_T5] = {
	"TP0", "TP1", "ULP", "SGE0", "SGE1", "NC-SI",	/* ibq's */
	"ULP0", "ULP1", "ULP2", "ULP3", "SGE", "NC-SI",	/* obq's */
	"SGE0-RX", "SGE1-RX"	/* additional obq's (T5 onwards) */
};

static int
sysctl_cim_ibq_obq(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i, n, qid = arg2;
	uint32_t *buf, *p;
	char *qtype;
	u_int cim_num_obq = sc->chip_params->cim_num_obq;

	KASSERT(qid >= 0 && qid < CIM_NUM_IBQ + cim_num_obq,
	    ("%s: bad qid %d\n", __func__, qid));

	if (qid < CIM_NUM_IBQ) {
		/* inbound queue */
		qtype = "IBQ";
		n = 4 * CIM_IBQ_SIZE;
		buf = malloc(n * sizeof(uint32_t), M_CXGBE, M_ZERO | M_WAITOK);
		rc = t4_read_cim_ibq(sc, qid, buf, n);
	} else {
		/* outbound queue */
		qtype = "OBQ";
		qid -= CIM_NUM_IBQ;
		n = 4 * cim_num_obq * CIM_OBQ_SIZE;
		buf = malloc(n * sizeof(uint32_t), M_CXGBE, M_ZERO | M_WAITOK);
		rc = t4_read_cim_obq(sc, qid, buf, n);
	}

	if (rc < 0) {
		rc = -rc;
		goto done;
	}
	n = rc * sizeof(uint32_t);	/* rc has # of words actually read */

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		goto done;

	sb = sbuf_new_for_sysctl(NULL, NULL, PAGE_SIZE, req);
	if (sb == NULL) {
		rc = ENOMEM;
		goto done;
	}

	sbuf_printf(sb, "%s%d %s", qtype , qid, qname[arg2]);
	for (i = 0, p = buf; i < n; i += 16, p += 4)
		sbuf_printf(sb, "\n%#06x: %08x %08x %08x %08x", i, p[0], p[1],
		    p[2], p[3]);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
done:
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_cim_la(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	u_int cfg;
	struct sbuf *sb;
	uint32_t *buf, *p;
	int rc;

	MPASS(chip_id(sc) <= CHELSIO_T5);

	rc = -t4_cim_read(sc, A_UP_UP_DBG_LA_CFG, 1, &cfg);
	if (rc != 0)
		return (rc);

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	buf = malloc(sc->params.cim_la_size * sizeof(uint32_t), M_CXGBE,
	    M_ZERO | M_WAITOK);

	rc = -t4_cim_read_la(sc, buf, NULL);
	if (rc != 0)
		goto done;

	sbuf_printf(sb, "Status   Data      PC%s",
	    cfg & F_UPDBGLACAPTPCONLY ? "" :
	    "     LS0Stat  LS0Addr             LS0Data");

	for (p = buf; p <= &buf[sc->params.cim_la_size - 8]; p += 8) {
		if (cfg & F_UPDBGLACAPTPCONLY) {
			sbuf_printf(sb, "\n  %02x   %08x %08x", p[5] & 0xff,
			    p[6], p[7]);
			sbuf_printf(sb, "\n  %02x   %02x%06x %02x%06x",
			    (p[3] >> 8) & 0xff, p[3] & 0xff, p[4] >> 8,
			    p[4] & 0xff, p[5] >> 8);
			sbuf_printf(sb, "\n  %02x   %x%07x %x%07x",
			    (p[0] >> 4) & 0xff, p[0] & 0xf, p[1] >> 4,
			    p[1] & 0xf, p[2] >> 4);
		} else {
			sbuf_printf(sb,
			    "\n  %02x   %x%07x %x%07x %08x %08x "
			    "%08x%08x%08x%08x",
			    (p[0] >> 4) & 0xff, p[0] & 0xf, p[1] >> 4,
			    p[1] & 0xf, p[2] >> 4, p[2] & 0xf, p[3], p[4], p[5],
			    p[6], p[7]);
		}
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
done:
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_cim_la_t6(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	u_int cfg;
	struct sbuf *sb;
	uint32_t *buf, *p;
	int rc;

	MPASS(chip_id(sc) > CHELSIO_T5);

	rc = -t4_cim_read(sc, A_UP_UP_DBG_LA_CFG, 1, &cfg);
	if (rc != 0)
		return (rc);

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	buf = malloc(sc->params.cim_la_size * sizeof(uint32_t), M_CXGBE,
	    M_ZERO | M_WAITOK);

	rc = -t4_cim_read_la(sc, buf, NULL);
	if (rc != 0)
		goto done;

	sbuf_printf(sb, "Status   Inst    Data      PC%s",
	    cfg & F_UPDBGLACAPTPCONLY ? "" :
	    "     LS0Stat  LS0Addr  LS0Data  LS1Stat  LS1Addr  LS1Data");

	for (p = buf; p <= &buf[sc->params.cim_la_size - 10]; p += 10) {
		if (cfg & F_UPDBGLACAPTPCONLY) {
			sbuf_printf(sb, "\n  %02x   %08x %08x %08x",
			    p[3] & 0xff, p[2], p[1], p[0]);
			sbuf_printf(sb, "\n  %02x   %02x%06x %02x%06x %02x%06x",
			    (p[6] >> 8) & 0xff, p[6] & 0xff, p[5] >> 8,
			    p[5] & 0xff, p[4] >> 8, p[4] & 0xff, p[3] >> 8);
			sbuf_printf(sb, "\n  %02x   %04x%04x %04x%04x %04x%04x",
			    (p[9] >> 16) & 0xff, p[9] & 0xffff, p[8] >> 16,
			    p[8] & 0xffff, p[7] >> 16, p[7] & 0xffff,
			    p[6] >> 16);
		} else {
			sbuf_printf(sb, "\n  %02x   %04x%04x %04x%04x %04x%04x "
			    "%08x %08x %08x %08x %08x %08x",
			    (p[9] >> 16) & 0xff,
			    p[9] & 0xffff, p[8] >> 16,
			    p[8] & 0xffff, p[7] >> 16,
			    p[7] & 0xffff, p[6] >> 16,
			    p[2], p[1], p[0], p[5], p[4], p[3]);
		}
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
done:
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_cim_ma_la(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	u_int i;
	struct sbuf *sb;
	uint32_t *buf, *p;
	int rc;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	buf = malloc(2 * CIM_MALA_SIZE * 5 * sizeof(uint32_t), M_CXGBE,
	    M_ZERO | M_WAITOK);

	t4_cim_read_ma_la(sc, buf, buf + 5 * CIM_MALA_SIZE);
	p = buf;

	for (i = 0; i < CIM_MALA_SIZE; i++, p += 5) {
		sbuf_printf(sb, "\n%02x%08x%08x%08x%08x", p[4], p[3], p[2],
		    p[1], p[0]);
	}

	sbuf_printf(sb, "\n\nCnt ID Tag UE       Data       RDY VLD");
	for (i = 0; i < CIM_MALA_SIZE; i++, p += 5) {
		sbuf_printf(sb, "\n%3u %2u  %x   %u %08x%08x  %u   %u",
		    (p[2] >> 10) & 0xff, (p[2] >> 7) & 7,
		    (p[2] >> 3) & 0xf, (p[2] >> 2) & 1,
		    (p[1] >> 2) | ((p[2] & 3) << 30),
		    (p[0] >> 2) | ((p[1] & 3) << 30), (p[0] >> 1) & 1,
		    p[0] & 1);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_cim_pif_la(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	u_int i;
	struct sbuf *sb;
	uint32_t *buf, *p;
	int rc;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	buf = malloc(2 * CIM_PIFLA_SIZE * 6 * sizeof(uint32_t), M_CXGBE,
	    M_ZERO | M_WAITOK);

	t4_cim_read_pif_la(sc, buf, buf + 6 * CIM_PIFLA_SIZE, NULL, NULL);
	p = buf;

	sbuf_printf(sb, "Cntl ID DataBE   Addr                 Data");
	for (i = 0; i < CIM_PIFLA_SIZE; i++, p += 6) {
		sbuf_printf(sb, "\n %02x  %02x  %04x  %08x %08x%08x%08x%08x",
		    (p[5] >> 22) & 0xff, (p[5] >> 16) & 0x3f, p[5] & 0xffff,
		    p[4], p[3], p[2], p[1], p[0]);
	}

	sbuf_printf(sb, "\n\nCntl ID               Data");
	for (i = 0; i < CIM_PIFLA_SIZE; i++, p += 6) {
		sbuf_printf(sb, "\n %02x  %02x %08x%08x%08x%08x",
		    (p[4] >> 6) & 0xff, p[4] & 0x3f, p[3], p[2], p[1], p[0]);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_cim_qcfg(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i;
	uint16_t base[CIM_NUM_IBQ + CIM_NUM_OBQ_T5];
	uint16_t size[CIM_NUM_IBQ + CIM_NUM_OBQ_T5];
	uint16_t thres[CIM_NUM_IBQ];
	uint32_t obq_wr[2 * CIM_NUM_OBQ_T5], *wr = obq_wr;
	uint32_t stat[4 * (CIM_NUM_IBQ + CIM_NUM_OBQ_T5)], *p = stat;
	u_int cim_num_obq, ibq_rdaddr, obq_rdaddr, nq;

	cim_num_obq = sc->chip_params->cim_num_obq;
	if (is_t4(sc)) {
		ibq_rdaddr = A_UP_IBQ_0_RDADDR;
		obq_rdaddr = A_UP_OBQ_0_REALADDR;
	} else {
		ibq_rdaddr = A_UP_IBQ_0_SHADOW_RDADDR;
		obq_rdaddr = A_UP_OBQ_0_SHADOW_REALADDR;
	}
	nq = CIM_NUM_IBQ + cim_num_obq;

	rc = -t4_cim_read(sc, ibq_rdaddr, 4 * nq, stat);
	if (rc == 0)
		rc = -t4_cim_read(sc, obq_rdaddr, 2 * cim_num_obq, obq_wr);
	if (rc != 0)
		return (rc);

	t4_read_cimq_cfg(sc, base, size, thres);

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, PAGE_SIZE, req);
	if (sb == NULL)
		return (ENOMEM);

	sbuf_printf(sb,
	    "  Queue  Base  Size Thres  RdPtr WrPtr  SOP  EOP Avail");

	for (i = 0; i < CIM_NUM_IBQ; i++, p += 4)
		sbuf_printf(sb, "\n%7s %5x %5u %5u %6x  %4x %4u %4u %5u",
		    qname[i], base[i], size[i], thres[i], G_IBQRDADDR(p[0]),
		    G_IBQWRADDR(p[1]), G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
		    G_QUEREMFLITS(p[2]) * 16);
	for ( ; i < nq; i++, p += 4, wr += 2)
		sbuf_printf(sb, "\n%7s %5x %5u %12x  %4x %4u %4u %5u", qname[i],
		    base[i], size[i], G_QUERDADDR(p[0]) & 0x3fff,
		    wr[0] - base[i], G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
		    G_QUEREMFLITS(p[2]) * 16);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_cpl_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	struct tp_cpl_stats stats;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	mtx_lock(&sc->reg_lock);
	t4_tp_get_cpl_stats(sc, &stats);
	mtx_unlock(&sc->reg_lock);

	if (sc->chip_params->nchan > 2) {
		sbuf_printf(sb, "                 channel 0  channel 1"
		    "  channel 2  channel 3");
		sbuf_printf(sb, "\nCPL requests:   %10u %10u %10u %10u",
		    stats.req[0], stats.req[1], stats.req[2], stats.req[3]);
		sbuf_printf(sb, "\nCPL responses:   %10u %10u %10u %10u",
		    stats.rsp[0], stats.rsp[1], stats.rsp[2], stats.rsp[3]);
	} else {
		sbuf_printf(sb, "                 channel 0  channel 1");
		sbuf_printf(sb, "\nCPL requests:   %10u %10u",
		    stats.req[0], stats.req[1]);
		sbuf_printf(sb, "\nCPL responses:   %10u %10u",
		    stats.rsp[0], stats.rsp[1]);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_ddp_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	struct tp_usm_stats stats;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return(rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	t4_get_usm_stats(sc, &stats);

	sbuf_printf(sb, "Frames: %u\n", stats.frames);
	sbuf_printf(sb, "Octets: %ju\n", stats.octets);
	sbuf_printf(sb, "Drops:  %u", stats.drops);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static const char * const devlog_level_strings[] = {
	[FW_DEVLOG_LEVEL_EMERG]		= "EMERG",
	[FW_DEVLOG_LEVEL_CRIT]		= "CRIT",
	[FW_DEVLOG_LEVEL_ERR]		= "ERR",
	[FW_DEVLOG_LEVEL_NOTICE]	= "NOTICE",
	[FW_DEVLOG_LEVEL_INFO]		= "INFO",
	[FW_DEVLOG_LEVEL_DEBUG]		= "DEBUG"
};

static const char * const devlog_facility_strings[] = {
	[FW_DEVLOG_FACILITY_CORE]	= "CORE",
	[FW_DEVLOG_FACILITY_CF]		= "CF",
	[FW_DEVLOG_FACILITY_SCHED]	= "SCHED",
	[FW_DEVLOG_FACILITY_TIMER]	= "TIMER",
	[FW_DEVLOG_FACILITY_RES]	= "RES",
	[FW_DEVLOG_FACILITY_HW]		= "HW",
	[FW_DEVLOG_FACILITY_FLR]	= "FLR",
	[FW_DEVLOG_FACILITY_DMAQ]	= "DMAQ",
	[FW_DEVLOG_FACILITY_PHY]	= "PHY",
	[FW_DEVLOG_FACILITY_MAC]	= "MAC",
	[FW_DEVLOG_FACILITY_PORT]	= "PORT",
	[FW_DEVLOG_FACILITY_VI]		= "VI",
	[FW_DEVLOG_FACILITY_FILTER]	= "FILTER",
	[FW_DEVLOG_FACILITY_ACL]	= "ACL",
	[FW_DEVLOG_FACILITY_TM]		= "TM",
	[FW_DEVLOG_FACILITY_QFC]	= "QFC",
	[FW_DEVLOG_FACILITY_DCB]	= "DCB",
	[FW_DEVLOG_FACILITY_ETH]	= "ETH",
	[FW_DEVLOG_FACILITY_OFLD]	= "OFLD",
	[FW_DEVLOG_FACILITY_RI]		= "RI",
	[FW_DEVLOG_FACILITY_ISCSI]	= "ISCSI",
	[FW_DEVLOG_FACILITY_FCOE]	= "FCOE",
	[FW_DEVLOG_FACILITY_FOISCSI]	= "FOISCSI",
	[FW_DEVLOG_FACILITY_FOFCOE]	= "FOFCOE",
	[FW_DEVLOG_FACILITY_CHNET]	= "CHNET",
};

static int
sysctl_devlog(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct devlog_params *dparams = &sc->params.devlog;
	struct fw_devlog_e *buf, *e;
	int i, j, rc, nentries, first = 0;
	struct sbuf *sb;
	uint64_t ftstamp = UINT64_MAX;

	if (dparams->addr == 0)
		return (ENXIO);

	buf = malloc(dparams->size, M_CXGBE, M_NOWAIT);
	if (buf == NULL)
		return (ENOMEM);

	rc = read_via_memwin(sc, 1, dparams->addr, (void *)buf, dparams->size);
	if (rc != 0)
		goto done;

	nentries = dparams->size / sizeof(struct fw_devlog_e);
	for (i = 0; i < nentries; i++) {
		e = &buf[i];

		if (e->timestamp == 0)
			break;	/* end */

		e->timestamp = be64toh(e->timestamp);
		e->seqno = be32toh(e->seqno);
		for (j = 0; j < 8; j++)
			e->params[j] = be32toh(e->params[j]);

		if (e->timestamp < ftstamp) {
			ftstamp = e->timestamp;
			first = i;
		}
	}

	if (buf[first].timestamp == 0)
		goto done;	/* nothing in the log */

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		goto done;

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL) {
		rc = ENOMEM;
		goto done;
	}
	sbuf_printf(sb, "%10s  %15s  %8s  %8s  %s\n",
	    "Seq#", "Tstamp", "Level", "Facility", "Message");

	i = first;
	do {
		e = &buf[i];
		if (e->timestamp == 0)
			break;	/* end */

		sbuf_printf(sb, "%10d  %15ju  %8s  %8s  ",
		    e->seqno, e->timestamp,
		    (e->level < nitems(devlog_level_strings) ?
			devlog_level_strings[e->level] : "UNKNOWN"),
		    (e->facility < nitems(devlog_facility_strings) ?
			devlog_facility_strings[e->facility] : "UNKNOWN"));
		sbuf_printf(sb, e->fmt, e->params[0], e->params[1],
		    e->params[2], e->params[3], e->params[4],
		    e->params[5], e->params[6], e->params[7]);

		if (++i == nentries)
			i = 0;
	} while (i != first);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
done:
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_fcoe_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	struct tp_fcoe_stats stats[MAX_NCHAN];
	int i, nchan = sc->chip_params->nchan;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	for (i = 0; i < nchan; i++)
		t4_get_fcoe_stats(sc, i, &stats[i]);

	if (nchan > 2) {
		sbuf_printf(sb, "                   channel 0        channel 1"
		    "        channel 2        channel 3");
		sbuf_printf(sb, "\noctetsDDP:  %16ju %16ju %16ju %16ju",
		    stats[0].octets_ddp, stats[1].octets_ddp,
		    stats[2].octets_ddp, stats[3].octets_ddp);
		sbuf_printf(sb, "\nframesDDP:  %16u %16u %16u %16u",
		    stats[0].frames_ddp, stats[1].frames_ddp,
		    stats[2].frames_ddp, stats[3].frames_ddp);
		sbuf_printf(sb, "\nframesDrop: %16u %16u %16u %16u",
		    stats[0].frames_drop, stats[1].frames_drop,
		    stats[2].frames_drop, stats[3].frames_drop);
	} else {
		sbuf_printf(sb, "                   channel 0        channel 1");
		sbuf_printf(sb, "\noctetsDDP:  %16ju %16ju",
		    stats[0].octets_ddp, stats[1].octets_ddp);
		sbuf_printf(sb, "\nframesDDP:  %16u %16u",
		    stats[0].frames_ddp, stats[1].frames_ddp);
		sbuf_printf(sb, "\nframesDrop: %16u %16u",
		    stats[0].frames_drop, stats[1].frames_drop);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_hw_sched(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i;
	unsigned int map, kbps, ipg, mode;
	unsigned int pace_tab[NTX_SCHED];

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	map = t4_read_reg(sc, A_TP_TX_MOD_QUEUE_REQ_MAP);
	mode = G_TIMERMODE(t4_read_reg(sc, A_TP_MOD_CONFIG));
	t4_read_pace_tbl(sc, pace_tab);

	sbuf_printf(sb, "Scheduler  Mode   Channel  Rate (Kbps)   "
	    "Class IPG (0.1 ns)   Flow IPG (us)");

	for (i = 0; i < NTX_SCHED; ++i, map >>= 2) {
		t4_get_tx_sched(sc, i, &kbps, &ipg);
		sbuf_printf(sb, "\n    %u      %-5s     %u     ", i,
		    (mode & (1 << i)) ? "flow" : "class", map & 3);
		if (kbps)
			sbuf_printf(sb, "%9u     ", kbps);
		else
			sbuf_printf(sb, " disabled     ");

		if (ipg)
			sbuf_printf(sb, "%13u        ", ipg);
		else
			sbuf_printf(sb, "     disabled        ");

		if (pace_tab[i])
			sbuf_printf(sb, "%10u", pace_tab[i]);
		else
			sbuf_printf(sb, "  disabled");
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_lb_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i, j;
	uint64_t *p0, *p1;
	struct lb_port_stats s[2];
	static const char *stat_name[] = {
		"OctetsOK:", "FramesOK:", "BcastFrames:", "McastFrames:",
		"UcastFrames:", "ErrorFrames:", "Frames64:", "Frames65To127:",
		"Frames128To255:", "Frames256To511:", "Frames512To1023:",
		"Frames1024To1518:", "Frames1519ToMax:", "FramesDropped:",
		"BG0FramesDropped:", "BG1FramesDropped:", "BG2FramesDropped:",
		"BG3FramesDropped:", "BG0FramesTrunc:", "BG1FramesTrunc:",
		"BG2FramesTrunc:", "BG3FramesTrunc:"
	};

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	memset(s, 0, sizeof(s));

	for (i = 0; i < sc->chip_params->nchan; i += 2) {
		t4_get_lb_stats(sc, i, &s[0]);
		t4_get_lb_stats(sc, i + 1, &s[1]);

		p0 = &s[0].octets;
		p1 = &s[1].octets;
		sbuf_printf(sb, "%s                       Loopback %u"
		    "           Loopback %u", i == 0 ? "" : "\n", i, i + 1);

		for (j = 0; j < nitems(stat_name); j++)
			sbuf_printf(sb, "\n%-17s %20ju %20ju", stat_name[j],
				   *p0++, *p1++);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

struct mem_desc {
	unsigned int base;
	unsigned int limit;
	unsigned int idx;
};

static int
mem_desc_cmp(const void *a, const void *b)
{
	return ((const struct mem_desc *)a)->base -
	       ((const struct mem_desc *)b)->base;
}

static void
mem_region_show(struct sbuf *sb, const char *name, unsigned int from,
    unsigned int to)
{
	unsigned int size;

	if (from == to)
		return;

	size = to - from + 1;
	if (size == 0)
		return;

	/* XXX: need humanize_number(3) in libkern for a more readable 'size' */
	sbuf_printf(sb, "%-15s %#x-%#x [%u]\n", name, from, to, size);
}

static int
sysctl_meminfo(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i, n;
	uint32_t lo, hi, used, alloc;
	static const char *memory[] = {"EDC0:", "EDC1:", "MC:", "MC0:", "MC1:"};
	static const char *region[] = {
		"DBQ contexts:", "IMSG contexts:", "FLM cache:", "TCBs:",
		"Pstructs:", "Timers:", "Rx FL:", "Tx FL:", "Pstruct FL:",
		"Tx payload:", "Rx payload:", "LE hash:", "iSCSI region:",
		"TDDP region:", "TPT region:", "STAG region:", "RQ region:",
		"RQUDP region:", "PBL region:", "TXPBL region:",
		"DBVFIFO region:", "ULPRX state:", "ULPTX state:",
		"On-chip queues:"
	};
	struct mem_desc avail[4];
	struct mem_desc mem[nitems(region) + 3];	/* up to 3 holes */
	struct mem_desc *md = mem;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	for (i = 0; i < nitems(mem); i++) {
		mem[i].limit = 0;
		mem[i].idx = i;
	}

	/* Find and sort the populated memory ranges */
	i = 0;
	lo = t4_read_reg(sc, A_MA_TARGET_MEM_ENABLE);
	if (lo & F_EDRAM0_ENABLE) {
		hi = t4_read_reg(sc, A_MA_EDRAM0_BAR);
		avail[i].base = G_EDRAM0_BASE(hi) << 20;
		avail[i].limit = avail[i].base + (G_EDRAM0_SIZE(hi) << 20);
		avail[i].idx = 0;
		i++;
	}
	if (lo & F_EDRAM1_ENABLE) {
		hi = t4_read_reg(sc, A_MA_EDRAM1_BAR);
		avail[i].base = G_EDRAM1_BASE(hi) << 20;
		avail[i].limit = avail[i].base + (G_EDRAM1_SIZE(hi) << 20);
		avail[i].idx = 1;
		i++;
	}
	if (lo & F_EXT_MEM_ENABLE) {
		hi = t4_read_reg(sc, A_MA_EXT_MEMORY_BAR);
		avail[i].base = G_EXT_MEM_BASE(hi) << 20;
		avail[i].limit = avail[i].base +
		    (G_EXT_MEM_SIZE(hi) << 20);
		avail[i].idx = is_t5(sc) ? 3 : 2;	/* Call it MC0 for T5 */
		i++;
	}
	if (is_t5(sc) && lo & F_EXT_MEM1_ENABLE) {
		hi = t4_read_reg(sc, A_MA_EXT_MEMORY1_BAR);
		avail[i].base = G_EXT_MEM1_BASE(hi) << 20;
		avail[i].limit = avail[i].base +
		    (G_EXT_MEM1_SIZE(hi) << 20);
		avail[i].idx = 4;
		i++;
	}
	if (!i)                                    /* no memory available */
		return 0;
	qsort(avail, i, sizeof(struct mem_desc), mem_desc_cmp);

	(md++)->base = t4_read_reg(sc, A_SGE_DBQ_CTXT_BADDR);
	(md++)->base = t4_read_reg(sc, A_SGE_IMSG_CTXT_BADDR);
	(md++)->base = t4_read_reg(sc, A_SGE_FLM_CACHE_BADDR);
	(md++)->base = t4_read_reg(sc, A_TP_CMM_TCB_BASE);
	(md++)->base = t4_read_reg(sc, A_TP_CMM_MM_BASE);
	(md++)->base = t4_read_reg(sc, A_TP_CMM_TIMER_BASE);
	(md++)->base = t4_read_reg(sc, A_TP_CMM_MM_RX_FLST_BASE);
	(md++)->base = t4_read_reg(sc, A_TP_CMM_MM_TX_FLST_BASE);
	(md++)->base = t4_read_reg(sc, A_TP_CMM_MM_PS_FLST_BASE);

	/* the next few have explicit upper bounds */
	md->base = t4_read_reg(sc, A_TP_PMM_TX_BASE);
	md->limit = md->base - 1 +
		    t4_read_reg(sc, A_TP_PMM_TX_PAGE_SIZE) *
		    G_PMTXMAXPAGE(t4_read_reg(sc, A_TP_PMM_TX_MAX_PAGE));
	md++;

	md->base = t4_read_reg(sc, A_TP_PMM_RX_BASE);
	md->limit = md->base - 1 +
		    t4_read_reg(sc, A_TP_PMM_RX_PAGE_SIZE) *
		    G_PMRXMAXPAGE(t4_read_reg(sc, A_TP_PMM_RX_MAX_PAGE));
	md++;

	if (t4_read_reg(sc, A_LE_DB_CONFIG) & F_HASHEN) {
		if (chip_id(sc) <= CHELSIO_T5)
			md->base = t4_read_reg(sc, A_LE_DB_HASH_TID_BASE);
		else
			md->base = t4_read_reg(sc, A_LE_DB_HASH_TBL_BASE_ADDR);
		md->limit = 0;
	} else {
		md->base = 0;
		md->idx = nitems(region);  /* hide it */
	}
	md++;

#define ulp_region(reg) \
	md->base = t4_read_reg(sc, A_ULP_ ## reg ## _LLIMIT);\
	(md++)->limit = t4_read_reg(sc, A_ULP_ ## reg ## _ULIMIT)

	ulp_region(RX_ISCSI);
	ulp_region(RX_TDDP);
	ulp_region(TX_TPT);
	ulp_region(RX_STAG);
	ulp_region(RX_RQ);
	ulp_region(RX_RQUDP);
	ulp_region(RX_PBL);
	ulp_region(TX_PBL);
#undef ulp_region

	md->base = 0;
	md->idx = nitems(region);
	if (!is_t4(sc)) {
		uint32_t size = 0;
		uint32_t sge_ctrl = t4_read_reg(sc, A_SGE_CONTROL2);
		uint32_t fifo_size = t4_read_reg(sc, A_SGE_DBVFIFO_SIZE);

		if (is_t5(sc)) {
			if (sge_ctrl & F_VFIFO_ENABLE)
				size = G_DBVFIFO_SIZE(fifo_size);
		} else
			size = G_T6_DBVFIFO_SIZE(fifo_size);

		if (size) {
			md->base = G_BASEADDR(t4_read_reg(sc,
			    A_SGE_DBVFIFO_BADDR));
			md->limit = md->base + (size << 2) - 1;
		}
	}
	md++;

	md->base = t4_read_reg(sc, A_ULP_RX_CTX_BASE);
	md->limit = 0;
	md++;
	md->base = t4_read_reg(sc, A_ULP_TX_ERR_TABLE_BASE);
	md->limit = 0;
	md++;

	md->base = sc->vres.ocq.start;
	if (sc->vres.ocq.size)
		md->limit = md->base + sc->vres.ocq.size - 1;
	else
		md->idx = nitems(region);  /* hide it */
	md++;

	/* add any address-space holes, there can be up to 3 */
	for (n = 0; n < i - 1; n++)
		if (avail[n].limit < avail[n + 1].base)
			(md++)->base = avail[n].limit;
	if (avail[n].limit)
		(md++)->base = avail[n].limit;

	n = md - mem;
	qsort(mem, n, sizeof(struct mem_desc), mem_desc_cmp);

	for (lo = 0; lo < i; lo++)
		mem_region_show(sb, memory[avail[lo].idx], avail[lo].base,
				avail[lo].limit - 1);

	sbuf_printf(sb, "\n");
	for (i = 0; i < n; i++) {
		if (mem[i].idx >= nitems(region))
			continue;                        /* skip holes */
		if (!mem[i].limit)
			mem[i].limit = i < n - 1 ? mem[i + 1].base - 1 : ~0;
		mem_region_show(sb, region[mem[i].idx], mem[i].base,
				mem[i].limit);
	}

	sbuf_printf(sb, "\n");
	lo = t4_read_reg(sc, A_CIM_SDRAM_BASE_ADDR);
	hi = t4_read_reg(sc, A_CIM_SDRAM_ADDR_SIZE) + lo - 1;
	mem_region_show(sb, "uP RAM:", lo, hi);

	lo = t4_read_reg(sc, A_CIM_EXTMEM2_BASE_ADDR);
	hi = t4_read_reg(sc, A_CIM_EXTMEM2_ADDR_SIZE) + lo - 1;
	mem_region_show(sb, "uP Extmem2:", lo, hi);

	lo = t4_read_reg(sc, A_TP_PMM_RX_MAX_PAGE);
	sbuf_printf(sb, "\n%u Rx pages of size %uKiB for %u channels\n",
		   G_PMRXMAXPAGE(lo),
		   t4_read_reg(sc, A_TP_PMM_RX_PAGE_SIZE) >> 10,
		   (lo & F_PMRXNUMCHN) ? 2 : 1);

	lo = t4_read_reg(sc, A_TP_PMM_TX_MAX_PAGE);
	hi = t4_read_reg(sc, A_TP_PMM_TX_PAGE_SIZE);
	sbuf_printf(sb, "%u Tx pages of size %u%ciB for %u channels\n",
		   G_PMTXMAXPAGE(lo),
		   hi >= (1 << 20) ? (hi >> 20) : (hi >> 10),
		   hi >= (1 << 20) ? 'M' : 'K', 1 << G_PMTXNUMCHN(lo));
	sbuf_printf(sb, "%u p-structs\n",
		   t4_read_reg(sc, A_TP_CMM_MM_MAX_PSTRUCT));

	for (i = 0; i < 4; i++) {
		if (chip_id(sc) > CHELSIO_T5)
			lo = t4_read_reg(sc, A_MPS_RX_MAC_BG_PG_CNT0 + i * 4);
		else
			lo = t4_read_reg(sc, A_MPS_RX_PG_RSV0 + i * 4);
		if (is_t5(sc)) {
			used = G_T5_USED(lo);
			alloc = G_T5_ALLOC(lo);
		} else {
			used = G_USED(lo);
			alloc = G_ALLOC(lo);
		}
		/* For T6 these are MAC buffer groups */
		sbuf_printf(sb, "\nPort %d using %u pages out of %u allocated",
		    i, used, alloc);
	}
	for (i = 0; i < sc->chip_params->nchan; i++) {
		if (chip_id(sc) > CHELSIO_T5)
			lo = t4_read_reg(sc, A_MPS_RX_LPBK_BG_PG_CNT0 + i * 4);
		else
			lo = t4_read_reg(sc, A_MPS_RX_PG_RSV4 + i * 4);
		if (is_t5(sc)) {
			used = G_T5_USED(lo);
			alloc = G_T5_ALLOC(lo);
		} else {
			used = G_USED(lo);
			alloc = G_ALLOC(lo);
		}
		/* For T6 these are MAC buffer groups */
		sbuf_printf(sb,
		    "\nLoopback %d using %u pages out of %u allocated",
		    i, used, alloc);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static inline void
tcamxy2valmask(uint64_t x, uint64_t y, uint8_t *addr, uint64_t *mask)
{
	*mask = x | y;
	y = htobe64(y);
	memcpy(addr, (char *)&y + 2, ETHER_ADDR_LEN);
}

static int
sysctl_mps_tcam(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i;

	MPASS(chip_id(sc) <= CHELSIO_T5);

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	sbuf_printf(sb,
	    "Idx  Ethernet address     Mask     Vld Ports PF"
	    "  VF              Replication             P0 P1 P2 P3  ML");
	for (i = 0; i < sc->chip_params->mps_tcam_size; i++) {
		uint64_t tcamx, tcamy, mask;
		uint32_t cls_lo, cls_hi;
		uint8_t addr[ETHER_ADDR_LEN];

		tcamy = t4_read_reg64(sc, MPS_CLS_TCAM_Y_L(i));
		tcamx = t4_read_reg64(sc, MPS_CLS_TCAM_X_L(i));
		if (tcamx & tcamy)
			continue;
		tcamxy2valmask(tcamx, tcamy, addr, &mask);
		cls_lo = t4_read_reg(sc, MPS_CLS_SRAM_L(i));
		cls_hi = t4_read_reg(sc, MPS_CLS_SRAM_H(i));
		sbuf_printf(sb, "\n%3u %02x:%02x:%02x:%02x:%02x:%02x %012jx"
			   "  %c   %#x%4u%4d", i, addr[0], addr[1], addr[2],
			   addr[3], addr[4], addr[5], (uintmax_t)mask,
			   (cls_lo & F_SRAM_VLD) ? 'Y' : 'N',
			   G_PORTMAP(cls_hi), G_PF(cls_lo),
			   (cls_lo & F_VF_VALID) ? G_VF(cls_lo) : -1);

		if (cls_lo & F_REPLICATE) {
			struct fw_ldst_cmd ldst_cmd;

			memset(&ldst_cmd, 0, sizeof(ldst_cmd));
			ldst_cmd.op_to_addrspace =
			    htobe32(V_FW_CMD_OP(FW_LDST_CMD) |
				F_FW_CMD_REQUEST | F_FW_CMD_READ |
				V_FW_LDST_CMD_ADDRSPACE(FW_LDST_ADDRSPC_MPS));
			ldst_cmd.cycles_to_len16 = htobe32(FW_LEN16(ldst_cmd));
			ldst_cmd.u.mps.rplc.fid_idx =
			    htobe16(V_FW_LDST_CMD_FID(FW_LDST_MPS_RPLC) |
				V_FW_LDST_CMD_IDX(i));

			rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK,
			    "t4mps");
			if (rc)
				break;
			rc = -t4_wr_mbox(sc, sc->mbox, &ldst_cmd,
			    sizeof(ldst_cmd), &ldst_cmd);
			end_synchronized_op(sc, 0);

			if (rc != 0) {
				sbuf_printf(sb, "%36d", rc);
				rc = 0;
			} else {
				sbuf_printf(sb, " %08x %08x %08x %08x",
				    be32toh(ldst_cmd.u.mps.rplc.rplc127_96),
				    be32toh(ldst_cmd.u.mps.rplc.rplc95_64),
				    be32toh(ldst_cmd.u.mps.rplc.rplc63_32),
				    be32toh(ldst_cmd.u.mps.rplc.rplc31_0));
			}
		} else
			sbuf_printf(sb, "%36s", "");

		sbuf_printf(sb, "%4u%3u%3u%3u %#3x", G_SRAM_PRIO0(cls_lo),
		    G_SRAM_PRIO1(cls_lo), G_SRAM_PRIO2(cls_lo),
		    G_SRAM_PRIO3(cls_lo), (cls_lo >> S_MULTILISTEN0) & 0xf);
	}

	if (rc)
		(void) sbuf_finish(sb);
	else
		rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_mps_tcam_t6(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i;

	MPASS(chip_id(sc) > CHELSIO_T5);

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	sbuf_printf(sb, "Idx  Ethernet address     Mask       VNI   Mask"
	    "   IVLAN Vld DIP_Hit   Lookup  Port Vld Ports PF  VF"
	    "                           Replication"
	    "                                    P0 P1 P2 P3  ML\n");

	for (i = 0; i < sc->chip_params->mps_tcam_size; i++) {
		uint8_t dip_hit, vlan_vld, lookup_type, port_num;
		uint16_t ivlan;
		uint64_t tcamx, tcamy, val, mask;
		uint32_t cls_lo, cls_hi, ctl, data2, vnix, vniy;
		uint8_t addr[ETHER_ADDR_LEN];

		ctl = V_CTLREQID(1) | V_CTLCMDTYPE(0) | V_CTLXYBITSEL(0);
		if (i < 256)
			ctl |= V_CTLTCAMINDEX(i) | V_CTLTCAMSEL(0);
		else
			ctl |= V_CTLTCAMINDEX(i - 256) | V_CTLTCAMSEL(1);
		t4_write_reg(sc, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
		val = t4_read_reg(sc, A_MPS_CLS_TCAM_RDATA1_REQ_ID1);
		tcamy = G_DMACH(val) << 32;
		tcamy |= t4_read_reg(sc, A_MPS_CLS_TCAM_RDATA0_REQ_ID1);
		data2 = t4_read_reg(sc, A_MPS_CLS_TCAM_RDATA2_REQ_ID1);
		lookup_type = G_DATALKPTYPE(data2);
		port_num = G_DATAPORTNUM(data2);
		if (lookup_type && lookup_type != M_DATALKPTYPE) {
			/* Inner header VNI */
			vniy = ((data2 & F_DATAVIDH2) << 23) |
				       (G_DATAVIDH1(data2) << 16) | G_VIDL(val);
			dip_hit = data2 & F_DATADIPHIT;
			vlan_vld = 0;
		} else {
			vniy = 0;
			dip_hit = 0;
			vlan_vld = data2 & F_DATAVIDH2;
			ivlan = G_VIDL(val);
		}

		ctl |= V_CTLXYBITSEL(1);
		t4_write_reg(sc, A_MPS_CLS_TCAM_DATA2_CTL, ctl);
		val = t4_read_reg(sc, A_MPS_CLS_TCAM_RDATA1_REQ_ID1);
		tcamx = G_DMACH(val) << 32;
		tcamx |= t4_read_reg(sc, A_MPS_CLS_TCAM_RDATA0_REQ_ID1);
		data2 = t4_read_reg(sc, A_MPS_CLS_TCAM_RDATA2_REQ_ID1);
		if (lookup_type && lookup_type != M_DATALKPTYPE) {
			/* Inner header VNI mask */
			vnix = ((data2 & F_DATAVIDH2) << 23) |
			       (G_DATAVIDH1(data2) << 16) | G_VIDL(val);
		} else
			vnix = 0;

		if (tcamx & tcamy)
			continue;
		tcamxy2valmask(tcamx, tcamy, addr, &mask);

		cls_lo = t4_read_reg(sc, MPS_CLS_SRAM_L(i));
		cls_hi = t4_read_reg(sc, MPS_CLS_SRAM_H(i));

		if (lookup_type && lookup_type != M_DATALKPTYPE) {
			sbuf_printf(sb, "\n%3u %02x:%02x:%02x:%02x:%02x:%02x "
			    "%012jx %06x %06x    -    -   %3c"
			    "      'I'  %4x   %3c   %#x%4u%4d", i, addr[0],
			    addr[1], addr[2], addr[3], addr[4], addr[5],
			    (uintmax_t)mask, vniy, vnix, dip_hit ? 'Y' : 'N',
			    port_num, cls_lo & F_T6_SRAM_VLD ? 'Y' : 'N',
			    G_PORTMAP(cls_hi), G_T6_PF(cls_lo),
			    cls_lo & F_T6_VF_VALID ? G_T6_VF(cls_lo) : -1);
		} else {
			sbuf_printf(sb, "\n%3u %02x:%02x:%02x:%02x:%02x:%02x "
			    "%012jx    -       -   ", i, addr[0], addr[1],
			    addr[2], addr[3], addr[4], addr[5],
			    (uintmax_t)mask);

			if (vlan_vld)
				sbuf_printf(sb, "%4u   Y     ", ivlan);
			else
				sbuf_printf(sb, "  -    N     ");

			sbuf_printf(sb, "-      %3c  %4x   %3c   %#x%4u%4d",
			    lookup_type ? 'I' : 'O', port_num,
			    cls_lo & F_T6_SRAM_VLD ? 'Y' : 'N',
			    G_PORTMAP(cls_hi), G_T6_PF(cls_lo),
			    cls_lo & F_T6_VF_VALID ? G_T6_VF(cls_lo) : -1);
		}


		if (cls_lo & F_T6_REPLICATE) {
			struct fw_ldst_cmd ldst_cmd;

			memset(&ldst_cmd, 0, sizeof(ldst_cmd));
			ldst_cmd.op_to_addrspace =
			    htobe32(V_FW_CMD_OP(FW_LDST_CMD) |
				F_FW_CMD_REQUEST | F_FW_CMD_READ |
				V_FW_LDST_CMD_ADDRSPACE(FW_LDST_ADDRSPC_MPS));
			ldst_cmd.cycles_to_len16 = htobe32(FW_LEN16(ldst_cmd));
			ldst_cmd.u.mps.rplc.fid_idx =
			    htobe16(V_FW_LDST_CMD_FID(FW_LDST_MPS_RPLC) |
				V_FW_LDST_CMD_IDX(i));

			rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK,
			    "t6mps");
			if (rc)
				break;
			rc = -t4_wr_mbox(sc, sc->mbox, &ldst_cmd,
			    sizeof(ldst_cmd), &ldst_cmd);
			end_synchronized_op(sc, 0);

			if (rc != 0) {
				sbuf_printf(sb, "%72d", rc);
				rc = 0;
			} else {
				sbuf_printf(sb, " %08x %08x %08x %08x"
				    " %08x %08x %08x %08x",
				    be32toh(ldst_cmd.u.mps.rplc.rplc255_224),
				    be32toh(ldst_cmd.u.mps.rplc.rplc223_192),
				    be32toh(ldst_cmd.u.mps.rplc.rplc191_160),
				    be32toh(ldst_cmd.u.mps.rplc.rplc159_128),
				    be32toh(ldst_cmd.u.mps.rplc.rplc127_96),
				    be32toh(ldst_cmd.u.mps.rplc.rplc95_64),
				    be32toh(ldst_cmd.u.mps.rplc.rplc63_32),
				    be32toh(ldst_cmd.u.mps.rplc.rplc31_0));
			}
		} else
			sbuf_printf(sb, "%72s", "");

		sbuf_printf(sb, "%4u%3u%3u%3u %#x",
		    G_T6_SRAM_PRIO0(cls_lo), G_T6_SRAM_PRIO1(cls_lo),
		    G_T6_SRAM_PRIO2(cls_lo), G_T6_SRAM_PRIO3(cls_lo),
		    (cls_lo >> S_T6_MULTILISTEN0) & 0xf);
	}

	if (rc)
		(void) sbuf_finish(sb);
	else
		rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_path_mtus(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	uint16_t mtus[NMTUS];

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	t4_read_mtu_tbl(sc, mtus, NULL);

	sbuf_printf(sb, "%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u",
	    mtus[0], mtus[1], mtus[2], mtus[3], mtus[4], mtus[5], mtus[6],
	    mtus[7], mtus[8], mtus[9], mtus[10], mtus[11], mtus[12], mtus[13],
	    mtus[14], mtus[15]);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_pm_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, i;
	uint32_t tx_cnt[MAX_PM_NSTATS], rx_cnt[MAX_PM_NSTATS];
	uint64_t tx_cyc[MAX_PM_NSTATS], rx_cyc[MAX_PM_NSTATS];
	static const char *tx_stats[MAX_PM_NSTATS] = {
		"Read:", "Write bypass:", "Write mem:", "Bypass + mem:",
		"Tx FIFO wait", NULL, "Tx latency"
	};
	static const char *rx_stats[MAX_PM_NSTATS] = {
		"Read:", "Write bypass:", "Write mem:", "Flush:",
		"Rx FIFO wait", NULL, "Rx latency"
	};

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	t4_pmtx_get_stats(sc, tx_cnt, tx_cyc);
	t4_pmrx_get_stats(sc, rx_cnt, rx_cyc);

	sbuf_printf(sb, "                Tx pcmds             Tx bytes");
	for (i = 0; i < 4; i++) {
		sbuf_printf(sb, "\n%-13s %10u %20ju", tx_stats[i], tx_cnt[i],
		    tx_cyc[i]);
	}

	sbuf_printf(sb, "\n                Rx pcmds             Rx bytes");
	for (i = 0; i < 4; i++) {
		sbuf_printf(sb, "\n%-13s %10u %20ju", rx_stats[i], rx_cnt[i],
		    rx_cyc[i]);
	}

	if (chip_id(sc) > CHELSIO_T5) {
		sbuf_printf(sb,
		    "\n              Total wait      Total occupancy");
		sbuf_printf(sb, "\n%-13s %10u %20ju", tx_stats[i], tx_cnt[i],
		    tx_cyc[i]);
		sbuf_printf(sb, "\n%-13s %10u %20ju", rx_stats[i], rx_cnt[i],
		    rx_cyc[i]);

		i += 2;
		MPASS(i < nitems(tx_stats));

		sbuf_printf(sb,
		    "\n                   Reads           Total wait");
		sbuf_printf(sb, "\n%-13s %10u %20ju", tx_stats[i], tx_cnt[i],
		    tx_cyc[i]);
		sbuf_printf(sb, "\n%-13s %10u %20ju", rx_stats[i], rx_cnt[i],
		    rx_cyc[i]);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_rdma_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	struct tp_rdma_stats stats;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	mtx_lock(&sc->reg_lock);
	t4_tp_get_rdma_stats(sc, &stats);
	mtx_unlock(&sc->reg_lock);

	sbuf_printf(sb, "NoRQEModDefferals: %u\n", stats.rqe_dfr_mod);
	sbuf_printf(sb, "NoRQEPktDefferals: %u", stats.rqe_dfr_pkt);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_tcp_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	struct tp_tcp_stats v4, v6;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	mtx_lock(&sc->reg_lock);
	t4_tp_get_tcp_stats(sc, &v4, &v6);
	mtx_unlock(&sc->reg_lock);

	sbuf_printf(sb,
	    "                                IP                 IPv6\n");
	sbuf_printf(sb, "OutRsts:      %20u %20u\n",
	    v4.tcp_out_rsts, v6.tcp_out_rsts);
	sbuf_printf(sb, "InSegs:       %20ju %20ju\n",
	    v4.tcp_in_segs, v6.tcp_in_segs);
	sbuf_printf(sb, "OutSegs:      %20ju %20ju\n",
	    v4.tcp_out_segs, v6.tcp_out_segs);
	sbuf_printf(sb, "RetransSegs:  %20ju %20ju",
	    v4.tcp_retrans_segs, v6.tcp_retrans_segs);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_tids(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	struct tid_info *t = &sc->tids;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	if (t->natids) {
		sbuf_printf(sb, "ATID range: 0-%u, in use: %u\n", t->natids - 1,
		    t->atids_in_use);
	}

	if (t->ntids) {
		if (t4_read_reg(sc, A_LE_DB_CONFIG) & F_HASHEN) {
			uint32_t b;

			if (chip_id(sc) <= CHELSIO_T5)
				b = t4_read_reg(sc, A_LE_DB_SERVER_INDEX) / 4;
			else
				b = t4_read_reg(sc, A_LE_DB_SRVR_START_INDEX);

			if (b) {
				sbuf_printf(sb, "TID range: 0-%u, %u-%u", b - 1,
				    t4_read_reg(sc, A_LE_DB_TID_HASHBASE) / 4,
				    t->ntids - 1);
			} else {
				sbuf_printf(sb, "TID range: %u-%u",
				    t4_read_reg(sc, A_LE_DB_TID_HASHBASE) / 4,
				    t->ntids - 1);
			}
		} else
			sbuf_printf(sb, "TID range: 0-%u", t->ntids - 1);
		sbuf_printf(sb, ", in use: %u\n",
		    atomic_load_acq_int(&t->tids_in_use));
	}

	if (t->nstids) {
		sbuf_printf(sb, "STID range: %u-%u, in use: %u\n", t->stid_base,
		    t->stid_base + t->nstids - 1, t->stids_in_use);
	}

	if (t->nftids) {
		sbuf_printf(sb, "FTID range: %u-%u\n", t->ftid_base,
		    t->ftid_base + t->nftids - 1);
	}

	if (t->netids) {
		sbuf_printf(sb, "ETID range: %u-%u\n", t->etid_base,
		    t->etid_base + t->netids - 1);
	}

	sbuf_printf(sb, "HW TID usage: %u IP users, %u IPv6 users",
	    t4_read_reg(sc, A_LE_DB_ACT_CNT_IPV4),
	    t4_read_reg(sc, A_LE_DB_ACT_CNT_IPV6));

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_tp_err_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	struct tp_err_stats stats;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	mtx_lock(&sc->reg_lock);
	t4_tp_get_err_stats(sc, &stats);
	mtx_unlock(&sc->reg_lock);

	if (sc->chip_params->nchan > 2) {
		sbuf_printf(sb, "                 channel 0  channel 1"
		    "  channel 2  channel 3\n");
		sbuf_printf(sb, "macInErrs:      %10u %10u %10u %10u\n",
		    stats.mac_in_errs[0], stats.mac_in_errs[1],
		    stats.mac_in_errs[2], stats.mac_in_errs[3]);
		sbuf_printf(sb, "hdrInErrs:      %10u %10u %10u %10u\n",
		    stats.hdr_in_errs[0], stats.hdr_in_errs[1],
		    stats.hdr_in_errs[2], stats.hdr_in_errs[3]);
		sbuf_printf(sb, "tcpInErrs:      %10u %10u %10u %10u\n",
		    stats.tcp_in_errs[0], stats.tcp_in_errs[1],
		    stats.tcp_in_errs[2], stats.tcp_in_errs[3]);
		sbuf_printf(sb, "tcp6InErrs:     %10u %10u %10u %10u\n",
		    stats.tcp6_in_errs[0], stats.tcp6_in_errs[1],
		    stats.tcp6_in_errs[2], stats.tcp6_in_errs[3]);
		sbuf_printf(sb, "tnlCongDrops:   %10u %10u %10u %10u\n",
		    stats.tnl_cong_drops[0], stats.tnl_cong_drops[1],
		    stats.tnl_cong_drops[2], stats.tnl_cong_drops[3]);
		sbuf_printf(sb, "tnlTxDrops:     %10u %10u %10u %10u\n",
		    stats.tnl_tx_drops[0], stats.tnl_tx_drops[1],
		    stats.tnl_tx_drops[2], stats.tnl_tx_drops[3]);
		sbuf_printf(sb, "ofldVlanDrops:  %10u %10u %10u %10u\n",
		    stats.ofld_vlan_drops[0], stats.ofld_vlan_drops[1],
		    stats.ofld_vlan_drops[2], stats.ofld_vlan_drops[3]);
		sbuf_printf(sb, "ofldChanDrops:  %10u %10u %10u %10u\n\n",
		    stats.ofld_chan_drops[0], stats.ofld_chan_drops[1],
		    stats.ofld_chan_drops[2], stats.ofld_chan_drops[3]);
	} else {
		sbuf_printf(sb, "                 channel 0  channel 1\n");
		sbuf_printf(sb, "macInErrs:      %10u %10u\n",
		    stats.mac_in_errs[0], stats.mac_in_errs[1]);
		sbuf_printf(sb, "hdrInErrs:      %10u %10u\n",
		    stats.hdr_in_errs[0], stats.hdr_in_errs[1]);
		sbuf_printf(sb, "tcpInErrs:      %10u %10u\n",
		    stats.tcp_in_errs[0], stats.tcp_in_errs[1]);
		sbuf_printf(sb, "tcp6InErrs:     %10u %10u\n",
		    stats.tcp6_in_errs[0], stats.tcp6_in_errs[1]);
		sbuf_printf(sb, "tnlCongDrops:   %10u %10u\n",
		    stats.tnl_cong_drops[0], stats.tnl_cong_drops[1]);
		sbuf_printf(sb, "tnlTxDrops:     %10u %10u\n",
		    stats.tnl_tx_drops[0], stats.tnl_tx_drops[1]);
		sbuf_printf(sb, "ofldVlanDrops:  %10u %10u\n",
		    stats.ofld_vlan_drops[0], stats.ofld_vlan_drops[1]);
		sbuf_printf(sb, "ofldChanDrops:  %10u %10u\n\n",
		    stats.ofld_chan_drops[0], stats.ofld_chan_drops[1]);
	}

	sbuf_printf(sb, "ofldNoNeigh:    %u\nofldCongDefer:  %u",
	    stats.ofld_no_neigh, stats.ofld_cong_defer);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_tp_la_mask(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct tp_params *tpp = &sc->params.tp;
	u_int mask;
	int rc;

	mask = tpp->la_mask >> 16;
	rc = sysctl_handle_int(oidp, &mask, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);
	if (mask > 0xffff)
		return (EINVAL);
	tpp->la_mask = mask << 16;
	t4_set_reg_field(sc, A_TP_DBG_LA_CONFIG, 0xffff0000U, tpp->la_mask);

	return (0);
}

struct field_desc {
	const char *name;
	u_int start;
	u_int width;
};

static void
field_desc_show(struct sbuf *sb, uint64_t v, const struct field_desc *f)
{
	char buf[32];
	int line_size = 0;

	while (f->name) {
		uint64_t mask = (1ULL << f->width) - 1;
		int len = snprintf(buf, sizeof(buf), "%s: %ju", f->name,
		    ((uintmax_t)v >> f->start) & mask);

		if (line_size + len >= 79) {
			line_size = 8;
			sbuf_printf(sb, "\n        ");
		}
		sbuf_printf(sb, "%s ", buf);
		line_size += len + 1;
		f++;
	}
	sbuf_printf(sb, "\n");
}

static const struct field_desc tp_la0[] = {
	{ "RcfOpCodeOut", 60, 4 },
	{ "State", 56, 4 },
	{ "WcfState", 52, 4 },
	{ "RcfOpcSrcOut", 50, 2 },
	{ "CRxError", 49, 1 },
	{ "ERxError", 48, 1 },
	{ "SanityFailed", 47, 1 },
	{ "SpuriousMsg", 46, 1 },
	{ "FlushInputMsg", 45, 1 },
	{ "FlushInputCpl", 44, 1 },
	{ "RssUpBit", 43, 1 },
	{ "RssFilterHit", 42, 1 },
	{ "Tid", 32, 10 },
	{ "InitTcb", 31, 1 },
	{ "LineNumber", 24, 7 },
	{ "Emsg", 23, 1 },
	{ "EdataOut", 22, 1 },
	{ "Cmsg", 21, 1 },
	{ "CdataOut", 20, 1 },
	{ "EreadPdu", 19, 1 },
	{ "CreadPdu", 18, 1 },
	{ "TunnelPkt", 17, 1 },
	{ "RcfPeerFin", 16, 1 },
	{ "RcfReasonOut", 12, 4 },
	{ "TxCchannel", 10, 2 },
	{ "RcfTxChannel", 8, 2 },
	{ "RxEchannel", 6, 2 },
	{ "RcfRxChannel", 5, 1 },
	{ "RcfDataOutSrdy", 4, 1 },
	{ "RxDvld", 3, 1 },
	{ "RxOoDvld", 2, 1 },
	{ "RxCongestion", 1, 1 },
	{ "TxCongestion", 0, 1 },
	{ NULL }
};

static const struct field_desc tp_la1[] = {
	{ "CplCmdIn", 56, 8 },
	{ "CplCmdOut", 48, 8 },
	{ "ESynOut", 47, 1 },
	{ "EAckOut", 46, 1 },
	{ "EFinOut", 45, 1 },
	{ "ERstOut", 44, 1 },
	{ "SynIn", 43, 1 },
	{ "AckIn", 42, 1 },
	{ "FinIn", 41, 1 },
	{ "RstIn", 40, 1 },
	{ "DataIn", 39, 1 },
	{ "DataInVld", 38, 1 },
	{ "PadIn", 37, 1 },
	{ "RxBufEmpty", 36, 1 },
	{ "RxDdp", 35, 1 },
	{ "RxFbCongestion", 34, 1 },
	{ "TxFbCongestion", 33, 1 },
	{ "TxPktSumSrdy", 32, 1 },
	{ "RcfUlpType", 28, 4 },
	{ "Eread", 27, 1 },
	{ "Ebypass", 26, 1 },
	{ "Esave", 25, 1 },
	{ "Static0", 24, 1 },
	{ "Cread", 23, 1 },
	{ "Cbypass", 22, 1 },
	{ "Csave", 21, 1 },
	{ "CPktOut", 20, 1 },
	{ "RxPagePoolFull", 18, 2 },
	{ "RxLpbkPkt", 17, 1 },
	{ "TxLpbkPkt", 16, 1 },
	{ "RxVfValid", 15, 1 },
	{ "SynLearned", 14, 1 },
	{ "SetDelEntry", 13, 1 },
	{ "SetInvEntry", 12, 1 },
	{ "CpcmdDvld", 11, 1 },
	{ "CpcmdSave", 10, 1 },
	{ "RxPstructsFull", 8, 2 },
	{ "EpcmdDvld", 7, 1 },
	{ "EpcmdFlush", 6, 1 },
	{ "EpcmdTrimPrefix", 5, 1 },
	{ "EpcmdTrimPostfix", 4, 1 },
	{ "ERssIp4Pkt", 3, 1 },
	{ "ERssIp6Pkt", 2, 1 },
	{ "ERssTcpUdpPkt", 1, 1 },
	{ "ERssFceFipPkt", 0, 1 },
	{ NULL }
};

static const struct field_desc tp_la2[] = {
	{ "CplCmdIn", 56, 8 },
	{ "MpsVfVld", 55, 1 },
	{ "MpsPf", 52, 3 },
	{ "MpsVf", 44, 8 },
	{ "SynIn", 43, 1 },
	{ "AckIn", 42, 1 },
	{ "FinIn", 41, 1 },
	{ "RstIn", 40, 1 },
	{ "DataIn", 39, 1 },
	{ "DataInVld", 38, 1 },
	{ "PadIn", 37, 1 },
	{ "RxBufEmpty", 36, 1 },
	{ "RxDdp", 35, 1 },
	{ "RxFbCongestion", 34, 1 },
	{ "TxFbCongestion", 33, 1 },
	{ "TxPktSumSrdy", 32, 1 },
	{ "RcfUlpType", 28, 4 },
	{ "Eread", 27, 1 },
	{ "Ebypass", 26, 1 },
	{ "Esave", 25, 1 },
	{ "Static0", 24, 1 },
	{ "Cread", 23, 1 },
	{ "Cbypass", 22, 1 },
	{ "Csave", 21, 1 },
	{ "CPktOut", 20, 1 },
	{ "RxPagePoolFull", 18, 2 },
	{ "RxLpbkPkt", 17, 1 },
	{ "TxLpbkPkt", 16, 1 },
	{ "RxVfValid", 15, 1 },
	{ "SynLearned", 14, 1 },
	{ "SetDelEntry", 13, 1 },
	{ "SetInvEntry", 12, 1 },
	{ "CpcmdDvld", 11, 1 },
	{ "CpcmdSave", 10, 1 },
	{ "RxPstructsFull", 8, 2 },
	{ "EpcmdDvld", 7, 1 },
	{ "EpcmdFlush", 6, 1 },
	{ "EpcmdTrimPrefix", 5, 1 },
	{ "EpcmdTrimPostfix", 4, 1 },
	{ "ERssIp4Pkt", 3, 1 },
	{ "ERssIp6Pkt", 2, 1 },
	{ "ERssTcpUdpPkt", 1, 1 },
	{ "ERssFceFipPkt", 0, 1 },
	{ NULL }
};

static void
tp_la_show(struct sbuf *sb, uint64_t *p, int idx)
{

	field_desc_show(sb, *p, tp_la0);
}

static void
tp_la_show2(struct sbuf *sb, uint64_t *p, int idx)
{

	if (idx)
		sbuf_printf(sb, "\n");
	field_desc_show(sb, p[0], tp_la0);
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		field_desc_show(sb, p[1], tp_la0);
}

static void
tp_la_show3(struct sbuf *sb, uint64_t *p, int idx)
{

	if (idx)
		sbuf_printf(sb, "\n");
	field_desc_show(sb, p[0], tp_la0);
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		field_desc_show(sb, p[1], (p[0] & (1 << 17)) ? tp_la2 : tp_la1);
}

static int
sysctl_tp_la(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	uint64_t *buf, *p;
	int rc;
	u_int i, inc;
	void (*show_func)(struct sbuf *, uint64_t *, int);

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	buf = malloc(TPLA_SIZE * sizeof(uint64_t), M_CXGBE, M_ZERO | M_WAITOK);

	t4_tp_read_la(sc, buf, NULL);
	p = buf;

	switch (G_DBGLAMODE(t4_read_reg(sc, A_TP_DBG_LA_CONFIG))) {
	case 2:
		inc = 2;
		show_func = tp_la_show2;
		break;
	case 3:
		inc = 2;
		show_func = tp_la_show3;
		break;
	default:
		inc = 1;
		show_func = tp_la_show;
	}

	for (i = 0; i < TPLA_SIZE / inc; i++, p += inc)
		(*show_func)(sb, p, i);

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_tx_rate(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc;
	u64 nrate[MAX_NCHAN], orate[MAX_NCHAN];

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 256, req);
	if (sb == NULL)
		return (ENOMEM);

	t4_get_chan_txrate(sc, nrate, orate);

	if (sc->chip_params->nchan > 2) {
		sbuf_printf(sb, "              channel 0   channel 1"
		    "   channel 2   channel 3\n");
		sbuf_printf(sb, "NIC B/s:     %10ju  %10ju  %10ju  %10ju\n",
		    nrate[0], nrate[1], nrate[2], nrate[3]);
		sbuf_printf(sb, "Offload B/s: %10ju  %10ju  %10ju  %10ju",
		    orate[0], orate[1], orate[2], orate[3]);
	} else {
		sbuf_printf(sb, "              channel 0   channel 1\n");
		sbuf_printf(sb, "NIC B/s:     %10ju  %10ju\n",
		    nrate[0], nrate[1]);
		sbuf_printf(sb, "Offload B/s: %10ju  %10ju",
		    orate[0], orate[1]);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_ulprx_la(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	uint32_t *buf, *p;
	int rc, i;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	buf = malloc(ULPRX_LA_SIZE * 8 * sizeof(uint32_t), M_CXGBE,
	    M_ZERO | M_WAITOK);

	t4_ulprx_read_la(sc, buf);
	p = buf;

	sbuf_printf(sb, "      Pcmd        Type   Message"
	    "                Data");
	for (i = 0; i < ULPRX_LA_SIZE; i++, p += 8) {
		sbuf_printf(sb, "\n%08x%08x  %4x  %08x  %08x%08x%08x%08x",
		    p[1], p[0], p[2], p[3], p[7], p[6], p[5], p[4]);
	}

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
	free(buf, M_CXGBE);
	return (rc);
}

static int
sysctl_wcwr_stats(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct sbuf *sb;
	int rc, v;

	MPASS(chip_id(sc) >= CHELSIO_T5);

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	v = t4_read_reg(sc, A_SGE_STAT_CFG);
	if (G_STATSOURCE_T5(v) == 7) {
		int mode;

		mode = is_t5(sc) ? G_STATMODE(v) : G_T6_STATMODE(v);
		if (mode == 0) {
			sbuf_printf(sb, "total %d, incomplete %d",
			    t4_read_reg(sc, A_SGE_STAT_TOTAL),
			    t4_read_reg(sc, A_SGE_STAT_MATCH));
		} else if (mode == 1) {
			sbuf_printf(sb, "total %d, data overflow %d",
			    t4_read_reg(sc, A_SGE_STAT_TOTAL),
			    t4_read_reg(sc, A_SGE_STAT_MATCH));
		} else {
			sbuf_printf(sb, "unknown mode %d", mode);
		}
	}
	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}
#endif

#ifdef TCP_OFFLOAD
static void
unit_conv(char *buf, size_t len, u_int val, u_int factor)
{
	u_int rem = val % factor;

	if (rem == 0)
		snprintf(buf, len, "%u", val / factor);
	else {
		while (rem % 10 == 0)
			rem /= 10;
		snprintf(buf, len, "%u.%u", val / factor, rem);
	}
}

static int
sysctl_tp_tick(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	char buf[16];
	u_int res, re;
	u_int cclk_ps = 1000000000 / sc->params.vpd.cclk;

	res = t4_read_reg(sc, A_TP_TIMER_RESOLUTION);
	switch (arg2) {
	case 0:
		/* timer_tick */
		re = G_TIMERRESOLUTION(res);
		break;
	case 1:
		/* TCP timestamp tick */
		re = G_TIMESTAMPRESOLUTION(res);
		break;
	case 2:
		/* DACK tick */
		re = G_DELAYEDACKRESOLUTION(res);
		break;
	default:
		return (EDOOFUS);
	}

	unit_conv(buf, sizeof(buf), (cclk_ps << re), 1000000);

	return (sysctl_handle_string(oidp, buf, sizeof(buf), req));
}

static int
sysctl_tp_dack_timer(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	u_int res, dack_re, v;
	u_int cclk_ps = 1000000000 / sc->params.vpd.cclk;

	res = t4_read_reg(sc, A_TP_TIMER_RESOLUTION);
	dack_re = G_DELAYEDACKRESOLUTION(res);
	v = ((cclk_ps << dack_re) / 1000000) * t4_read_reg(sc, A_TP_DACK_TIMER);

	return (sysctl_handle_int(oidp, &v, 0, req));
}

static int
sysctl_tp_timer(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	int reg = arg2;
	u_int tre;
	u_long tp_tick_us, v;
	u_int cclk_ps = 1000000000 / sc->params.vpd.cclk;

	MPASS(reg == A_TP_RXT_MIN || reg == A_TP_RXT_MAX ||
	    reg == A_TP_PERS_MIN || reg == A_TP_PERS_MAX ||
	    reg == A_TP_KEEP_IDLE || A_TP_KEEP_INTVL || reg == A_TP_INIT_SRTT ||
	    reg == A_TP_FINWAIT2_TIMER);

	tre = G_TIMERRESOLUTION(t4_read_reg(sc, A_TP_TIMER_RESOLUTION));
	tp_tick_us = (cclk_ps << tre) / 1000000;

	if (reg == A_TP_INIT_SRTT)
		v = tp_tick_us * G_INITSRTT(t4_read_reg(sc, reg));
	else
		v = tp_tick_us * t4_read_reg(sc, reg);

	return (sysctl_handle_long(oidp, &v, 0, req));
}
#endif

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

/*
 * Come up with reasonable defaults for some of the tunables, provided they're
 * not set by the user (in which case we'll use the values as is).
 */
static void
tweak_tunables(void *dummy)
{
	int nc = mp_ncpus;	/* our snapshot of the number of CPUs */

	if (t4_ntxq_vi < 1)
		t4_ntxq_vi = min(nc, NTXQ_VI);

	if (t4_nrxq_vi < 1)
		t4_nrxq_vi = min(nc, NRXQ_VI);

#ifdef TCP_OFFLOAD
	if (t4_nofldtxq10g < 1)
		t4_nofldtxq10g = min(nc, NOFLDTXQ_10G);

	if (t4_nofldtxq1g < 1)
		t4_nofldtxq1g = min(nc, NOFLDTXQ_1G);

	if (t4_nofldtxq_vi < 1)
		t4_nofldtxq_vi = min(nc, NOFLDTXQ_VI);

	if (t4_nofldrxq10g < 1)
		t4_nofldrxq10g = min(nc, NOFLDRXQ_10G);

	if (t4_nofldrxq1g < 1)
		t4_nofldrxq1g = min(nc, NOFLDRXQ_1G);

	if (t4_nofldrxq_vi < 1)
		t4_nofldrxq_vi = min(nc, NOFLDRXQ_VI);

	if (t4_toecaps_allowed == -1)
		t4_toecaps_allowed = FW_CAPS_CONFIG_TOE;

	if (t4_rdmacaps_allowed == -1) {
		t4_rdmacaps_allowed = FW_CAPS_CONFIG_RDMA_RDDP |
		    FW_CAPS_CONFIG_RDMA_RDMAC;
	}

	if (t4_iscsicaps_allowed == -1) {
		t4_iscsicaps_allowed = FW_CAPS_CONFIG_ISCSI_INITIATOR_PDU |
		    FW_CAPS_CONFIG_ISCSI_TARGET_PDU |
		    FW_CAPS_CONFIG_ISCSI_T10DIF;
	}
#else
	if (t4_toecaps_allowed == -1)
		t4_toecaps_allowed = 0;

	if (t4_rdmacaps_allowed == -1)
		t4_rdmacaps_allowed = 0;

	if (t4_iscsicaps_allowed == -1)
		t4_iscsicaps_allowed = 0;
#endif

#ifdef DEV_NETMAP
	if (t4_nnmtxq_vi < 1)
		t4_nnmtxq_vi = min(nc, NNMTXQ_VI);

	if (t4_nnmrxq_vi < 1)
		t4_nnmrxq_vi = min(nc, NNMRXQ_VI);
#endif
}
SYSINIT(t4nex_tunables, SI_SUB_CPU, SI_ORDER_ANY, tweak_tunables, NULL);

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
