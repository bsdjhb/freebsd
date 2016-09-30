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

/* Common port methods */
static int cxgbe_probe(device_t);
static int cxgbe_attach(device_t);
static int cxgbe_detach(device_t);
device_method_t cxgbe_methods[] = {
	DEVMETHOD(device_probe,		cxgbe_probe),
	DEVMETHOD(device_attach,	cxgbe_attach),
	DEVMETHOD(device_detach,	cxgbe_detach),
	{ 0, 0 }
};

/* ifnet + media interface */
static void cxgbe_init(void *);
static int cxgbe_ioctl(struct ifnet *, unsigned long, caddr_t);
static int cxgbe_transmit(struct ifnet *, struct mbuf *);
static void cxgbe_qflush(struct ifnet *);
static int cxgbe_media_change(struct ifnet *);
static void cxgbe_media_status(struct ifnet *, struct ifmediareq *);

MALLOC_DEFINE(M_CXGBE, "cxgbe", "Chelsio T4/T5/T6 Ethernet driver and services");

/*
 * Correct lock order when you need to acquire multiple locks is t4_list_lock,
 * then ADAPTER_LOCK, then t4_uld_list_lock.
 */
static struct sx t4_list_lock;
SLIST_HEAD(, adapter) t4_list;
#ifdef TCP_OFFLOAD
static struct sx t4_uld_list_lock;
SLIST_HEAD(, uld_info) t4_uld_list;
#endif

/*
 * Tunables shared by all drivers.  See tweak_tunables() too.
 *
 * Each tunable is set to a default value here if it's known at compile-time.
 * Otherwise it is set to -1 as an indication to tweak_tunables() that it should
 * provide a reasonable default when the driver is loaded.
 *
 * Tunables applicable to both T4 and T5 are under hw.cxgbe.  Those specific to
 * T5 are under hw.cxl.
 */

/*
 * Number of queues for tx and rx, 10G and 1G.
 */
#define NTXQ_10G 16
int t4_ntxq10g = -1;
TUNABLE_INT("hw.cxgbe.ntxq10g", &t4_ntxq10g);

#define NRXQ_10G 8
int t4_nrxq10g = -1;
TUNABLE_INT("hw.cxgbe.nrxq10g", &t4_nrxq10g);

#define NTXQ_1G 4
int t4_ntxq1g = -1;
TUNABLE_INT("hw.cxgbe.ntxq1g", &t4_ntxq1g);

#define NRXQ_1G 2
int t4_nrxq1g = -1;
TUNABLE_INT("hw.cxgbe.nrxq1g", &t4_nrxq1g);

/*
 * Holdoff parameters for 10G and 1G ports.
 */
#define TMR_IDX_10G 1
int t4_tmr_idx_10g = TMR_IDX_10G;
TUNABLE_INT("hw.cxgbe.holdoff_timer_idx_10G", &t4_tmr_idx_10g);

#define PKTC_IDX_10G (-1)
int t4_pktc_idx_10g = PKTC_IDX_10G;
TUNABLE_INT("hw.cxgbe.holdoff_pktc_idx_10G", &t4_pktc_idx_10g);

#define TMR_IDX_1G 1
int t4_tmr_idx_1g = TMR_IDX_1G;
TUNABLE_INT("hw.cxgbe.holdoff_timer_idx_1G", &t4_tmr_idx_1g);

#define PKTC_IDX_1G (-1)
int t4_pktc_idx_1g = PKTC_IDX_1G;
TUNABLE_INT("hw.cxgbe.holdoff_pktc_idx_1G", &t4_pktc_idx_1g);

/*
 * Size (# of entries) of each tx and rx queue.
 */
unsigned int t4_qsize_txq = TX_EQ_QSIZE;
TUNABLE_INT("hw.cxgbe.qsize_txq", &t4_qsize_txq);

unsigned int t4_qsize_rxq = RX_IQ_QSIZE;
TUNABLE_INT("hw.cxgbe.qsize_rxq", &t4_qsize_rxq);

/*
 * Interrupt types allowed (bits 0, 1, 2 = INTx, MSI, MSI-X respectively).
 */
int t4_intr_types = INTR_MSIX | INTR_MSI | INTR_INTX;
TUNABLE_INT("hw.cxgbe.interrupt_types", &t4_intr_types);

static int t5_write_combine = 0;
TUNABLE_INT("hw.cxl.write_combine", &t5_write_combine);

static void build_medialist(struct port_info *, struct ifmedia *);
static int cxgbe_init_synchronized(struct vi_info *);
static int cxgbe_uninit_synchronized(struct vi_info *);
static void quiesce_txq(struct adapter *, struct sge_txq *);
static void quiesce_wrq(struct adapter *, struct sge_wrq *);
static void quiesce_iq(struct adapter *, struct sge_iq *);
static void quiesce_fl(struct adapter *, struct sge_fl *);
static int t4_alloc_irq(struct adapter *, struct irq *, int rid,
    driver_intr_t *, void *, char *);
static int t4_free_irq(struct adapter *, struct irq *);
static void vi_refresh_stats(struct adapter *, struct vi_info *);
static void cxgbe_refresh_stats(struct adapter *, struct port_info *);
static void cxgbe_tick(void *);
static void cxgbe_vlan_config(void *, struct ifnet *, uint16_t);
static void cxgbe_sysctls(struct port_info *);
static int sysctl_int_array(SYSCTL_HANDLER_ARGS);
static int sysctl_btphy(SYSCTL_HANDLER_ARGS);
static int sysctl_noflowq(SYSCTL_HANDLER_ARGS);
static int sysctl_holdoff_tmr_idx(SYSCTL_HANDLER_ARGS);
static int sysctl_holdoff_pktc_idx(SYSCTL_HANDLER_ARGS);
static int sysctl_qsize_rxq(SYSCTL_HANDLER_ARGS);
static int sysctl_qsize_txq(SYSCTL_HANDLER_ARGS);
static int sysctl_pause_settings(SYSCTL_HANDLER_ARGS);
static int sysctl_handle_t4_reg64(SYSCTL_HANDLER_ARGS);
#ifdef SBUF_DRAIN
static int sysctl_linkdnrc(SYSCTL_HANDLER_ARGS);
static int sysctl_tc_params(SYSCTL_HANDLER_ARGS);
#endif
static int set_tcb_rpl(struct sge_iq *, const struct rss_header *,
    struct mbuf *);
#ifdef TCP_OFFLOAD
static int toe_capability(struct vi_info *, int);
#endif
static int mod_event(module_t, int, void *);

#ifdef TCP_OFFLOAD
/*
 * service_iq() has an iq and needs the fl.  Offset of fl from the iq should be
 * exactly the same for both rxq and ofld_rxq.
 */
CTASSERT(offsetof(struct sge_ofld_rxq, iq) == offsetof(struct sge_rxq, iq));
CTASSERT(offsetof(struct sge_ofld_rxq, fl) == offsetof(struct sge_rxq, fl));
#endif
CTASSERT(sizeof(struct cluster_metadata) <= CL_METADATA_SIZE);

static const struct devnames devnames[] = {
	{
		.nexus_name = "t4nex",
		.ifnet_name = "cxgbe",
		.vi_ifnet_name = "vcxgbe",
		.pf03_drv_name = "t4iov",
		.vf_nexus_name = "t4vf",
		.vf_ifnet_name = "cxgbev"
	}, {
		.nexus_name = "t5nex",
		.ifnet_name = "cxl",
		.vi_ifnet_name = "vcxl",
		.pf03_drv_name = "t5iov",
		.vf_nexus_name = "t5vf",
		.vf_ifnet_name = "cxlv"
	}, {
		.nexus_name = "t6nex",
		.ifnet_name = "cc",
		.vi_ifnet_name = "vcc",
		.pf03_drv_name = "t6iov",
		.vf_nexus_name = "t6vf",
		.vf_ifnet_name = "ccv"
	}
};

void
t4_init_devnames(struct adapter *sc)
{
	int id;

	id = chip_id(sc);
	if (id >= CHELSIO_T4 && id - CHELSIO_T4 < nitems(devnames))
		sc->names = &devnames[id - CHELSIO_T4];
	else {
		device_printf(sc->dev, "chip id %d is not supported.\n", id);
		sc->names = NULL;
	}
}

int
t4_detach_common(device_t dev)
{
	struct adapter *sc;
	struct port_info *pi;
	int i, rc;

	sc = device_get_softc(dev);

	if (sc->flags & FULL_INIT_DONE) {
		if (!(sc->flags & IS_VF))
			t4_intr_disable(sc);
	}

	if (sc->cdev) {
		destroy_dev(sc->cdev);
		sc->cdev = NULL;
	}

	if (device_is_attached(dev)) {
		rc = bus_generic_detach(dev);
		if (rc) {
			device_printf(dev,
			    "failed to detach child devices: %d\n", rc);
			return (rc);
		}
	}

	for (i = 0; i < sc->intr_count; i++)
		t4_free_irq(sc, &sc->irq[i]);

	for (i = 0; i < MAX_NPORTS; i++) {
		pi = sc->port[i];
		if (pi) {
			t4_free_vi(sc, sc->mbox, sc->pf, 0, pi->vi[0].viid);
			if (pi->dev)
				device_delete_child(dev, pi->dev);

			mtx_destroy(&pi->pi_lock);
			free(pi->vi, M_CXGBE);
			free(pi->tc, M_CXGBE);
			free(pi, M_CXGBE);
		}
	}

	if (sc->flags & FULL_INIT_DONE)
		adapter_full_uninit(sc);

	if ((sc->flags & (IS_VF | FW_OK)) == FW_OK)
		t4_fw_bye(sc, sc->mbox);

	if (sc->intr_type == INTR_MSI || sc->intr_type == INTR_MSIX)
		pci_release_msi(dev);

	if (sc->regs_res)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->regs_rid,
		    sc->regs_res);

	if (sc->udbs_res)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->udbs_rid,
		    sc->udbs_res);

	if (sc->msix_res)
		bus_release_resource(dev, SYS_RES_MEMORY, sc->msix_rid,
		    sc->msix_res);

	free(sc->irq, M_CXGBE);
	free(sc->sge.rxq, M_CXGBE);
	free(sc->sge.txq, M_CXGBE);
	free(sc->sge.iqmap, M_CXGBE);
	free(sc->sge.eqmap, M_CXGBE);
	t4_destroy_dma_tag(sc);
	if (mtx_initialized(&sc->sc_lock)) {
		sx_xlock(&t4_list_lock);
		SLIST_REMOVE(&t4_list, sc, adapter, link);
		sx_xunlock(&t4_list_lock);
		mtx_destroy(&sc->sc_lock);
	}

	callout_drain(&sc->sfl_callout);
	if (mtx_initialized(&sc->sfl_lock))
		mtx_destroy(&sc->sfl_lock);
	if (mtx_initialized(&sc->reg_lock))
		mtx_destroy(&sc->reg_lock);

	return (0);
}

static int
cxgbe_probe(device_t dev)
{
	char buf[128];
	struct port_info *pi = device_get_softc(dev);

	snprintf(buf, sizeof(buf), "port %d", pi->port_id);
	device_set_desc_copy(dev, buf);

	return (BUS_PROBE_DEFAULT);
}

#define T4_CAP (IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_MTU | IFCAP_HWCSUM | \
    IFCAP_VLAN_HWCSUM | IFCAP_TSO | IFCAP_JUMBO_MTU | IFCAP_LRO | \
    IFCAP_VLAN_HWTSO | IFCAP_LINKSTATE | IFCAP_HWCSUM_IPV6 | IFCAP_HWSTATS)
#define T4_CAP_ENABLE (T4_CAP)

int
cxgbe_vi_attach(device_t dev, struct vi_info *vi)
{
	struct ifnet *ifp;
	struct sbuf *sb;

	vi->xact_addr_filt = -1;
	callout_init(&vi->tick, 1);

	/* Allocate an ifnet and set it up */
	ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		device_printf(dev, "Cannot allocate ifnet\n");
		return (ENOMEM);
	}
	vi->ifp = ifp;
	ifp->if_softc = vi;

	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;

	ifp->if_init = cxgbe_init;
	ifp->if_ioctl = cxgbe_ioctl;
	ifp->if_transmit = cxgbe_transmit;
	ifp->if_qflush = cxgbe_qflush;
	ifp->if_get_counter = cxgbe_get_counter;

	ifp->if_capabilities = T4_CAP;
#ifdef TCP_OFFLOAD
	if (vi->nofldrxq != 0)
		ifp->if_capabilities |= IFCAP_TOE;
#endif
	ifp->if_capenable = T4_CAP_ENABLE;
	ifp->if_hwassist = CSUM_TCP | CSUM_UDP | CSUM_IP | CSUM_TSO |
	    CSUM_UDP_IPV6 | CSUM_TCP_IPV6;

	ifp->if_hw_tsomax = 65536 - (ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN);
	ifp->if_hw_tsomaxsegcount = TX_SGL_SEGS;
	ifp->if_hw_tsomaxsegsize = 65536;

	/* Initialize ifmedia for this VI */
	ifmedia_init(&vi->media, IFM_IMASK, cxgbe_media_change,
	    cxgbe_media_status);
	build_medialist(vi->pi, &vi->media);

	vi->vlan_c = EVENTHANDLER_REGISTER(vlan_config, cxgbe_vlan_config, ifp,
	    EVENTHANDLER_PRI_ANY);

	ether_ifattach(ifp, vi->hw_addr);
#ifdef DEV_NETMAP
	if (vi->nnmrxq != 0)
		cxgbe_nm_attach(vi);
#endif
	sb = sbuf_new_auto();
	sbuf_printf(sb, "%d txq, %d rxq (NIC)", vi->ntxq, vi->nrxq);
#ifdef TCP_OFFLOAD
	if (ifp->if_capabilities & IFCAP_TOE)
		sbuf_printf(sb, "; %d txq, %d rxq (TOE)",
		    vi->nofldtxq, vi->nofldrxq);
#endif
#ifdef DEV_NETMAP
	if (ifp->if_capabilities & IFCAP_NETMAP)
		sbuf_printf(sb, "; %d txq, %d rxq (netmap)",
		    vi->nnmtxq, vi->nnmrxq);
#endif
	sbuf_finish(sb);
	device_printf(dev, "%s\n", sbuf_data(sb));
	sbuf_delete(sb);

	vi_sysctls(vi);

	return (0);
}

static int
cxgbe_attach(device_t dev)
{
	struct port_info *pi = device_get_softc(dev);
	struct adapter *sc = pi->adapter;
	struct vi_info *vi;
	int i, rc;

	callout_init_mtx(&pi->tick, &pi->pi_lock, 0);

	rc = cxgbe_vi_attach(dev, &pi->vi[0]);
	if (rc)
		return (rc);

	for_each_vi(pi, i, vi) {
		if (i == 0)
			continue;
		vi->dev = device_add_child(dev, sc->names->vi_ifnet_name, -1);
		if (vi->dev == NULL) {
			device_printf(dev, "failed to add VI %d\n", i);
			continue;
		}
		device_set_softc(vi->dev, vi);
	}

	cxgbe_sysctls(pi);

	bus_generic_attach(dev);

	return (0);
}

void
cxgbe_vi_detach(struct vi_info *vi)
{
	struct ifnet *ifp = vi->ifp;

	ether_ifdetach(ifp);

	if (vi->vlan_c)
		EVENTHANDLER_DEREGISTER(vlan_config, vi->vlan_c);

	/* Let detach proceed even if these fail. */
#ifdef DEV_NETMAP
	if (ifp->if_capabilities & IFCAP_NETMAP)
		cxgbe_nm_detach(vi);
#endif
	cxgbe_uninit_synchronized(vi);
	callout_drain(&vi->tick);
	vi_full_uninit(vi);

	ifmedia_removeall(&vi->media);
	if_free(vi->ifp);
	vi->ifp = NULL;
}

static int
cxgbe_detach(device_t dev)
{
	struct port_info *pi = device_get_softc(dev);
	struct adapter *sc = pi->adapter;
	int rc;

	/* Detach the extra VIs first. */
	rc = bus_generic_detach(dev);
	if (rc)
		return (rc);
	device_delete_children(dev);

	doom_vi(sc, &pi->vi[0]);

	if (pi->flags & HAS_TRACEQ) {
		sc->traceq = -1;	/* cloner should not create ifnet */
		t4_tracer_port_detach(sc);
	}

	cxgbe_vi_detach(&pi->vi[0]);
	callout_drain(&pi->tick);

	end_synchronized_op(sc, 0);

	return (0);
}

static void
cxgbe_init(void *arg)
{
	struct vi_info *vi = arg;
	struct adapter *sc = vi->pi->adapter;

	if (begin_synchronized_op(sc, vi, SLEEP_OK | INTR_OK, "t4init") != 0)
		return;
	cxgbe_init_synchronized(vi);
	end_synchronized_op(sc, 0);
}

static int
cxgbe_ioctl(struct ifnet *ifp, unsigned long cmd, caddr_t data)
{
	int rc = 0, mtu, flags, can_sleep;
	struct vi_info *vi = ifp->if_softc;
	struct adapter *sc = vi->pi->adapter;
	struct ifreq *ifr = (struct ifreq *)data;
	uint32_t mask;

	switch (cmd) {
	case SIOCSIFMTU:
		mtu = ifr->ifr_mtu;
		if (mtu < ETHERMIN || mtu > MAX_MTU)
			return (EINVAL);

		rc = begin_synchronized_op(sc, vi, SLEEP_OK | INTR_OK, "t4mtu");
		if (rc)
			return (rc);
		ifp->if_mtu = mtu;
		if (vi->flags & VI_INIT_DONE) {
			t4_update_fl_bufsize(ifp);
			if (ifp->if_drv_flags & IFF_DRV_RUNNING)
				rc = update_mac_settings(ifp, XGMAC_MTU);
		}
		end_synchronized_op(sc, 0);
		break;

	case SIOCSIFFLAGS:
		can_sleep = 0;
redo_sifflags:
		rc = begin_synchronized_op(sc, vi,
		    can_sleep ? (SLEEP_OK | INTR_OK) : HOLD_LOCK, "t4flg");
		if (rc)
			return (rc);

		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
				flags = vi->if_flags;
				if ((ifp->if_flags ^ flags) &
				    (IFF_PROMISC | IFF_ALLMULTI)) {
					if (can_sleep == 1) {
						end_synchronized_op(sc, 0);
						can_sleep = 0;
						goto redo_sifflags;
					}
					rc = update_mac_settings(ifp,
					    XGMAC_PROMISC | XGMAC_ALLMULTI);
				}
			} else {
				if (can_sleep == 0) {
					end_synchronized_op(sc, LOCK_HELD);
					can_sleep = 1;
					goto redo_sifflags;
				}
				rc = cxgbe_init_synchronized(vi);
			}
			vi->if_flags = ifp->if_flags;
		} else if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
			if (can_sleep == 0) {
				end_synchronized_op(sc, LOCK_HELD);
				can_sleep = 1;
				goto redo_sifflags;
			}
			rc = cxgbe_uninit_synchronized(vi);
		}
		end_synchronized_op(sc, can_sleep ? 0 : LOCK_HELD);
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI: /* these two are called with a mutex held :-( */
		rc = begin_synchronized_op(sc, vi, HOLD_LOCK, "t4multi");
		if (rc)
			return (rc);
		if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			rc = update_mac_settings(ifp, XGMAC_MCADDRS);
		end_synchronized_op(sc, LOCK_HELD);
		break;

	case SIOCSIFCAP:
		rc = begin_synchronized_op(sc, vi, SLEEP_OK | INTR_OK, "t4cap");
		if (rc)
			return (rc);

		mask = ifr->ifr_reqcap ^ ifp->if_capenable;
		if (mask & IFCAP_TXCSUM) {
			ifp->if_capenable ^= IFCAP_TXCSUM;
			ifp->if_hwassist ^= (CSUM_TCP | CSUM_UDP | CSUM_IP);

			if (IFCAP_TSO4 & ifp->if_capenable &&
			    !(IFCAP_TXCSUM & ifp->if_capenable)) {
				ifp->if_capenable &= ~IFCAP_TSO4;
				if_printf(ifp,
				    "tso4 disabled due to -txcsum.\n");
			}
		}
		if (mask & IFCAP_TXCSUM_IPV6) {
			ifp->if_capenable ^= IFCAP_TXCSUM_IPV6;
			ifp->if_hwassist ^= (CSUM_UDP_IPV6 | CSUM_TCP_IPV6);

			if (IFCAP_TSO6 & ifp->if_capenable &&
			    !(IFCAP_TXCSUM_IPV6 & ifp->if_capenable)) {
				ifp->if_capenable &= ~IFCAP_TSO6;
				if_printf(ifp,
				    "tso6 disabled due to -txcsum6.\n");
			}
		}
		if (mask & IFCAP_RXCSUM)
			ifp->if_capenable ^= IFCAP_RXCSUM;
		if (mask & IFCAP_RXCSUM_IPV6)
			ifp->if_capenable ^= IFCAP_RXCSUM_IPV6;

		/*
		 * Note that we leave CSUM_TSO alone (it is always set).  The
		 * kernel takes both IFCAP_TSOx and CSUM_TSO into account before
		 * sending a TSO request our way, so it's sufficient to toggle
		 * IFCAP_TSOx only.
		 */
		if (mask & IFCAP_TSO4) {
			if (!(IFCAP_TSO4 & ifp->if_capenable) &&
			    !(IFCAP_TXCSUM & ifp->if_capenable)) {
				if_printf(ifp, "enable txcsum first.\n");
				rc = EAGAIN;
				goto fail;
			}
			ifp->if_capenable ^= IFCAP_TSO4;
		}
		if (mask & IFCAP_TSO6) {
			if (!(IFCAP_TSO6 & ifp->if_capenable) &&
			    !(IFCAP_TXCSUM_IPV6 & ifp->if_capenable)) {
				if_printf(ifp, "enable txcsum6 first.\n");
				rc = EAGAIN;
				goto fail;
			}
			ifp->if_capenable ^= IFCAP_TSO6;
		}
		if (mask & IFCAP_LRO) {
#if defined(INET) || defined(INET6)
			int i;
			struct sge_rxq *rxq;

			ifp->if_capenable ^= IFCAP_LRO;
			for_each_rxq(vi, i, rxq) {
				if (ifp->if_capenable & IFCAP_LRO)
					rxq->iq.flags |= IQ_LRO_ENABLED;
				else
					rxq->iq.flags &= ~IQ_LRO_ENABLED;
			}
#endif
		}
#ifdef TCP_OFFLOAD
		if (mask & IFCAP_TOE) {
			int enable = (ifp->if_capenable ^ mask) & IFCAP_TOE;

			rc = toe_capability(vi, enable);
			if (rc != 0)
				goto fail;

			ifp->if_capenable ^= mask;
		}
#endif
		if (mask & IFCAP_VLAN_HWTAGGING) {
			ifp->if_capenable ^= IFCAP_VLAN_HWTAGGING;
			if (ifp->if_drv_flags & IFF_DRV_RUNNING)
				rc = update_mac_settings(ifp, XGMAC_VLANEX);
		}
		if (mask & IFCAP_VLAN_MTU) {
			ifp->if_capenable ^= IFCAP_VLAN_MTU;

			/* Need to find out how to disable auto-mtu-inflation */
		}
		if (mask & IFCAP_VLAN_HWTSO)
			ifp->if_capenable ^= IFCAP_VLAN_HWTSO;
		if (mask & IFCAP_VLAN_HWCSUM)
			ifp->if_capenable ^= IFCAP_VLAN_HWCSUM;

#ifdef VLAN_CAPABILITIES
		VLAN_CAPABILITIES(ifp);
#endif
fail:
		end_synchronized_op(sc, 0);
		break;

	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
	case SIOCGIFXMEDIA:
		ifmedia_ioctl(ifp, ifr, &vi->media, cmd);
		break;

	case SIOCGI2C: {
		struct ifi2creq i2c;

		rc = copyin(ifr->ifr_data, &i2c, sizeof(i2c));
		if (rc != 0)
			break;
		if (i2c.dev_addr != 0xA0 && i2c.dev_addr != 0xA2) {
			rc = EPERM;
			break;
		}
		if (i2c.len > sizeof(i2c.data)) {
			rc = EINVAL;
			break;
		}
		rc = begin_synchronized_op(sc, vi, SLEEP_OK | INTR_OK, "t4i2c");
		if (rc)
			return (rc);
		rc = -t4_i2c_rd(sc, sc->mbox, vi->pi->port_id, i2c.dev_addr,
		    i2c.offset, i2c.len, &i2c.data[0]);
		end_synchronized_op(sc, 0);
		if (rc == 0)
			rc = copyout(&i2c, ifr->ifr_data, sizeof(i2c));
		break;
	}

	default:
		rc = ether_ioctl(ifp, cmd, data);
	}

	return (rc);
}

static int
cxgbe_transmit(struct ifnet *ifp, struct mbuf *m)
{
	struct vi_info *vi = ifp->if_softc;
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	struct sge_txq *txq;
	void *items[1];
	int rc;

	M_ASSERTPKTHDR(m);
	MPASS(m->m_nextpkt == NULL);	/* not quite ready for this yet */

	if (__predict_false(pi->link_cfg.link_ok == 0)) {
		m_freem(m);
		return (ENETDOWN);
	}

	rc = parse_pkt(sc, &m);
	if (__predict_false(rc != 0)) {
		MPASS(m == NULL);			/* was freed already */
		atomic_add_int(&pi->tx_parse_error, 1);	/* rare, atomic is ok */
		return (rc);
	}

	/* Select a txq. */
	txq = &sc->sge.txq[vi->first_txq];
	if (M_HASHTYPE_GET(m) != M_HASHTYPE_NONE)
		txq += ((m->m_pkthdr.flowid % (vi->ntxq - vi->rsrv_noflowq)) +
		    vi->rsrv_noflowq);

	items[0] = m;
	rc = mp_ring_enqueue(txq->r, items, 1, 4096);
	if (__predict_false(rc != 0))
		m_freem(m);

	return (rc);
}

static void
cxgbe_qflush(struct ifnet *ifp)
{
	struct vi_info *vi = ifp->if_softc;
	struct sge_txq *txq;
	int i;

	/* queues do not exist if !VI_INIT_DONE. */
	if (vi->flags & VI_INIT_DONE) {
		for_each_txq(vi, i, txq) {
			TXQ_LOCK(txq);
			txq->eq.flags &= ~EQ_ENABLED;
			TXQ_UNLOCK(txq);
			while (!mp_ring_is_idle(txq->r)) {
				mp_ring_check_drainage(txq->r, 0);
				pause("qflush", 1);
			}
		}
	}
	if_qflush(ifp);
}

static uint64_t
vi_get_counter(struct ifnet *ifp, ift_counter c)
{
	struct vi_info *vi = ifp->if_softc;
	struct fw_vi_stats_vf *s = &vi->stats;

	vi_refresh_stats(vi->pi->adapter, vi);

	switch (c) {
	case IFCOUNTER_IPACKETS:
		return (s->rx_bcast_frames + s->rx_mcast_frames +
		    s->rx_ucast_frames);
	case IFCOUNTER_IERRORS:
		return (s->rx_err_frames);
	case IFCOUNTER_OPACKETS:
		return (s->tx_bcast_frames + s->tx_mcast_frames +
		    s->tx_ucast_frames + s->tx_offload_frames);
	case IFCOUNTER_OERRORS:
		return (s->tx_drop_frames);
	case IFCOUNTER_IBYTES:
		return (s->rx_bcast_bytes + s->rx_mcast_bytes +
		    s->rx_ucast_bytes);
	case IFCOUNTER_OBYTES:
		return (s->tx_bcast_bytes + s->tx_mcast_bytes +
		    s->tx_ucast_bytes + s->tx_offload_bytes);
	case IFCOUNTER_IMCASTS:
		return (s->rx_mcast_frames);
	case IFCOUNTER_OMCASTS:
		return (s->tx_mcast_frames);
	case IFCOUNTER_OQDROPS: {
		uint64_t drops;

		drops = 0;
		if (vi->flags & VI_INIT_DONE) {
			int i;
			struct sge_txq *txq;

			for_each_txq(vi, i, txq)
				drops += counter_u64_fetch(txq->r->drops);
		}

		return (drops);

	}

	default:
		return (if_get_counter_default(ifp, c));
	}
}

uint64_t
cxgbe_get_counter(struct ifnet *ifp, ift_counter c)
{
	struct vi_info *vi = ifp->if_softc;
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	struct port_stats *s = &pi->stats;

	if (pi->nvi > 1 || sc->flags & IS_VF)
		return (vi_get_counter(ifp, c));

	cxgbe_refresh_stats(sc, pi);

	switch (c) {
	case IFCOUNTER_IPACKETS:
		return (s->rx_frames);

	case IFCOUNTER_IERRORS:
		return (s->rx_jabber + s->rx_runt + s->rx_too_long +
		    s->rx_fcs_err + s->rx_len_err);

	case IFCOUNTER_OPACKETS:
		return (s->tx_frames);

	case IFCOUNTER_OERRORS:
		return (s->tx_error_frames);

	case IFCOUNTER_IBYTES:
		return (s->rx_octets);

	case IFCOUNTER_OBYTES:
		return (s->tx_octets);

	case IFCOUNTER_IMCASTS:
		return (s->rx_mcast_frames);

	case IFCOUNTER_OMCASTS:
		return (s->tx_mcast_frames);

	case IFCOUNTER_IQDROPS:
		return (s->rx_ovflow0 + s->rx_ovflow1 + s->rx_ovflow2 +
		    s->rx_ovflow3 + s->rx_trunc0 + s->rx_trunc1 + s->rx_trunc2 +
		    s->rx_trunc3 + pi->tnl_cong_drops);

	case IFCOUNTER_OQDROPS: {
		uint64_t drops;

		drops = s->tx_drop;
		if (vi->flags & VI_INIT_DONE) {
			int i;
			struct sge_txq *txq;

			for_each_txq(vi, i, txq)
				drops += counter_u64_fetch(txq->r->drops);
		}

		return (drops);

	}

	default:
		return (if_get_counter_default(ifp, c));
	}
}

static int
cxgbe_media_change(struct ifnet *ifp)
{
	struct vi_info *vi = ifp->if_softc;

	device_printf(vi->dev, "%s unimplemented.\n", __func__);

	return (EOPNOTSUPP);
}

static void
cxgbe_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct vi_info *vi = ifp->if_softc;
	struct port_info *pi = vi->pi;
	struct ifmedia_entry *cur;
	int speed = pi->link_cfg.speed;

	cur = vi->media.ifm_cur;

	ifmr->ifm_status = IFM_AVALID;
	if (!pi->link_cfg.link_ok)
		return;

	ifmr->ifm_status |= IFM_ACTIVE;

	/* active and current will differ iff current media is autoselect. */
	if (IFM_SUBTYPE(cur->ifm_media) != IFM_AUTO)
		return;

	ifmr->ifm_active = IFM_ETHER | IFM_FDX;
	if (speed == 10000)
		ifmr->ifm_active |= IFM_10G_T;
	else if (speed == 1000)
		ifmr->ifm_active |= IFM_1000_T;
	else if (speed == 100)
		ifmr->ifm_active |= IFM_100_TX;
	else if (speed == 10)
		ifmr->ifm_active |= IFM_10_T;
	else
		KASSERT(0, ("%s: link up but speed unknown (%u)", __func__,
			    speed));
}

void
t4_fatal_err(struct adapter *sc)
{
	t4_set_reg_field(sc, A_SGE_CONTROL, F_GLOBALENABLE, 0);
	t4_intr_disable(sc);
	log(LOG_EMERG, "%s: encountered fatal error, adapter stopped.\n",
	    device_get_nameunit(sc->dev));
}

void
t4_add_adapter(struct adapter *sc)
{
	sx_xlock(&t4_list_lock);
	SLIST_INSERT_HEAD(&t4_list, sc, link);
	sx_xunlock(&t4_list_lock);
}

int
t4_map_bars_0_and_4(struct adapter *sc)
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

int
t4_map_bar_2(struct adapter *sc)
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

	if (chip_id(sc) >= CHELSIO_T5) {
		setbit(&sc->doorbells, DOORBELL_UDB);
#if defined(__i386__) || defined(__amd64__)
		if (t5_write_combine) {
			int rc, mode;

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

			mode = is_t5(sc) ? V_STATMODE(0) : V_T6_STATMODE(0);
			t4_write_reg(sc, A_SGE_STAT_CFG,
			    V_STATSOURCE_T5(7) | mode);
		}
#endif
	}

	return (0);
}

static void
build_medialist(struct port_info *pi, struct ifmedia *media)
{
	int m;

	PORT_LOCK(pi);

	ifmedia_removeall(media);

	m = IFM_ETHER | IFM_FDX;

	switch(pi->port_type) {
	case FW_PORT_TYPE_BT_XFI:
	case FW_PORT_TYPE_BT_XAUI:
		ifmedia_add(media, m | IFM_10G_T, 0, NULL);
		/* fall through */

	case FW_PORT_TYPE_BT_SGMII:
		ifmedia_add(media, m | IFM_1000_T, 0, NULL);
		ifmedia_add(media, m | IFM_100_TX, 0, NULL);
		ifmedia_add(media, IFM_ETHER | IFM_AUTO, 0, NULL);
		ifmedia_set(media, IFM_ETHER | IFM_AUTO);
		break;

	case FW_PORT_TYPE_CX4:
		ifmedia_add(media, m | IFM_10G_CX4, 0, NULL);
		ifmedia_set(media, m | IFM_10G_CX4);
		break;

	case FW_PORT_TYPE_QSFP_10G:
	case FW_PORT_TYPE_SFP:
	case FW_PORT_TYPE_FIBER_XFI:
	case FW_PORT_TYPE_FIBER_XAUI:
		switch (pi->mod_type) {

		case FW_PORT_MOD_TYPE_LR:
			ifmedia_add(media, m | IFM_10G_LR, 0, NULL);
			ifmedia_set(media, m | IFM_10G_LR);
			break;

		case FW_PORT_MOD_TYPE_SR:
			ifmedia_add(media, m | IFM_10G_SR, 0, NULL);
			ifmedia_set(media, m | IFM_10G_SR);
			break;

		case FW_PORT_MOD_TYPE_LRM:
			ifmedia_add(media, m | IFM_10G_LRM, 0, NULL);
			ifmedia_set(media, m | IFM_10G_LRM);
			break;

		case FW_PORT_MOD_TYPE_TWINAX_PASSIVE:
		case FW_PORT_MOD_TYPE_TWINAX_ACTIVE:
			ifmedia_add(media, m | IFM_10G_TWINAX, 0, NULL);
			ifmedia_set(media, m | IFM_10G_TWINAX);
			break;

		case FW_PORT_MOD_TYPE_NONE:
			m &= ~IFM_FDX;
			ifmedia_add(media, m | IFM_NONE, 0, NULL);
			ifmedia_set(media, m | IFM_NONE);
			break;

		case FW_PORT_MOD_TYPE_NA:
		case FW_PORT_MOD_TYPE_ER:
		default:
			device_printf(pi->dev,
			    "unknown port_type (%d), mod_type (%d)\n",
			    pi->port_type, pi->mod_type);
			ifmedia_add(media, m | IFM_UNKNOWN, 0, NULL);
			ifmedia_set(media, m | IFM_UNKNOWN);
			break;
		}
		break;

	case FW_PORT_TYPE_CR_QSFP:
	case FW_PORT_TYPE_SFP28:
		switch (pi->mod_type) {

		case FW_PORT_MOD_TYPE_SR:
			MPASS(pi->port_type == FW_PORT_TYPE_SFP28);
			ifmedia_add(media, m | IFM_25G_SR, 0, NULL);
			ifmedia_set(media, m | IFM_25G_SR);
			break;

		case FW_PORT_MOD_TYPE_TWINAX_PASSIVE:
		case FW_PORT_MOD_TYPE_TWINAX_ACTIVE:
			ifmedia_add(media, m | IFM_25G_CR, 0, NULL);
			ifmedia_set(media, m | IFM_25G_CR);
			break;

		case FW_PORT_MOD_TYPE_NONE:
			m &= ~IFM_FDX;
			ifmedia_add(media, m | IFM_NONE, 0, NULL);
			ifmedia_set(media, m | IFM_NONE);
			break;

		default:
			device_printf(pi->dev,
			    "unknown port_type (%d), mod_type (%d)\n",
			    pi->port_type, pi->mod_type);
			ifmedia_add(media, m | IFM_UNKNOWN, 0, NULL);
			ifmedia_set(media, m | IFM_UNKNOWN);
			break;
		}
		break;

	case FW_PORT_TYPE_QSFP:
		switch (pi->mod_type) {

		case FW_PORT_MOD_TYPE_LR:
			ifmedia_add(media, m | IFM_40G_LR4, 0, NULL);
			ifmedia_set(media, m | IFM_40G_LR4);
			break;

		case FW_PORT_MOD_TYPE_SR:
			ifmedia_add(media, m | IFM_40G_SR4, 0, NULL);
			ifmedia_set(media, m | IFM_40G_SR4);
			break;

		case FW_PORT_MOD_TYPE_TWINAX_PASSIVE:
		case FW_PORT_MOD_TYPE_TWINAX_ACTIVE:
			ifmedia_add(media, m | IFM_40G_CR4, 0, NULL);
			ifmedia_set(media, m | IFM_40G_CR4);
			break;

		case FW_PORT_MOD_TYPE_NONE:
			m &= ~IFM_FDX;
			ifmedia_add(media, m | IFM_NONE, 0, NULL);
			ifmedia_set(media, m | IFM_NONE);
			break;

		default:
			device_printf(pi->dev,
			    "unknown port_type (%d), mod_type (%d)\n",
			    pi->port_type, pi->mod_type);
			ifmedia_add(media, m | IFM_UNKNOWN, 0, NULL);
			ifmedia_set(media, m | IFM_UNKNOWN);
			break;
		}
		break;

	case FW_PORT_TYPE_CR2_QSFP:
		switch (pi->mod_type) {

		case FW_PORT_MOD_TYPE_TWINAX_PASSIVE:
		case FW_PORT_MOD_TYPE_TWINAX_ACTIVE:
			ifmedia_add(media, m | IFM_50G_CR2, 0, NULL);
			ifmedia_set(media, m | IFM_50G_CR2);
			break;

		case FW_PORT_MOD_TYPE_NONE:
			m &= ~IFM_FDX;
			ifmedia_add(media, m | IFM_NONE, 0, NULL);
			ifmedia_set(media, m | IFM_NONE);
			break;

		default:
			device_printf(pi->dev,
			    "unknown port_type (%d), mod_type (%d)\n",
			    pi->port_type, pi->mod_type);
			ifmedia_add(media, m | IFM_UNKNOWN, 0, NULL);
			ifmedia_set(media, m | IFM_UNKNOWN);
			break;
		}
		break;

	case FW_PORT_TYPE_KR4_100G:
	case FW_PORT_TYPE_CR4_QSFP:
		switch (pi->mod_type) {

		case FW_PORT_MOD_TYPE_LR:
			ifmedia_add(media, m | IFM_100G_LR4, 0, NULL);
			ifmedia_set(media, m | IFM_100G_LR4);
			break;

		case FW_PORT_MOD_TYPE_SR:
			ifmedia_add(media, m | IFM_100G_SR4, 0, NULL);
			ifmedia_set(media, m | IFM_100G_SR4);
			break;

		case FW_PORT_MOD_TYPE_TWINAX_PASSIVE:
		case FW_PORT_MOD_TYPE_TWINAX_ACTIVE:
			ifmedia_add(media, m | IFM_100G_CR4, 0, NULL);
			ifmedia_set(media, m | IFM_100G_CR4);
			break;

		case FW_PORT_MOD_TYPE_NONE:
			m &= ~IFM_FDX;
			ifmedia_add(media, m | IFM_NONE, 0, NULL);
			ifmedia_set(media, m | IFM_NONE);
			break;

		default:
			device_printf(pi->dev,
			    "unknown port_type (%d), mod_type (%d)\n",
			    pi->port_type, pi->mod_type);
			ifmedia_add(media, m | IFM_UNKNOWN, 0, NULL);
			ifmedia_set(media, m | IFM_UNKNOWN);
			break;
		}
		break;

	default:
		device_printf(pi->dev,
		    "unknown port_type (%d), mod_type (%d)\n", pi->port_type,
		    pi->mod_type);
		ifmedia_add(media, m | IFM_UNKNOWN, 0, NULL);
		ifmedia_set(media, m | IFM_UNKNOWN);
		break;
	}

	PORT_UNLOCK(pi);
}

#define FW_MAC_EXACT_CHUNK	7

/*
 * Program the port's XGMAC based on parameters in ifnet.  The caller also
 * indicates which parameters should be programmed (the rest are left alone).
 */
int
update_mac_settings(struct ifnet *ifp, int flags)
{
	int rc = 0;
	struct vi_info *vi = ifp->if_softc;
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	int mtu = -1, promisc = -1, allmulti = -1, vlanex = -1;

	ASSERT_SYNCHRONIZED_OP(sc);
	KASSERT(flags, ("%s: not told what to update.", __func__));

	if (flags & XGMAC_MTU)
		mtu = ifp->if_mtu;

	if (flags & XGMAC_PROMISC)
		promisc = ifp->if_flags & IFF_PROMISC ? 1 : 0;

	if (flags & XGMAC_ALLMULTI)
		allmulti = ifp->if_flags & IFF_ALLMULTI ? 1 : 0;

	if (flags & XGMAC_VLANEX)
		vlanex = ifp->if_capenable & IFCAP_VLAN_HWTAGGING ? 1 : 0;

	if (flags & (XGMAC_MTU|XGMAC_PROMISC|XGMAC_ALLMULTI|XGMAC_VLANEX)) {
		rc = -t4_set_rxmode(sc, sc->mbox, vi->viid, mtu, promisc,
		    allmulti, 1, vlanex, false);
		if (rc) {
			if_printf(ifp, "set_rxmode (%x) failed: %d\n", flags,
			    rc);
			return (rc);
		}
	}

	if (flags & XGMAC_UCADDR) {
		uint8_t ucaddr[ETHER_ADDR_LEN];

		bcopy(IF_LLADDR(ifp), ucaddr, sizeof(ucaddr));
		rc = t4_change_mac(sc, sc->mbox, vi->viid, vi->xact_addr_filt,
		    ucaddr, true, true);
		if (rc < 0) {
			rc = -rc;
			if_printf(ifp, "change_mac failed: %d\n", rc);
			return (rc);
		} else {
			vi->xact_addr_filt = rc;
			rc = 0;
		}
	}

	if (flags & XGMAC_MCADDRS) {
		const uint8_t *mcaddr[FW_MAC_EXACT_CHUNK];
		int del = 1;
		uint64_t hash = 0;
		struct ifmultiaddr *ifma;
		int i = 0, j;

		if_maddr_rlock(ifp);
		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr->sa_family != AF_LINK)
				continue;
			mcaddr[i] =
			    LLADDR((struct sockaddr_dl *)ifma->ifma_addr);
			MPASS(ETHER_IS_MULTICAST(mcaddr[i]));
			i++;

			if (i == FW_MAC_EXACT_CHUNK) {
				rc = t4_alloc_mac_filt(sc, sc->mbox, vi->viid,
				    del, i, mcaddr, NULL, &hash, 0);
				if (rc < 0) {
					rc = -rc;
					for (j = 0; j < i; j++) {
						if_printf(ifp,
						    "failed to add mc address"
						    " %02x:%02x:%02x:"
						    "%02x:%02x:%02x rc=%d\n",
						    mcaddr[j][0], mcaddr[j][1],
						    mcaddr[j][2], mcaddr[j][3],
						    mcaddr[j][4], mcaddr[j][5],
						    rc);
					}
					goto mcfail;
				}
				del = 0;
				i = 0;
			}
		}
		if (i > 0) {
			rc = t4_alloc_mac_filt(sc, sc->mbox, vi->viid, del, i,
			    mcaddr, NULL, &hash, 0);
			if (rc < 0) {
				rc = -rc;
				for (j = 0; j < i; j++) {
					if_printf(ifp,
					    "failed to add mc address"
					    " %02x:%02x:%02x:"
					    "%02x:%02x:%02x rc=%d\n",
					    mcaddr[j][0], mcaddr[j][1],
					    mcaddr[j][2], mcaddr[j][3],
					    mcaddr[j][4], mcaddr[j][5],
					    rc);
				}
				goto mcfail;
			}
		}

		rc = -t4_set_addr_hash(sc, sc->mbox, vi->viid, 0, hash, 0);
		if (rc != 0)
			if_printf(ifp, "failed to set mc address hash: %d", rc);
mcfail:
		if_maddr_runlock(ifp);
	}

	return (rc);
}

/*
 * {begin|end}_synchronized_op must be called from the same thread.
 */
int
begin_synchronized_op(struct adapter *sc, struct vi_info *vi, int flags,
    char *wmesg)
{
	int rc, pri;

#ifdef WITNESS
	/* the caller thinks it's ok to sleep, but is it really? */
	if (flags & SLEEP_OK)
		WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
		    "begin_synchronized_op");
#endif

	if (INTR_OK)
		pri = PCATCH;
	else
		pri = 0;

	ADAPTER_LOCK(sc);
	for (;;) {

		if (vi && IS_DOOMED(vi)) {
			rc = ENXIO;
			goto done;
		}

		if (!IS_BUSY(sc)) {
			rc = 0;
			break;
		}

		if (!(flags & SLEEP_OK)) {
			rc = EBUSY;
			goto done;
		}

		if (mtx_sleep(&sc->flags, &sc->sc_lock, pri, wmesg, 0)) {
			rc = EINTR;
			goto done;
		}
	}

	KASSERT(!IS_BUSY(sc), ("%s: controller busy.", __func__));
	SET_BUSY(sc);
#ifdef INVARIANTS
	sc->last_op = wmesg;
	sc->last_op_thr = curthread;
	sc->last_op_flags = flags;
#endif

done:
	if (!(flags & HOLD_LOCK) || rc)
		ADAPTER_UNLOCK(sc);

	return (rc);
}

/*
 * Tell if_ioctl and if_init that the VI is going away.  This is
 * special variant of begin_synchronized_op and must be paired with a
 * call to end_synchronized_op.
 */
void
doom_vi(struct adapter *sc, struct vi_info *vi)
{

	ADAPTER_LOCK(sc);
	SET_DOOMED(vi);
	wakeup(&sc->flags);
	while (IS_BUSY(sc))
		mtx_sleep(&sc->flags, &sc->sc_lock, 0, "t4detach", 0);
	SET_BUSY(sc);
#ifdef INVARIANTS
	sc->last_op = "t4detach";
	sc->last_op_thr = curthread;
	sc->last_op_flags = 0;
#endif
	ADAPTER_UNLOCK(sc);
}

/*
 * {begin|end}_synchronized_op must be called from the same thread.
 */
void
end_synchronized_op(struct adapter *sc, int flags)
{

	if (flags & LOCK_HELD)
		ADAPTER_LOCK_ASSERT_OWNED(sc);
	else
		ADAPTER_LOCK(sc);

	KASSERT(IS_BUSY(sc), ("%s: controller not busy.", __func__));
	CLR_BUSY(sc);
	wakeup(&sc->flags);
	ADAPTER_UNLOCK(sc);
}

static int
cxgbe_init_synchronized(struct vi_info *vi)
{
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	struct ifnet *ifp = vi->ifp;
	int rc = 0, i;
	struct sge_txq *txq;

	ASSERT_SYNCHRONIZED_OP(sc);

	if (ifp->if_drv_flags & IFF_DRV_RUNNING)
		return (0);	/* already running */

	if (!(sc->flags & FULL_INIT_DONE) &&
	    ((rc = adapter_full_init(sc)) != 0))
		return (rc);	/* error message displayed already */

	if (!(vi->flags & VI_INIT_DONE) &&
	    ((rc = vi_full_init(vi)) != 0))
		return (rc); /* error message displayed already */

	rc = update_mac_settings(ifp, XGMAC_ALL);
	if (rc)
		goto done;	/* error message displayed already */

	rc = -t4_enable_vi(sc, sc->mbox, vi->viid, true, true);
	if (rc != 0) {
		if_printf(ifp, "enable_vi failed: %d\n", rc);
		goto done;
	}

	/*
	 * Can't fail from this point onwards.  Review cxgbe_uninit_synchronized
	 * if this changes.
	 */

	for_each_txq(vi, i, txq) {
		TXQ_LOCK(txq);
		txq->eq.flags |= EQ_ENABLED;
		TXQ_UNLOCK(txq);
	}

	/*
	 * The first iq of the first port to come up is used for tracing.
	 */
	if (sc->traceq < 0 && IS_MAIN_VI(vi)) {
		sc->traceq = sc->sge.rxq[vi->first_rxq].iq.abs_id;
		t4_write_reg(sc, is_t4(sc) ?  A_MPS_TRC_RSS_CONTROL :
		    A_MPS_T5_TRC_RSS_CONTROL, V_RSSCONTROL(pi->tx_chan) |
		    V_QUEUENUMBER(sc->traceq));
		pi->flags |= HAS_TRACEQ;
	}

	/* all ok */
	PORT_LOCK(pi);
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	pi->up_vis++;

	if (pi->nvi > 1 || sc->flags & IS_VF)
		callout_reset(&vi->tick, hz, vi_tick, vi);
	else
		callout_reset(&pi->tick, hz, cxgbe_tick, pi);
	PORT_UNLOCK(pi);
done:
	if (rc != 0)
		cxgbe_uninit_synchronized(vi);

	return (rc);
}

/*
 * Idempotent.
 */
static int
cxgbe_uninit_synchronized(struct vi_info *vi)
{
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	struct ifnet *ifp = vi->ifp;
	int rc, i;
	struct sge_txq *txq;

	ASSERT_SYNCHRONIZED_OP(sc);

	if (!(vi->flags & VI_INIT_DONE)) {
		KASSERT(!(ifp->if_drv_flags & IFF_DRV_RUNNING),
		    ("uninited VI is running"));
		return (0);
	}

	/*
	 * Disable the VI so that all its data in either direction is discarded
	 * by the MPS.  Leave everything else (the queues, interrupts, and 1Hz
	 * tick) intact as the TP can deliver negative advice or data that it's
	 * holding in its RAM (for an offloaded connection) even after the VI is
	 * disabled.
	 */
	rc = -t4_enable_vi(sc, sc->mbox, vi->viid, false, false);
	if (rc) {
		if_printf(ifp, "disable_vi failed: %d\n", rc);
		return (rc);
	}

	for_each_txq(vi, i, txq) {
		TXQ_LOCK(txq);
		txq->eq.flags &= ~EQ_ENABLED;
		TXQ_UNLOCK(txq);
	}

	PORT_LOCK(pi);
	if (pi->nvi > 1 || sc->flags & IS_VF)
		callout_stop(&vi->tick);
	else
		callout_stop(&pi->tick);
	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		PORT_UNLOCK(pi);
		return (0);
	}
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	pi->up_vis--;
	if (pi->up_vis > 0) {
		PORT_UNLOCK(pi);
		return (0);
	}
	PORT_UNLOCK(pi);

	pi->link_cfg.link_ok = 0;
	pi->link_cfg.speed = 0;
	pi->linkdnrc = -1;
	t4_os_link_changed(sc, pi->port_id, 0, -1);

	return (0);
}

/*
 * It is ok for this function to fail midway and return right away.  t4_detach
 * will walk the entire sc->irq list and clean up whatever is valid.
 */
int
t4_setup_intr_handlers(struct adapter *sc)
{
	int rc, rid, p, q, v;
	char s[8];
	struct irq *irq;
	struct port_info *pi;
	struct vi_info *vi;
	struct sge *sge = &sc->sge;
	struct sge_rxq *rxq;
#ifdef TCP_OFFLOAD
	struct sge_ofld_rxq *ofld_rxq;
#endif
#ifdef DEV_NETMAP
	struct sge_nm_rxq *nm_rxq;
#endif
#ifdef RSS
	int nbuckets = rss_getnumbuckets();
#endif

	/*
	 * Setup interrupts.
	 */
	irq = &sc->irq[0];
	rid = sc->intr_type == INTR_INTX ? 0 : 1;
	if (sc->intr_count == 1)
		return (t4_alloc_irq(sc, irq, rid, t4_intr_all, sc, "all"));

	/* Multiple interrupts. */
	if (sc->flags & IS_VF)
		KASSERT(sc->intr_count >= T4VF_EXTRA_INTR + sc->params.nports,
		    ("%s: too few intr.", __func__));
	else
		KASSERT(sc->intr_count >= T4_EXTRA_INTR + sc->params.nports,
		    ("%s: too few intr.", __func__));

	/* The first one is always error intr on PFs */
	if (!(sc->flags & IS_VF)) {
		rc = t4_alloc_irq(sc, irq, rid, t4_intr_err, sc, "err");
		if (rc != 0)
			return (rc);
		irq++;
		rid++;
	}

	/* The second one is always the firmware event queue (first on VFs) */
	rc = t4_alloc_irq(sc, irq, rid, t4_intr_evt, &sge->fwq, "evt");
	if (rc != 0)
		return (rc);
	irq++;
	rid++;

	for_each_port(sc, p) {
		pi = sc->port[p];
		for_each_vi(pi, v, vi) {
			vi->first_intr = rid - 1;

			if (vi->nnmrxq > 0) {
				int n = max(vi->nrxq, vi->nnmrxq);

				MPASS(vi->flags & INTR_RXQ);

				rxq = &sge->rxq[vi->first_rxq];
#ifdef DEV_NETMAP
				nm_rxq = &sge->nm_rxq[vi->first_nm_rxq];
#endif
				for (q = 0; q < n; q++) {
					snprintf(s, sizeof(s), "%x%c%x", p,
					    'a' + v, q);
					if (q < vi->nrxq)
						irq->rxq = rxq++;
#ifdef DEV_NETMAP
					if (q < vi->nnmrxq)
						irq->nm_rxq = nm_rxq++;
#endif
					rc = t4_alloc_irq(sc, irq, rid,
					    t4_vi_intr, irq, s);
					if (rc != 0)
						return (rc);
					irq++;
					rid++;
					vi->nintr++;
				}
			} else if (vi->flags & INTR_RXQ) {
				for_each_rxq(vi, q, rxq) {
					snprintf(s, sizeof(s), "%x%c%x", p,
					    'a' + v, q);
					rc = t4_alloc_irq(sc, irq, rid,
					    t4_intr, rxq, s);
					if (rc != 0)
						return (rc);
#ifdef RSS
					bus_bind_intr(sc->dev, irq->res,
					    rss_getcpu(q % nbuckets));
#endif
					irq++;
					rid++;
					vi->nintr++;
				}
			}
#ifdef TCP_OFFLOAD
			if (vi->flags & INTR_OFLD_RXQ) {
				for_each_ofld_rxq(vi, q, ofld_rxq) {
					snprintf(s, sizeof(s), "%x%c%x", p,
					    'A' + v, q);
					rc = t4_alloc_irq(sc, irq, rid,
					    t4_intr, ofld_rxq, s);
					if (rc != 0)
						return (rc);
					irq++;
					rid++;
					vi->nintr++;
				}
			}
#endif
		}
	}
	MPASS(irq == &sc->irq[sc->intr_count]);

	return (0);
}

int
adapter_full_init(struct adapter *sc)
{
	int rc, i;

	ASSERT_SYNCHRONIZED_OP(sc);
	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);
	KASSERT((sc->flags & FULL_INIT_DONE) == 0,
	    ("%s: FULL_INIT_DONE already", __func__));

	/*
	 * queues that belong to the adapter (not any particular port).
	 */
	rc = t4_setup_adapter_queues(sc);
	if (rc != 0)
		goto done;

	for (i = 0; i < nitems(sc->tq); i++) {
		sc->tq[i] = taskqueue_create("t4 taskq", M_NOWAIT,
		    taskqueue_thread_enqueue, &sc->tq[i]);
		if (sc->tq[i] == NULL) {
			device_printf(sc->dev,
			    "failed to allocate task queue %d\n", i);
			rc = ENOMEM;
			goto done;
		}
		taskqueue_start_threads(&sc->tq[i], 1, PI_NET, "%s tq%d",
		    device_get_nameunit(sc->dev), i);
	}

	if (!(sc->flags & IS_VF))
		t4_intr_enable(sc);
	sc->flags |= FULL_INIT_DONE;
done:
	if (rc != 0)
		adapter_full_uninit(sc);

	return (rc);
}

int
adapter_full_uninit(struct adapter *sc)
{
	int i;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	t4_teardown_adapter_queues(sc);

	for (i = 0; i < nitems(sc->tq) && sc->tq[i]; i++) {
		taskqueue_free(sc->tq[i]);
		sc->tq[i] = NULL;
	}

	sc->flags &= ~FULL_INIT_DONE;

	return (0);
}

#ifdef RSS
#define SUPPORTED_RSS_HASHTYPES (RSS_HASHTYPE_RSS_IPV4 | \
    RSS_HASHTYPE_RSS_TCP_IPV4 | RSS_HASHTYPE_RSS_IPV6 | \
    RSS_HASHTYPE_RSS_TCP_IPV6 | RSS_HASHTYPE_RSS_UDP_IPV4 | \
    RSS_HASHTYPE_RSS_UDP_IPV6)

/* Translates kernel hash types to hardware. */
static int
hashconfig_to_hashen(int hashconfig)
{
	int hashen = 0;

	if (hashconfig & RSS_HASHTYPE_RSS_IPV4)
		hashen |= F_FW_RSS_VI_CONFIG_CMD_IP4TWOTUPEN;
	if (hashconfig & RSS_HASHTYPE_RSS_IPV6)
		hashen |= F_FW_RSS_VI_CONFIG_CMD_IP6TWOTUPEN;
	if (hashconfig & RSS_HASHTYPE_RSS_UDP_IPV4) {
		hashen |= F_FW_RSS_VI_CONFIG_CMD_UDPEN |
		    F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN;
	}
	if (hashconfig & RSS_HASHTYPE_RSS_UDP_IPV6) {
		hashen |= F_FW_RSS_VI_CONFIG_CMD_UDPEN |
		    F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN;
	}
	if (hashconfig & RSS_HASHTYPE_RSS_TCP_IPV4)
		hashen |= F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN;
	if (hashconfig & RSS_HASHTYPE_RSS_TCP_IPV6)
		hashen |= F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN;

	return (hashen);
}

/* Translates hardware hash types to kernel. */
static int
hashen_to_hashconfig(int hashen)
{
	int hashconfig = 0;

	if (hashen & F_FW_RSS_VI_CONFIG_CMD_UDPEN) {
		/*
		 * If UDP hashing was enabled it must have been enabled for
		 * either IPv4 or IPv6 (inclusive or).  Enabling UDP without
		 * enabling any 4-tuple hash is nonsense configuration.
		 */
		MPASS(hashen & (F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN |
		    F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN));

		if (hashen & F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN)
			hashconfig |= RSS_HASHTYPE_RSS_UDP_IPV4;
		if (hashen & F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN)
			hashconfig |= RSS_HASHTYPE_RSS_UDP_IPV6;
	}
	if (hashen & F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN)
		hashconfig |= RSS_HASHTYPE_RSS_TCP_IPV4;
	if (hashen & F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN)
		hashconfig |= RSS_HASHTYPE_RSS_TCP_IPV6;
	if (hashen & F_FW_RSS_VI_CONFIG_CMD_IP4TWOTUPEN)
		hashconfig |= RSS_HASHTYPE_RSS_IPV4;
	if (hashen & F_FW_RSS_VI_CONFIG_CMD_IP6TWOTUPEN)
		hashconfig |= RSS_HASHTYPE_RSS_IPV6;

	return (hashconfig);
}
#endif

int
vi_full_init(struct vi_info *vi)
{
	struct adapter *sc = vi->pi->adapter;
	struct ifnet *ifp = vi->ifp;
	uint16_t *rss;
	struct sge_rxq *rxq;
	int rc, i, j, hashen;
#ifdef RSS
	int nbuckets = rss_getnumbuckets();
	int hashconfig = rss_gethashconfig();
	int extra;
	uint32_t raw_rss_key[RSS_KEYSIZE / sizeof(uint32_t)];
	uint32_t rss_key[RSS_KEYSIZE / sizeof(uint32_t)];
#endif

	ASSERT_SYNCHRONIZED_OP(sc);
	KASSERT((vi->flags & VI_INIT_DONE) == 0,
	    ("%s: VI_INIT_DONE already", __func__));

	sysctl_ctx_init(&vi->ctx);
	vi->flags |= VI_SYSCTL_CTX;

	/*
	 * Allocate tx/rx/fl queues for this VI.
	 */
	rc = t4_setup_vi_queues(vi);
	if (rc != 0)
		goto done;	/* error message displayed already */

	/*
	 * Setup RSS for this VI.  Save a copy of the RSS table for later use.
	 */
	if (vi->nrxq > vi->rss_size) {
		if_printf(ifp, "nrxq (%d) > hw RSS table size (%d); "
		    "some queues will never receive traffic.\n", vi->nrxq,
		    vi->rss_size);
	} else if (vi->rss_size % vi->nrxq) {
		if_printf(ifp, "nrxq (%d), hw RSS table size (%d); "
		    "expect uneven traffic distribution.\n", vi->nrxq,
		    vi->rss_size);
	}
#ifdef RSS
	MPASS(RSS_KEYSIZE == 40);
	if (vi->nrxq != nbuckets) {
		if_printf(ifp, "nrxq (%d) != kernel RSS buckets (%d);"
		    "performance will be impacted.\n", vi->nrxq, nbuckets);
	}

	rss_getkey((void *)&raw_rss_key[0]);
	for (i = 0; i < nitems(rss_key); i++) {
		rss_key[i] = htobe32(raw_rss_key[nitems(rss_key) - 1 - i]);
	}
	t4_write_rss_key(sc, &rss_key[0], -1);
#endif
	rss = malloc(vi->rss_size * sizeof (*rss), M_CXGBE, M_ZERO | M_WAITOK);
	for (i = 0; i < vi->rss_size;) {
#ifdef RSS
		j = rss_get_indirection_to_bucket(i);
		j %= vi->nrxq;
		rxq = &sc->sge.rxq[vi->first_rxq + j];
		rss[i++] = rxq->iq.abs_id;
#else
		for_each_rxq(vi, j, rxq) {
			rss[i++] = rxq->iq.abs_id;
			if (i == vi->rss_size)
				break;
		}
#endif
	}

	rc = -t4_config_rss_range(sc, sc->mbox, vi->viid, 0, vi->rss_size, rss,
	    vi->rss_size);
	if (rc != 0) {
		if_printf(ifp, "rss_config failed: %d\n", rc);
		goto done;
	}

#ifdef RSS
	hashen = hashconfig_to_hashen(hashconfig);

	/*
	 * We may have had to enable some hashes even though the global config
	 * wants them disabled.  This is a potential problem that must be
	 * reported to the user.
	 */
	extra = hashen_to_hashconfig(hashen) ^ hashconfig;

	/*
	 * If we consider only the supported hash types, then the enabled hashes
	 * are a superset of the requested hashes.  In other words, there cannot
	 * be any supported hash that was requested but not enabled, but there
	 * can be hashes that were not requested but had to be enabled.
	 */
	extra &= SUPPORTED_RSS_HASHTYPES;
	MPASS((extra & hashconfig) == 0);

	if (extra) {
		if_printf(ifp,
		    "global RSS config (0x%x) cannot be accommodated.\n",
		    hashconfig);
	}
	if (extra & RSS_HASHTYPE_RSS_IPV4)
		if_printf(ifp, "IPv4 2-tuple hashing forced on.\n");
	if (extra & RSS_HASHTYPE_RSS_TCP_IPV4)
		if_printf(ifp, "TCP/IPv4 4-tuple hashing forced on.\n");
	if (extra & RSS_HASHTYPE_RSS_IPV6)
		if_printf(ifp, "IPv6 2-tuple hashing forced on.\n");
	if (extra & RSS_HASHTYPE_RSS_TCP_IPV6)
		if_printf(ifp, "TCP/IPv6 4-tuple hashing forced on.\n");
	if (extra & RSS_HASHTYPE_RSS_UDP_IPV4)
		if_printf(ifp, "UDP/IPv4 4-tuple hashing forced on.\n");
	if (extra & RSS_HASHTYPE_RSS_UDP_IPV6)
		if_printf(ifp, "UDP/IPv6 4-tuple hashing forced on.\n");
#else
	hashen = F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN |
	    F_FW_RSS_VI_CONFIG_CMD_IP6TWOTUPEN |
	    F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN |
	    F_FW_RSS_VI_CONFIG_CMD_IP4TWOTUPEN | F_FW_RSS_VI_CONFIG_CMD_UDPEN;
#endif
	rc = -t4_config_vi_rss(sc, sc->mbox, vi->viid, hashen, rss[0]);
	if (rc != 0) {
		if_printf(ifp, "rss hash/defaultq config failed: %d\n", rc);
		goto done;
	}

	vi->rss = rss;
	vi->flags |= VI_INIT_DONE;
done:
	if (rc != 0)
		vi_full_uninit(vi);

	return (rc);
}

/*
 * Idempotent.
 */
int
vi_full_uninit(struct vi_info *vi)
{
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;
	int i;
	struct sge_rxq *rxq;
	struct sge_txq *txq;
#ifdef TCP_OFFLOAD
	struct sge_ofld_rxq *ofld_rxq;
	struct sge_wrq *ofld_txq;
#endif

	if (vi->flags & VI_INIT_DONE) {

		/* Need to quiesce queues.  */

		/* XXX: Only for the first VI? */
		if (IS_MAIN_VI(vi) && !(sc->flags & IS_VF))
			quiesce_wrq(sc, &sc->sge.ctrlq[pi->port_id]);

		for_each_txq(vi, i, txq) {
			quiesce_txq(sc, txq);
		}

#ifdef TCP_OFFLOAD
		for_each_ofld_txq(vi, i, ofld_txq) {
			quiesce_wrq(sc, ofld_txq);
		}
#endif

		for_each_rxq(vi, i, rxq) {
			quiesce_iq(sc, &rxq->iq);
			quiesce_fl(sc, &rxq->fl);
		}

#ifdef TCP_OFFLOAD
		for_each_ofld_rxq(vi, i, ofld_rxq) {
			quiesce_iq(sc, &ofld_rxq->iq);
			quiesce_fl(sc, &ofld_rxq->fl);
		}
#endif
		free(vi->rss, M_CXGBE);
		free(vi->nm_rss, M_CXGBE);
	}

	t4_teardown_vi_queues(vi);
	vi->flags &= ~VI_INIT_DONE;

	return (0);
}

static void
quiesce_txq(struct adapter *sc, struct sge_txq *txq)
{
	struct sge_eq *eq = &txq->eq;
	struct sge_qstat *spg = (void *)&eq->desc[eq->sidx];

	(void) sc;	/* unused */

#ifdef INVARIANTS
	TXQ_LOCK(txq);
	MPASS((eq->flags & EQ_ENABLED) == 0);
	TXQ_UNLOCK(txq);
#endif

	/* Wait for the mp_ring to empty. */
	while (!mp_ring_is_idle(txq->r)) {
		mp_ring_check_drainage(txq->r, 0);
		pause("rquiesce", 1);
	}

	/* Then wait for the hardware to finish. */
	while (spg->cidx != htobe16(eq->pidx))
		pause("equiesce", 1);

	/* Finally, wait for the driver to reclaim all descriptors. */
	while (eq->cidx != eq->pidx)
		pause("dquiesce", 1);
}

static void
quiesce_wrq(struct adapter *sc, struct sge_wrq *wrq)
{

	/* XXXTX */
}

static void
quiesce_iq(struct adapter *sc, struct sge_iq *iq)
{
	(void) sc;	/* unused */

	/* Synchronize with the interrupt handler */
	while (!atomic_cmpset_int(&iq->state, IQS_IDLE, IQS_DISABLED))
		pause("iqfree", 1);
}

static void
quiesce_fl(struct adapter *sc, struct sge_fl *fl)
{
	mtx_lock(&sc->sfl_lock);
	FL_LOCK(fl);
	fl->flags |= FL_DOOMED;
	FL_UNLOCK(fl);
	callout_stop(&sc->sfl_callout);
	mtx_unlock(&sc->sfl_lock);

	KASSERT((fl->flags & FL_STARVING) == 0,
	    ("%s: still starving", __func__));
}

static int
t4_alloc_irq(struct adapter *sc, struct irq *irq, int rid,
    driver_intr_t *handler, void *arg, char *name)
{
	int rc;

	irq->rid = rid;
	irq->res = bus_alloc_resource_any(sc->dev, SYS_RES_IRQ, &irq->rid,
	    RF_SHAREABLE | RF_ACTIVE);
	if (irq->res == NULL) {
		device_printf(sc->dev,
		    "failed to allocate IRQ for rid %d, name %s.\n", rid, name);
		return (ENOMEM);
	}

	rc = bus_setup_intr(sc->dev, irq->res, INTR_MPSAFE | INTR_TYPE_NET,
	    NULL, handler, arg, &irq->tag);
	if (rc != 0) {
		device_printf(sc->dev,
		    "failed to setup interrupt for rid %d, name %s: %d\n",
		    rid, name, rc);
	} else if (name)
		bus_describe_intr(sc->dev, irq->res, irq->tag, "%s", name);

	return (rc);
}

static int
t4_free_irq(struct adapter *sc, struct irq *irq)
{
	if (irq->tag)
		bus_teardown_intr(sc->dev, irq->res, irq->tag);
	if (irq->res)
		bus_release_resource(sc->dev, SYS_RES_IRQ, irq->rid, irq->res);

	bzero(irq, sizeof(*irq));

	return (0);
}

static uint64_t
read_vf_stat(struct adapter *sc, unsigned int viid, int reg)
{
	u32 stats[2];

	mtx_assert(&sc->reg_lock, MA_OWNED);
	if (sc->flags & IS_VF) {
		stats[0] = t4_read_reg(sc, VF_MPS_REG(reg));
		stats[1] = t4_read_reg(sc, VF_MPS_REG(reg + 4));
	} else {
		t4_write_reg(sc, A_PL_INDIR_CMD, V_PL_AUTOINC(1) |
		    V_PL_VFID(G_FW_VIID_VIN(viid)) |
		    V_PL_ADDR(VF_MPS_REG(reg)));
		stats[0] = t4_read_reg(sc, A_PL_INDIR_DATA);
		stats[1] = t4_read_reg(sc, A_PL_INDIR_DATA);
	}
	return (((uint64_t)stats[1]) << 32 | stats[0]);
}

static void
t4_get_vi_stats(struct adapter *sc, unsigned int viid,
    struct fw_vi_stats_vf *stats)
{

#define GET_STAT(name) \
	read_vf_stat(sc, viid, A_MPS_VF_STAT_##name##_L)

	stats->tx_bcast_bytes    = GET_STAT(TX_VF_BCAST_BYTES);
	stats->tx_bcast_frames   = GET_STAT(TX_VF_BCAST_FRAMES);
	stats->tx_mcast_bytes    = GET_STAT(TX_VF_MCAST_BYTES);
	stats->tx_mcast_frames   = GET_STAT(TX_VF_MCAST_FRAMES);
	stats->tx_ucast_bytes    = GET_STAT(TX_VF_UCAST_BYTES);
	stats->tx_ucast_frames   = GET_STAT(TX_VF_UCAST_FRAMES);
	stats->tx_drop_frames    = GET_STAT(TX_VF_DROP_FRAMES);
	stats->tx_offload_bytes  = GET_STAT(TX_VF_OFFLOAD_BYTES);
	stats->tx_offload_frames = GET_STAT(TX_VF_OFFLOAD_FRAMES);
	stats->rx_bcast_bytes    = GET_STAT(RX_VF_BCAST_BYTES);
	stats->rx_bcast_frames   = GET_STAT(RX_VF_BCAST_FRAMES);
	stats->rx_mcast_bytes    = GET_STAT(RX_VF_MCAST_BYTES);
	stats->rx_mcast_frames   = GET_STAT(RX_VF_MCAST_FRAMES);
	stats->rx_ucast_bytes    = GET_STAT(RX_VF_UCAST_BYTES);
	stats->rx_ucast_frames   = GET_STAT(RX_VF_UCAST_FRAMES);
	stats->rx_err_frames     = GET_STAT(RX_VF_ERR_FRAMES);

#undef GET_STAT
}

static void
vi_refresh_stats(struct adapter *sc, struct vi_info *vi)
{
	struct timeval tv;
	const struct timeval interval = {0, 250000};	/* 250ms */

	if (!(vi->flags & VI_INIT_DONE))
		return;

	getmicrotime(&tv);
	timevalsub(&tv, &interval);
	if (timevalcmp(&tv, &vi->last_refreshed, <))
		return;

	mtx_lock(&sc->reg_lock);
	t4_get_vi_stats(sc, vi->viid, &vi->stats);
	getmicrotime(&vi->last_refreshed);
	mtx_unlock(&sc->reg_lock);
}

static void
cxgbe_refresh_stats(struct adapter *sc, struct port_info *pi)
{
	int i;
	u_int v, tnl_cong_drops;
	struct timeval tv;
	const struct timeval interval = {0, 250000};	/* 250ms */

	getmicrotime(&tv);
	timevalsub(&tv, &interval);
	if (timevalcmp(&tv, &pi->last_refreshed, <))
		return;

	tnl_cong_drops = 0;
	t4_get_port_stats(sc, pi->tx_chan, &pi->stats);
	for (i = 0; i < sc->chip_params->nchan; i++) {
		if (pi->rx_chan_map & (1 << i)) {
			mtx_lock(&sc->reg_lock);
			t4_read_indirect(sc, A_TP_MIB_INDEX, A_TP_MIB_DATA, &v,
			    1, A_TP_MIB_TNL_CNG_DROP_0 + i);
			mtx_unlock(&sc->reg_lock);
			tnl_cong_drops += v;
		}
	}
	pi->tnl_cong_drops = tnl_cong_drops;
	getmicrotime(&pi->last_refreshed);
}

static void
cxgbe_tick(void *arg)
{
	struct port_info *pi = arg;
	struct adapter *sc = pi->adapter;

	PORT_LOCK_ASSERT_OWNED(pi);
	cxgbe_refresh_stats(sc, pi);

	callout_schedule(&pi->tick, hz);
}

void
vi_tick(void *arg)
{
	struct vi_info *vi = arg;
	struct adapter *sc = vi->pi->adapter;

	vi_refresh_stats(sc, vi);

	callout_schedule(&vi->tick, hz);
}

static void
cxgbe_vlan_config(void *arg, struct ifnet *ifp, uint16_t vid)
{
	struct ifnet *vlan;

	if (arg != ifp || ifp->if_type != IFT_ETHER)
		return;

	vlan = VLAN_DEVAT(ifp, vid);
	VLAN_SETCOOKIE(vlan, ifp);
}

void
t4_sysctls_common(struct adapter *sc)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *children;
	static char *doorbells = {"\20\1UDB\2WCWR\3UDBWC\4KDB"};

	ctx = device_get_sysctl_ctx(sc->dev);

	/*
	 * dev.t4nex.X.
	 */
	oid = device_get_sysctl_tree(sc->dev);
	children = SYSCTL_CHILDREN(oid);

	sc->sc_do_rxcopy = 1;
	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "do_rx_copy", CTLFLAG_RW,
	    &sc->sc_do_rxcopy, 1, "Do RX copy of small frames");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "nports", CTLFLAG_RD, NULL,
	    sc->params.nports, "# of ports");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "doorbells",
	    CTLTYPE_STRING | CTLFLAG_RD, doorbells, sc->doorbells,
	    sysctl_bitfield, "A", "available doorbells");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "core_clock", CTLFLAG_RD, NULL,
	    sc->params.vpd.cclk, "core clock frequency (in KHz)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "holdoff_timers",
	    CTLTYPE_STRING | CTLFLAG_RD, sc->params.sge.timer_val,
	    sizeof(sc->params.sge.timer_val), sysctl_int_array, "A",
	    "interrupt holdoff timer values (us)");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "holdoff_pkt_counts",
	    CTLTYPE_STRING | CTLFLAG_RD, sc->params.sge.counter_val,
	    sizeof(sc->params.sge.counter_val), sysctl_int_array, "A",
	    "interrupt holdoff packet counter values");

	t4_sge_sysctls(sc, ctx, children);

	sc->lro_timeout = 100;
	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "lro_timeout", CTLFLAG_RW,
	    &sc->lro_timeout, 0, "lro inactive-flush timeout (in us)");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "dflags", CTLFLAG_RW,
	    &sc->debug_flags, 0, "flags to enable runtime debugging");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "tp_version",
	    CTLFLAG_RD, sc->tp_version, 0, "TP microcode version");

	SYSCTL_ADD_STRING(ctx, children, OID_AUTO, "firmware_version",
	    CTLFLAG_RD, sc->fw_version, 0, "firmware version");
}

void
vi_sysctls(struct vi_info *vi)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *children;

	ctx = device_get_sysctl_ctx(vi->dev);

	/*
	 * dev.v?(cxgbe|cxl).X.
	 */
	oid = device_get_sysctl_tree(vi->dev);
	children = SYSCTL_CHILDREN(oid);

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, "viid", CTLFLAG_RD, NULL,
	    vi->viid, "VI identifer");
	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "nrxq", CTLFLAG_RD,
	    &vi->nrxq, 0, "# of rx queues");
	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "ntxq", CTLFLAG_RD,
	    &vi->ntxq, 0, "# of tx queues");
	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "first_rxq", CTLFLAG_RD,
	    &vi->first_rxq, 0, "index of first rx queue");
	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "first_txq", CTLFLAG_RD,
	    &vi->first_txq, 0, "index of first tx queue");
	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, "rss_size", CTLFLAG_RD, NULL,
	    vi->rss_size, "size of RSS indirection table");

	if (IS_MAIN_VI(vi)) {
		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rsrv_noflowq",
		    CTLTYPE_INT | CTLFLAG_RW, vi, 0, sysctl_noflowq, "IU",
		    "Reserve queue 0 for non-flowid packets");
	}

#ifdef TCP_OFFLOAD
	if (vi->nofldrxq != 0) {
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "nofldrxq", CTLFLAG_RD,
		    &vi->nofldrxq, 0,
		    "# of rx queues for offloaded TCP connections");
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "nofldtxq", CTLFLAG_RD,
		    &vi->nofldtxq, 0,
		    "# of tx queues for offloaded TCP connections");
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "first_ofld_rxq",
		    CTLFLAG_RD, &vi->first_ofld_rxq, 0,
		    "index of first TOE rx queue");
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "first_ofld_txq",
		    CTLFLAG_RD, &vi->first_ofld_txq, 0,
		    "index of first TOE tx queue");
	}
#endif
#ifdef DEV_NETMAP
	if (vi->nnmrxq != 0) {
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "nnmrxq", CTLFLAG_RD,
		    &vi->nnmrxq, 0, "# of netmap rx queues");
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "nnmtxq", CTLFLAG_RD,
		    &vi->nnmtxq, 0, "# of netmap tx queues");
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "first_nm_rxq",
		    CTLFLAG_RD, &vi->first_nm_rxq, 0,
		    "index of first netmap rx queue");
		SYSCTL_ADD_INT(ctx, children, OID_AUTO, "first_nm_txq",
		    CTLFLAG_RD, &vi->first_nm_txq, 0,
		    "index of first netmap tx queue");
	}
#endif

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "holdoff_tmr_idx",
	    CTLTYPE_INT | CTLFLAG_RW, vi, 0, sysctl_holdoff_tmr_idx, "I",
	    "holdoff timer index");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "holdoff_pktc_idx",
	    CTLTYPE_INT | CTLFLAG_RW, vi, 0, sysctl_holdoff_pktc_idx, "I",
	    "holdoff packet counter index");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "qsize_rxq",
	    CTLTYPE_INT | CTLFLAG_RW, vi, 0, sysctl_qsize_rxq, "I",
	    "rx queue size");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "qsize_txq",
	    CTLTYPE_INT | CTLFLAG_RW, vi, 0, sysctl_qsize_txq, "I",
	    "tx queue size");
}

static void
cxgbe_sysctls(struct port_info *pi)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *oid;
	struct sysctl_oid_list *children, *children2;
	struct adapter *sc = pi->adapter;
	int i;
	char name[16];

	ctx = device_get_sysctl_ctx(pi->dev);

	/*
	 * dev.cxgbe.X.
	 */
	oid = device_get_sysctl_tree(pi->dev);
	children = SYSCTL_CHILDREN(oid);

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "linkdnrc", CTLTYPE_STRING |
	   CTLFLAG_RD, pi, 0, sysctl_linkdnrc, "A", "reason why link is down");
	if (pi->port_type == FW_PORT_TYPE_BT_XAUI) {
		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "temperature",
		    CTLTYPE_INT | CTLFLAG_RD, pi, 0, sysctl_btphy, "I",
		    "PHY temperature (in Celsius)");
		SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "fw_version",
		    CTLTYPE_INT | CTLFLAG_RD, pi, 1, sysctl_btphy, "I",
		    "PHY firmware version");
	}

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "pause_settings",
	    CTLTYPE_STRING | CTLFLAG_RW, pi, PAUSE_TX, sysctl_pause_settings,
	    "A", "PAUSE settings (bit 0 = rx_pause, bit 1 = tx_pause)");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, "max_speed", CTLFLAG_RD, NULL,
	    port_top_speed(pi), "max speed (in Gbps)");

	if (sc->flags & IS_VF)
		return;

	/*
	 * dev.(cxgbe|cxl).X.tc.
	 */
	oid = SYSCTL_ADD_NODE(ctx, children, OID_AUTO, "tc", CTLFLAG_RD, NULL,
	    "Tx scheduler traffic classes");
	for (i = 0; i < sc->chip_params->nsched_cls; i++) {
		struct tx_sched_class *tc = &pi->tc[i];

		snprintf(name, sizeof(name), "%d", i);
		children2 = SYSCTL_CHILDREN(SYSCTL_ADD_NODE(ctx,
		    SYSCTL_CHILDREN(oid), OID_AUTO, name, CTLFLAG_RD, NULL,
		    "traffic class"));
		SYSCTL_ADD_UINT(ctx, children2, OID_AUTO, "flags", CTLFLAG_RD,
		    &tc->flags, 0, "flags");
		SYSCTL_ADD_UINT(ctx, children2, OID_AUTO, "refcount",
		    CTLFLAG_RD, &tc->refcount, 0, "references to this class");
#ifdef SBUF_DRAIN
		SYSCTL_ADD_PROC(ctx, children2, OID_AUTO, "params",
		    CTLTYPE_STRING | CTLFLAG_RD, sc, (pi->port_id << 16) | i,
		    sysctl_tc_params, "A", "traffic class parameters");
#endif
	}

	/*
	 * dev.cxgbe.X.stats.
	 */
	oid = SYSCTL_ADD_NODE(ctx, children, OID_AUTO, "stats", CTLFLAG_RD,
	    NULL, "port statistics");
	children = SYSCTL_CHILDREN(oid);
	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, "tx_parse_error", CTLFLAG_RD,
	    &pi->tx_parse_error, 0,
	    "# of tx packets with invalid length or # of segments");

#define SYSCTL_ADD_T4_REG64(pi, name, desc, reg) \
	SYSCTL_ADD_OID(ctx, children, OID_AUTO, name, \
	    CTLTYPE_U64 | CTLFLAG_RD, sc, reg, \
	    sysctl_handle_t4_reg64, "QU", desc)

	SYSCTL_ADD_T4_REG64(pi, "tx_octets", "# of octets in good frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_BYTES_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames", "total # of good frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_FRAMES_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_bcast_frames", "# of broadcast frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_BCAST_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_mcast_frames", "# of multicast frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_MCAST_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ucast_frames", "# of unicast frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_UCAST_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_error_frames", "# of error frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_ERROR_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames_64",
	    "# of tx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_64B_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames_65_127",
	    "# of tx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_65B_127B_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames_128_255",
	    "# of tx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_128B_255B_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames_256_511",
	    "# of tx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_256B_511B_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames_512_1023",
	    "# of tx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_512B_1023B_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames_1024_1518",
	    "# of tx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_1024B_1518B_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_frames_1519_max",
	    "# of tx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_1519B_MAX_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_drop", "# of dropped tx frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_DROP_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_pause", "# of pause frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PAUSE_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp0", "# of PPP prio 0 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP0_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp1", "# of PPP prio 1 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP1_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp2", "# of PPP prio 2 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP2_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp3", "# of PPP prio 3 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP3_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp4", "# of PPP prio 4 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP4_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp5", "# of PPP prio 5 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP5_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp6", "# of PPP prio 6 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP6_L));
	SYSCTL_ADD_T4_REG64(pi, "tx_ppp7", "# of PPP prio 7 frames transmitted",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_TX_PORT_PPP7_L));

	SYSCTL_ADD_T4_REG64(pi, "rx_octets", "# of octets in good frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_BYTES_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames", "total # of good frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_FRAMES_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_bcast_frames", "# of broadcast frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_BCAST_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_mcast_frames", "# of multicast frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_MCAST_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ucast_frames", "# of unicast frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_UCAST_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_too_long", "# of frames exceeding MTU",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_MTU_ERROR_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_jabber", "# of jabber frames",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_MTU_CRC_ERROR_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_fcs_err",
	    "# of frames received with bad FCS",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_CRC_ERROR_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_len_err",
	    "# of frames received with length error",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_LEN_ERROR_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_symbol_err", "symbol errors",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_SYM_ERROR_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_runt", "# of short frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_LESS_64B_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames_64",
	    "# of rx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_64B_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames_65_127",
	    "# of rx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_65B_127B_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames_128_255",
	    "# of rx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_128B_255B_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames_256_511",
	    "# of rx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_256B_511B_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames_512_1023",
	    "# of rx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_512B_1023B_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames_1024_1518",
	    "# of rx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_1024B_1518B_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_frames_1519_max",
	    "# of rx frames in this range",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_1519B_MAX_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_pause", "# of pause frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PAUSE_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp0", "# of PPP prio 0 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP0_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp1", "# of PPP prio 1 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP1_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp2", "# of PPP prio 2 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP2_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp3", "# of PPP prio 3 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP3_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp4", "# of PPP prio 4 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP4_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp5", "# of PPP prio 5 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP5_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp6", "# of PPP prio 6 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP6_L));
	SYSCTL_ADD_T4_REG64(pi, "rx_ppp7", "# of PPP prio 7 frames received",
	    PORT_REG(pi->tx_chan, A_MPS_PORT_STAT_RX_PORT_PPP7_L));

#undef SYSCTL_ADD_T4_REG64

#define SYSCTL_ADD_T4_PORTSTAT(name, desc) \
	SYSCTL_ADD_UQUAD(ctx, children, OID_AUTO, #name, CTLFLAG_RD, \
	    &pi->stats.name, desc)

	/* We get these from port_stats and they may be stale by up to 1s */
	SYSCTL_ADD_T4_PORTSTAT(rx_ovflow0,
	    "# drops due to buffer-group 0 overflows");
	SYSCTL_ADD_T4_PORTSTAT(rx_ovflow1,
	    "# drops due to buffer-group 1 overflows");
	SYSCTL_ADD_T4_PORTSTAT(rx_ovflow2,
	    "# drops due to buffer-group 2 overflows");
	SYSCTL_ADD_T4_PORTSTAT(rx_ovflow3,
	    "# drops due to buffer-group 3 overflows");
	SYSCTL_ADD_T4_PORTSTAT(rx_trunc0,
	    "# of buffer-group 0 truncated packets");
	SYSCTL_ADD_T4_PORTSTAT(rx_trunc1,
	    "# of buffer-group 1 truncated packets");
	SYSCTL_ADD_T4_PORTSTAT(rx_trunc2,
	    "# of buffer-group 2 truncated packets");
	SYSCTL_ADD_T4_PORTSTAT(rx_trunc3,
	    "# of buffer-group 3 truncated packets");

#undef SYSCTL_ADD_T4_PORTSTAT
}

static int
sysctl_int_array(SYSCTL_HANDLER_ARGS)
{
	int rc, *i, space = 0;
	struct sbuf sb;

	sbuf_new_for_sysctl(&sb, NULL, 64, req);
	for (i = arg1; arg2; arg2 -= sizeof(int), i++) {
		if (space)
			sbuf_printf(&sb, " ");
		sbuf_printf(&sb, "%d", *i);
		space = 1;
	}
	rc = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (rc);
}

int
sysctl_bitfield(SYSCTL_HANDLER_ARGS)
{
	int rc;
	struct sbuf *sb;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return(rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	if (sb == NULL)
		return (ENOMEM);

	sbuf_printf(sb, "%b", (int)arg2, (char *)arg1);
	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_btphy(SYSCTL_HANDLER_ARGS)
{
	struct port_info *pi = arg1;
	int op = arg2;
	struct adapter *sc = pi->adapter;
	u_int v;
	int rc;

	rc = begin_synchronized_op(sc, &pi->vi[0], SLEEP_OK | INTR_OK, "t4btt");
	if (rc)
		return (rc);
	/* XXX: magic numbers */
	rc = -t4_mdio_rd(sc, sc->mbox, pi->mdio_addr, 0x1e, op ? 0x20 : 0xc820,
	    &v);
	end_synchronized_op(sc, 0);
	if (rc)
		return (rc);
	if (op == 0)
		v /= 256;

	rc = sysctl_handle_int(oidp, &v, 0, req);
	return (rc);
}

static int
sysctl_noflowq(SYSCTL_HANDLER_ARGS)
{
	struct vi_info *vi = arg1;
	int rc, val;

	val = vi->rsrv_noflowq;
	rc = sysctl_handle_int(oidp, &val, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	if ((val >= 1) && (vi->ntxq > 1))
		vi->rsrv_noflowq = 1;
	else
		vi->rsrv_noflowq = 0;

	return (rc);
}

static int
sysctl_holdoff_tmr_idx(SYSCTL_HANDLER_ARGS)
{
	struct vi_info *vi = arg1;
	struct adapter *sc = vi->pi->adapter;
	int idx, rc, i;
	struct sge_rxq *rxq;
#ifdef TCP_OFFLOAD
	struct sge_ofld_rxq *ofld_rxq;
#endif
	uint8_t v;

	idx = vi->tmr_idx;

	rc = sysctl_handle_int(oidp, &idx, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	if (idx < 0 || idx >= SGE_NTIMERS)
		return (EINVAL);

	rc = begin_synchronized_op(sc, vi, HOLD_LOCK | SLEEP_OK | INTR_OK,
	    "t4tmr");
	if (rc)
		return (rc);

	v = V_QINTR_TIMER_IDX(idx) | V_QINTR_CNT_EN(vi->pktc_idx != -1);
	for_each_rxq(vi, i, rxq) {
#ifdef atomic_store_rel_8
		atomic_store_rel_8(&rxq->iq.intr_params, v);
#else
		rxq->iq.intr_params = v;
#endif
	}
#ifdef TCP_OFFLOAD
	for_each_ofld_rxq(vi, i, ofld_rxq) {
#ifdef atomic_store_rel_8
		atomic_store_rel_8(&ofld_rxq->iq.intr_params, v);
#else
		ofld_rxq->iq.intr_params = v;
#endif
	}
#endif
	vi->tmr_idx = idx;

	end_synchronized_op(sc, LOCK_HELD);
	return (0);
}

static int
sysctl_holdoff_pktc_idx(SYSCTL_HANDLER_ARGS)
{
	struct vi_info *vi = arg1;
	struct adapter *sc = vi->pi->adapter;
	int idx, rc;

	idx = vi->pktc_idx;

	rc = sysctl_handle_int(oidp, &idx, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	if (idx < -1 || idx >= SGE_NCOUNTERS)
		return (EINVAL);

	rc = begin_synchronized_op(sc, vi, HOLD_LOCK | SLEEP_OK | INTR_OK,
	    "t4pktc");
	if (rc)
		return (rc);

	if (vi->flags & VI_INIT_DONE)
		rc = EBUSY; /* cannot be changed once the queues are created */
	else
		vi->pktc_idx = idx;

	end_synchronized_op(sc, LOCK_HELD);
	return (rc);
}

static int
sysctl_qsize_rxq(SYSCTL_HANDLER_ARGS)
{
	struct vi_info *vi = arg1;
	struct adapter *sc = vi->pi->adapter;
	int qsize, rc;

	qsize = vi->qsize_rxq;

	rc = sysctl_handle_int(oidp, &qsize, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	if (qsize < 128 || (qsize & 7))
		return (EINVAL);

	rc = begin_synchronized_op(sc, vi, HOLD_LOCK | SLEEP_OK | INTR_OK,
	    "t4rxqs");
	if (rc)
		return (rc);

	if (vi->flags & VI_INIT_DONE)
		rc = EBUSY; /* cannot be changed once the queues are created */
	else
		vi->qsize_rxq = qsize;

	end_synchronized_op(sc, LOCK_HELD);
	return (rc);
}

static int
sysctl_qsize_txq(SYSCTL_HANDLER_ARGS)
{
	struct vi_info *vi = arg1;
	struct adapter *sc = vi->pi->adapter;
	int qsize, rc;

	qsize = vi->qsize_txq;

	rc = sysctl_handle_int(oidp, &qsize, 0, req);
	if (rc != 0 || req->newptr == NULL)
		return (rc);

	if (qsize < 128 || qsize > 65536)
		return (EINVAL);

	rc = begin_synchronized_op(sc, vi, HOLD_LOCK | SLEEP_OK | INTR_OK,
	    "t4txqs");
	if (rc)
		return (rc);

	if (vi->flags & VI_INIT_DONE)
		rc = EBUSY; /* cannot be changed once the queues are created */
	else
		vi->qsize_txq = qsize;

	end_synchronized_op(sc, LOCK_HELD);
	return (rc);
}

static int
sysctl_pause_settings(SYSCTL_HANDLER_ARGS)
{
	struct port_info *pi = arg1;
	struct adapter *sc = pi->adapter;
	struct link_config *lc = &pi->link_cfg;
	int rc;

	if (req->newptr == NULL) {
		struct sbuf *sb;
		static char *bits = "\20\1PAUSE_RX\2PAUSE_TX";

		rc = sysctl_wire_old_buffer(req, 0);
		if (rc != 0)
			return(rc);

		sb = sbuf_new_for_sysctl(NULL, NULL, 128, req);
		if (sb == NULL)
			return (ENOMEM);

		sbuf_printf(sb, "%b", lc->fc & (PAUSE_TX | PAUSE_RX), bits);
		rc = sbuf_finish(sb);
		sbuf_delete(sb);
	} else {
		char s[2];
		int n;

		s[0] = '0' + (lc->requested_fc & (PAUSE_TX | PAUSE_RX));
		s[1] = 0;

		rc = sysctl_handle_string(oidp, s, sizeof(s), req);
		if (rc != 0)
			return(rc);

		if (s[1] != 0)
			return (EINVAL);
		if (s[0] < '0' || s[0] > '9')
			return (EINVAL);	/* not a number */
		n = s[0] - '0';
		if (n & ~(PAUSE_TX | PAUSE_RX))
			return (EINVAL);	/* some other bit is set too */

		rc = begin_synchronized_op(sc, &pi->vi[0], SLEEP_OK | INTR_OK,
		    "t4PAUSE");
		if (rc)
			return (rc);
		if ((lc->requested_fc & (PAUSE_TX | PAUSE_RX)) != n) {
			int link_ok = lc->link_ok;

			lc->requested_fc &= ~(PAUSE_TX | PAUSE_RX);
			lc->requested_fc |= n;
			rc = -t4_link_l1cfg(sc, sc->mbox, pi->tx_chan, lc);
			lc->link_ok = link_ok;	/* restore */
		}
		end_synchronized_op(sc, 0);
	}

	return (rc);
}

static int
sysctl_handle_t4_reg64(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	int reg = arg2;
	uint64_t val;

	val = t4_read_reg64(sc, reg);

	return (sysctl_handle_64(oidp, &val, 0, req));
}

#ifdef SBUF_DRAIN
static int
sysctl_linkdnrc(SYSCTL_HANDLER_ARGS)
{
	int rc = 0;
	struct port_info *pi = arg1;
	struct sbuf *sb;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return(rc);
	sb = sbuf_new_for_sysctl(NULL, NULL, 64, req);
	if (sb == NULL)
		return (ENOMEM);

	if (pi->linkdnrc < 0)
		sbuf_printf(sb, "n/a");
	else
		sbuf_printf(sb, "%s", t4_link_down_rc_str(pi->linkdnrc));

	rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}

static int
sysctl_tc_params(SYSCTL_HANDLER_ARGS)
{
	struct adapter *sc = arg1;
	struct tx_sched_class *tc;
	struct t4_sched_class_params p;
	struct sbuf *sb;
	int i, rc, port_id, flags, mbps, gbps;

	rc = sysctl_wire_old_buffer(req, 0);
	if (rc != 0)
		return (rc);

	sb = sbuf_new_for_sysctl(NULL, NULL, 4096, req);
	if (sb == NULL)
		return (ENOMEM);

	port_id = arg2 >> 16;
	MPASS(port_id < sc->params.nports);
	MPASS(sc->port[port_id] != NULL);
	i = arg2 & 0xffff;
	MPASS(i < sc->chip_params->nsched_cls);
	tc = &sc->port[port_id]->tc[i];

	rc = begin_synchronized_op(sc, NULL, HOLD_LOCK | SLEEP_OK | INTR_OK,
	    "t4tc_p");
	if (rc)
		goto done;
	flags = tc->flags;
	p = tc->params;
	end_synchronized_op(sc, LOCK_HELD);

	if ((flags & TX_SC_OK) == 0) {
		sbuf_printf(sb, "none");
		goto done;
	}

	if (p.level == SCHED_CLASS_LEVEL_CL_WRR) {
		sbuf_printf(sb, "cl-wrr weight %u", p.weight);
		goto done;
	} else if (p.level == SCHED_CLASS_LEVEL_CL_RL)
		sbuf_printf(sb, "cl-rl");
	else if (p.level == SCHED_CLASS_LEVEL_CH_RL)
		sbuf_printf(sb, "ch-rl");
	else {
		rc = ENXIO;
		goto done;
	}

	if (p.ratemode == SCHED_CLASS_RATEMODE_REL) {
		/* XXX: top speed or actual link speed? */
		gbps = port_top_speed(sc->port[port_id]);
		sbuf_printf(sb, " %u%% of %uGbps", p.maxrate, gbps);
	}
	else if (p.ratemode == SCHED_CLASS_RATEMODE_ABS) {
		switch (p.rateunit) {
		case SCHED_CLASS_RATEUNIT_BITS:
			mbps = p.maxrate / 1000;
			gbps = p.maxrate / 1000000;
			if (p.maxrate == gbps * 1000000)
				sbuf_printf(sb, " %uGbps", gbps);
			else if (p.maxrate == mbps * 1000)
				sbuf_printf(sb, " %uMbps", mbps);
			else
				sbuf_printf(sb, " %uKbps", p.maxrate);
			break;
		case SCHED_CLASS_RATEUNIT_PKTS:
			sbuf_printf(sb, " %upps", p.maxrate);
			break;
		default:
			rc = ENXIO;
			goto done;
		}
	}

	switch (p.mode) {
	case SCHED_CLASS_MODE_CLASS:
		sbuf_printf(sb, " aggregate");
		break;
	case SCHED_CLASS_MODE_FLOW:
		sbuf_printf(sb, " per-flow");
		break;
	default:
		rc = ENXIO;
		goto done;
	}

done:
	if (rc == 0)
		rc = sbuf_finish(sb);
	sbuf_delete(sb);

	return (rc);
}
#endif

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
in_range(int val, int lo, int hi)
{

	return (val < 0 || (val <= hi && val >= lo));
}

static int
set_sched_class_config(struct adapter *sc, int minmax)
{
	int rc;

	if (minmax < 0)
		return (EINVAL);

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4sscc");
	if (rc)
		return (rc);
	rc = -t4_sched_config(sc, FW_SCHED_TYPE_PKTSCHED, minmax, 1);
	end_synchronized_op(sc, 0);

	return (rc);
}

static int
set_sched_class_params(struct adapter *sc, struct t4_sched_class_params *p,
    int sleep_ok)
{
	int rc, top_speed, fw_level, fw_mode, fw_rateunit, fw_ratemode;
	struct port_info *pi;
	struct tx_sched_class *tc;

	if (p->level == SCHED_CLASS_LEVEL_CL_RL)
		fw_level = FW_SCHED_PARAMS_LEVEL_CL_RL;
	else if (p->level == SCHED_CLASS_LEVEL_CL_WRR)
		fw_level = FW_SCHED_PARAMS_LEVEL_CL_WRR;
	else if (p->level == SCHED_CLASS_LEVEL_CH_RL)
		fw_level = FW_SCHED_PARAMS_LEVEL_CH_RL;
	else
		return (EINVAL);

	if (p->mode == SCHED_CLASS_MODE_CLASS)
		fw_mode = FW_SCHED_PARAMS_MODE_CLASS;
	else if (p->mode == SCHED_CLASS_MODE_FLOW)
		fw_mode = FW_SCHED_PARAMS_MODE_FLOW;
	else
		return (EINVAL);

	if (p->rateunit == SCHED_CLASS_RATEUNIT_BITS)
		fw_rateunit = FW_SCHED_PARAMS_UNIT_BITRATE;
	else if (p->rateunit == SCHED_CLASS_RATEUNIT_PKTS)
		fw_rateunit = FW_SCHED_PARAMS_UNIT_PKTRATE;
	else
		return (EINVAL);

	if (p->ratemode == SCHED_CLASS_RATEMODE_REL)
		fw_ratemode = FW_SCHED_PARAMS_RATE_REL;
	else if (p->ratemode == SCHED_CLASS_RATEMODE_ABS)
		fw_ratemode = FW_SCHED_PARAMS_RATE_ABS;
	else
		return (EINVAL);

	/* Vet our parameters ... */
	if (!in_range(p->channel, 0, sc->chip_params->nchan - 1))
		return (ERANGE);

	pi = sc->port[sc->chan_map[p->channel]];
	if (pi == NULL)
		return (ENXIO);
	MPASS(pi->tx_chan == p->channel);
	top_speed = port_top_speed(pi) * 1000000; /* Gbps -> Kbps */

	if (!in_range(p->cl, 0, sc->chip_params->nsched_cls) ||
	    !in_range(p->minrate, 0, top_speed) ||
	    !in_range(p->maxrate, 0, top_speed) ||
	    !in_range(p->weight, 0, 100))
		return (ERANGE);

	/*
	 * Translate any unset parameters into the firmware's
	 * nomenclature and/or fail the call if the parameters
	 * are required ...
	 */
	if (p->rateunit < 0 || p->ratemode < 0 || p->channel < 0 || p->cl < 0)
		return (EINVAL);

	if (p->minrate < 0)
		p->minrate = 0;
	if (p->maxrate < 0) {
		if (p->level == SCHED_CLASS_LEVEL_CL_RL ||
		    p->level == SCHED_CLASS_LEVEL_CH_RL)
			return (EINVAL);
		else
			p->maxrate = 0;
	}
	if (p->weight < 0) {
		if (p->level == SCHED_CLASS_LEVEL_CL_WRR)
			return (EINVAL);
		else
			p->weight = 0;
	}
	if (p->pktsize < 0) {
		if (p->level == SCHED_CLASS_LEVEL_CL_RL ||
		    p->level == SCHED_CLASS_LEVEL_CH_RL)
			return (EINVAL);
		else
			p->pktsize = 0;
	}

	rc = begin_synchronized_op(sc, NULL,
	    sleep_ok ? (SLEEP_OK | INTR_OK) : HOLD_LOCK, "t4sscp");
	if (rc)
		return (rc);
	tc = &pi->tc[p->cl];
	tc->params = *p;
	rc = -t4_sched_params(sc, FW_SCHED_TYPE_PKTSCHED, fw_level, fw_mode,
	    fw_rateunit, fw_ratemode, p->channel, p->cl, p->minrate, p->maxrate,
	    p->weight, p->pktsize, sleep_ok);
	if (rc == 0)
		tc->flags |= TX_SC_OK;
	else {
		/*
		 * Unknown state at this point, see tc->params for what was
		 * attempted.
		 */
		tc->flags &= ~TX_SC_OK;
	}
	end_synchronized_op(sc, sleep_ok ? 0 : LOCK_HELD);

	return (rc);
}

int
t4_set_sched_class(struct adapter *sc, struct t4_sched_params *p)
{

	if (p->type != SCHED_CLASS_TYPE_PACKET)
		return (EINVAL);

	if (p->subcmd == SCHED_CLASS_SUBCMD_CONFIG)
		return (set_sched_class_config(sc, p->u.config.minmax));

	if (p->subcmd == SCHED_CLASS_SUBCMD_PARAMS)
		return (set_sched_class_params(sc, &p->u.params, 1));

	return (EINVAL);
}

int
t4_set_sched_queue(struct adapter *sc, struct t4_sched_queue *p)
{
	struct port_info *pi = NULL;
	struct vi_info *vi;
	struct sge_txq *txq;
	uint32_t fw_mnem, fw_queue, fw_class;
	int i, rc;

	rc = begin_synchronized_op(sc, NULL, SLEEP_OK | INTR_OK, "t4setsq");
	if (rc)
		return (rc);

	if (p->port >= sc->params.nports) {
		rc = EINVAL;
		goto done;
	}

	/* XXX: Only supported for the main VI. */
	pi = sc->port[p->port];
	vi = &pi->vi[0];
	if (!(vi->flags & VI_INIT_DONE)) {
		/* tx queues not set up yet */
		rc = EAGAIN;
		goto done;
	}

	if (!in_range(p->queue, 0, vi->ntxq - 1) ||
	    !in_range(p->cl, 0, sc->chip_params->nsched_cls - 1)) {
		rc = EINVAL;
		goto done;
	}

	/*
	 * Create a template for the FW_PARAMS_CMD mnemonic and value (TX
	 * Scheduling Class in this case).
	 */
	fw_mnem = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_SCHEDCLASS_ETH));
	fw_class = p->cl < 0 ? 0xffffffff : p->cl;

	/*
	 * If op.queue is non-negative, then we're only changing the scheduling
	 * on a single specified TX queue.
	 */
	if (p->queue >= 0) {
		txq = &sc->sge.txq[vi->first_txq + p->queue];
		fw_queue = (fw_mnem | V_FW_PARAMS_PARAM_YZ(txq->eq.cntxt_id));
		rc = -t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &fw_queue,
		    &fw_class);
		goto done;
	}

	/*
	 * Change the scheduling on all the TX queues for the
	 * interface.
	 */
	for_each_txq(vi, i, txq) {
		fw_queue = (fw_mnem | V_FW_PARAMS_PARAM_YZ(txq->eq.cntxt_id));
		rc = -t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &fw_queue,
		    &fw_class);
		if (rc)
			goto done;
	}

	rc = 0;
done:
	end_synchronized_op(sc, 0);
	return (rc);
}

int
t4_os_find_pci_capability(struct adapter *sc, int cap)
{
	int i;

	return (pci_find_cap(sc->dev, cap, &i) == 0 ? i : 0);
}

int
t4_os_pci_save_state(struct adapter *sc)
{
	device_t dev;
	struct pci_devinfo *dinfo;

	dev = sc->dev;
	dinfo = device_get_ivars(dev);

	pci_cfg_save(dev, dinfo, 0);
	return (0);
}

int
t4_os_pci_restore_state(struct adapter *sc)
{
	device_t dev;
	struct pci_devinfo *dinfo;

	dev = sc->dev;
	dinfo = device_get_ivars(dev);

	pci_cfg_restore(dev, dinfo);
	return (0);
}

void
t4_os_portmod_changed(const struct adapter *sc, int idx)
{
	struct port_info *pi = sc->port[idx];
	struct vi_info *vi;
	struct ifnet *ifp;
	int v;
	static const char *mod_str[] = {
		NULL, "LR", "SR", "ER", "TWINAX", "active TWINAX", "LRM"
	};

	for_each_vi(pi, v, vi) {
		build_medialist(pi, &vi->media);
	}

	ifp = pi->vi[0].ifp;
	if (pi->mod_type == FW_PORT_MOD_TYPE_NONE)
		if_printf(ifp, "transceiver unplugged.\n");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		if_printf(ifp, "unknown transceiver inserted.\n");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		if_printf(ifp, "unsupported transceiver inserted.\n");
	else if (pi->mod_type > 0 && pi->mod_type < nitems(mod_str)) {
		if_printf(ifp, "%s transceiver inserted.\n",
		    mod_str[pi->mod_type]);
	} else {
		if_printf(ifp, "transceiver (type %d) inserted.\n",
		    pi->mod_type);
	}
}

void
t4_os_link_changed(struct adapter *sc, int idx, int link_stat, int reason)
{
	struct port_info *pi = sc->port[idx];
	struct vi_info *vi;
	struct ifnet *ifp;
	int v;

	if (link_stat)
		pi->linkdnrc = -1;
	else {
		if (reason >= 0)
			pi->linkdnrc = reason;
	}
	for_each_vi(pi, v, vi) {
		ifp = vi->ifp;
		if (ifp == NULL)
			continue;

		if (link_stat) {
			ifp->if_baudrate = IF_Mbps(pi->link_cfg.speed);
			if_link_state_change(ifp, LINK_STATE_UP);
		} else {
			if_link_state_change(ifp, LINK_STATE_DOWN);
		}
	}
}

void
t4_iterate(void (*func)(struct adapter *, void *), void *arg)
{
	struct adapter *sc;

	sx_slock(&t4_list_lock);
	SLIST_FOREACH(sc, &t4_list, link) {
		/*
		 * func should not make any assumptions about what state sc is
		 * in - the only guarantee is that sc->sc_lock is a valid lock.
		 */
		func(sc, arg);
	}
	sx_sunlock(&t4_list_lock);
}

void
t4_db_full(struct adapter *sc)
{

	CXGBE_UNIMPLEMENTED(__func__);
}

void
t4_db_dropped(struct adapter *sc)
{

	CXGBE_UNIMPLEMENTED(__func__);
}

#ifdef TCP_OFFLOAD
static int
toe_capability(struct vi_info *vi, int enable)
{
	int rc;
	struct port_info *pi = vi->pi;
	struct adapter *sc = pi->adapter;

	ASSERT_SYNCHRONIZED_OP(sc);

	if (!is_offload(sc))
		return (ENODEV);

	if (enable) {
		if ((vi->ifp->if_capenable & IFCAP_TOE) != 0) {
			/* TOE is already enabled. */
			return (0);
		}

		/*
		 * We need the port's queues around so that we're able to send
		 * and receive CPLs to/from the TOE even if the ifnet for this
		 * port has never been UP'd administratively.
		 */
		if (!(vi->flags & VI_INIT_DONE)) {
			rc = vi_full_init(vi);
			if (rc)
				return (rc);
		}
		if (!(pi->vi[0].flags & VI_INIT_DONE)) {
			rc = vi_full_init(&pi->vi[0]);
			if (rc)
				return (rc);
		}

		if (isset(&sc->offload_map, pi->port_id)) {
			/* TOE is enabled on another VI of this port. */
			pi->uld_vis++;
			return (0);
		}

		if (!uld_active(sc, ULD_TOM)) {
			rc = t4_activate_uld(sc, ULD_TOM);
			if (rc == EAGAIN) {
				log(LOG_WARNING,
				    "You must kldload t4_tom.ko before trying "
				    "to enable TOE on a cxgbe interface.\n");
			}
			if (rc != 0)
				return (rc);
			KASSERT(sc->tom_softc != NULL,
			    ("%s: TOM activated but softc NULL", __func__));
			KASSERT(uld_active(sc, ULD_TOM),
			    ("%s: TOM activated but flag not set", __func__));
		}

		/* Activate iWARP and iSCSI too, if the modules are loaded. */
		if (!uld_active(sc, ULD_IWARP))
			(void) t4_activate_uld(sc, ULD_IWARP);
		if (!uld_active(sc, ULD_ISCSI))
			(void) t4_activate_uld(sc, ULD_ISCSI);

		pi->uld_vis++;
		setbit(&sc->offload_map, pi->port_id);
	} else {
		pi->uld_vis--;

		if (!isset(&sc->offload_map, pi->port_id) || pi->uld_vis > 0)
			return (0);

		KASSERT(uld_active(sc, ULD_TOM),
		    ("%s: TOM never initialized?", __func__));
		clrbit(&sc->offload_map, pi->port_id);
	}

	return (0);
}

/*
 * Add an upper layer driver to the global list.
 */
int
t4_register_uld(struct uld_info *ui)
{
	int rc = 0;
	struct uld_info *u;

	sx_xlock(&t4_uld_list_lock);
	SLIST_FOREACH(u, &t4_uld_list, link) {
	    if (u->uld_id == ui->uld_id) {
		    rc = EEXIST;
		    goto done;
	    }
	}

	SLIST_INSERT_HEAD(&t4_uld_list, ui, link);
	ui->refcount = 0;
done:
	sx_xunlock(&t4_uld_list_lock);
	return (rc);
}

int
t4_unregister_uld(struct uld_info *ui)
{
	int rc = EINVAL;
	struct uld_info *u;

	sx_xlock(&t4_uld_list_lock);

	SLIST_FOREACH(u, &t4_uld_list, link) {
	    if (u == ui) {
		    if (ui->refcount > 0) {
			    rc = EBUSY;
			    goto done;
		    }

		    SLIST_REMOVE(&t4_uld_list, ui, uld_info, link);
		    rc = 0;
		    goto done;
	    }
	}
done:
	sx_xunlock(&t4_uld_list_lock);
	return (rc);
}

int
t4_activate_uld(struct adapter *sc, int id)
{
	int rc;
	struct uld_info *ui;

	ASSERT_SYNCHRONIZED_OP(sc);

	if (id < 0 || id > ULD_MAX)
		return (EINVAL);
	rc = EAGAIN;	/* kldoad the module with this ULD and try again. */

	sx_slock(&t4_uld_list_lock);

	SLIST_FOREACH(ui, &t4_uld_list, link) {
		if (ui->uld_id == id) {
			if (!(sc->flags & FULL_INIT_DONE)) {
				rc = adapter_full_init(sc);
				if (rc != 0)
					break;
			}

			rc = ui->activate(sc);
			if (rc == 0) {
				setbit(&sc->active_ulds, id);
				ui->refcount++;
			}
			break;
		}
	}

	sx_sunlock(&t4_uld_list_lock);

	return (rc);
}

int
t4_deactivate_uld(struct adapter *sc, int id)
{
	int rc;
	struct uld_info *ui;

	ASSERT_SYNCHRONIZED_OP(sc);

	if (id < 0 || id > ULD_MAX)
		return (EINVAL);
	rc = ENXIO;

	sx_slock(&t4_uld_list_lock);

	SLIST_FOREACH(ui, &t4_uld_list, link) {
		if (ui->uld_id == id) {
			rc = ui->deactivate(sc);
			if (rc == 0) {
				clrbit(&sc->active_ulds, id);
				ui->refcount--;
			}
			break;
		}
	}

	sx_sunlock(&t4_uld_list_lock);

	return (rc);
}

int
uld_active(struct adapter *sc, int uld_id)
{

	MPASS(uld_id >= 0 && uld_id <= ULD_MAX);

	return (isset(&sc->active_ulds, uld_id));
}
#endif

/*
 * Come up with reasonable defaults for some of the tunables, provided they're
 * not set by the user (in which case we'll use the values as is).
 */
static void
tweak_tunables(void)
{
	int nc = mp_ncpus;	/* our snapshot of the number of CPUs */

	if (t4_ntxq10g < 1) {
#ifdef RSS
		t4_ntxq10g = rss_getnumbuckets();
#else
		t4_ntxq10g = min(nc, NTXQ_10G);
#endif
	}

	if (t4_ntxq1g < 1) {
#ifdef RSS
		/* XXX: way too many for 1GbE? */
		t4_ntxq1g = rss_getnumbuckets();
#else
		t4_ntxq1g = min(nc, NTXQ_1G);
#endif
	}

	if (t4_nrxq10g < 1) {
#ifdef RSS
		t4_nrxq10g = rss_getnumbuckets();
#else
		t4_nrxq10g = min(nc, NRXQ_10G);
#endif
	}

	if (t4_nrxq1g < 1) {
#ifdef RSS
		/* XXX: way too many for 1GbE? */
		t4_nrxq1g = rss_getnumbuckets();
#else
		t4_nrxq1g = min(nc, NRXQ_1G);
#endif
	}

	if (t4_tmr_idx_10g < 0 || t4_tmr_idx_10g >= SGE_NTIMERS)
		t4_tmr_idx_10g = TMR_IDX_10G;

	if (t4_pktc_idx_10g < -1 || t4_pktc_idx_10g >= SGE_NCOUNTERS)
		t4_pktc_idx_10g = PKTC_IDX_10G;

	if (t4_tmr_idx_1g < 0 || t4_tmr_idx_1g >= SGE_NTIMERS)
		t4_tmr_idx_1g = TMR_IDX_1G;

	if (t4_pktc_idx_1g < -1 || t4_pktc_idx_1g >= SGE_NCOUNTERS)
		t4_pktc_idx_1g = PKTC_IDX_1G;

	if (t4_qsize_txq < 128)
		t4_qsize_txq = 128;

	if (t4_qsize_rxq < 128)
		t4_qsize_rxq = 128;
	while (t4_qsize_rxq & 7)
		t4_qsize_rxq++;

	t4_intr_types &= INTR_MSIX | INTR_MSI | INTR_INTX;
}

static int
mod_event(module_t mod, int cmd, void *arg)
{
	int rc = 0, tries;

	switch (cmd) {
	case MOD_LOAD:
		t4_sge_modload();
		t4_register_cpl_handler(CPL_SET_TCB_RPL, set_tcb_rpl);
		t4_register_cpl_handler(CPL_L2T_WRITE_RPL, l2t_write_rpl);
		t4_register_cpl_handler(CPL_TRACE_PKT, t4_trace_pkt);
		t4_register_cpl_handler(CPL_T5_TRACE_PKT, t5_trace_pkt);
		sx_init(&t4_list_lock, "T4/T5 adapters");
		SLIST_INIT(&t4_list);
#ifdef TCP_OFFLOAD
		sx_init(&t4_uld_list_lock, "T4/T5 ULDs");
		SLIST_INIT(&t4_uld_list);
#endif
		t4_tracer_modload();
		tweak_tunables();
		break;

	case MOD_UNLOAD:
		sx_slock(&t4_list_lock);
		if (!SLIST_EMPTY(&t4_list)) {
			rc = EBUSY;
			sx_sunlock(&t4_list_lock);
			break;
		}
#ifdef TCP_OFFLOAD
		sx_slock(&t4_uld_list_lock);
		if (!SLIST_EMPTY(&t4_uld_list)) {
			rc = EBUSY;
			sx_sunlock(&t4_uld_list_lock);
			sx_sunlock(&t4_list_lock);
			break;
		}
#endif
		tries = 0;
		while (tries++ < 5 && t4_sge_extfree_refs() != 0) {
			uprintf("%ju clusters with custom free routine "
			    "still is use.\n", t4_sge_extfree_refs());
			pause("t4unload", 2 * hz);
		}
#ifdef TCP_OFFLOAD
		sx_sunlock(&t4_uld_list_lock);
#endif
		sx_sunlock(&t4_list_lock);

		if (t4_sge_extfree_refs() == 0) {
			t4_tracer_modunload();
#ifdef TCP_OFFLOAD
			sx_destroy(&t4_uld_list_lock);
#endif
			sx_destroy(&t4_list_lock);
			t4_sge_modunload();
		} else {
			rc = EBUSY;
		}
		break;
	}

	return (rc);
}

static moduledata_t t4_common_mod = {
	"t4_common",
	&mod_event,
	NULL
};

DECLARE_MODULE(t4_common, t4_common_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
