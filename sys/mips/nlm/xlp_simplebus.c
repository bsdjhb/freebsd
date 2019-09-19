/*-
 * Copyright (c) 2015 Broadcom Corporation
 * (based on sys/dev/fdt/simplebus.c)
 * Copyright (c) 2013 Nathan Whitehorn
 * All rights reserved.
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
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/rman.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/intr_machdep.h>

#include <mips/nlm/hal/haldefs.h>
#include <mips/nlm/interrupt.h>
#include <mips/nlm/hal/iomap.h>
#include <mips/nlm/hal/mips-extns.h>
#include <mips/nlm/hal/pcibus.h>
#include <mips/nlm/xlp.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/fdt/simplebus.h>

/* flash memory region for chipselects */
#define	GBU_MEM_BASE	0x16000000UL
#define	GBU_MEM_LIMIT	0x17ffffffUL

/*
 * Device registers in pci ecfg memory region for devices without regular PCI BARs
 */
#define	PCI_ECFG_BASE	XLP_DEFAULT_IO_BASE
#define	PCI_ECFG_LIMIT	(XLP_DEFAULT_IO_BASE + 0x0fffffff)

/*
 * Bus interface.
 */
static int		xlp_simplebus_probe(device_t dev);
static struct resource *xlp_simplebus_alloc_resource(device_t, device_t, int,
    int *, rman_res_t, rman_res_t, rman_res_t, u_int);
static int		xlp_simplebus_adjust_resource(device_t, device_t, int,
    struct resource *, rman_res_t, rman_res_t);
static int		xlp_simplebus_activate_resource(device_t, device_t, int,
    int, struct resource *);
static int		xlp_simplebus_map_resource(device_t, device_t, int,
    struct resource *, struct resource_map_request *, struct resource_map *);
static int		xlp_simplebus_unmap_resource(device_t, device_t, int,
    struct resource *, struct resource_map *);
static int		xlp_simplebus_setup_intr(device_t, device_t,
    struct resource *, int, driver_filter_t *, driver_intr_t *, void *, void **);

/*
 * ofw_bus interface
 */
static int		xlp_simplebus_ofw_map_intr(device_t, device_t, phandle_t,
    int, pcell_t *);

static devclass_t simplebus_devclass;
static device_method_t xlp_simplebus_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		xlp_simplebus_probe),

	DEVMETHOD(bus_alloc_resource,	xlp_simplebus_alloc_resource),
	DEVMETHOD(bus_adjust_resource,	xlp_simplebus_adjust_resource),
	DEVMETHOD(bus_activate_resource, xlp_simplebus_activate_resource),
	DEVMETHOD(bus_map_resource,	xlp_simplebus_map_resource),
	DEVMETHOD(bus_unmap_resource,	xlp_simplebus_unmap_resource),
	DEVMETHOD(bus_setup_intr,	xlp_simplebus_setup_intr),

	DEVMETHOD(ofw_bus_map_intr,	xlp_simplebus_ofw_map_intr),
	DEVMETHOD_END
};

DEFINE_CLASS_1(simplebus, xlp_simplebus_driver, xlp_simplebus_methods,
    sizeof(struct simplebus_softc), simplebus_driver);
DRIVER_MODULE(xlp_simplebus, ofwbus, xlp_simplebus_driver, simplebus_devclass,
    0, 0);

static struct rman irq_rman, port_rman, mem_rman, pci_ecfg_rman, gbu_rman;

static void
xlp_simplebus_init_resources(void)
{
	irq_rman.rm_start = 0;
	irq_rman.rm_end = 255;
	irq_rman.rm_type = RMAN_ARRAY;
	irq_rman.rm_descr = "PCI Mapped Interrupts";
	if (rman_init(&irq_rman)
	    || rman_manage_region(&irq_rman, 0, 255))
		panic("xlp_simplebus_init_resources irq_rman");

	port_rman.rm_type = RMAN_ARRAY;
	port_rman.rm_descr = "I/O ports";
	if (rman_init(&port_rman)
	    || rman_manage_region(&port_rman, PCIE_IO_BASE, PCIE_IO_LIMIT))
		panic("xlp_simplebus_init_resources port_rman");

	mem_rman.rm_type = RMAN_ARRAY;
	mem_rman.rm_descr = "I/O memory";
	if (rman_init(&mem_rman)
	    || rman_manage_region(&mem_rman, PCIE_MEM_BASE, PCIE_MEM_LIMIT))
		panic("xlp_simplebus_init_resources mem_rman");

	pci_ecfg_rman.rm_type = RMAN_ARRAY;
	pci_ecfg_rman.rm_descr = "PCI ECFG IO";
	if (rman_init(&pci_ecfg_rman) || rman_manage_region(&pci_ecfg_rman,
	    PCI_ECFG_BASE, PCI_ECFG_LIMIT))
		panic("xlp_simplebus_init_resources pci_ecfg_rman");

	gbu_rman.rm_type = RMAN_ARRAY;
	gbu_rman.rm_descr = "Flash region";
	if (rman_init(&gbu_rman)
	    || rman_manage_region(&gbu_rman, GBU_MEM_BASE, GBU_MEM_LIMIT))
		panic("xlp_simplebus_init_resources gbu_rman");
}

static int
xlp_simplebus_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	/*
	 * FDT data puts a "simple-bus" compatible string on many things that
	 * have children but aren't really busses in our world.  Without a
	 * ranges property we will fail to attach, so just fail to probe too.
	 */
	if (!(ofw_bus_is_compatible(dev, "simple-bus") &&
	    ofw_bus_has_prop(dev, "ranges")) &&
	    (ofw_bus_get_type(dev) == NULL || strcmp(ofw_bus_get_type(dev),
	     "soc") != 0))
		return (ENXIO);

	xlp_simplebus_init_resources();
	device_set_desc(dev, "XLP SoC bus");

	return (BUS_PROBE_SPECIFIC);
}

/*
 * Because this driver uses 3 rman's for SYS_RES_MEMORY, it can't implement
 * BUS_GET_RMAN().
 */
static struct rman *
xlp_simplebus_get_rman(int type, rman_res_t start, rman_res_t end)
{

	switch (type) {
	case SYS_RES_IRQ:
		return (&irq_rman);
	case SYS_RES_IOPORT:
		return (&port_rman);
		break;
	case SYS_RES_MEMORY:
		if (start >= GBU_MEM_BASE && end <= GBU_MEM_LIMIT)
			return (&gbu_rman);
		if (start >= PCI_ECFG_BASE && end <= PCI_ECFG_LIMIT)
			return (&pci_ecfg_rman);
		if (start >= PCIE_MEM_BASE && end <= PCIE_MEM_LIMIT)
			return (&mem_rman);
		return (NULL);
	default:
		return (NULL);
	}
}

static struct resource *
xlp_simplebus_alloc_resource(device_t bus, device_t child, int type, int *rid,
    rman_res_t start, rman_res_t end, rman_res_t count, u_int flags)
{
	struct rman			*rm;
	struct resource			*rv;
	struct resource_list_entry	*rle;
	struct simplebus_softc		*sc;
	struct simplebus_devinfo	*di;
	int j, isdefault, passthrough, needsactivate;

	passthrough = (device_get_parent(child) != bus);
	needsactivate = flags & RF_ACTIVE;
	sc = device_get_softc(bus);
        di = device_get_ivars(child);
	rle = NULL;

	if (!passthrough) {
		isdefault = RMAN_IS_DEFAULT_RANGE(start, end);
		if (isdefault) {
			rle = resource_list_find(&di->rl, type, *rid);
			if (rle == NULL)
				return (NULL);
			if (rle->res != NULL)
				panic("%s: resource entry is busy", __func__);
			start = rle->start;
			count = ulmax(count, rle->count);
			end = ulmax(rle->end, start + count - 1);
		}
		if (type == SYS_RES_MEMORY) {
			/* Remap through ranges property */
			for (j = 0; j < sc->nranges; j++) {
				if (start >= sc->ranges[j].bus && end <
				    sc->ranges[j].bus + sc->ranges[j].size) {
					start -= sc->ranges[j].bus;
					start += sc->ranges[j].host;
					end -= sc->ranges[j].bus;
					end += sc->ranges[j].host;
					break;
				}
			}
			if (j == sc->nranges && sc->nranges != 0) {
				if (bootverbose)
					device_printf(bus, "Could not map resource "
					    "%#jx-%#jx\n", start, end);
				return (NULL);
			}
		}
	}

	rm = xlp_simplebus_get_rman(type, start, end);
	if (rm == NULL) {
		if (type == SYS_RES_MEMORY) {
			if (bootverbose)
				device_printf(bus, "Invalid MEM range"
					    "%#jx-%#jx\n", start, end);
		}
		return (NULL);
	}

	rv = rman_reserve_resource(rm, start, end, count, flags, child);
	if (rv == NULL) {
		device_printf(bus, "%s: could not reserve resource for %s\n",
		    __func__, device_get_nameunit(child));
		return (NULL);
	}

	rman_set_rid(rv, *rid);

	if (needsactivate) {
		if (bus_activate_resource(child, type, *rid, rv)) {
			device_printf(bus, "%s: could not activate resource\n",
			    __func__);
			rman_release_resource(rv);
			return (NULL);
		}
	}

	return (rv);
}

static int
xlp_simplebus_adjust_resource(device_t dev, device_t child, int type,
    struct resource *r, rman_res_t start, rman_res_t end)
{
	struct rman *rm;

	rm = xlp_simplebus_get_rman(type, rman_get_start(r),
	    rman_get_end(r));
	if (rm == NULL)
		return (ENXIO);
	if (!rman_is_region_manager(r, rm))
		return (EINVAL);
	return (rman_adjust_resource(r, start, end));
}

static int
xlp_simplebus_activate_resource(device_t bus, device_t child, int type, int rid,
    struct resource *r)
{
	struct resource_map map;
#ifdef INVARIANTS
	struct rman *rm;
#endif
	int error;

#ifdef INVARIANTS
	rm = xlp_simplebus_get_rman(type, rman_get_start(r),
	    rman_get_end(r));
	KASSERT(rman_is_region_manager(r, rm),
	    ("%s: rman %p doesn't match for resource %p", __func__, rm, r));
#endif

	error = rman_activate_resource(r);
	if (error)
		return (error);

	if ((rman_get_flags(r) & RF_UNMAPPED) == 0 &&
	    (type == SYS_RES_MEMORY || type == SYS_RES_IOPORT)) {
		error = BUS_MAP_RESOURCE(bus, child, type, r, NULL, &map);
		if (error) {
			rman_deactivate_resource(r);
			return (error);
		}

		rman_set_mapping(r, &map);
	}
	return (0);
}

static int
xlp_simplebus_map_resource(device_t bus, device_t child, int type,
    struct resource *r, struct resource_map_request *argsp,
    struct resource_map *map)
{
	struct resource_map_request args;
	rman_res_t length, start;
	int error;

	/* Resources must be active to be mapped. */
	if (!(rman_get_flags(r) & RF_ACTIVE))
		return (ENXIO);

	/* Mappings are only supported on I/O and memory resources. */
	switch (type) {
	case SYS_RES_IOPORT:
	case SYS_RES_MEMORY:
		break;
	default:
		return (EINVAL);
	}

	resource_init_map_request(&args);
	error = resource_validate_map_request(r, argsp, &args, &start, &length);
	if (error)
		return (error);

	/* Lookup bus space tag. */
	if (type == SYS_RES_MEMORY && start >= PCI_ECFG_BASE &&
	    start <= PCI_ECFG_LIMIT)
		map->r_bustag = rmi_uart_bus_space;
	else
		map->r_bustag = rmi_bus_space;

	map->r_vaddr = pmap_mapdev(start, length);
	map->r_size = length;
	map->r_bushandle = (bus_space_handle_t)map->r_vaddr;
	return (0);
}

static int
xlp_simplebus_unmap_resource(device_t bus, device_t child, int type,
    struct resource *r, struct resource_map *map)
{

	switch (type) {
	case SYS_RES_IOPORT:
	case SYS_RES_MEMORY:
		pmap_unmapdev((vm_offset_t)map->r_vaddr, map->r_size);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static int
xlp_simplebus_setup_intr(device_t dev, device_t child, struct resource *res, int flags,
    driver_filter_t *filt, driver_intr_t *intr, void *arg, void **cookiep)
{
	register_t s;
	int irq;

	/* setup irq */
	s = intr_disable();
	irq = rman_get_start(res);
	cpu_establish_hardintr(device_get_nameunit(child), filt, intr, arg,
	    irq, flags, cookiep);
	intr_restore(s);
	return (0);
}

static int
xlp_simplebus_ofw_map_intr(device_t dev, device_t child, phandle_t iparent, int icells,
    pcell_t *irq)
{

	return ((int)irq[0]);
}
