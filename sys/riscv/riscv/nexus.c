/*-
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * This code implements a `root nexus' for RISC-V Architecture
 * machines.  The function of the root nexus is to serve as an
 * attachment point for both processors and buses, and to manage
 * resources which are common to all of them.  In particular,
 * this code implements the core resource managers for interrupt
 * requests, DMA requests (which rightfully should be a part of the
 * ISA code but it's easier to do it here for now), I/O port addresses,
 * and I/O memory address space.
 */
#include "opt_platform.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/interrupt.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <machine/intr.h>

#ifdef FDT
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>
#include "ofw_bus_if.h"
#endif

extern struct bus_space memmap_bus;

static MALLOC_DEFINE(M_NEXUSDEV, "nexusdev", "Nexus device");

struct nexus_device {
	struct resource_list	nx_resources;
};

#define DEVTONX(dev)	((struct nexus_device *)device_get_ivars(dev))

static struct rman mem_rman;
static struct rman irq_rman;

static device_probe_t nexus_fdt_probe;
static int nexus_attach(device_t);

static	int nexus_print_child(device_t, device_t);
static	device_t nexus_add_child(device_t, u_int, const char *, int);
static struct rman *nexus_get_rman(device_t, int, u_int);
static	struct resource *nexus_alloc_resource(device_t, device_t, int, int *,
    u_long, u_long, u_long, u_int);
static	int nexus_activate_resource(device_t, device_t, int, int,
    struct resource *);
static int nexus_map_resource(device_t, device_t, int, struct resource *,
    struct resource_map_request *, struct resource_map *);
static int nexus_config_intr(device_t dev, int irq, enum intr_trigger trig,
    enum intr_polarity pol);
static struct resource_list *nexus_get_reslist(device_t, device_t);
static	int nexus_set_resource(device_t, device_t, int, int, u_long, u_long);
static int nexus_unmap_resource(device_t, device_t, int, struct resource *,
    struct resource_map *);
static	int nexus_deactivate_resource(device_t, device_t, int, int,
    struct resource *);

static int nexus_setup_intr(device_t dev, device_t child, struct resource *res,
    int flags, driver_filter_t *filt, driver_intr_t *intr, void *arg, void **cookiep);
static int nexus_teardown_intr(device_t, device_t, struct resource *, void *);

static int nexus_ofw_map_intr(device_t dev, device_t child, phandle_t iparent,
    int icells, pcell_t *intr);

static device_method_t nexus_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		nexus_fdt_probe),
	DEVMETHOD(device_attach,	nexus_attach),

	/* OFW interface */
	DEVMETHOD(ofw_bus_map_intr,	nexus_ofw_map_intr),

	/* Bus interface */
	DEVMETHOD(bus_print_child,	nexus_print_child),
	DEVMETHOD(bus_add_child,	nexus_add_child),
	DEVMETHOD(bus_get_rman,		nexus_get_rman),
	DEVMETHOD(bus_alloc_resource,	nexus_alloc_resource),
	DEVMETHOD(bus_adjust_resource,	bus_generic_rman_adjust_resource),
	DEVMETHOD(bus_release_resource,	bus_generic_rman_release_resource),
	DEVMETHOD(bus_activate_resource,	nexus_activate_resource),
	DEVMETHOD(bus_map_resource,	nexus_map_resource),
	DEVMETHOD(bus_config_intr,	nexus_config_intr),
	DEVMETHOD(bus_get_resource_list, nexus_get_reslist),
	DEVMETHOD(bus_set_resource,	nexus_set_resource),
	DEVMETHOD(bus_unmap_resource,	nexus_unmap_resource),
	DEVMETHOD(bus_deactivate_resource,	nexus_deactivate_resource),
	DEVMETHOD(bus_setup_intr,	nexus_setup_intr),
	DEVMETHOD(bus_teardown_intr,	nexus_teardown_intr),
	{ 0, 0 }
};

static driver_t nexus_fdt_driver = {
	"nexus",
	nexus_methods,
	1			/* no softc */
};

static int
nexus_fdt_probe(device_t dev)
{

	device_quiet(dev);
	return (BUS_PROBE_DEFAULT);
}

static int
nexus_attach(device_t dev)
{

	mem_rman.rm_start = 0;
	mem_rman.rm_end = BUS_SPACE_MAXADDR;
	mem_rman.rm_type = RMAN_ARRAY;
	mem_rman.rm_descr = "I/O memory addresses";
	if (rman_init(&mem_rman) ||
	    rman_manage_region(&mem_rman, 0, BUS_SPACE_MAXADDR))
		panic("nexus_attach mem_rman");
	irq_rman.rm_start = 0;
	irq_rman.rm_end = ~0;
	irq_rman.rm_type = RMAN_ARRAY;
	irq_rman.rm_descr = "Interrupts";
	if (rman_init(&irq_rman) || rman_manage_region(&irq_rman, 0, ~0))
		panic("nexus_attach irq_rman");

	nexus_add_child(dev, 8, "timer", 0);
	nexus_add_child(dev, 9, "rcons", 0);
	nexus_add_child(dev, 10, "ofwbus", 0);

	bus_generic_probe(dev);
	bus_generic_attach(dev);

	return (0);
}

static int
nexus_print_child(device_t bus, device_t child)
{
	int retval = 0;

	retval += bus_print_child_header(bus, child);
	retval += printf("\n");

	return (retval);
}

static device_t
nexus_add_child(device_t bus, u_int order, const char *name, int unit)
{
	device_t child;
	struct nexus_device *ndev;

	ndev = malloc(sizeof(struct nexus_device), M_NEXUSDEV, M_NOWAIT|M_ZERO);
	if (!ndev)
		return (0);
	resource_list_init(&ndev->nx_resources);

	child = device_add_child_ordered(bus, order, name, unit);

	/* should we free this in nexus_child_detached? */
	device_set_ivars(child, ndev);

	return (child);
}

static struct rman *
nexus_get_rman(device_t bus, int type, u_int flags)
{

	switch (type) {
	case SYS_RES_IRQ:
		return (&irq_rman);
	case SYS_RES_MEMORY:
	case SYS_RES_IOPORT:
		return (&mem_rman);
	default:
		return (NULL);
	}
}

/*
 * Allocate a resource on behalf of child.  NB: child is usually going to be a
 * child of one of our descendants, not a direct child of nexus0.
 * (Exceptions include footbridge.)
 */
static struct resource *
nexus_alloc_resource(device_t bus, device_t child, int type, int *rid,
    u_long start, u_long end, u_long count, u_int flags)
{
	struct nexus_device *ndev = DEVTONX(child);
	struct resource_list_entry *rle;

	/*
	 * If this is an allocation of the "default" range for a given
	 * RID, and we know what the resources for this device are
	 * (ie. they aren't maintained by a child bus), then work out
	 * the start/end values.
	 */
	if (RMAN_IS_DEFAULT_RANGE(start, end) && (count == 1)) {
		if (device_get_parent(child) != bus || ndev == NULL)
			return(NULL);
		rle = resource_list_find(&ndev->nx_resources, type, *rid);
		if (rle == NULL)
			return(NULL);
		start = rle->start;
		end = rle->end;
		count = rle->count;
	}

	return (bus_generic_rman_alloc_resource(bus, child, type, rid,
	    start, end, count, flags));
}

static int
nexus_config_intr(device_t dev, int irq, enum intr_trigger trig,
    enum intr_polarity pol)
{

	return (EOPNOTSUPP);
}

static int
nexus_setup_intr(device_t dev, device_t child, struct resource *res, int flags,
    driver_filter_t *filt, driver_intr_t *intr, void *arg, void **cookiep)
{
	int error;

	if ((rman_get_flags(res) & RF_SHAREABLE) == 0)
		flags |= INTR_EXCL;

	/* We depend here on rman_activate_resource() being idempotent. */
	error = rman_activate_resource(res);
	if (error)
		return (error);

	error = intr_setup_irq(child, res, filt, intr, arg, flags, cookiep);

	return (error);
}

static int
nexus_teardown_intr(device_t dev, device_t child, struct resource *r, void *ih)
{

	return (intr_teardown_irq(child, r, ih));
}

static int
nexus_activate_resource(device_t bus, device_t child, int type, int rid,
    struct resource *r)
{
	int error;

	switch (type) {
	case SYS_RES_IOPORT:
	case SYS_RES_MEMORY:
		error = bus_generic_rman_activate_resource(bus, child, type,
		    rid, r);
		break;
	case SYS_RES_IRQ:
		error = rman_activate_resource(r);
		if (error != 0)
			return (error);
		error = intr_activate_irq(child, r);
		if (error != 0) {
			rman_deactivate_resource(r);
			return (error);
		}
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

static int
nexus_map_resource(device_t bus, device_t child, int type, struct resource *r,
    struct resource_map_request *argsp, struct resource_map *map)
{
	struct resource_map_request args;
	rman_res_t length, start;
	bus_space_handle_t vaddr;
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

	/*
	 * If this is a memory resource, map it into the kernel.
	 */
	error = bus_space_map(&memmap_bus, start, length, 0, &vaddr);
	if (error)
		return (error);
	map->r_bushandle = vaddr;
	map->r_bustag = &memmap_bus;
	map->r_size = length;
	map->r_vaddr = (void *)vaddr;
	return (0);
}

static struct resource_list *
nexus_get_reslist(device_t dev, device_t child)
{
	struct nexus_device *ndev = DEVTONX(child);

	return (&ndev->nx_resources);
}

static int
nexus_set_resource(device_t dev, device_t child, int type, int rid,
    u_long start, u_long count)
{
	struct nexus_device	*ndev = DEVTONX(child);
	struct resource_list	*rl = &ndev->nx_resources;

	/* XXX this should return a success/failure indicator */
	resource_list_add(rl, type, rid, start, start + count - 1, count);

	return(0);
}

static int
nexus_unmap_resource(device_t bus, device_t child, int type, struct resource *r,
    struct resource_map *map)
{

	/*
	 * If this is a memory resource, unmap it.
	 */
	switch (type) {
	case SYS_RES_IOPORT:
	case SYS_RES_MEMORY:
		if (map->r_bushandle != 0)
			bus_space_unmap(&memmap_bus, map->r_bushandle,
			    map->r_size);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static int
nexus_deactivate_resource(device_t bus, device_t child, int type, int rid,
    struct resource *r)
{
	int error;

	switch (type) {
	case SYS_RES_IOPORT:
	case SYS_RES_MEMORY:
		error = bus_generic_rman_deactivate_resource(bus, child, type,
		    rid, r);
		break;
	case SYS_RES_IRQ:
		error = rman_deactivate_resource(r);
		if (error != 0)
			return (error);
		intr_deactivate_irq(child, r);
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

static devclass_t nexus_fdt_devclass;

EARLY_DRIVER_MODULE(nexus_fdt, root, nexus_fdt_driver, nexus_fdt_devclass,
    0, 0, BUS_PASS_BUS + BUS_PASS_ORDER_FIRST);

static int
nexus_ofw_map_intr(device_t dev, device_t child, phandle_t iparent, int icells,
    pcell_t *intr)
{
	struct intr_map_data_fdt *fdt_data;
	size_t len;
	u_int irq;

	len = sizeof(*fdt_data) + icells * sizeof(pcell_t);
	fdt_data = (struct intr_map_data_fdt *)intr_alloc_map_data(
	    INTR_MAP_DATA_FDT, len, M_WAITOK | M_ZERO);
	fdt_data->iparent = iparent;
	fdt_data->ncells = icells;
	memcpy(fdt_data->cells, intr, icells * sizeof(pcell_t));
	irq = intr_map_irq(NULL, iparent, (struct intr_map_data *)fdt_data);

	return (irq);
}
