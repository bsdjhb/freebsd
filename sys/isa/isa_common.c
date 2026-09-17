/*-
 * SPDX-License-Identifier: BSD-2-Clause AND MIT
 *
 * Copyright (c) 1999 Doug Rabson
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
/*
 * Modifications for Intel architecture by Garrett A. Wollman.
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
 */

/*
 * Parts of the ISA bus implementation common to all architectures.
 */

#include <sys/cdefs.h>
#include "opt_isa.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>

#include <machine/resource.h>

#include <isa/isavar.h>
#include <isa/isa_common.h>

static int	isa_print_child(device_t bus, device_t dev);

static MALLOC_DEFINE(M_ISADEV, "isadev", "ISA device");

static int isa_running;

/*
 * At 'probe' time, we add all the devices which we know about to the
 * bus.  The generic attach routine will probe and attach them if they
 * are alive.
 */
static int
isa_probe(device_t dev)
{
	device_set_desc(dev, "ISA bus");
	return (0);
}

extern device_t isa_bus_device;

static int
isa_attach(device_t dev)
{
	/*
	 * Arrange for isa_probe_children(dev) to be called later. XXX
	 */
	isa_bus_device = dev;
	return (0);
}

/*
 * Called after other devices have initialised to probe for isa devices.
 */
void
isa_probe_children(device_t dev)
{
	struct isa_device *idev;
	device_t *children, child;
	int nchildren, i;

	/*
	 * Create all the non-hinted children by calling drivers'
	 * identify methods.
	 */
	bus_identify_children(dev);

	/* Next, enumerate hinted devices. */
	bus_enumerate_hinted_children(dev);

	bus_attach_children(dev);

	isa_running = 1;

	/* In GENERIC kernels, warn about non-PNP ISA devices. */
	if (strcmp(kern_ident, "GENERIC") != 0)
		return;

	if (device_get_children(dev, &children, &nchildren))
		return;
	for (i = 0; i < nchildren; i++) {
		child = children[i];
		idev = DEVTOISA(child);

		if (idev->id_vendorid == 0 && device_is_attached(child))
			device_printf(child,
			    "non-PNP ISA device will be removed from GENERIC in FreeBSD 16.\n");
	}
}

/*
 * Add a new child with default ivars.
 */
static device_t
isa_add_child(device_t dev, u_int order, const char *name, int unit)
{
	device_t child;
	struct	isa_device *idev;

	child = device_add_child_ordered(dev, order, name, unit);
	if (child == NULL) 
		return (child);
	
	idev = malloc(sizeof(struct isa_device), M_ISADEV, M_NOWAIT | M_ZERO);
	if (!idev)
		return (0);

	resource_list_init(&idev->id_resources);
	idev->id_order = order;

	device_set_ivars(child, idev);

	return (child);
}

static void
isa_child_deleted(device_t dev, device_t child)
{
	free(device_get_ivars(child), M_ISADEV);
}

static int
isa_print_all_resources(device_t dev)
{
	struct	isa_device *idev = DEVTOISA(dev);
	struct resource_list *rl = &idev->id_resources;
	int retval = 0;

	if (STAILQ_FIRST(rl) || device_get_flags(dev))
		retval += printf(" at");
	
	retval += resource_list_print_type(rl, "port", SYS_RES_IOPORT, "%#jx");
	retval += resource_list_print_type(rl, "iomem", SYS_RES_MEMORY, "%#jx");
	retval += resource_list_print_type(rl, "irq", SYS_RES_IRQ, "%jd");
	retval += resource_list_print_type(rl, "drq", SYS_RES_DRQ, "%jd");
	if (device_get_flags(dev))
		retval += printf(" flags %#x", device_get_flags(dev));
	if (idev->id_vendorid)
		retval += printf(" pnpid %s", pnp_eisaformat(idev->id_vendorid));

	return (retval);
}

static int
isa_print_child(device_t bus, device_t dev)
{
	int retval = 0;

	retval += bus_print_child_header(bus, dev);
	retval += isa_print_all_resources(dev);
	retval += bus_print_child_footer(bus, dev);

	return (retval);
}

static void
isa_probe_nomatch(device_t dev, device_t child)
{
	if (bootverbose) {
		bus_print_child_header(dev, child);
		printf(" failed to probe");
		isa_print_all_resources(child);
		bus_print_child_footer(dev, child);
	}
                                      
	return;
}

static int
isa_read_ivar(device_t bus, device_t dev, int index, uintptr_t * result)
{
	struct isa_device* idev = DEVTOISA(dev);
	struct resource_list *rl = &idev->id_resources;
	struct resource_list_entry *rle;

	switch (index) {
	case ISA_IVAR_PORT_0:
		rle = resource_list_find(rl, SYS_RES_IOPORT, 0);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_PORT_1:
		rle = resource_list_find(rl, SYS_RES_IOPORT, 1);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_PORTSIZE_0:
		rle = resource_list_find(rl, SYS_RES_IOPORT, 0);
		if (rle)
			*result = rle->count;
		else
			*result = 0;
		break;

	case ISA_IVAR_PORTSIZE_1:
		rle = resource_list_find(rl, SYS_RES_IOPORT, 1);
		if (rle)
			*result = rle->count;
		else
			*result = 0;
		break;

	case ISA_IVAR_MADDR_0:
		rle = resource_list_find(rl, SYS_RES_MEMORY, 0);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_MADDR_1:
		rle = resource_list_find(rl, SYS_RES_MEMORY, 1);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_MEMSIZE_0:
		rle = resource_list_find(rl, SYS_RES_MEMORY, 0);
		if (rle)
			*result = rle->count;
		else
			*result = 0;
		break;

	case ISA_IVAR_MEMSIZE_1:
		rle = resource_list_find(rl, SYS_RES_MEMORY, 1);
		if (rle)
			*result = rle->count;
		else
			*result = 0;
		break;

	case ISA_IVAR_IRQ_0:
		rle = resource_list_find(rl, SYS_RES_IRQ, 0);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_IRQ_1:
		rle = resource_list_find(rl, SYS_RES_IRQ, 1);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_DRQ_0:
		rle = resource_list_find(rl, SYS_RES_DRQ, 0);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_DRQ_1:
		rle = resource_list_find(rl, SYS_RES_DRQ, 1);
		if (rle)
			*result = rle->start;
		else
			*result = -1;
		break;

	case ISA_IVAR_VENDORID:
		*result = idev->id_vendorid;
		break;

	case ISA_IVAR_LOGICALID:
		*result = idev->id_logicalid;
		break;

	default:
		return (ENOENT);
	}

	return (0);
}

static int
isa_write_ivar(device_t bus, device_t dev, int index, uintptr_t value)
{
	struct isa_device* idev = DEVTOISA(dev);

	switch (index) {
	case ISA_IVAR_PORT_0:
	case ISA_IVAR_PORT_1:
	case ISA_IVAR_PORTSIZE_0:
	case ISA_IVAR_PORTSIZE_1:
	case ISA_IVAR_MADDR_0:
	case ISA_IVAR_MADDR_1:
	case ISA_IVAR_MEMSIZE_0:
	case ISA_IVAR_MEMSIZE_1:
	case ISA_IVAR_IRQ_0:
	case ISA_IVAR_IRQ_1:
	case ISA_IVAR_DRQ_0:
	case ISA_IVAR_DRQ_1:
		return (EINVAL);

	case ISA_IVAR_VENDORID:
		idev->id_vendorid = value;
		break;

	case ISA_IVAR_LOGICALID:
		idev->id_logicalid = value;
		break;

	default:
		return (ENOENT);
	}

	return (0);
}

static void
isa_driver_added(device_t dev, driver_t *driver)
{
	device_t *children;
	int nchildren, i;

	/*
	 * Don't do anything if drivers are dynamically
	 * added during autoconfiguration (cf. ymf724).
	 * since that would end up calling identify
	 * twice.
	 */
	if (!isa_running)
		return;

	DEVICE_IDENTIFY(driver, dev);
	if (device_get_children(dev, &children, &nchildren))
		return;

	for (i = 0; i < nchildren; i++) {
		device_t child = children[i];
		struct isa_device *idev = DEVTOISA(child);
		struct resource_list *rl = &idev->id_resources;
		struct resource_list_entry *rle;

		if (device_get_state(child) != DS_NOTPRESENT)
			continue;
		if (!device_is_enabled(child))
			continue;

		/*
		 * Free resources which we were holding on behalf of
		 * the device.
		 */
		STAILQ_FOREACH(rle, &idev->id_resources, link) {
			if (rle->res)
				resource_list_release(rl, dev, child,
						      rle->res);
		}

		device_probe_and_attach(child);
	}

	free(children, M_TEMP);
}

static int
isa_set_resource(device_t dev, device_t child, int type, int rid,
    rman_res_t start, rman_res_t count)
{
	struct isa_device* idev = DEVTOISA(child);
	struct resource_list *rl = &idev->id_resources;

	if (type != SYS_RES_IOPORT && type != SYS_RES_MEMORY
	    && type != SYS_RES_IRQ && type != SYS_RES_DRQ)
		return (EINVAL);
	if (rid < 0)
		return (EINVAL);
	if (type == SYS_RES_IOPORT && rid >= ISA_NPORT)
		return (EINVAL);
	if (type == SYS_RES_MEMORY && rid >= ISA_NMEM)
		return (EINVAL);
	if (type == SYS_RES_IRQ && rid >= ISA_NIRQ)
		return (EINVAL);
	if (type == SYS_RES_DRQ && rid >= ISA_NDRQ)
		return (EINVAL);

	resource_list_add(rl, type, rid, start, start + count - 1, count);

	return (0);
}

static struct resource_list *
isa_get_resource_list (device_t dev, device_t child)
{
	struct isa_device* idev = DEVTOISA(child);
	struct resource_list *rl = &idev->id_resources;

	if (!rl)
		return (NULL);

	return (rl);
}

static int
isa_pnp_probe(device_t dev, device_t child, struct isa_pnp_id *ids)
{
	struct isa_device* idev = DEVTOISA(child);

	if (!idev->id_vendorid)
		return (ENOENT);

	while (ids && ids->ip_id) {
		if (idev->id_logicalid == ids->ip_id) {
			if (ids->ip_desc)
				device_set_desc(child, ids->ip_desc);
			return (0);
		}
		ids++;
	}

	return (ENXIO);
}

static int
isa_child_pnpinfo(device_t bus, device_t child, struct sbuf *sb)
{
	struct isa_device *idev = DEVTOISA(child);

	if (idev->id_vendorid)
		sbuf_printf(sb, "pnpid=%s",
		    pnp_eisaformat(idev->id_vendorid));
	return (0);
}

static int
isa_child_location(device_t bus, device_t child, struct sbuf *sb)
{
#if 0
	/* id_pnphandle isn't there yet */
	struct isa_device *idev = DEVTOISA(child);

	if (idev->id_vendorid)
		sbuf_printf(sbuf, "pnphandle=%d", idev->id_pnphandle);
#endif
	return (0);
}

static device_method_t isa_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		isa_probe),
	DEVMETHOD(device_attach,	isa_attach),
	DEVMETHOD(device_detach,	bus_generic_detach),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),
	DEVMETHOD(device_suspend,	bus_generic_suspend),
	DEVMETHOD(device_resume,	bus_generic_resume),

	/* Bus interface */
	DEVMETHOD(bus_add_child,	isa_add_child),
	DEVMETHOD(bus_child_deleted,	isa_child_deleted),
	DEVMETHOD(bus_print_child,	isa_print_child),
	DEVMETHOD(bus_probe_nomatch,	isa_probe_nomatch),
	DEVMETHOD(bus_read_ivar,	isa_read_ivar),
	DEVMETHOD(bus_write_ivar,	isa_write_ivar),
	DEVMETHOD(bus_driver_added,	isa_driver_added),
	DEVMETHOD(bus_setup_intr,	bus_generic_setup_intr),
	DEVMETHOD(bus_teardown_intr,	bus_generic_teardown_intr),

	DEVMETHOD(bus_get_resource_list,isa_get_resource_list),
	DEVMETHOD(bus_alloc_resource,	isa_alloc_resource),
	DEVMETHOD(bus_release_resource,	isa_release_resource),
	DEVMETHOD(bus_set_resource,	isa_set_resource),
	DEVMETHOD(bus_get_resource,	bus_generic_rl_get_resource),
	DEVMETHOD(bus_delete_resource,	bus_generic_rl_delete_resource),
	DEVMETHOD(bus_activate_resource, bus_generic_activate_resource),
	DEVMETHOD(bus_deactivate_resource, bus_generic_deactivate_resource),
	DEVMETHOD(bus_child_pnpinfo,	isa_child_pnpinfo),
	DEVMETHOD(bus_child_location,	isa_child_location),
	DEVMETHOD(bus_hinted_child,	isa_hinted_child),
	DEVMETHOD(bus_hint_device_unit,	isa_hint_device_unit),

	/* ISA interface */
	DEVMETHOD(isa_pnp_probe,	isa_pnp_probe),

	{ 0, 0 }
};

DEFINE_CLASS_0(isa, isa_driver, isa_methods, 0);

/*
 * ISA can be attached to a PCI-ISA bridge, or other locations on some
 * platforms.
 */
DRIVER_MODULE(isa, isab, isa_driver, 0, 0);
DRIVER_MODULE(isa, eisab, isa_driver, 0, 0);
MODULE_VERSION(isa, 1);

/*
 * Code common to ISA bridges.
 */

int
isab_attach(device_t dev)
{
	device_t child;

	child = device_add_child(dev, "isa", DEVICE_UNIT_ANY);
	if (child == NULL)
		return (ENXIO);
	bus_attach_children(dev);
	return (0);
}

char *
pnp_eisaformat(uint32_t id)
{
	uint8_t *data;
	static char idbuf[8];
	const char  hextoascii[] = "0123456789abcdef";

	id = htole32(id);
	data = (uint8_t *)&id;
	idbuf[0] = '@' + ((data[0] & 0x7c) >> 2);
	idbuf[1] = '@' + (((data[0] & 0x3) << 3) + ((data[1] & 0xe0) >> 5));
	idbuf[2] = '@' + (data[1] & 0x1f);
	idbuf[3] = hextoascii[(data[2] >> 4)];
	idbuf[4] = hextoascii[(data[2] & 0xf)];
	idbuf[5] = hextoascii[(data[3] >> 4)];
	idbuf[6] = hextoascii[(data[3] & 0xf)];
	idbuf[7] = 0;
	return(idbuf);
}
