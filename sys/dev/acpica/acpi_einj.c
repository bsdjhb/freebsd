/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Netflix, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>
#include <contrib/dev/acpica/include/actables.h>

#include <dev/acpica/acpiio.h>
#include <dev/acpica/acpivar.h>

#define	ACPI_EINJ_MAX_ACTION	(ACPI_EINJV2_GET_ERROR_TYPE)

struct einj_instruction {
	struct resource *res;
	u_int instruction;
	u_int flags;
	uint64_t value;
	uint64_t mask;
};

struct einj_action {
	struct einj_instruction *instructions;
	u_int num_instructions;
	u_int action;
};

struct einj_softc {
	device_t dev;
	ACPI_TABLE_EINJ *einj;
	struct einj_action actions[ACPI_EINJ_MAX_ACTION + 1];
	struct resource **res;
	u_int num_res;
};

static MALLOC_DEFINE(M_EINJ, "einj", "ACPI error injection");

static bool
einj_validate_instruction(u_int i, ACPI_EINJ_ENTRY *e)
{
	ACPI_GENERIC_ADDRESS *gas;
	UINT8 valid_flags;

	valid_flags = 0;
	switch (e->WheaHeader.Instruction) {
	case ACPI_EINJ_WRITE_REGISTER:
	case ACPI_EINJ_WRITE_REGISTER_VALUE:
		valid_flags |= ACPI_EINJ_PRESERVE;
		break;
	case ACPI_EINJ_READ_REGISTER:
	case ACPI_EINJ_READ_REGISTER_VALUE:
	case ACPI_EINJ_NOOP:
#if 0
		/* Not documented. */
	case ACPI_EINJ_FLUSH_CACHELINE:
#endif
		break;
	default:
		if (bootverbose)
			printf("EINJ: Unknown instruction at index %u\n", i);
		return (false);
	}
	if ((e->WheaHeader.Flags & ~valid_flags) != 0) {
		if (bootverbose)
			printf("EINJ: Invalid instruction flag at index %u\n",
			    i);
		return (false);
	}

	gas = &e->WheaHeader.RegisterRegion;
	switch (gas->SpaceId) {
	case ACPI_ADR_SPACE_SYSTEM_MEMORY:
	case ACPI_ADR_SPACE_SYSTEM_IO:
		break;
	default:
		if (bootverbose)
			printf("EINJ: Unsupported register address space at index %u\n",
			    i);
		return (false);
	}

	/*
	 * The spec seems to suggest sub-bit ranges of registers might
	 * be valid, but punt on handling those until one is actually
	 * encountered in the wild.
	 */
	if (gas->BitOffset != 0) {
		if (bootverbose)
			printf("EINJ: Unsupported register offset at index %u\n",
			    i);
		return (false);
	}
	if (!(gas->BitWidth == 8 || gas->BitWidth == 16 ||
	    gas->BitWidth == 32 || gas->BitWidth == 64)) {
		if (bootverbose)
			printf("EINJ: Unsupported register width at index %u\n",
			    i);
		return (false);
	}
	return (true);
}

static bool
einj_validate_table(ACPI_TABLE_EINJ *einj)
{
	ACPI_EINJ_ENTRY *e;
	UINT8 last_action;
	u_int i;

	if (einj->Header.Revision < 1 || einj->Header.Revision > 2) {
		if (bootverbose)
			printf("EINJ: Unsupported revision %u\n",
			    einj->Header.Revision);
		return (false);
	}
	if (einj->HeaderLength != sizeof(*einj) - sizeof(ACPI_TABLE_HEADER)) {
		if (bootverbose)
			printf("EINJ: Invalid Injection Interface Header Length\n");
		return (false);
	}
	if (einj->Entries == 0) {
		if (bootverbose)
			printf("EINJ: No actions\n");
		return (false);
	}
	if (einj->Header.Length != sizeof(*einj) + einj->Entries * sizeof(*e)) {
		if (bootverbose)
			printf("EINJ: Invalid table length\n");
		return (false);
	}

	/*
	 * Require the actions to be in ascending order.  This seems
	 * to be implied by the specification and simplifies
	 * implementation.
	 */
	e = (ACPI_EINJ_ENTRY *)(einj + 1);
	last_action = e->WheaHeader.Action;
	e++;
	for (i = 1; i < einj->Entries; i++, e++) {
		if (e->WheaHeader.Action < last_action) {
			if (bootverbose)
				printf("EINJ: Action out of order at index %u\n",
				    i);
			return (false);
		}
		last_action = e->WheaHeader.Action;

		if (!einj_validate_instruction(i, e))
			return (false);
	}
	return (true);
}

static uint64_t
einj_read_register(struct einj_instruction *inst)
{
	switch (rman_get_size(inst->res)) {
	case 1:
		return (bus_read_1(inst->res, 0));
	case 2:
		return (bus_read_2(inst->res, 0));
	case 4:
		return (bus_read_4(inst->res, 0));
	case 8:
		return (bus_read_8(inst->res, 0));
	default:
		__assert_unreachable();
	}
}

static void
einj_write_register(struct einj_instruction *inst, uint64_t value)
{
	switch (rman_get_size(inst->res)) {
	case 1:
		bus_write_1(inst->res, 0, value);
		break;
	case 2:
		bus_write_2(inst->res, 0, value);
		break;
	case 4:
		bus_write_4(inst->res, 0, value);
		break;
	case 8:
		bus_write_8(inst->res, 0, value);
		break;
	default:
		__assert_unreachable();
	}
}

static uint64_t
einj_execute_instructions(struct einj_instruction *inst, u_int count,
    uint64_t initial_value)
{
	uint64_t old, value;

	value = initial_value;
	for (u_int i = 0; i < count; i++, inst++) {
		switch (inst->instruction) {
		case ACPI_EINJ_READ_REGISTER:
		case ACPI_EINJ_READ_REGISTER_VALUE:
			value = einj_read_register(inst);
			value &= inst->mask;
			if (inst->instruction == ACPI_EINJ_READ_REGISTER_VALUE)
				value = (value == inst->value);
			break;
		case ACPI_EINJ_WRITE_REGISTER_VALUE:
			value = inst->value;
			/* FALLTHROUGH */
		case ACPI_EINJ_WRITE_REGISTER:
			value &= inst->mask;
			if (inst->flags & ACPI_EINJ_PRESERVE) {
				old = einj_read_register(inst);
				value |= (old & ~inst->mask);
			}
			einj_write_register(inst, value);
			break;
		case ACPI_EINJ_NOOP:
			break;
		default:
			__assert_unreachable();
		}
	}
	return (value);
}

static int
einj_execute_action(struct einj_softc *sc, u_int action, uint64_t *value)
{
	struct einj_action *ea;

	if (action >= nitems(sc->actions))
		return (ENOENT);
	ea = &sc->actions[action];
	if (ea->num_instructions == 0)
		return (ENOENT);

	*value = einj_execute_instructions(ea->instructions,
	    ea->num_instructions, *value);
	return (0);
}

static int
einj_ioctl(u_long cmd, caddr_t addr, void *arg)
{
	struct einj_softc *sc = arg;
	uint64_t value;
	int error;

	switch (cmd) {
	case ACPIIO_EINJ_GET_ERROR_TYPE:
		value = 0;
		error = einj_execute_action(sc, ACPI_EINJ_GET_ERROR_TYPE,
		    &value);
		if (error == 0)
			*(uint64_t *)addr = value;
		break;
	default:
		error = ENOIOCTL;
		break;
	}
	return (error);
}

static void
einj_identify(driver_t *driver, device_t parent)
{
	ACPI_TABLE_HEADER *einj;
	ACPI_STATUS status;
	bool valid;

	if (device_find_child(parent, "einj", DEVICE_UNIT_ANY) != NULL)
		return;

	status = AcpiGetTable(ACPI_SIG_EINJ, 0, &einj);
	if (ACPI_FAILURE(status))
		return;
	valid = einj_validate_table((ACPI_TABLE_EINJ *)einj);
	AcpiPutTable(einj);
	if (!valid)
		return;

	BUS_ADD_CHILD(parent, 2, "einj", DEVICE_UNIT_ANY);
}

static struct resource *
einj_lookup_resource(struct einj_softc *sc, ACPI_GENERIC_ADDRESS *gas)
{
	struct resource *res;
	u_int rid, type;
	int error;

	/* First, look for an existing resource. */
	type = (gas->SpaceId == ACPI_ADR_SPACE_SYSTEM_MEMORY) ? SYS_RES_MEMORY :
	    SYS_RES_IOPORT;
	for (u_int i = 0; i < sc->num_res; i++) {
		res = sc->res[i];
		if (rman_get_type(res) == type &&
		    rman_get_start(res) == gas->Address) {
			if (rman_get_size(res) != gas->BitWidth / 8) {
				device_printf(sc->dev, "Multiple sizes for %s register at address %#jx\n",
				    type == SYS_RES_MEMORY ? "memory" : "I/O",
				    (uintmax_t)gas->Address);
				return (NULL);
			}
			return (res);
		}
	}

	error = acpi_bus_alloc_gas(sc->dev, &type, &rid, gas, &res, 0);
	if (error != 0) {
		device_printf(sc->dev,
		    "Failed to allocate %s register at address %#jx\n",
		    type == SYS_RES_MEMORY ? "memory" : "I/O",
		    (uintmax_t)gas->Address);
		return (NULL);
	}

	sc->res = realloc(sc->res, sizeof(res) * (sc->num_res + 1), M_EINJ,
	    M_WAITOK);
	sc->res[sc->num_res] = res;
	sc->num_res++;
	return (res);
}

static bool
einj_parse_table(struct einj_softc *sc)
{
	ACPI_EINJ_ENTRY *e;
	struct resource *res;
	u_int i;

	e = (ACPI_EINJ_ENTRY *)(sc->einj + 1);
	for (i = 0; i < sc->einj->Entries; i++, e++) {
		struct einj_action *ea = &sc->actions[e->WheaHeader.Action];
		struct einj_instruction *ei;

		res = einj_lookup_resource(sc, &e->WheaHeader.RegisterRegion);
		if (res == NULL)
			return (false);

		ea->instructions = realloc(ea->instructions,
		    sizeof(*ea->instructions) + (ea->num_instructions + 1),
		    M_EINJ, M_WAITOK);
		ei = &ea->instructions[ea->num_instructions];
		ei->res = res;
		ei->instruction = e->WheaHeader.Instruction;
		ei->flags = e->WheaHeader.Flags;
		ei->value = e->WheaHeader.Value;
		ei->mask = e->WheaHeader.Mask;
		ea->num_instructions++;
	}
	return (true);
}

static int
einj_probe(device_t dev)
{
	device_set_desc(dev, "ACPI Error Injection Interface");
	return (BUS_PROBE_GENERIC);
}

static int
einj_attach(device_t dev)
{
	struct einj_softc *sc = device_get_softc(dev);
	ACPI_TABLE_HEADER *hdr;
	ACPI_STATUS status;
	int error;

	sc->dev = dev;
	status = AcpiGetTable(ACPI_SIG_EINJ, 0, &hdr);
	if (ACPI_FAILURE(status)) {
		device_printf(dev, "Failed to read " ACPI_SIG_EINJ " table\n");
		return (ENXIO);
	}
	sc->einj = (ACPI_TABLE_EINJ *)hdr;

	if (!einj_validate_table(sc->einj)) {
		device_printf(dev, "Invalid " ACPI_SIG_EINJ " table\n");
		goto out;
	}
	if (!einj_parse_table(sc))
		goto out;

	error = acpi_register_ioctl(ACPIIO_EINJ_GET_ERROR_TYPE, einj_ioctl, sc);
	if (error) {
		device_printf(dev, "Failed to register ioctl handler\n");
		goto out;
	}
	return (0);
out:
	for (u_int i = 0; i < nitems(sc->actions); i++)
		free(sc->actions[i].instructions, M_EINJ);
	for (u_int i = 0; i < sc->num_res; i++)
		bus_release_resource(dev, sc->res[i]);
	free(sc->res, M_EINJ);
	AcpiPutTable(hdr);
	return (ENXIO);
}

static int
einj_detach(device_t dev)
{
	struct einj_softc *sc = device_get_softc(dev);

	acpi_deregister_ioctl(ACPIIO_EINJ_GET_ERROR_TYPE, einj_ioctl);
	for (u_int i = 0; i < nitems(sc->actions); i++)
		free(sc->actions[i].instructions, M_EINJ);
	for (u_int i = 0; i < sc->num_res; i++)
		bus_release_resource(dev, sc->res[i]);
	free(sc->res, M_EINJ);
	AcpiPutTable((ACPI_TABLE_HEADER *)sc->einj);
	return (0);
}

static device_method_t einj_methods[] = {
	DEVMETHOD(device_identify, einj_identify),
	DEVMETHOD(device_probe, einj_probe),
	DEVMETHOD(device_attach, einj_attach),
	DEVMETHOD(device_detach, einj_detach),
	DEVMETHOD_END
};

static driver_t einj_driver = {
	"einj",
	einj_methods,
	sizeof(struct einj_softc)
};

DRIVER_MODULE(einj, acpi, einj_driver, NULL, NULL);
MODULE_DEPEND(einj, acpi, 1, 1, 1);
