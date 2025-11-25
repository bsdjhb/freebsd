/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Netflix, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/acconfig.h>
#include <contrib/dev/acpica/include/actbl1.h>
#pragma GCC diagnostic pop

#include <dev/acpica/acpiio.h>

static int fd;

static struct error_type_info {
	const char *name;
	uint32_t bit;
	const char *description;
} error_types[] = {
	{ "cpu.cor", ACPI_EINJ_PROCESSOR_CORRECTABLE, "Processor Correctable" },
	{ "cpu.uc", ACPI_EINJ_PROCESSOR_UNCORRECTABLE,
	  "Processor Uncorrectable Non-Fatal" },
	{ "cpu.fatal", ACPI_EINJ_PROCESSOR_FATAL,
	  "Processor Uncorrectable Fatal" },
	{ "mem.cor", ACPI_EINJ_MEMORY_CORRECTABLE, "Memory Correctable" },
	{ "mem.uc", ACPI_EINJ_MEMORY_UNCORRECTABLE,
	  "Memory Uncorrectable Non-Fatal" },
	{ "mem.fatal", ACPI_EINJ_MEMORY_FATAL, "Memory Uncorrectable Fatal" },
	{ "pcie.cor", ACPI_EINJ_PCIX_CORRECTABLE, "PCI Express Correctable" },
	{ "pcie.uc", ACPI_EINJ_PCIX_UNCORRECTABLE,
	  "PCI Express Uncorrectable Non-Fatal" },
	{ "pcie.fatal", ACPI_EINJ_PCIX_FATAL,
	  "PCI Express Uncorrectable Fatal" },
	{ "platform.cor", ACPI_EINJ_PLATFORM_CORRECTABLE,
	  "Platform Correctable" },
	{ "platform.uc", ACPI_EINJ_PLATFORM_UNCORRECTABLE,
	  "Platform Uncorrectable Non-Fatal" },
	{ "platform.fatal", ACPI_EINJ_PLATFORM_FATAL,
	  "Platform Uncorrectable Fatal" },
	{ "cxl.cache.cor", ACPI_EINJ_CXL_CACHE_CORRECTABLE,
	  "CXL.cache Correctable" },
	{ "cxl.cache.uc", ACPI_EINJ_CXL_CACHE_UNCORRECTABLE,
	  "CXL.cache Uncorrectable Non-Fatal" },
	{ "cxl.cache.fatal", ACPI_EINJ_CXL_CACHE_FATAL,
	  "CXL.cache Uncorrectable Fatal" },
	{ "cxl.mem.cor", ACPI_EINJ_CXL_MEM_CORRECTABLE, "CXL.mem Correctable" },
	{ "cxl.mem.uc", ACPI_EINJ_CXL_MEM_UNCORRECTABLE,
	  "CXL.mem Uncorrectable Non-Fatal" },
	{ "cxl.mem.fatal", ACPI_EINJ_CXL_MEM_FATAL,
	  "CXL.mem Uncorrectable Fatal" },
	{ "vendor", ACPI_EINJ_VENDOR_DEFINED, "Vendor Defined" },
};

static void
list_error_types(void)
{
	uint64_t error_type;

	if (ioctl(fd, ACPIIO_EINJ_GET_ERROR_TYPE, &error_type) == -1)
		err(1, "ACPIIO_EINJ_GET_ERROR_TYPE");

	printf("Supported errors <%#jx>:\n", (uintmax_t)error_type);
	for (u_int i = 0; i < nitems(error_types); i++) {
		struct error_type_info *eti = &error_types[i];

		if ((error_type & eti->bit) == 0)
			continue;
		printf("\t%s (%s)\n", eti->name, eti->description);
	}
}

int
main(int argc __unused, char *argv[] __unused)
{
	fd = open("/dev/acpi", O_RDWR);
	if (fd == -1)
		err(1, "/dev/acpi");

	list_error_types();
	close(fd);
	return (0);
}
