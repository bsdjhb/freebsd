/*-
 * Copyright (c) 2017 Netflix, Inc.
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
 *
 * $FreeBSD$
 */

#ifndef __SMBIOS_H__
#define	__SMBIOS_H__

#include <machine/pc/bios.h>

struct smbios_handle;

typedef struct smbios_handle *smbios_handle_t;

enum smbios_structure_types {
	SMBIOS_BASEBOARD_INFO = 2,
	SMBIOS_MEMORY_DEVICE = 17,
};

struct smbios_baseboard_info {
	uint8_t		type;
	uint8_t		length;
	uint16_t	handle;
	uint8_t		manufacturer;
	uint8_t		product;
	uint8_t		version;
	uint8_t		serial_number;
	uint8_t		asset_tag;
	uint8_t		feature_flags;
	uint8_t		location_in_chassis;
	uint16_t	chassis_handle;
	uint8_t		board_type;
	uint8_t		number_of_contained_object_handles;
	uint16_t	contained_object_handles[0];
} __packed;

struct smbios_memory_device {
	uint8_t		type;
	uint8_t		length;
	uint16_t	handle;
	uint16_t	physical_memory_array_handle;
	uint16_t	memory_error_info_handle;
	uint16_t	total_width;
	uint16_t	data_width;
	uint16_t	size;
	uint8_t		form_factor;
	uint8_t		device_set;
	uint8_t		device_locator;
	uint8_t		bank_locator;
	uint8_t		memory_type;
	uint16_t	type_detail;
	uint16_t	speed;
	uint8_t		manufacturer;
	uint8_t		serial_number;
	uint8_t		asset_tag;
	uint8_t		part_number;
	uint8_t		attributes;
	uint32_t	extended_size;
	uint16_t	configured_memory_clock_speed;
	uint16_t	minimum_voltage;
	uint16_t	maximum_voltage;
	uint16_t	configured_voltage;
} __packed;

enum smbios_cb_retval {
	SMBIOS_CONTINUE,
	SMBIOS_STOP
};

typedef enum smbios_cb_retval (*smbios_callback)(
    smbios_handle_t, struct smbios_structure_header *, void *);

int	smbios_open(smbios_handle_t *);
int	smbios_close(smbios_handle_t);
const struct smbios_structure_header *smbios_find_by_handle(smbios_handle_t,
    u_int);
const struct smbios_structure_header *smbios_find_by_type(smbios_handle_t,
    u_int);
const char *smbios_find_string(smbios_handle_t,
    const struct smbios_structure_header *, u_int);
void	smbios_walk_table(smbios_handle_t, smbios_callback, void *);

#endif /* !__SMBIOS_H__ */
