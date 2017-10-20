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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <kenv.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smbios.h"

struct smbios_handle {
	struct smbios_eps eps;
	struct smbios_structure_header *table;
	struct smbios_structure_header *table_end;
};

#define	BIOS_END	0x100000

static void *
bios_map(int mem_fd, uint32_t start, size_t length)
{
	void *p;

	p = mmap(NULL, length, PROT_READ, MAP_SHARED, mem_fd, start);
	if (p == MAP_FAILED)
		return (NULL);
	return (p);
}

static int
valid_eps(void *buf)
{
	struct smbios_eps *e;
	uint8_t *ptr;
	uint8_t cksum;
	int i;

	e = buf;
	ptr = buf;
	cksum = 0;
	for (i = 0; i < e->length; i++) {
		cksum += ptr[i];
	}

	return (cksum == 0);
}

static int
find_eps_hint(int mem_fd, struct smbios_eps *eps)
{
	char buf[KENV_MVALLEN + 1], *cp, *p;
	long addr;

	if (kenv(KENV_GET, "hint.smbios.0.mem", buf, sizeof(buf)) == -1)
		return (errno);
	addr = strtol(buf, &cp, 0);
	if (*cp != '\0' || cp == buf)
		return (EINVAL);

	p = bios_map(mem_fd, addr, sizeof(*eps));
	if (p == NULL)
		return (errno);
	if (memcmp(p + SMBIOS_OFF, SMBIOS_SIG, SMBIOS_LEN) == 0 &&
	    valid_eps(p)) {
		memcpy(eps, p, sizeof(*eps));
		munmap(p, sizeof(*eps));
		return (0);
	}
	munmap(p, sizeof(*eps));
	return (ENOENT);
}

static int
find_eps_search(int mem_fd, struct smbios_eps *eps)
{
	char *bios_base, *bios_end, *p;

	bios_base = bios_map(mem_fd, SMBIOS_START, BIOS_END - SMBIOS_START);
	if (bios_base == NULL)
		return (errno);
	bios_end = bios_base + BIOS_END - SMBIOS_START;
	for (p = bios_base; (p + sizeof(*eps)) < bios_end; p += SMBIOS_STEP) {
		if (memcmp(p + SMBIOS_OFF, SMBIOS_SIG, SMBIOS_LEN) == 0 &&
		    valid_eps(p)) {
			memcpy(eps, p, sizeof(*eps));
			munmap(bios_base, BIOS_END - SMBIOS_START);
			return (0);
		}
	}
	munmap(bios_base, BIOS_END - SMBIOS_START);
	return (ENOENT);
}

int
smbios_open(smbios_handle_t *handlep)
{
	struct smbios_handle *handle;
	int error, mem_fd;

	handle = NULL;
	mem_fd = open("/dev/mem", O_RDONLY | O_CLOEXEC);
	if (mem_fd < 0)
		return (errno);

	handle = calloc(1, sizeof(*handle));
	if (handle == NULL) {
		error = errno;
		goto out;
	}

	error = find_eps_hint(mem_fd, &handle->eps);
	if (error) {
		error = find_eps_search(mem_fd, &handle->eps);
		if (error)
			goto out;
	}

	handle->table = bios_map(mem_fd, handle->eps.structure_table_address,
	    handle->eps.structure_table_length);
	if (handle->table == NULL) {
		error = errno;
		goto out;
	}
	handle->table_end = (struct smbios_structure_header *)
	    ((char *)handle->table + handle->eps.structure_table_length);

	*handlep = handle;
	return (0);

out:
	free(handle);
	close(mem_fd);
	return (error);
}

int
smbios_close(smbios_handle_t handle)
{

	munmap(handle->table, handle->eps.structure_table_length);
	free(handle);
	return (0);
}

void
smbios_walk_table(smbios_handle_t handle, smbios_callback callback, void *arg)
{
	struct smbios_structure_header *s;
	char *p;
	int i;

	for (s = handle->table, i = 0;
	     s < handle->table_end && i < handle->eps.number_structures; i++) {

		/*
		 * Ignore table entries that walk off the end of the
		 * table.
		 */
		if ((char *)s + s->length >= (char *)handle->table_end)
			return;

		if (callback(handle, s, arg) == SMBIOS_STOP)
			return;

		/*
		 * Look for a double-nul after the end of the
		 * formatted area of this structure.
		 */
		p = (char *)s + s->length;
		for (;;) {
			/* Don't walk off the end of the table. */
			if (p + 1 >= (char *)handle->table_end)
				return;

			if (p[0] == 0 && p[1] == 0)
				break;
			p++;
		}

		/*
		 * Skip over the double-nul to the start of the next
		 * structure.
		 */
		p += 2;
		s = (struct smbios_structure_header *)p;
	}
}

struct find_handle_data {
	u_int	handle_id;
	struct smbios_structure_header *hdr;
};

static enum smbios_cb_retval
find_handle_cb(smbios_handle_t handle __unused,
    struct smbios_structure_header *hdr, void *arg)
{
	struct find_handle_data *fhd;

	fhd = arg;
	if (hdr->handle == fhd->handle_id) {
		fhd->hdr = hdr;
		return (SMBIOS_STOP);
	}
	return (SMBIOS_CONTINUE);
}

const struct smbios_structure_header *
smbios_find_handle(smbios_handle_t handle, u_int handle_id)
{
	struct find_handle_data fhd;

	fhd.handle_id = handle_id;
	fhd.hdr = NULL;
	smbios_walk_table(handle, find_handle_cb, &fhd);
	return (fhd.hdr);
}

const char *
smbios_find_string(smbios_handle_t handle,
    const struct smbios_structure_header *hdr, u_int index)
{
	const char *p, *end, *next;

	/* Verify supplied header is within handle's table. */
	if (!(hdr >= handle->table && hdr < handle->table_end))
		return (NULL);

	/* A string index of 0 indicates a non-existent string. */
	if (index == 0)
		return (NULL);

	end = (const char *)handle->table_end;
	p = (const char *)hdr + hdr->length;

	/* Check for empty string list. */
	if (p >= end || (p[0] == '\0' && p[1] == '\0'))
		return (NULL);
	for (;;) {
		/* Bail if 'p' is beyond the end of the table. */
		if (p >= end)
			return (NULL);

		/*
		 * If '*p' is nul, there are two cases.  If this is
		 * the first iteration, then the string list began
		 * with a nul character.  The next character is either
		 * the second nul (which means end of list), or some
		 * non-nul character (which is not defined in the
		 * standard).  If this is not the first iteration,
		 * then '*(p - 1)' is a nul character and 'p'
		 * references the second of a double nul terminating
		 * the string list.  Treat '*p' as nul as signalling
		 * end of the list in all cases.
		 */
		if (*p == '\0')
			return (NULL);

		/* Find the end of the current string. */
		next = memchr(p, 0, end - p);

		/* Search for '\0' walked off the end of the table. */
		if (next == NULL)
			return (NULL);

		if (index == 1)
			return (p);

		p = next + 1;
		index--;
	}
}
