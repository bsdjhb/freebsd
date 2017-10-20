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
#include <err.h>
#include <smbios.h>
#include <stdio.h>

static enum smbios_cb_retval
print_entry(smbios_handle_t handle, struct smbios_structure_header *hdr,
    void *arg)
{
	const char *str;
	int *countp;
	int i;

	countp = arg;
	printf("[%d]: type %d length %d handle 0x%04x\n", *countp,
	    hdr->type, hdr->length, hdr->handle);
	*countp += 1;

	for (i = 1; (str = smbios_find_string(handle, hdr, i)) != NULL; i++)
		printf("    str[%d]: \"%s\"\n", i, str);
	return (SMBIOS_CONTINUE);
}

int
main(int ac __unused, char **av __unused)
{
	smbios_handle_t handle;
	int counter, error;

	error = smbios_open(&handle);
	if (error)
		errc(1, error, "smbios_open");
	counter = 0;
	smbios_walk_table(handle, print_entry, &counter);
	smbios_close(handle);
}
