/*-
 * Copyright (c) 2005-2006 John H. Baldwin <jhb@FreeBSD.org>
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

#include <sys/ioccom.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

static void
usage(char **av)
{
	fprintf(stderr, "%s: <ioctl> [ ... ]\n", av[0]);
	exit(1);
}

int
main(int ac, char **av)
{
	unsigned long cmd;
	char *cp;
	int i;

	if (ac < 2)
		usage(av);
	printf("  command :  dir  grp num len\n");
	for (i = 1; i < ac; i++) {
		cmd = strtoll(av[i], &cp, 0);
		if (*cp != '\0') {
			fprintf(stderr, "Invalid integer: %s\n", av[i]);
			usage(av);
		}
		printf("0x%08x: ", cmd);
		switch (cmd & IOC_DIRMASK) {
		case IOC_VOID:
			printf("VOID ");
			break;
		case IOC_OUT:
			printf("OUT  ");
			break;
		case IOC_IN:
			printf("IN   ");
			break;
		case IOC_INOUT:
			printf("INOUT");
			break;
		default:
			printf("%01x ???", (cmd & IOC_DIRMASK) >> 29);
			break;
		}
		printf(" '%c' %3d %d\n", IOCGROUP(cmd), cmd & 0xff,
		    IOCPARM_LEN(cmd));
	}
	return (0);
}
