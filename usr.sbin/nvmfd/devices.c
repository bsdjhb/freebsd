/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
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

#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <libutil.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

#define	RAMDISK_PREFIX	"ramdisk:"

struct backing_device {
	enum { RAMDISK, FILE, CDEV } type;
	union {
		int	fd;	/* FILE, CDEV */
		void	*mem;	/* RAMDISK */
	};
	u_int	sector_size;
	off_t	len;
};

static struct backing_device *devices;
static u_int ndevices;

static void
init_ramdisk(const char *config, struct backing_device *dev)
{
	uint64_t num;

	dev->type = RAMDISK;
	dev->sector_size = 512;
	if (expand_number(config, &num))
		errx(1, "Invalid ramdisk specification: %s", config);
	if ((num % dev->sector_size) != 0)
		errx(1, "Invalid ramdisk size %ju", (uintmax_t)num);
	dev->mem = calloc(num, 1);
	dev->len = num;
}

static void
init_filedevice(const char *config, int fd, struct stat *sb,
    struct backing_device *dev)
{
	dev->type = FILE;
	dev->fd = fd;
	dev->sector_size = 512;
	if ((sb->st_size % dev->sector_size) != 0)
		errx(1, "File size is not a multiple of 512: %s", config);
	dev->len = sb->st_size;
}

static void
init_chardevice(const char *config, int fd, struct backing_device *dev)
{
	dev->type = CDEV;
	dev->fd = fd;
	if (ioctl(fd, DIOCGSECTORSIZE, &dev->sector_size) != 0)
		err(1, "Failed to fetch sector size for %s", config);
	if (ioctl(fd, DIOCGMEDIASIZE, &dev->len) != 0)
		err(1, "Failed to fetch sector size for %s", config);
}

static void
init_device(const char *config, struct backing_device *dev)
{
	struct stat sb;
	int fd;

	/* Check for a RAM disk. */
	if (strncmp(RAMDISK_PREFIX, config, strlen(RAMDISK_PREFIX)) == 0) {
		init_ramdisk(config + strlen(RAMDISK_PREFIX), dev);
		return;
	}

	fd = open(config, O_RDWR);
	if (fd == -1)
		err(1, "Failed to open %s", config);
	if (fstat(fd, &sb) == -1)
		err(1, "fstat");
	switch (sb.st_mode & S_IFMT) {
	case S_IFCHR:
		init_filedevice(config, fd, &sb, dev);
		break;
	case S_IFREG:
		init_chardevice(config, fd, dev);
		break;
	default:
		errx(1, "Invalid file type for %s", config);
	}
}

void
register_devices(int ac, char **av)
{
	ndevices = ac;
	devices = calloc(ndevices, sizeof(*devices));

	for (int i = 0; i < ac; i++)
		init_device(av[i], &devices[i]);
}

