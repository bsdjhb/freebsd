/*-
 * Copyright (c) 2023 Chelsio Communications, Inc.
 * All rights reserved.
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

#include <err.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <devctl.h>

#include "nvmecontrol.h"

static struct options {
	const char *dev;
} opt = {
	.dev = NULL
};

static const struct args args[] = {
	{ arg_string, &opt.dev, "controller-id|namespace-id" },
	{ arg_none, NULL, NULL },
};

static void
disconnect(const struct cmd *f, int argc, char *argv[])
{
	int	fd;
	char	*path;

	if (arg_parse(argc, argv, f))
		return;
	open_dev(opt.dev, &fd, 1, 1);
	get_nsid(fd, &path, NULL);
	close(fd);

	if (devctl_detach(path, false) == -1)
		err(EX_IOERR, "detach of %s failed", path);
	if (devctl_delete(path, true) == -1)
		err(EX_IOERR, "delete of %s failed", path);

	exit(0);
}

static struct cmd disconnect_cmd = {
	.name = "disconnect",
	.fn = disconnect,
	.descr = "Disconnect from a fabrics controller",
	.args = args,
};

CMD_COMMAND(disconnect_cmd);
