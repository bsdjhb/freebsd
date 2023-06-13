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

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/host/nvmf_var.h>

static struct cdev *nvmf_cdev;

static int
nvmf_handoff_host(struct nvmf_handoff_host *hh)
{
	struct nvmf_ivars ivars;
	device_t dev;
	size_t len;
	u_int i;
	int error;

	memset(&ivars, 0, sizeof(ivars));

	if (!hh->admin.admin || hh->num_io_queues < 1)
		return (EINVAL);

	ivars.cdata = malloc(sizeof(*ivars.cdata), M_NVMF, M_WAITOK);
	error = copyin(hh->cdata, ivars.cdata, sizeof(*ivars.cdata));
	if (error != 0)
		goto out;

	len = hh->num_io_queues * sizeof(*ivars.io_params);
	ivars.io_params = malloc(len, M_NVMF, M_WAITOK);
	error = copyin(hh->io, ivars.io_params, len);
	if (error != 0)
		goto out;

	for (i = 0; i < hh->num_io_queues; i++) {
		if (ivars.io_params[i].admin) {
			error = EINVAL;
			goto out;
		}
	}

	ivars.hh = hh;

	bus_topo_lock();
	dev = device_add_child(root_bus, "nvme", -1);
	if (dev == NULL) {
		bus_topo_unlock();
		error = ENXIO;
		goto out;
	}

	device_set_ivars(dev, &ivars);
	error = device_probe_and_attach(dev);
	device_set_ivars(dev, NULL);
	if (error != 0)
		device_delete_child(root_bus, dev);
	bus_topo_unlock();

out:
	free(ivars.io_params, M_NVMF);
	free(ivars.cdata, M_NVMF);
	return (error);
}

static int
nvmf_ctl_ioctl(struct cdev *dev, u_long cmd, caddr_t arg, int flag,
    struct thread *td)
{
	switch (cmd) {
	case NVMF_HANDOFF_HOST:
		return (nvmf_handoff_host((struct nvmf_handoff_host *)arg));
	default:
		return (ENOTTY);
	}
}

static struct cdevsw nvmf_ctl_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl = nvmf_ctl_ioctl
};

int
nvmf_ctl_load(void)
{
	struct make_dev_args mda;
	int error;

	make_dev_args_init(&mda);
	mda.mda_devsw = &nvmf_ctl_cdevsw;
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_WHEEL;
	mda.mda_mode = 0600;
	error = make_dev_s(&mda, &nvmf_cdev, "nvmf");
	if (error != 0)
		nvmf_cdev = NULL;
	return (error);
}

void
nvmf_ctl_unload(void)
{
	if (nvmf_cdev != NULL) {
		destroy_dev(nvmf_cdev);
		nvmf_cdev = NULL;
	}
}
