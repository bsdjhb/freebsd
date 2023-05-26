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
#include <sys/lock.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <dev/nvme/nvme.h>
#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/host/nvmf_var.h>

static struct cdevsw nvmf_cdevsw;

MALLOC_DEFINE(M_NVMF, "nvmf", "NVMe over Fabrics host");

struct nvmf_completion_status {
	struct nvme_completion cqe;
	bool	done;
};

static void
nvmf_complete(void *arg, struct nvmf_capsule *nc)
{
	struct nvmf_completion_status *status = arg;
	struct mtx *mtx;

	memcpy(&status->cqe, nvmf_capsule_cqe(nc), sizeof(status->cqe));
	mtx = mtx_pool_find(mtxpool_sleep, status);
	mtx_lock(mtx);
	status->done = true;
	mtx_unlock(mtx);
	wakeup(status);
	nvmf_free_capsule(nc);
}

static void
nvmf_wait_for_reply(struct nvmf_completion_status *status)
{
	struct mtx *mtx;

	mtx = mtx_pool_find(mtxpool_sleep, status);
	mtx_lock(mtx);
	while (!status->done)
		mtx_sleep(status, mtx, 0, "nvmfcmd", 0);
	mtx_unlock(mtx);
}

static int
nvmf_read_property(struct nvmf_softc *sc, uint32_t offset, uint8_t size,
    uint64_t *value)
{
	const struct nvmf_fabric_prop_get_rsp *rsp;
	struct nvmf_completion_status status;

	status.done = false;
	nvmf_cmd_get_property(sc, offset, size, nvmf_complete, &status,
	    M_WAITOK);
	nvmf_wait_for_reply(&status);

	if (status.cqe.status != 0) {
		device_printf(sc->dev, "PROPERTY_GET failed, status %#x\n",
		    le16toh(status.cqe.status));
		return (EIO);
	}

	rsp = (const struct nvmf_fabric_prop_get_rsp *)&status.cqe;
	if (size == 8)
		*value = le64toh(rsp->value.u64);
	else
		*value = le32toh(rsp->value.u32.low);
	return (0);
}

static int
nvmf_write_property(struct nvmf_softc *sc, uint32_t offset, uint8_t size,
    uint64_t value)
{
	struct nvmf_completion_status status;

	status.done = false;
	nvmf_cmd_set_property(sc, offset, size, value, nvmf_complete, &status,
	    M_WAITOK);
	nvmf_wait_for_reply(&status);

	if (status.cqe.status != 0) {
		device_printf(sc->dev, "PROPERTY_SET failed, status %#x\n",
		    le16toh(status.cqe.status));
		return (EIO);
	}
	return (0);
}

static void
nvmf_shutdown_controller(struct nvmf_softc *sc)
{
	uint64_t cc;
	int error;

	error = nvmf_read_property(sc, NVMF_PROP_CC, 4, &cc);
	if (error != 0) {
		device_printf(sc->dev, "Failed to fetch CC for shutdown\n");
		return;
	}

	cc |= NVME_SHN_NORMAL << NVME_CC_REG_SHN_SHIFT;

	error = nvmf_write_property(sc, NVMF_PROP_CC, 4, cc);
	if (error != 0)
		device_printf(sc->dev,
		    "Failed to set CC to trigger shutdown\n");
}

static int
nvmf_probe(device_t dev)
{
	device_set_desc(dev, "Fabrics");
	return (BUS_PROBE_DEFAULT);
}

static int
nvmf_attach(device_t dev)
{
	struct make_dev_args mda;
	struct nvmf_softc *sc = device_get_softc(dev);
	struct nvmf_ivars *ivars = device_get_ivars(dev);
	u_int i;
	int error;

	sc->dev = dev;

	/* Setup the admin queue. */
	sc->admin = nvmf_init_qp(sc, ivars->hh->trtype, &ivars->hh->admin);
	if (sc->admin == NULL) {
		device_printf(dev, "Failed to setup admin queue\n");
		goto out;
	}

	sc->io = malloc(ivars->hh->num_io_queues * sizeof(*sc->io), M_NVMF,
	    M_WAITOK | M_ZERO);
	sc->num_io_queues = ivars->hh->num_io_queues;
	for (i = 0; i < sc->num_io_queues; i++) {
		sc->io[i] = nvmf_init_qp(sc, ivars->hh->trtype,
		    &ivars->io_params[i]);
		if (sc->io[i] == NULL) {
			device_printf(dev, "Failed to setup I/O queue %u\n", i);
			goto out;
		}
	}

	make_dev_args_init(&mda);
	mda.mda_devsw = &nvmf_cdevsw;
	mda.mda_uid = UID_ROOT;
	mda.mda_gid = GID_WHEEL;
	mda.mda_mode = 0600;
	mda.mda_si_drv1 = sc;
	error = make_dev_s(&mda, &sc->cdev, "%s", device_get_nameunit(dev));
	if (error != 0) {
		sc->dev = NULL;
		goto out;
	}

out:
	for (i = 0; i < sc->num_io_queues; i++) {
		if (sc->io[i] != NULL)
			nvmf_destroy_qp(sc->io[i]);
	}
	free(sc->io, M_NVMF);
	if (sc->admin != NULL) {
		nvmf_shutdown_controller(sc);
		nvmf_destroy_qp(sc->admin);
	}
	return (error);
}

static int
nvmf_detach(device_t dev)
{
	struct nvmf_softc *sc = device_get_softc(dev);
	u_int i;

	/*
	 * Use deferred destruction to avoid deadlock with
	 * NVMF_DISCONNECT in nvmf_ioctl.
	 */
	destroy_dev_sched(sc->cdev);

	for (i = 0; i < sc->num_io_queues; i++) {
		nvmf_destroy_qp(sc->io[i]);
	}
	free(sc->io, M_NVMF);
	nvmf_shutdown_controller(sc);
	nvmf_destroy_qp(sc->admin);
	return (0);
}

static int
nvmf_ioctl(struct cdev *cdev, u_long cmd, caddr_t arg, int flag,
    struct thread *td)
{
	struct nvmf_softc *sc = cdev->si_drv1;
	device_t dev;
	int error;

	switch (cmd) {
	case NVMF_DISCONNECT:
		dev = sc->dev;
		bus_topo_lock();
		error = device_detach(dev);
		if (error == 0)
			device_delete_child(root_bus, dev);
		bus_topo_unlock();
		return (error);
	default:
		return (ENOTTY);
	}
}

static struct cdevsw nvmf_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl = nvmf_ioctl
};

static int
nvmf_modevent(module_t mod, int what, void *arg)
{
	switch (what) {
	case MOD_LOAD:
		return (nvmf_ctl_load());
	case MOD_QUIESCE:
		return (0);
	case MOD_UNLOAD:
		nvmf_ctl_unload();
		destroy_dev_drain(&nvmf_cdevsw);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static device_method_t nvmf_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,     nvmf_probe),
	DEVMETHOD(device_attach,    nvmf_attach),
	DEVMETHOD(device_detach,    nvmf_detach),
#if 0
	DEVMETHOD(device_suspend,   nvmf_suspend),
	DEVMETHOD(device_resume,    nvmf_resume),
	DEVMETHOD(device_shutdown,  nvmf_shutdown),
#endif
	DEVMETHOD_END
};

static driver_t nvme_nvmf_driver = {
	"nvme",
	nvmf_methods,
	sizeof(struct nvmf_softc),
};

DRIVER_MODULE(nvme, root, nvme_nvmf_driver, nvmf_modevent, NULL);
MODULE_DEPEND(nvme, nvmf_transport, 1, 1, 1);
