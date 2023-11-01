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

#include <sys/param.h>
#include <sys/dnv.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/sx.h>

#include <dev/nvmf/nvmf.h>
#include <dev/nvmf/nvmf_transport.h>
#include <dev/nvmf/controller/nvmft_var.h>

#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl_frontend.h>

static int	nvmft_init(void);
static int	nvmft_ioctl(struct cdev *cdev, u_long cmd, caddr_t data,
    int flag, struct thread *td);
static int	nvmft_shutdown(void);

static TAILQ_HEAD(, nvmft_port) nvmft_ports;
static struct sx nvmft_ports_lock;

MALLOC_DEFINE(M_NVMFT, "nvmft", "NVMe over Fabrics controller");

static struct ctl_frontend nvmft_frontend = {
	.name = "nvmf",
	.init = nvmft_init,
	.ioctl = nvmft_ioctl,
	.fe_dump = NULL,
	.shutdown = nvmft_shutdown,
};

static void
nvmft_online(void *arg)
{
	struct nvmft_port *np = arg;

	/* Likely nothing to do here, probably remove this eventually. */
	printf("%s(%p)\n", __func__, np);
}

static void
nvmft_offline(void *arg)
{
	struct nvmft_port *np = arg;

	/* TODO: Shutdown existing controllers. */
	printf("%s(%p)\n", __func__, np);
}

static int
nvmft_lun_enable(void *arg, int lun_id)
{
	struct nvmft_port *np = arg;
	u_int *old_luns, *new_luns;
	u_int i;

	sx_xlock(&np->lock);
	new_luns = mallocarray(np->num_luns + 1, sizeof(*new_luns), M_NVMFT,
	    M_WAITOK);
	for (i = 0; i < np->num_luns; i++) {
		if (np->luns[i] < lun_id)
			continue;
		if (np->luns[i] == lun_id) {
			sx_xunlock(&np->lock);
			free(new_luns, M_NVMFT);
			printf("NVMFT: %s duplicate lun %d\n",
			    np->cdata.subnqn, lun_id);
			return (EINVAL);
		}
		break;
	}

	/* Copy over luns smaller than lun_id. */
	memcpy(new_luns, np->luns, i * sizeof(*np->luns));

	/* Insert lun_id. */
	new_luns[i] = lun_id;

	/* Copy over luns greater than lun_id. */
	memcpy(new_luns + i + 1, np->luns + i, (np->num_luns - i) *
	    sizeof(*np->luns));

	np->num_luns++;
	old_luns = np->luns;
	np->luns = new_luns;

	/* TODO: Notify existing controllers. */

	sx_xunlock(&np->lock);
	free(old_luns, M_NVMFT);

	return (0);
}

static int
nvmft_lun_disable(void *arg, int lun_id)
{
	struct nvmft_port *np = arg;
	u_int i;

	sx_xlock(&np->lock);
	for (i = 0; i < np->num_luns; i++) {
		if (np->luns[i] == lun_id)
			goto found;
	}
	sx_xunlock(&np->lock);
	printf("NVMFT: %s request to disable nonexistent lun %d\n",
	    np->cdata.subnqn, lun_id);
	return (EINVAL);

found:
	/* Move down luns greater than lun_id. */
	memmove(np->luns + i, np->luns + i + 1, (np->num_luns - (i + 1)) *
	    sizeof(*np->luns));
	np->num_luns--;

	/* NB: Don't bother freeing the old luns array. */

	/* TODO: Notify existing controllers. */

	sx_xunlock(&np->lock);

	return (0);
}

static void
nvmft_datamove(union ctl_io *io)
{
	/*
	 * TODO: Get nvmf_capsule pointer from CTL_PRIV_FRONTEND and
	 * use it to send/receive controller data.
	 */
	printf("%s(%p)\n", __func__, io);
}

static void
nvmft_done(union ctl_io *io)
{
	/*
	 * TODO: Get nvmf_capsule pointer and qp from CTL_PRIV_FRONTEND and
	 * send response (either success or CQE from nvmeio.cpl).
	 */
	printf("%s(%p)\n", __func__, io);
	ctl_free_io(io);
}

static int
nvmft_init(void)
{
	TAILQ_INIT(&nvmft_ports);
	sx_init(&nvmft_ports_lock, "nvmft ports");
	return (0);
}

void
nvmft_port_free(struct nvmft_port *np)
{
	KASSERT(TAILQ_EMPTY(&np->controllers),
	    ("%s(%p): active controllers", __func__, np));
	free(np->luns, M_NVMFT);
	clean_unrhdr(np->ids);
	delete_unrhdr(np->ids);
	sx_destroy(&np->lock);
	free(np, M_NVMFT);
}

static struct nvmft_port *
nvmft_port_find(const char *subnqn)
{
	struct nvmft_port *np;

	KASSERT(nvmf_nqn_valid(subnqn), ("%s: invalid nqn", __func__));

	sx_assert(&nvmft_ports_lock, SA_LOCKED);
	TAILQ_FOREACH(np, &nvmft_ports, link) {
		if (strcmp(np->cdata.subnqn, subnqn) == 0)
			break;
	}
	return (np);
}

/*
 * Helper function to fetch a number stored as a string in an nv_list.
 * Returns false if the string was not a valid number.
 */
static bool
dnvlist_get_strnum(nvlist_t *nvl, const char *name, u_long default_value,
	u_long *value)
{
	const char *str;
	char *cp;

	str = dnvlist_get_string(nvl, name, NULL);
	if (str == NULL) {
		*value = default_value;
		return (true);
	}
	if (*str == '\0')
		return (false);
	*value = strtoul(str, &cp, 0);
	if (*cp != '\0')
		return (false);
	return (true);
}

/*
 * NVMeoF ports support the following parameters:
 *
 * Mandatory:
 *
 * subnqn: subsystem NVMe Qualified Name
 * portid: integer port ID from Discovery Log Page entry
 *
 * Optional:
 * serial: Serial Number string
 * max_io_qsize: Maximum number of I/O queue entries
 * enable_timeout: Timeout for controller enable in milliseconds
 * ioccsz: Maximum command capsule size
 * iorcsz: Maximum response capsule size
 * nn: Number of namespaces
 */
static void
nvmft_port_create(struct ctl_req *req)
{
	struct nvmft_port *np;
	struct ctl_port *port;
	const char *serial, *subnqn;
	char serial_buf[NVME_SERIAL_NUMBER_LENGTH];
	u_long enable_timeout, hostid, ioccsz, iorcsz, max_io_qsize, nn, portid;
	int error;

	/* Required parameters. */
	subnqn = dnvlist_get_string(req->args_nvl, "subnqn", NULL);
	if (subnqn == NULL || !nvlist_exists_string(req->args_nvl, "portid")) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Missing required argument");
		return;
	}
	if (!nvmf_nqn_valid(subnqn)) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Invalid SubNQN");
		return;
	}
	if (!dnvlist_get_strnum(req->args_nvl, "portid", UINT16_MAX, &portid) ||
	    portid > UINT16_MAX) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Invalid port ID");
		return;
	}

	/* Optional parameters. */
	if (!dnvlist_get_strnum(req->args_nvl, "max_io_qsize",
	    NVMF_MAX_IO_ENTRIES, &max_io_qsize) ||
	    max_io_qsize < NVME_MIN_IO_ENTRIES ||
	    max_io_qsize > NVME_MAX_IO_ENTRIES) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Invalid maximum I/O queue size");
		return;
	}

	if (!dnvlist_get_strnum(req->args_nvl, "enable_timeout",
	    NVMF_CC_EN_TIMEOUT * 500, &enable_timeout) ||
	    (enable_timeout % 500) != 0 || (enable_timeout / 500) > 255) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Invalid enable timeout");
		return;
	}

	if (!dnvlist_get_strnum(req->args_nvl, "ioccsz", NVMF_IOCCSZ,
	    &ioccsz) || ioccsz < sizeof(struct nvme_command) ||
	    (ioccsz % 16) != 0) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Invalid Command Capsule size");
		return;
	}

	if (!dnvlist_get_strnum(req->args_nvl, "iorcsz", NVMF_IORCSZ,
	    &iorcsz) || iorcsz < sizeof(struct nvme_completion) ||
	    (iorcsz % 16) != 0) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Invalid Response Capsule size");
		return;
	}

	if (!dnvlist_get_strnum(req->args_nvl, "nn", NVMF_NN, &nn) ||
	    nn < 1 || nn > UINT32_MAX) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Invalid number of namespaces");
		return;
	}

	serial = dnvlist_get_string(req->args_nvl, "serial", NULL);
	if (serial == NULL) {
		getcredhostid(curthread->td_ucred, &hostid);
		nvmf_controller_serial(serial_buf, sizeof(serial_buf), hostid);
		serial = serial_buf;
	}

	sx_xlock(&nvmft_ports_lock);

	np = nvmft_port_find(subnqn);
	if (np != NULL) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "SubNQN \"%s\" already exists", subnqn);
		sx_xunlock(&nvmft_ports_lock);
		return;
	}

	np = malloc(sizeof(*np), M_NVMFT, M_WAITOK | M_ZERO);
	refcount_init(&np->refs, 1);
	np->max_io_qsize = max_io_qsize;
	np->cap = nvmf_controller_cap(max_io_qsize, enable_timeout / 500);
	sx_init(&np->lock, "nvmft port");
	np->ids = new_unrhdr(0, NVMF_CNTLID_STATIC_MAX, UNR_NO_MTX);
	TAILQ_INIT(&np->controllers);

	/* The controller ID is set later for individual controllers. */
	nvmf_init_io_controller_data(0, max_io_qsize, serial, ostype, osrelease,
	    subnqn, nn, ioccsz, iorcsz, &np->cdata);

	port = &np->port;

	port->frontend = &nvmft_frontend;
	port->port_type = CTL_PORT_NVMF;
	port->num_requested_ctl_io = max_io_qsize;
	port->port_name = "nvmf";
	port->physical_port = portid;
	port->virtual_port = 0;
	port->port_online = nvmft_online;
	port->port_offline = nvmft_offline;
#ifdef notyet
	port->port_info = nvmft_info;
#endif
	port->onoff_arg = np;
	port->lun_enable = nvmft_lun_enable;
	port->lun_disable = nvmft_lun_disable;
	port->targ_lun_arg = np;
	port->fe_datamove = nvmft_datamove;
	port->fe_done = nvmft_done;
	port->targ_port = -1;
	port->options = nvlist_clone(req->args_nvl);

	error = ctl_port_register(port);
	if (error != 0) {
		sx_xunlock(&nvmft_ports_lock);
		nvlist_destroy(port->options);
		nvmft_port_rele(np);
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Failed to register CTL port with error %d", error);
		return;
	}

	TAILQ_INSERT_TAIL(&nvmft_ports, np, link);
	sx_xunlock(&nvmft_ports_lock);
	
	req->status = CTL_LUN_OK;
	req->result_nvl = nvlist_create(0);
	nvlist_add_number(req->result_nvl, "port_id", port->targ_port);
}

static void
nvmft_port_remove(struct ctl_req *req)
{
	struct nvmft_port *np;
	const char *subnqn;

	/* Required parameters. */
	subnqn = dnvlist_get_string(req->args_nvl, "subnqn", NULL);
	if (subnqn == NULL) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "Missing required argument");
		return;
	}

	sx_xlock(&nvmft_ports_lock);

	np = nvmft_port_find(subnqn);
	if (np == NULL) {
		req->status = CTL_LUN_ERROR;
		snprintf(req->error_str, sizeof(req->error_str),
		    "SubNQN \"%s\" does not exist", subnqn);
		sx_xunlock(&nvmft_ports_lock);
		return;
	}

	TAILQ_REMOVE(&nvmft_ports, np, link);
	sx_xunlock(&nvmft_ports_lock);

	ctl_port_offline(&np->port);
	nvmft_port_rele(np);
	req->status = CTL_LUN_OK;
}

static void
nvmft_handoff(struct ctl_nvmf *cn)
{
	struct nvmf_fabric_connect_cmd cmd;
	struct nvmf_handoff_controller_qpair *handoff;
	struct nvmf_fabric_connect_data *data;
	struct nvmft_port *np;
	int error;

	np = NULL;
	data = NULL;
	handoff = &cn->data.handoff;
	error = copyin(handoff->cmd, &cmd, sizeof(cmd));
	if (error != 0) {
		cn->status = CTL_NVMF_ERROR;
		snprintf(cn->error_str, sizeof(cn->error_str),
		    "Failed to copyin CONNECT SQE");
		return;
	}

	data = malloc(sizeof(*data), M_NVMFT, M_WAITOK);
	error = copyin(handoff->data, data, sizeof(*data));
	if (error != 0) {
		cn->status = CTL_NVMF_ERROR;
		snprintf(cn->error_str, sizeof(cn->error_str),
		    "Failed to copyin CONNECT data");
		goto out;
	}

	if (!nvmf_nqn_valid(data->subnqn)) {
		cn->status = CTL_NVMF_ERROR;
		snprintf(cn->error_str, sizeof(cn->error_str),
		    "Invalid SubNQN");
		goto out;
	}
		
	sx_slock(&nvmft_ports_lock);
	np = nvmft_port_find(data->subnqn);
	if (np == NULL) {
		sx_sunlock(&nvmft_ports_lock);
		cn->status = CTL_NVMF_ERROR;
		snprintf(cn->error_str, sizeof(cn->error_str),
		    "Unknown SubNQN");
		goto out;
	}
	nvmft_port_ref(np);
	sx_sunlock(&nvmft_ports_lock);

	if (handoff->params.admin) {
		error = nvmft_handoff_admin_queue(np, handoff, &cmd, data);
		if (error != 0) {
			cn->status = CTL_NVMF_ERROR;
			snprintf(cn->error_str, sizeof(cn->error_str),
			    "Failed to handoff admin queue: %d", error);
			goto out;
		}
	} else {
		error = nvmft_handoff_io_queue(np, handoff, &cmd, data);
		if (error != 0) {
			cn->status = CTL_NVMF_ERROR;
			snprintf(cn->error_str, sizeof(cn->error_str),
			    "Failed to handoff admin queue: %d", error);
			goto out;
		}
	}

	cn->status = CTL_NVMF_OK;
out:
	if (np != NULL)
		nvmft_port_rele(np);
	free(data, M_NVMFT);
}

static int
nvmft_ioctl(struct cdev *cdev, u_long cmd, caddr_t data, int flag,
    struct thread *td)
{
	struct ctl_nvmf *cn;
	struct ctl_req *req;

	switch (cmd) {
	case CTL_PORT_REQ:
		req = (struct ctl_req *)data;
		switch (req->reqtype) {
		case CTL_REQ_CREATE:
			nvmft_port_create(req);
			break;
		case CTL_REQ_REMOVE:
			nvmft_port_remove(req);
			break;
		default:
			req->status = CTL_LUN_ERROR;
			snprintf(req->error_str, sizeof(req->error_str),
			    "Unsupported request type %d", req->reqtype);
			break;
		}
		return (0);
	case CTL_NVMF:
		cn = (struct ctl_nvmf *)data;
		switch (cn->type) {
		case CTL_NVMF_HANDOFF:
			nvmft_handoff(cn);
			break;
		default:
			cn->status = CTL_NVMF_ERROR;
			snprintf(cn->error_str, sizeof(cn->error_str),
			    "Invalid NVMeoF request type %d", cn->type);
			break;
		}
		return (0);
	default:
		return (ENOTTY);
	}
}

static int
nvmft_shutdown(void)
{
	/* TODO: Need to check for active controllers. */
	if (!TAILQ_EMPTY(&nvmft_ports))
		return (EBUSY);

	sx_destroy(&nvmft_ports_lock);
	return (0);
}

CTL_FRONTEND_DECLARE(nvmft, nvmft_frontend);
MODULE_DEPEND(nvmft, nvmf_transport, 1, 1, 1);
