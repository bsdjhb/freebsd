/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/refcount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "ddp_test.h"

static struct cdev *ddp_test_cdev;
static volatile u_int ddp_sockets;

static void
sink_thread(void *arg)
{
	struct socket *so = arg;
	struct uio uio;
	struct mbuf *m;
	int error, flags;

	for (;;) {
		SOCK_RECVBUF_LOCK(so);
		while (!soreadable(so))
			(void)sbwait(so, SO_RCV);
		uio.uio_resid = sbavail(&so->so_rcv);

		if (uio.uio_resid == 0 &&
		    (so->so_rcv.sb_state & SBS_CANTRCVMORE) != 0) {
			SOCK_RECVBUF_UNLOCK(so);
			break;
		}
		SOCK_RECVBUF_UNLOCK(so);

		m = NULL;
		flags = MSG_DONTWAIT;
		error = soreceive(so, NULL, &uio, &m, NULL, &flags);
		if (error != 0) {
			printf("ddp_test: soreceive failed with %d\n", error);
			break;
		}

		m_freem(m);
	}

	soclose(so);
	refcount_release(&ddp_sockets);

	kthread_exit();
}

static void
echo_thread(void *arg)
{
	struct socket *so = arg;
	struct uio uio;
	struct mbuf *m;
	int error, flags;

	memset(&uio, 0, sizeof(uio));
	for (;;) {
		SOCK_RECVBUF_LOCK(so);
		while (!soreadable(so))
			(void)sbwait(so, SO_RCV);
		uio.uio_resid = sbavail(&so->so_rcv);

		if (uio.uio_resid == 0 &&
		    (so->so_rcv.sb_state & SBS_CANTRCVMORE) != 0) {
			SOCK_RECVBUF_UNLOCK(so);
			break;
		}
		SOCK_RECVBUF_UNLOCK(so);

		m = NULL;
		flags = MSG_DONTWAIT;
		error = soreceive(so, NULL, &uio, &m, NULL, &flags);
		if (error != 0) {
			printf("ddp_test: soreceive failed with %d\n", error);
			break;
		}

		error = sosend(so, NULL, NULL, m, NULL, 0, NULL);
		if (error != 0) {
			printf("ddp_test: sosend failed with %d\n", error);
			break;
		}
	}

	soclose(so);
	refcount_release(&ddp_sockets);

	kthread_exit();
}

static int
add_thread(int fd, void (*func)(void *), const char *name)
{
	struct file *fp;
	struct socket *so;
	cap_rights_t rights;
	int error;

	error = fget(curthread, fd, cap_rights_init_one(&rights,
	    CAP_SOCK_CLIENT), &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_SOCKET) {
		fdrop(fp, curthread);
		return (EINVAL);
	}
	so = fp->f_data;
	if (so->so_type != SOCK_STREAM ||
	    so->so_proto->pr_protocol != IPPROTO_TCP) {
		fdrop(fp, curthread);
		return (EPROTONOSUPPORT);
	}

	if (!refcount_acquire_checked(&ddp_sockets))
		return (EBUSY);

	/* Claim socket from file descriptor. */
	fp->f_ops = &badfileops;
	fp->f_data = NULL;
	fdrop(fp, curthread);

	error = kthread_add(func, so, NULL, NULL, 0, 0, "%s", name);
	if (error != 0) {
		soclose(so);
		refcount_release(&ddp_sockets);
	}

	return (error);
}

static int
ddp_test_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	switch (cmd) {
	case DDP_TEST_SINK:
		return (add_thread(*(int *)data, sink_thread, "ddp sink"));
	case DDP_TEST_ECHO:
		return (add_thread(*(int *)data, echo_thread, "ddp echo"));
	default:
		return (ENOTTY);
	}
}

static struct cdevsw ddp_test_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "ddp_test",
	.d_ioctl = ddp_test_ioctl
};

static int
ddp_test_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		ddp_test_cdev = make_dev(&ddp_test_cdevsw, 0, UID_ROOT,
		    GID_WHEEL, 0600, "ddp_test");
		if (ddp_test_cdev == NULL)
			return (ENXIO);
		break;
	case MOD_QUIESCE:
		if (ddp_sockets != 0)
			return (EBUSY);
		break;
	case MOD_UNLOAD:
		if (ddp_test_cdev != NULL) {
			destroy_dev(ddp_test_cdev);
			ddp_test_cdev = NULL;
		}
		if (ddp_sockets != 0)
			return (EBUSY);
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

DEV_MODULE(ddp_test, ddp_test_modevent, NULL);
MODULE_VERSION(ddp_test, 1);
