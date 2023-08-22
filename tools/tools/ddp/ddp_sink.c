/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "ddp_test.h"

static void
usage(void)
{
	fprintf(stderr, "ddp_sink <port>\n");
	exit(1);
}

static void
create_passive_sockets(int kqfd, const char *port)
{
	struct addrinfo hints, *ai, *list;
	struct kevent kev;
	bool created;
	int error, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(NULL, port, &hints, &list);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));
	created = false;

	for (ai = list; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			continue;

		if (bind(s, ai->ai_addr, ai->ai_addrlen) != 0) {
			close(s);
			continue;
		}

		if (listen(s, -1) != 0) {
			close(s);
			continue;
		}

		EV_SET(&kev, s, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(kqfd, &kev, 1, NULL, 0, NULL) == -1)
			err(1, "kevent: failed to add listen socket");
		created = true;
	}

	freeaddrinfo(list);
	if (!created)
		err(1, "Failed to create any listen sockets");
}

static void
handle_connections(int kqfd, int fd)
{
	struct kevent ev;
	int s;

	for (;;) {
		if (kevent(kqfd, NULL, 0, &ev, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent");
		}

		assert(ev.filter == EVFILT_READ);

		s = accept(ev.ident, NULL, NULL);
		if (s == -1) {
			warn("accept");
			continue;
		}

		if (ioctl(fd, DDP_TEST_SINK, &s) == -1)
			warn("ioctl(DDP_TEST_SINK)");

		close(s);
	}
}

int
main(int ac, char **av)
{
	int fd, kq;

	if (ac != 2)
		usage();

	fd = open("/dev/ddp_test", O_RDONLY);
	if (fd == -1)
		err(1, "open(/dev/ddp_test)");

	kq = kqueue();
	if (kq == -1)
		err(1, "kqueue");

	create_passive_sockets(kq, av[1]);
	handle_connections(kq, fd);
	return (0);
}
