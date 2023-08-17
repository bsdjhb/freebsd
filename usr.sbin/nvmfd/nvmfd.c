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

#include <sys/event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <libnvmf.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

bool data_digests = false;
bool header_digests = false;
bool flow_control_disable = false;

static const char *subnqn;

static void
usage(void)
{
	fprintf(stderr, "nvmfd [-DFH] [-P port] [-p port] [-t transport] [-n subnqn]\n"
	    "\tdevice [device [...]]\n"
	    "\n"
	    "Devices use one of the following syntaxes:\n"
	    "\tpathame      - file or disk device\n"
	    "\tramdisk:size - memory disk of given size\n");
	exit(1);
}

static void
register_listen_socket(int kqfd, int s, void *udata)
{
	struct kevent kev;

	if (listen(s, -1) != 0)
		err(1, "listen");

	EV_SET(&kev, s, EVFILT_READ, EV_ADD, 0, 0, udata);
	if (kevent(kqfd, &kev, 1, NULL, 0, NULL) == -1)
		err(1, "kevent: failed to add listen socket");
}

static void
create_passive_sockets(int kqfd, const char *port, bool discovery)
{
	struct addrinfo hints, *ai, *list;
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

		if (discovery) {
			register_listen_socket(kqfd, s, (void *)1);
		} else {
			register_listen_socket(kqfd, s, (void *)2);
			discovery_add_io_controller(s, subnqn);
		}
		created = true;
	}

	freeaddrinfo(list);
	if (!created)
		err(1, "Failed to create any listen sockets");
}

static void
handle_connections(int kqfd)
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

		switch ((uintptr_t)ev.udata) {
		case 1:
			handle_discovery_socket(s);
			break;
		case 2:
			handle_io_socket(s);
			break;
		default:
			__builtin_unreachable();
		}
	}
}

int
main(int ac, char **av)
{
	const char *dport, *ioport, *transport;
	int ch, error, kqfd;
	static char nqn[NVMF_NQN_MAX_LEN];

	/* 7.4.9.3 Default port for discovery */
	dport = "8009";

	ioport = "0";
	subnqn = NULL;
	transport = "tcp";
	while ((ch = getopt(ac, av, "DFHn:P:p:t:")) != -1) {
		switch (ch) {
		case 'D':
			data_digests = true;
			break;
		case 'F':
			flow_control_disable = true;
			break;
		case 'H':
			header_digests = true;
			break;
		case 'n':
			subnqn = optarg;
			break;
		case 'P':
			dport = optarg;
			break;
		case 'p':
			ioport = optarg;
			break;
		case 't':
			transport = optarg;
			break;
		default:
			usage();
		}
	}

	av += optind;
	ac -= optind;

	if (ac < 1)
		usage();

	if (strcasecmp(transport, "tcp") == 0) {
	} else
		errx(1, "Invalid transport %s", transport);

	if (subnqn == NULL) {
		error = nvmf_nqn_from_hostuuid(nqn);
		if (error != 0)
			errc(1, error, "Failed to generate NQN");
		subnqn = nqn;
	}

	register_devices(ac, av);

	init_discovery();
	init_io(subnqn);

	kqfd = kqueue();
	if (kqfd == -1)
		err(1, "kqueue");

	create_passive_sockets(kqfd, dport, true);
	create_passive_sockets(kqfd, ioport, false);

	handle_connections(kqfd);
	return (0);
}
