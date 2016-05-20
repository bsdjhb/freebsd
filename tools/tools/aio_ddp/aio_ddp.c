/*-
 * Copyright (c) 2014-2016 Chelsio Communications, Inc.
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

/*
 * A simple test program for TCP TOE DDP.  This functions like a simple
 * telnet client accepting line buffered input and sending it to a remote
 * echo server.  It expects to get the same output back before accepting
 * the next line of input.  Uses blocking I/O and TCP_NODELAY.
 */

#define _WITH_GETLINE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <aio.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc_np.h>
#include <netdb.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr, "Usage: aio_ddp [-ABFNw] [-b burst] [-c count] "
	    "[-s size] [-S size] <host> [port]\n");
	exit(1);
}

static int
opensock(const char *host, const char *port, int rcv_size)
{
	struct addrinfo hints, *res, *res0;
	int error, optval, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));
	s = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0)
			continue;
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
			close(s);
			s = -1;
			continue;
		}
		break;
	}
	if (s < 0)
		err(1, "Failed to connect");
	freeaddrinfo(res0);

	/* Set TCP_NODELAY */
	optval = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval))
	    < 0)
		err(1, "setsockopt(TCP_NODELAY)");

	/* Set SO_RCVBUF. */
	if (rcv_size > 0) {
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcv_size,
		    sizeof(rcv_size)) < 0)
			err(1, "setsockopt(SO_RCVBUF)");
	}
	return (s);
}

static void
check_for_toe(int s)
{
	struct tcp_info info;
	socklen_t len;

	len = sizeof(info);
	if (getsockopt(s, IPPROTO_TCP, TCP_INFO, &info, &len) < 0)
		err(1, "getsockopt(TCP_INFO)");
	if (info.tcpi_options & TCPI_OPT_TOE)
		printf("Using TOE\n");
}

static struct aiocb *
alloc_aio_requests(int count, int size)
{
	struct aiocb *req;
	int i;

	req = calloc(count, sizeof(*req));
	if (req == NULL)
		err(1, "Failed to allocate AIO requests");
	for (i = 0; i < count; i++) {
		req[i].aio_buf = malloc(size);
		if (req[i].aio_buf == NULL)
			err(1, "Failed to allocate AIO requests");
	}
	return (req);
}

static void
aio_queue_request(struct aiocb *req, int s, int size)
{

	req->aio_nbytes = size;
	req->aio_fildes = s;
	req->aio_offset = 0;
	if (aio_read(req) == -1)
		err(1, "aio_read");
}

static void
aio_queue_all_requests(struct aiocb *req, int s, int count, int size)
{

	while (count > 0) {
		aio_queue_request(req, s, size);
		req++;
		count--;
	}
}

static void
read_aio(int s, const char *data, size_t len, int size)
{
	struct aiocb *req;
	ssize_t nread;

	while (len > 0) {
		nread = aio_waitcomplete(&req, NULL);
		if (nread < 0)
			err(1, "aio_waitcomplete");
		if ((size_t)nread > len)
			errx(1, "long aio read: %zd vs %zu", nread, len);
		if (memcmp(__DEVOLATILE(void *, req->aio_buf), data, nread) !=
		    0)
			errx(1, "aio data mismatch");
		aio_queue_request(req, s, size);
		data += nread;
		len -= nread;
	}
	printf("Received AIO data matched\n");
}

static void
read_plain(int s, const char *data, size_t len)
{
	static char *buf;
	static size_t buflen;
	struct pollfd pfd[1];
	ssize_t nread;

	if (buflen < len) {
		buf = realloc(buf, len);
		if (buf == NULL)
			err(1, "realloc");
		buflen = malloc_usable_size(buf);
	}

	while (len > 0) {
		nread = read(s, buf, buflen);
		if (nread < 0) {
			if (errno == EAGAIN) {
				pfd[0].fd = s;
				pfd[0].events = POLLIN;
				pfd[0].revents = 0;
				if (poll(pfd, 1, INFTIM) == -1)
					err(1, "poll");
				continue;
			}
			err(1, "socket read");
		}
		if (nread == 0)
			errx(1, "socket EOF");
		if ((size_t)nread > len)
			errx(1, "long read: %zd vs %zu", nread, len);
		if (memcmp(data, buf, nread) != 0)
			errx(1, "data mismatch");
		data += nread;
		len -= nread;
	}
	printf("Received data matched\n");
}

static ssize_t
write_aio(int s, char *data, size_t len)
{
	const struct aiocb *reqs[1];
	struct aiocb req;

	memset(&req, 0, sizeof(req));
	req.aio_nbytes = len;
	req.aio_buf = data;
	req.aio_fildes = s;
	if (aio_write(&req) == -1)
		err(1, "aio_write");
	reqs[0] = &req;
	if (aio_suspend(reqs, 1, NULL) == -1)
		err(1, "aio_suspend");
	return (aio_return(&req));
}

static char *
build_burst(int len)
{
	char *buf;
	int c, i;

	if (len <= 0)
		err(1, "Invalid burst length");
	buf = malloc(len);
	c = 0;
	for (i = 0; i < len; i++) {
		while (!isprint(c)) {
			c++;
			if (c == 128)
				c = 0;
		}
		buf[i] = c;
	}
	return (buf);
}

static void
set_nonblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		err(1, "fcntl(F_GETFL)");
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fcntl(F_SETFL)");
}

int
main(int ac, char **av)
{
	struct aiocb *req;
	char *line;
	size_t linecap;
	ssize_t linelen, nwritten;
	bool aio, aio_active, aio_tx, force_fin, nonblock, wait;
	int ch, burst, count, rcv_size, s, size;

	burst = 0;
	count = 2;
	rcv_size = 0;
	size = 64 * 1024;
	force_fin = false;
	wait = false;
	aio = false;
	aio_active = false;
	aio_tx = false;
	nonblock = false;
	while ((ch = getopt(ac, av, "ABb:c:FNS:s:w")) != -1)
		switch (ch) {
		case 'A':
			aio = true;
			break;
		case 'B':
			aio_tx = true;
			break;
		case 'b':
			burst = atoi(optarg);
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 'F':
			force_fin = true;
			break;
		case 'N':
			nonblock = true;
			break;
		case 'S':
			rcv_size = atoi(optarg);
			break;
		case 's':
			size = atoi(optarg);
			break;
		case 'w':
			wait = true;
			break;
		default:
			usage();
		}
	ac -= optind;
	av += optind;

	if (ac < 1 || ac > 2)
		usage();
	s = opensock(av[0], ac == 2 ? av[1] : "echo", rcv_size);
	if (nonblock)
		set_nonblocking(s);
	check_for_toe(s);
	if (aio) {
		req = alloc_aio_requests(count, size);
		if (!wait) {
			aio_queue_all_requests(req, s, count, size);
			aio_active = true;
		}
	} else
		req = NULL;

	line = NULL;
	linecap = 0;
	for (;;) {
		if (burst) {
			line = build_burst(burst);
			linelen = burst;
			linecap = burst;
		} else {
			linelen = getline(&line, &linecap, stdin);
			if (linelen < 0) {
				if (feof(stdin))
					break;
				errx(1, "stdin returned an error");
			}
			if (linelen == 0)
				errx(1, "zero-length line");
		}
		if (aio_tx)
			nwritten = write_aio(s, line, linelen);
		else
			nwritten = write(s, line, linelen);
		if (nwritten < 0)
			err(1, "socket write");
		if (nwritten != linelen)
			errx(1, "short write: %zd of %zd", nwritten, linelen);
		if (force_fin) {
			if (shutdown(s, SHUT_WR) < 0)
				err(1, "shutdown(SHUT_WR)");
		}
		if (aio && !aio_active) {
			aio_queue_all_requests(req, s, count, size);
			aio_active = true;
		}
		if (aio_active)
			read_aio(s, line, linelen, size);
		else
			read_plain(s, line, linelen);
		if (burst)
			burst = 0;
		if (force_fin)
			break;
	}
	close(s);
	return (0);
}
