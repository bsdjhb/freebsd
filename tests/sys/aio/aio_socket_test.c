/*-
 * Copyright (c) 2015 John H. Baldwin <jhb@FreeBSD.org>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/socket.h>
#include <aio.h>

#include <atf-c.h>

#include "freebsd_test_suite/macros.h"

/*
 * This tests for a bug where arriving socket data can wakeup multiple
 * AIO read requests resulting in an uncancellable request.
 */
ATF_TC_WITHOUT_HEAD(aio_socket_two_reads);
ATF_TC_BODY(aio_socket_two_reads, tc)
{
	struct ioreq {
		struct aiocb iocb;
		char buffer[1024];
	} ioreq[2];
	struct aiocb *iocb;
	unsigned i;
	int s[2];
	char c;

	ATF_REQUIRE_KERNEL_MODULE("aio");

	ATF_REQUIRE(socketpair(PF_UNIX, SOCK_STREAM, 0, s) != -1);

	/* Queue two read requests. */
	memset(&ioreq, 0, sizeof(ioreq));
	for (i = 0; i < nitems(ioreq); i++) {
		ioreq[i].iocb.aio_nbytes = sizeof(ioreq[i].buffer);
		ioreq[i].iocb.aio_fildes = s[0];
		ioreq[i].iocb.aio_buf = ioreq[i].buffer;
		ATF_REQUIRE(aio_read(&ioreq[i].iocb) == 0);
	}

	/* Send a single byte.  This should complete one request. */
	c = 0xc3;
	ATF_REQUIRE(write(s[1], &c, sizeof(c)) == 1);

	ATF_REQUIRE(aio_waitcomplete(&iocb, NULL) == 1);

	/* Determine which request completed and verify the data was read. */
	if (iocb == &ioreq[0].iocb)
		i = 0;
	else
		i = 1;
	ATF_REQUIRE(ioreq[i].buffer[0] == c);

	i ^= 1;

	/*
	 * Try to cancel the other request.  On broken systems this
	 * will hang.
	 */
	ATF_REQUIRE(aio_error(&ioreq[i].iocb) == EINPROGRESS);
	ATF_REQUIRE(aio_cancel(s[0], &ioreq[i].iocb) == AIO_CANCELED);

	close(s[1]);
	close(s[0]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, aio_socket_two_reads);

	return (atf_no_error());
}
