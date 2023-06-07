/*-
 * Copyright (c) 2022 Chelsio Communications, Inc.
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

#ifndef __NVMF_H__
#define	__NVMF_H__

#include <sys/ioccom.h>
#ifndef _KERNEL
#include <stdbool.h>
#endif

struct nvmf_handoff_qpair_params {
	bool admin;
	bool sq_flow_control;
	uint16_t qsize;
	uint16_t sqhd;
	uint16_t sqtail;	/* host only */
	union {
		struct {
			int	fd;
			uint8_t	rxpda;
			uint8_t txpda;
			bool	header_digests;
			bool	data_digests;
			uint32_t maxr2t;
			uint32_t maxh2cdata;
			uint32_t max_icd;
		} tcp;
	};
};

struct nvmf_handoff_host {
	u_int	trtype;
	u_int	num_io_queues;
	u_int	kato;
	struct nvmf_handoff_qpair_params admin;
	struct nvmf_handoff_qpair_params *io;
	const struct nvme_controller_data *cdata;
};

/* Operations on /dev/nvmf */
#define	NVMF_HANDOFF_HOST	_IOW('n', 200, struct nvmf_handoff_host)

/* nvmf-specific operations on /dev/nvmeX */
#define	NVMF_DISCONNECT		_IO('n', 201)

#endif /* !__NVMF_H__ */
