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

#ifndef __NVMFT_SUBR_H__
#define	__NVMFT_SUBR_H__

/*
 * Lower-level controller-specific routines shared between the kernel
 * and userland.
 */

/* Validate a NVMe Qualified Name. */
bool	nvmf_nqn_valid(const char *nqn);

/* Compute the initial state of CAP for a controller. */
uint64_t _nvmf_controller_cap(uint32_t max_io_qsize, uint8_t enable_timeout);

/*
 * Validate if a new value for CC is legal given the existing values of
 * CAP and CC.
 */
bool	_nvmf_validate_cc(uint32_t max_io_qsize, uint64_t cap, uint32_t old_cc,
    uint32_t new_cc);

/* Generate a serial number string from a host ID. */
void	nvmf_controller_serial(char *buf, size_t len, u_long hostid);

/*
 * Copy an ASCII string into the destination buffer but pad the end of
 * the buffer with spaces and no terminating nul.
 */
void	nvmf_strpad(char *dst, const char *src, size_t len);

/*
 * Populate an Identify Controller data structure for an I/O
 * controller.
 */
void	_nvmf_init_io_controller_data(uint16_t cntlid, uint32_t max_io_qsize,
    const char *serial, const char *model, const char *firmware_version,
    const char *subnqn, int nn, uint32_t ioccsz, uint32_t iorcsz,
    struct nvme_controller_data *cdata);

#endif	/* !__NVMFT_SUBR_H__ */
