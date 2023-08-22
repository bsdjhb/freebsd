/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#ifndef __DDP_TEST_H__
#define	__DDP_TEST_H__

#include <sys/ioccom.h>

#define	DDP_TEST_SINK	_IOW('D', 100, int)
#define	DDP_TEST_ECHO	_IOW('D', 101, int)

#endif /* !__DDP_TEST_H__ */
