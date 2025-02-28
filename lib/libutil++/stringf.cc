/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#include "libutil++"

std::string
freebsd::stringf(const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	vasprintf(&str, fmt, ap);
	va_end(ap);
	if (str == NULL)
		throw std::bad_alloc();

	std::string res(str);
	free(str);
	return res;
}
