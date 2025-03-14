/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Chelsio Communications, Inc.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 */

#include <stdarg.h>
#include <stdio.h>
#include <string>

#include "libutil++"

static int
stringf_write(void *cookie, const char *buf, int len)
{
	std::string *str = reinterpret_cast<std::string *>(cookie);
	try {
		str->append(buf, len);
	} catch (std::bad_alloc) {
		errno = ENOMEM;
		return (-1);
	} catch (std::length_error) {
		errno = EFBIG;
		return (-1);
	}
	return (len);
}

std::string
freebsd::stringf(const char *fmt, ...)
{
	va_list ap;
	std::string str;
	freebsd::FILE_up fp(fwopen(reinterpret_cast<void *>(&str),
	    stringf_write));

	va_start(ap, fmt);
	vfprintf(fp.get(), fmt, ap);
	va_end(ap);

	if (ferror(fp.get()))
		throw std::bad_alloc();
	fp.reset(nullptr);

	return str;
}
