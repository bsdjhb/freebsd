/*
 * Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * $FreeBSD$
 */

#ifndef __OSSL_H__
#define	__OSSL_H__

/* Compatibility shims. */
#define	OPENSSL_cleanse		explicit_bzero

/* Used by assembly routines to select CPU-specific variants. */
extern unsigned int OPENSSL_ia32cap_P[4];

/* Needs to be big enough to hold any hash context. */
struct ossl_hash_context {
	uint32_t	dummy[24];
};

/* ossl_sha1.c */
extern struct auth_hash ossl_hash_sha1;

#endif /* !__OSSL_H__ */
