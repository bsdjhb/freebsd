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

/* From openssl/sha.h */
# define SHA_LONG unsigned int

# define SHA_LBLOCK      16
# define SHA_CBLOCK      (SHA_LBLOCK*4)/* SHA treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
# define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
# define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

/* ossl_sha1.c */
void	ossl_sha1_init(SHA_CTX *c);
int	ossl_sha1_update(void *c_, const void *data_, unsigned int len);
void	ossl_sha1_final(unsigned char *md, SHA_CTX *c);

#endif /* !__OSSL_H__ */
