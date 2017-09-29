/*-
 * Copyright (c) 2017 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>, Atul Gupta
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
 *
 * $FreeBSD$
 *
 */

#ifndef __T4_TLS_H__
#define __T4_TLS_H__

/* Custom socket options for TLS+TOE. */

#define MAX_MAC_KSZ		64	/*512 bits */
#define MAX_CIPHER_KSZ		32	/* 256 bits */
#define CIPHER_BLOCK_SZ		16
#define SALT_SIZE		4

/* Can accomodate 16, 11-15 are reserved */
enum {
    CHSSL_SHA_NOP,
    CHSSL_SHA1,
    CHSSL_SHA224,
    CHSSL_SHA256,
    CHSSL_GHASH,
    CHSSL_SHA512_224,
    CHSSL_SHA512_256,
    CHSSL_SHA512_384,
    CHSSL_SHA512_512,
    CHSSL_CBCMAC,
    CHSSL_CMAC,
};

/* Can accomodate 16, 8-15 are reserved */
enum {
    CHSSL_CIPH_NOP,
    CHSSL_AES_CBC,
    CHSSL_AES_GCM,
    CHSSL_AES_CTR,
    CHSSL_AES_GEN,
    CHSSL_IPSEC_ESP,
    CHSSL_AES_XTS,
    CHSSL_AES_CCM,
};

#define S_KEY_CLR_LOC		4
#define M_KEY_CLR_LOC		0xf
#define V_KEY_CLR_LOC(x)	((x) << S_KEY_CLR_LOC)
#define G_KEY_CLR_LOC(s)	(((x) >> S_KEY_CLR_LOC) & M_KEY_CLR_LOC)
#define F_KEY_CLR_LOC		V_KEY_CLR_LOC(1U)

#define S_KEY_GET_LOC           0
#define M_KEY_GET_LOC           0xf
#define V_KEY_GET_LOC(x)        ((x) << S_KEY_GET_LOC)
#define G_KEY_GET_LOC(s)        (((x) >> S_KEY_GET_LOC) & M_KEY_GET_LOC)

struct tls_ofld_state {
    unsigned char enc_mode;
    unsigned char mac_mode;
    unsigned char key_loc;
    unsigned char ofld_mode;
    unsigned char auth_mode;
    unsigned char resv[3];
};

struct tls_tx_ctxt {
    unsigned char   salt[SALT_SIZE];
    unsigned char key[MAX_CIPHER_KSZ];
    unsigned char ipad[MAX_MAC_KSZ];
    unsigned char opad[MAX_MAC_KSZ];
};

struct tls_rx_ctxt {
    unsigned char   salt[SALT_SIZE];
    unsigned char key[MAX_CIPHER_KSZ];
    unsigned char ipad[MAX_MAC_KSZ];
    unsigned char opad[MAX_MAC_KSZ];
};

struct tls_key_context {
    struct tls_tx_ctxt tx;
    struct tls_rx_ctxt rx;

    unsigned char l_p_key;
    unsigned char hmac_ctrl;
    unsigned char mac_first;
    unsigned char iv_size;
    unsigned char iv_ctrl;
    unsigned char iv_algo;
    unsigned char tx_seq_no;
    unsigned char rx_seq_no;

    struct tls_ofld_state state;

    unsigned int tx_key_info_size;
    unsigned int rx_key_info_size;
    unsigned int frag_size;
    unsigned int mac_secret_size;
    unsigned int cipher_secret_size;
    int proto_ver;
    unsigned int sock_fd;
    unsigned short dtls_epoch;
    unsigned short rsv;
};

/* Set with 'struct tls_key_context'. */
#define	TCP_TLSOM_SET_TLS_CONTEXT	(TCP_VENDOR)

/* Get returns int of enabled (1) / disabled (0). */
#define	TCP_TLSOM_GET_TLS_TOM		(TCP_VENDOR + 1)

/* Set with no value. */
#define	TCP_TLSOM_CLR_TLS_TOM		(TCP_VENDOR + 2)

/* Set with no value. */
#define	TCP_TLSOM_CLR_QUIES		(TCP_VENDOR + 3)

#ifdef _KERNEL
int	t4_ctloutput_tls(struct socket *, struct sockopt *);
#endif /* _KERNEL */

#endif /* !__T4_TLS_H__ */
