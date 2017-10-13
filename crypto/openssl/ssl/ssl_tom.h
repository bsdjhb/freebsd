/*
 * Common Header file TLSOM functionalities
 *
 * Copyright (C) 2011-2015 Chelsio Communications.  All rights reserved.
 *
 * Written by Atul Gupta
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifdef __linux__
#include <linux/byteorder/little_endian.h>
#endif
#ifndef __TLSOM_CMN_H
#define __TLSOM_CMN_H

#define TLSOM_SUCCESS 0
#define TLSOM_FAILURE -1

#ifdef CHSSL_DEBUG
        #define chssl_print(f,c) fprintf(f,c)
#else
        #define chssl_print(f,c) ;
#endif

#define MAX_MAC_KSZ		64	/*512 bits */
#define SHA512_BLOCK		128	/* Block size for 512 */
#define MAX_CIPHER_KSZ		32	/* 256 bits */
#define CIPHER_BLOCK_SZ		16
#define IV_SIZE			(4+8)	/*reserved 8 bytes */
#define SALT_SIZE		4
#define TLS_TX_HDR_SZ		16
#define TLS_RX_HDR_SZ		16
#define GHASH_SIZE		16
#define MAX_TLS_KSZ	(2*MAX_MAC_KSZ + MAX_CIPHER_KSZ)

#ifdef __FreeBSD__
#include <dev/cxgbe/tom/t4_tls.h>
#endif
#ifdef __linux__
/* XXX: TCP_TLSKEY is not used */
#define TCP_TLSKEY 291 /* Program Key Context on HW */
#define IOCTL_TLSOM_SET_TLS_CONTEXT 201 /* Program Key Context on HW */
#define IOCTL_TLSOM_GET_TLS_TOM     202 /* Query the TLS offload mode */
#define IOCTL_TLSOM_CLR_TLS_TOM     203	/* Clear the Key */
#define IOCTL_TLSOM_CLR_QUIES     204	/* Clear the Quiesec */
#endif

enum {
    TLS_OFLD_FALSE = 0,
    TLS_OFLD_TRUE,
};

#ifdef __linux__
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

#define KEY_WRITE_RX	0x1	/* Program Receive Key */
#define KEY_WRITE_TX	0x2	/* Program Transmit Key */
#define KEY_DELETE_RX	0x4	/* Delete Receive Key */
#define KEY_DELETE_TX	0x8	/* Delete Transmit Key */

#define S_KEY_CLR_LOC		4
#define M_KEY_CLR_LOC		0xf
#define V_KEY_CLR_LOC(x)	((x) << S_KEY_CLR_LOC)
#define G_FW_WR_EQUIQ(s)	(((x) >> S_KEY_CLR_LOC) & M_KEY_CLR_LOC)
#define F_KEY_CLR_LOC		V_KEY_CLR_LOC(1U)

/* XXX: Not used. */
#define S_KEY_GET_LOC           0
#define M_KEY_GET_LOC           0xf
#define V_KEY_GET_LOC(x)        ((x) << S_KEY_GET_LOC)
#define G_KEY_GET_LOC(s)        (((x) >> S_KEY_GET_LOC) & M_KEY_GET_LOC)

/* XXX: Not used. */
enum {
    CHSSL_OFLDMODE_NONE,
    CHSSL_OFLDMODE_ALLIN_HOST,
    CHSSL_OFLDMODE_ALLIN_CARD,
    CHSSL_OFLDMODE_MACIN_HOST,
    CHSSL_OFLDMODE_FRAGMENTATIONIN_HOST,
};

/* XXX: Not used. */
enum {
    CHSSL_HOST_FRAGMENT,
    CHSSL_CARD_FRAGMENT,
};

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
#endif

/* XXX: Not used. */
struct tls_key_location {
    unsigned int sock_fd;
    unsigned int key_location;
};

struct ch_ssl_st *chssl_new(SSL *s);
struct ch_ssl_st *chssl_free(SSL *s);
int ssl_tls_offload(SSL *s);
int SSL_ofld_vers(const SSL *s);
#ifdef CHSSL_TLS_RX
int SSL_ofld_rx(const SSL *s);
int SSL_clr_quiesce(const SSL *s);
#endif
#endif

