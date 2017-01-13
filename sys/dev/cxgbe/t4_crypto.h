/*-
 * Copyright (c) 2017 Chelsio Communications, Inc.
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

#ifndef __T4_CRYPTO_H__
#define	__T4_CRYPTO_H__

/* From chr_core.h */
#define PAD_ERROR_BIT		1
#define CHK_PAD_ERR_BIT(x)	(((x) >> PAD_ERROR_BIT) & 1)

#define MAC_ERROR_BIT		0
#define CHK_MAC_ERR_BIT(x)	(((x) >> MAC_ERROR_BIT) & 1)
#define MAX_SALT                4

struct _key_ctx {
	__be32 ctx_hdr;
	u8 salt[MAX_SALT];
	__be64 reserverd;
	unsigned char key[0];
};

struct chcr_wr {
	struct fw_crypto_lookaside_wr wreq;
	struct ulp_txpkt ulptx;
	struct ulptx_idata sc_imm;
	struct cpl_tx_sec_pdu sec_cpl;
	struct _key_ctx key_ctx;
};

/* From chr_algo.h */
#define CHCR_HASH_MAX_DIGEST_SIZE 64

#define DUMMY_BYTES 16

#define IPAD_DATA 0x36363636
#define OPAD_DATA 0x5c5c5c5c

#define TRANSHDR_SIZE(kctx_len)\
	(sizeof(struct chcr_wr) +\
	 kctx_len)
#define CIPHER_TRANSHDR_SIZE(kctx_len, sge_pairs) \
	(TRANSHDR_SIZE((kctx_len)) + (sge_pairs) +\
	 sizeof(struct cpl_rx_phys_dsgl))
#define HASH_TRANSHDR_SIZE(kctx_len)\
	(TRANSHDR_SIZE(kctx_len) + DUMMY_BYTES)

/* From chr_crypto.h */
#define CHCR_SCMD_PROTO_VERSION_GENERIC 4

#define CHCR_SCMD_CIPHER_MODE_NOP               0
#define CHCR_SCMD_CIPHER_MODE_AES_CBC           1
#define CHCR_SCMD_CIPHER_MODE_AES_GCM           2
#define CHCR_SCMD_CIPHER_MODE_AES_CTR           3
#define CHCR_SCMD_CIPHER_MODE_GENERIC_AES       4
#define CHCR_SCMD_CIPHER_MODE_AES_XTS           6
#define CHCR_SCMD_CIPHER_MODE_AES_CCM           7

#define CHCR_SCMD_AUTH_MODE_NOP             0
#define CHCR_SCMD_AUTH_MODE_SHA1            1
#define CHCR_SCMD_AUTH_MODE_SHA224          2
#define CHCR_SCMD_AUTH_MODE_SHA256          3
#define CHCR_SCMD_AUTH_MODE_GHASH           4
#define CHCR_SCMD_AUTH_MODE_SHA512_224      5
#define CHCR_SCMD_AUTH_MODE_SHA512_256      6
#define CHCR_SCMD_AUTH_MODE_SHA512_384      7
#define CHCR_SCMD_AUTH_MODE_SHA512_512      8
#define CHCR_SCMD_AUTH_MODE_CBCMAC          9
#define CHCR_SCMD_AUTH_MODE_CMAC            10

#define CHCR_SCMD_HMAC_CTRL_NOP             0
#define CHCR_SCMD_HMAC_CTRL_NO_TRUNC        1
#define CHCR_SCMD_HMAC_CTRL_TRUNC_RFC4366   2
#define CHCR_SCMD_HMAC_CTRL_IPSEC_96BIT     3
#define CHCR_SCMD_HMAC_CTRL_PL1		    4
#define CHCR_SCMD_HMAC_CTRL_PL2		    5
#define CHCR_SCMD_HMAC_CTRL_PL3		    6
#define CHCR_SCMD_HMAC_CTRL_DIV2	    7

#define CHCR_HASH_MAX_BLOCK_SIZE_64  64
#define CHCR_HASH_MAX_BLOCK_SIZE_128 128

#endif /* !__T4_CRYPTO_H__ */
