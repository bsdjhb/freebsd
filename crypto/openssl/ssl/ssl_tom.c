/* ssl/ssl_tom.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * w
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
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
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 * Chelsio Software written by Atul Gupta (atul.gupta@chelsio.com)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/genetlink.h>
#include <linux/types.h>
#endif
#ifdef __FreeBSD__
#include <netinet/tcp.h>
#endif
#include "ssl_locl.h"
#include <openssl/ssl.h>
#include <netinet/in.h>
#include "ssl_tom.h"
#include <sys/uio.h>

#ifdef CHSSL_OFFLOAD
int ssl_tls_offload(SSL *s)
{
#ifdef __FreeBSD__
    socklen_t optlen;
#endif
    int ret, mode = 0;

    if ((s->wbio == NULL) || (s->rbio == NULL)) {
        SSLerr(SSL_R_BAD_STATE, SSL_R_BIO_NOT_SET);
        return mode;
    }
    s->chssl->sock_fd = s->wbio->num = s->rbio->num;

#ifdef __linux__
    ret = ioctl(s->chssl->sock_fd, IOCTL_TLSOM_GET_TLS_TOM, &mode);
#else
    optlen = sizeof(mode);
    ret = getsockopt(s->chssl->sock_fd, IPPROTO_TCP, TCP_TLSOM_GET_TLS_TOM,
	&mode, &optlen);
#endif

    if (!ret && mode)
        s->chssl->ofld_enable = TLS_OFLD_TRUE;
    else
        s->chssl->ofld_enable = TLS_OFLD_FALSE;
    return mode;
}

int SSL_ofld_vers(const SSL *s)
{
    return (s->version == TLS1_1_VERSION || s->version == TLS1_2_VERSION
            || s->version == DTLS1_2_VERSION);
}

int SSL_ofld(const SSL *s)
{
    return(SSL_ofld_vers(s) && s->chssl && s->chssl->ofld_enable);
}

#ifdef CHSSL_TLS_RX
int SSL_ofld_rx(const SSL *s)
{
    return(s->chssl && s->chssl->ofld_enable);
}
#endif

int SSL_compress(const SSL *s)
{
    return(s->compress != NULL);
}

#ifdef CHSSL_TLS_RX
int SSL_Rx_keys(const SSL *s)
{
    return(s->chssl && s->chssl->rx_keys_copied);
}
#endif

int SSL_Tx_keys(const SSL *s)
{
    return(s->chssl && s->chssl->tx_keys_copied);
}

int SSL_enc(const SSL *s)
{
    return(s->chssl && s->chssl->ofld_enable && s->chssl->ofld_enc);
}

int SSL_mac(const SSL *s)
{
    return(s->chssl && s->chssl->ofld_enable && s->chssl->ofld_mac);
}

int SSL_Chelsio_ofld(const SSL *s)
{
    return (SSL_ofld(s) && SSL_enc(s) && SSL_mac(s));
}

#ifdef CHSSL_TLS_RX
int SSL_clr_quiesce(const SSL *s)
{
    return (s->chssl && (s->chssl->key_state == KEY_SPACE_NOTAVL));
}
#endif

/* 
 * Determine HW capability for Digest and Cipher Offload 
 */
static int tls_ofld_enc_mac(SSL *s)
{
    const EVP_CIPHER *p;
    const SSL_CIPHER *c;

    c = s->s3->tmp.new_cipher;
    p = s->s3->tmp.new_sym_enc;

    switch(c->algorithm_enc) {
    case SSL_AES128GCM:
    case SSL_AES256GCM:
        s->chssl->ofld_enc = SSL_ENC_OFLD;
        s->chssl->ofld_mac = SSL_MAC_OFLD;
        return TLS_OFLD_TRUE;

    case SSL_AES128 :
    case SSL_AES256 :
        switch(EVP_CIPHER_mode(p)) {
        case EVP_CIPH_CTR_MODE:
        case EVP_CIPH_CBC_MODE:
            s->chssl->ofld_enc  = SSL_ENC_OFLD;
            break;
        default:
           chssl_print(cl,"No HW support\n");
           return TLS_OFLD_FALSE;
        }
    break;

    case SSL_eNULL:
        s->chssl->ofld_enc = SSL_ENC_OFLD;
        break;

    default:
        chssl_print(cl,"No HW support for ENC\n");
                    s->chssl->ofld_enc = SSL_ENC_HOST;
        return TLS_OFLD_FALSE;
    }

    switch(c->algorithm_mac) {
    case SSL_SHA1:
    case SSL_SHA256:
    case SSL_SHA384:
        s->chssl->ofld_mac= SSL_MAC_OFLD;
        break;

    default:
        s->chssl->ofld_mac= SSL_MAC_HOST;
	/* Revert enc mode to non-offload */
        s->chssl->ofld_enc  = SSL_ENC_HOST;
        chssl_print(cl,"No HW support for MAC\n");
        return TLS_OFLD_FALSE;
    }
    return TLS_OFLD_TRUE;
}

/* 
 * Authentication Mode expected by HW
 */
static unsigned char get_auth_mode(SSL *s)
{
    const SSL_CIPHER *c = s->s3->tmp.new_cipher;

    if(c==NULL) return CHSSL_SHA_NOP;

    switch(c->algorithm_mac) {
    case SSL_SHA1:
        return CHSSL_SHA1;
    case SSL_SHA256:
       return CHSSL_SHA256;
    case SSL_SHA384:
       return CHSSL_SHA512_384;
    case SSL_AEAD:
        return CHSSL_GHASH;
    default:
        return CHSSL_SHA_NOP;
}
}

/* 
 * Cipher Mode expected by HW
 */
static unsigned char get_cipher_mode(SSL *s)
{
    const EVP_CIPHER *c = s->s3->tmp.new_sym_enc;

    switch(EVP_CIPHER_mode(c)) {
    case EVP_CIPH_CBC_MODE:
        return CHSSL_AES_CBC;
    case EVP_CIPH_GCM_MODE:
        return CHSSL_AES_GCM;
    case EVP_CIPH_CTR_MODE:
        return CHSSL_AES_CTR;
    case EVP_CIPH_STREAM_CIPHER:
        return CHSSL_CIPH_NOP;
    default:
        chssl_print(cl,"invalid cipher mode\n");
        return CHSSL_CIPH_NOP;
    }
}

static void chssl_compute_ipad_opad(unsigned char *key,
				 unsigned char *ipad,
				 unsigned char *opad,
				 int k)
{
    int i;

    if(k < MAX_MAC_KSZ) {
        for(i=k; i < MAX_MAC_KSZ; i++) {
            ipad[i] = 0x0;
            opad[i] = 0x0;
        }
    }
    for(i=0; i < MAX_MAC_KSZ; i++) {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5c;
    }

    if(k == SHA_DIGEST_LENGTH) {
        CHSSL_EVP_Digest(ipad, MAX_MAC_KSZ, ipad, NULL, EVP_sha1(), NULL);
        CHSSL_EVP_Digest(opad, MAX_MAC_KSZ, opad, NULL, EVP_sha1(), NULL);
    } else if (k == SHA256_DIGEST_LENGTH) {
        CHSSL_EVP_Digest(ipad, MAX_MAC_KSZ, ipad, NULL, EVP_sha256(), NULL);
        CHSSL_EVP_Digest(opad, MAX_MAC_KSZ, opad, NULL, EVP_sha256(), NULL);
    }
}

static void chssl_compute_ipad_opad_512(unsigned char *key,
				 unsigned char *ipad,
				 unsigned char *opad,
				 int k)
{
    int i;
    char ipad_512[SHA512_BLOCK] = {0};
    char opad_512[SHA512_BLOCK] = {0};

    for(i = 0; i < SHA512_BLOCK; i++) {
        if (i < k) {
            ipad_512[i] = key[i] ^ 0x36;
            opad_512[i] = key[i] ^ 0x5c;
        } else {
            ipad_512[i] = 0x36;
            opad_512[i] = 0x5c;
        } 
    }

    if(k == SHA384_DIGEST_LENGTH) {
        CHSSL_EVP_Digest(ipad_512, SHA512_BLOCK, ipad_512, NULL,
                         EVP_sha384(), NULL);
        CHSSL_EVP_Digest(opad_512, SHA512_BLOCK, opad_512, NULL,
                         EVP_sha384(), NULL);
    } else if (k == SHA512_DIGEST_LENGTH) {
        CHSSL_EVP_Digest(ipad_512, SHA512_BLOCK, ipad_512, NULL,
                         EVP_sha512(), NULL);
        CHSSL_EVP_Digest(opad_512, SHA512_BLOCK, opad_512, NULL,
                         EVP_sha512(), NULL);
    }
    memcpy(ipad, ipad_512, MAX_MAC_KSZ);
    memcpy(opad, opad_512, MAX_MAC_KSZ);
}

static void chssl_compute_cipher_key(unsigned char *key,
				     int key_len,
				     unsigned char *ghash)
{
    int len,len1;
    EVP_CIPHER_CTX ctx;
    unsigned char plaintext[GHASH_SIZE] = {0};

    EVP_CIPHER_CTX_init(&ctx);
    if(key_len == 16)
        EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, NULL);
    else
        EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    EVP_EncryptUpdate(&ctx, ghash, &len, plaintext, 16);
    EVP_EncryptFinal_ex(&ctx, ghash+len, &len1);
    EVP_CIPHER_CTX_cleanup(&ctx);
}

/*
 * Create key Context for receive/transmit and program on HW
 */
static int ssl_key_context(SSL *s, int rw, int state)
{
    const EVP_CIPHER *c;
    const EVP_MD *m;
    const SSL_CIPHER *sc;
    unsigned int  mac_key_size = 0, cipher_key_size, iv_size;
    unsigned char *key;
    unsigned char s_ipad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */
    unsigned char s_opad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */
    unsigned char c_ipad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */
    unsigned char c_opad_hash[MAX_MAC_KSZ]= {0x0}; /* blk sz for hashing */

    unsigned char s_mac_key[MAX_MAC_KSZ] = {0x0};
    unsigned char c_mac_key[MAX_MAC_KSZ] = {0x0};
    unsigned char s_key[MAX_CIPHER_KSZ] = {0x0};
    unsigned char c_key[MAX_CIPHER_KSZ] = {0x0};
    unsigned char s_iv[MAX_CIPHER_KSZ] = {0x0};
    unsigned char c_iv[MAX_CIPHER_KSZ] = {0x0};
    unsigned char ghash[GHASH_SIZE] = {0x0};
    int pad = 12;
    int index = 0;
    int ret = 0;
    struct tls_key_context *kctx = s->chssl->key_context;

    if (!tls_ofld_enc_mac(s)) {
        return ret;
    }

    c = s->s3->tmp.new_sym_enc;
    m = s->s3->tmp.new_hash;
    sc = s->s3->tmp.new_cipher;
    kctx->l_p_key = rw;

    if (s->new_session)
    kctx->l_p_key |= F_KEY_CLR_LOC;
    key = s->s3->tmp.key_block;

    if (s->version >= TLS1_VERSION)
        mac_key_size = s->s3->tmp.new_mac_secret_size;
    else
        if (m) mac_key_size = m->md_size;
    kctx->mac_secret_size = mac_key_size;

    cipher_key_size = EVP_CIPHER_key_length(c);
    kctx->cipher_secret_size = cipher_key_size;

    iv_size = (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) ?
    EVP_GCM_TLS_FIXED_IV_LEN:
    EVP_CIPHER_iv_length(c);
    kctx->iv_size = iv_size;
    kctx->iv_ctrl = 1;
    kctx->iv_algo = 0;

    if ((mac_key_size == SHA256_DIGEST_LENGTH) ||
        (mac_key_size == SHA384_DIGEST_LENGTH))
        pad = 0;

    if (mac_key_size) {
        memcpy(c_mac_key, key, mac_key_size);
        key += mac_key_size;
        memcpy(s_mac_key, key, mac_key_size);
        key += mac_key_size;
    }
    memcpy(c_key, key, cipher_key_size);
    key += cipher_key_size;
    memcpy(s_key, key, cipher_key_size);
    key += cipher_key_size;

    memcpy(c_iv, key, iv_size);
    key += iv_size;
    memcpy(s_iv, key, iv_size);

    if (s->chssl->ofld_mac) {
        /* IPAD/OPAD for SHA384/512 calculated over 128B block */   
        if (mac_key_size >= SHA384_DIGEST_LENGTH) {
            chssl_compute_ipad_opad_512(c_mac_key, c_ipad_hash,
                                    c_opad_hash, mac_key_size);
            chssl_compute_ipad_opad_512(s_mac_key, s_ipad_hash,
                                    s_opad_hash, mac_key_size);
        } else {
            chssl_compute_ipad_opad(c_mac_key, c_ipad_hash,
                                    c_opad_hash, mac_key_size);
            chssl_compute_ipad_opad(s_mac_key, s_ipad_hash,
                                    s_opad_hash, mac_key_size);
        }
    }

    if (state == SSL_ST_ACCEPT) {
        memcpy(kctx->tx.key, s_key, cipher_key_size);
        memcpy(kctx->rx.key, c_key, cipher_key_size);
    } else {
        memcpy(kctx->tx.key, c_key, cipher_key_size);
        memcpy(kctx->rx.key, s_key, cipher_key_size);
    }

    if (mac_key_size == SHA384_DIGEST_LENGTH) mac_key_size = MAX_MAC_KSZ;
    index = cipher_key_size;
    if (s->chssl->ofld_mac) {
        if (mac_key_size) {
            if (state == SSL_ST_ACCEPT)
                memcpy(kctx->tx.key+index, s_ipad_hash, mac_key_size);
            else
                memcpy(kctx->tx.key+index, c_ipad_hash, mac_key_size);

            index += (mac_key_size + pad);
            if (state == SSL_ST_ACCEPT)
                memcpy(kctx->tx.key+index, s_opad_hash, mac_key_size);
            else
                memcpy(kctx->tx.key+index, c_opad_hash, mac_key_size);

            index += (mac_key_size + pad);
        } else {
            if (state == SSL_ST_ACCEPT) {
               chssl_compute_cipher_key(s_key, cipher_key_size, ghash);
               memcpy(kctx->tx.key+index, ghash, GHASH_SIZE);
            } else {
               chssl_compute_cipher_key(c_key, cipher_key_size, ghash);
               memcpy(kctx->tx.key+index, ghash, GHASH_SIZE);
            }
            index += GHASH_SIZE;
        }
    }
    kctx->tx_key_info_size = TLS_TX_HDR_SZ + index;

    index = cipher_key_size;
    if (s->chssl->ofld_mac) {
        if (mac_key_size) {
            if (state == SSL_ST_ACCEPT)
                memcpy(kctx->rx.key+index, c_ipad_hash, mac_key_size);
            else
                memcpy(kctx->rx.key+index, s_ipad_hash, mac_key_size);

        index += (mac_key_size + pad);
        if (state == SSL_ST_ACCEPT)
            memcpy(kctx->rx.key+index, c_opad_hash, mac_key_size);
        else
            memcpy(kctx->rx.key+index, s_opad_hash, mac_key_size);

        index += (mac_key_size + pad);
        } else {
            if (state == SSL_ST_ACCEPT)  {
                chssl_compute_cipher_key(c_key, cipher_key_size, ghash);
                memcpy(kctx->rx.key+index, ghash, GHASH_SIZE);
            } else {
                chssl_compute_cipher_key(s_key, cipher_key_size, ghash);
                memcpy(kctx->rx.key+index, ghash, GHASH_SIZE);
            }
	index += GHASH_SIZE;
        }
    }

    kctx->tx_key_info_size = TLS_RX_HDR_SZ + index;

    if (EVP_CIPHER_mode(c) == EVP_CIPH_GCM_MODE) {
        if (state == SSL_ST_ACCEPT)  {
            memcpy(kctx->tx.salt, s_iv, SALT_SIZE);
            memcpy(kctx->rx.salt, c_iv, SALT_SIZE);
        } else {
            memcpy(kctx->tx.salt, c_iv, SALT_SIZE);
            memcpy(kctx->rx.salt, s_iv, SALT_SIZE);
        }
    }

    kctx->proto_ver = s->version;
    kctx->state.auth_mode = get_auth_mode(s);
    kctx->state.enc_mode = get_cipher_mode(s);
    if (s->version == DTLS1_2_VERSION)
        kctx->dtls_epoch = s->d1->r_epoch;

    if (s->max_send_fragment)
        kctx->frag_size = s->max_send_fragment;
    else
        kctx->frag_size = SSL3_RT_MAX_PLAIN_LENGTH;

    /* handle renegotiation here */
    if(!s->chssl->tx_keys_copied)
        kctx->tx_seq_no = 0;
    else
        kctx->tx_seq_no = 1;

    if(!s->chssl->rx_keys_copied)
        kctx->rx_seq_no = 0;
    else
        kctx->rx_seq_no = 1;

    if(EVP_CIPHER_mode(c) != EVP_CIPH_GCM_MODE) {
        if (!SSL_mac(s) && SSL_enc(s))
            kctx->hmac_ctrl = 0;
        else
            kctx->hmac_ctrl = 1;
    }
    kctx->sock_fd = s->chssl->sock_fd;

    return 1;
}

void chssl_program_hwkey_context(SSL *s, int rw, int state)
{
    int ret = 0;

    if (!s->chssl->key_context) {
        s->chssl->key_context = (struct tls_key_context *)
        OPENSSL_malloc(sizeof(struct tls_key_context));
        if (s->chssl->key_context == NULL)
            return;
    }

    memset(s->chssl->key_context, 0, sizeof(struct tls_key_context));
    if((ret = ssl_key_context(s, rw, state)) <=0) {
#ifdef CHSSL_TLS_RX
        /* Clear quiesce after CCS receive */
        if (rw == KEY_WRITE_RX) {
            ret = chssl_clear_tom(s);
            s->chssl->ofld_enable = TLS_OFLD_FALSE;
        }
#endif
	goto end;
    }

#ifdef __linux__
    ret = ioctl(s->chssl->sock_fd, IOCTL_TLSOM_SET_TLS_CONTEXT,
		s->chssl->key_context);
#else
    ret = setsockopt(s->chssl->sock_fd, IPPROTO_TCP, TCP_TLSOM_SET_TLS_CONTEXT,
	s->chssl->key_context, sizeof(*s->chssl->key_context));
#endif
    if (!ret) {
        if (rw & KEY_WRITE_TX)
            s->chssl->tx_keys_copied = 1;
        else
            s->chssl->rx_keys_copied = 1;
    } else {
        s->chssl->ofld_enable = TLS_OFLD_FALSE;
        s->chssl->key_state = KEY_SPACE_NOTAVL;
    }

end:
    free(s->chssl->key_context);
    s->chssl->key_context = NULL;
    return;
}

#ifdef CHSSL_TLS_RX
int chssl_clear_quies(const SSL *s)
{
#ifdef __linux__
    return ioctl(s->chssl->sock_fd, IOCTL_TLSOM_CLR_QUIES);
#else
    return setsockopt(s->chssl->sock_fd, IPPROTO_TCP, TCP_TLSOM_CLR_QUIES,
	NULL, 0);
#endif
}

int chssl_clear_tom(const SSL *s)
{
#ifdef __linux__
    return ioctl(s->chssl->sock_fd, IOCTL_TLSOM_CLR_TLS_TOM);
#else
    return setsockopt(s->chssl->sock_fd, IPPROTO_TCP, TCP_TLSOM_CLR_TLS_TOM,
	NULL, 0);
#endif
}
#endif

int chssl_process_cherror(SSL *s)
{
    const char *buf = &(s->s3->rbuf.buf[0]);
    unsigned int err = atoi(buf);

    switch (err) {
    case 0:
        return SSL_AD_BAD_RECORD_MAC;
    case 1:
    case 2:
        return SSL_AD_ILLEGAL_PARAMETER;
    case 3:
        return SSL_AD_RECORD_OVERFLOW;
    case 4:
        return SSL_AD_INTERNAL_ERROR;
    }
    return 0;
}

struct ch_ssl_st *chssl_new(SSL *s)
{
    if (s->chssl)
        return s->chssl;
    s->chssl = OPENSSL_malloc(sizeof(struct ch_ssl_st));
    if (s->chssl)
        memset(s->chssl, 0, sizeof(struct ch_ssl_st));
    return s->chssl;
}

struct ch_ssl_st *chssl_free(SSL *s)
{
    if (!s->chssl)
        return NULL;

    free(s->chssl);
    s->chssl = NULL;
    return NULL;
}
#endif
