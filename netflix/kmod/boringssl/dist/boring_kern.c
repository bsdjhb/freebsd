/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014-2018  Netflix Inc.
 * All rights reserved.
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sockbuf.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <sys/counter.h>
#include <sys/sockbuf_tls.h>
#include <sys/module.h>
#include <machine/fpu.h>
#include <opencrypto/xform.h>

#include "openssl/modes.h"
#include "openssl/base.h"
#include "openssl/aead.h"
#include "openssl/crypto.h"
#include "openssl/internal_modes.h"
#include "openssl/internal_crypto.h"
#include "openssl/internal_cipher.h"



static counter_u64_t sbtls_offload_boring_aead;
static counter_u64_t sbtls_offload_boring_cbc;
static counter_u64_t sbtls_offload_boring_cbc_cp;
static counter_u64_t sbtls_offload_boring_cbc_ok;


static int
sbtls_crypt_boringssl_aead(struct sbtls_session *tls,
    const struct tls_record_layer *hdr, uint8_t *trailer, struct iovec *iniov,
    struct iovec *outiov, int iovcnt, uint64_t seqno)
{
	size_t taglen;
	struct evp_aead_ctx_st *bssl;
	struct tls_aead_data ad;
	struct tls_nonce_data nd;
	size_t noncelen, adlen;
	int ret;
	uint16_t tls_comp_len;


	bssl = (struct evp_aead_ctx_st *)tls->cipher;
	if (tls->sb_params.iv_len != TLS_AEAD_GCM_LEN) {
		return (EINVAL);
	}
	KASSERT(bssl != NULL, ("Null cipher"));
	counter_u64_add(sbtls_offload_boring_aead, 1);

	/* Setup the nonce */
	memcpy(nd.fixed, tls->sb_params.iv, TLS_AEAD_GCM_LEN);
	memcpy(&nd.seq, hdr + 1, sizeof(nd.seq));
	noncelen = sizeof(nd);
	/* Setup the associated data */
	tls_comp_len = ntohs(hdr->tls_length) -
	    (bssl->aead->overhead + sizeof(nd.seq));
	ad.type = hdr->tls_type;
	ad.tls_vmajor = hdr->tls_vmajor;
	ad.tls_vminor = hdr->tls_vminor;
	ad.tls_length = htons(tls_comp_len);
	memcpy(&ad.seq, &nd.seq, sizeof(uint64_t));
	adlen = sizeof(ad);
	taglen = bssl->aead->overhead;
	tls->taglen = taglen;
	ret = bssl->aead->seal(bssl, outiov, iovcnt,
	    (uint8_t *) & nd, noncelen, iniov, iovcnt,
	    (uint8_t *) & ad, adlen, trailer, &taglen);

	if (ret == 0) {
		/* Seal failed? */
		return EFAULT;
	}

	return (0);
}

static uint64_t
iov_pulldown(struct iovec *iov, size_t bytes)
{
	char *to, *from;
	struct iovec *next;
	size_t len, recurse;


	KASSERT(iov->iov_len + bytes <= PAGE_SIZE,
	    ("pull down:  %ld bytes > PAGE_SIZE\n",
		iov->iov_len + bytes));

	/*
	 *  we need to use the space at the end of the first
	 *  iov and copy bytes from the next iov, or the trailer
	 *
	 *  [xxxx000] [yyyyyy] becomes
	 *       t     f
	 *  [xxxxyyy] [000yyy]
	 */

	to = (char *)iov->iov_base + iov->iov_len;
	next = iov + 1;
	from = next->iov_base;

	if (bytes > next->iov_len) {
		/*
		 * we need to pull more bytes down into this
		 * segment, so we recursively call ourselves
		 */
		recurse = iov_pulldown(next, bytes - next->iov_len);
	} else {
		recurse = 0;
	}

	memcpy(to, from, bytes);
	iov->iov_len += bytes;
	next->iov_len -= bytes;

	/*
	 * now we've created a hole at the front of "next" that
	 * we have to fill
	 *
	 *  [xxxxyyy] [000yyy] becomes
	 *             t  f
	 *  [xxxxyyy] [yyy000]
	 */
	to = (char *)next->iov_base;
	from = (char *)next->iov_base + bytes;
	len = next->iov_len;
	memmove(to, from, len);
	return (bytes + len + recurse);
}

/*
 * CBC may move unaligned data forward from one iovec to the
 * next and into the tag due to blocksize and/or alignment
 * issues.
 *
 * This wreaks havovoc with the upper layers, since we cannot
 * reflect the iovec length changes back up the stack.
 * Luckily, this happens in a minority of cases.  To work
 * around this, we can copy the data the back into its old
 * layout in the iovec.
 *
 */

static void
sbtls_boring_cbc_fixup(struct sbtls_session *tls,
    struct iovec *iniov, struct iovec *outiov,
    uint8_t *trailer, int iovcnt)
{
	struct iovec *in, *out;
	struct iovec work_iov[2 + btoc(TLS_MAX_MSG_SIZE_V10_2)];
	uint64_t good, bad;
	int i, delta;

	/*
	 * First we setup a work iov that contains the tag, so that we
	 * can deal entirely in iovecs and not have to have a
	 * special case for the last entry.  The iovec passed into
	 * us may not have enough space for the tag, so we need
	 * to copy into a bigger one.
	 */
	KASSERT(iovcnt < 2 + btoc(TLS_MAX_MSG_SIZE_V10_2),
	    ("iovcnt too large?"));
	memcpy(work_iov, outiov, iovcnt * sizeof(outiov[0]));
	work_iov[iovcnt].iov_base = trailer;
	work_iov[iovcnt].iov_len = tls->taglen;


	 /* Now loop over the in/out iovecs, restoring the input len. */
	good = bad = 0;
	for (i = 0, delta = 0, in = iniov, out = work_iov;
	     i < iovcnt;
	     i++, in++, out++) {
		delta = in->iov_len - out->iov_len;
		if (delta != 0) {
			bad += iov_pulldown(out, delta);
		} else {
			good += out->iov_len;
		}
	}
	/* if we fixed anything, copy the fixed iovec entries back */
	if (bad != 0) {
		memcpy(outiov, work_iov, iovcnt * sizeof(work_iov[0]));
	}

	/* This check can eventually be moved under INVARIANTS */
	for (i = 0; i < iovcnt; i++) {
		KASSERT(iniov[i].iov_len == outiov[i].iov_len,
		    ("boring wasn't fixed: in= %p, out= %p, work= %p, tls= %p",
			iniov, outiov, work_iov, tls));
	}
	counter_u64_add(sbtls_offload_boring_cbc_ok, good);
	counter_u64_add(sbtls_offload_boring_cbc_cp, bad);
}

static int
sbtls_crypt_boringssl_cbc(struct sbtls_session *tls,
    const struct tls_record_layer *hdr, uint8_t *trailer, struct iovec *iniov,
    struct iovec *outiov, int iovcnt, uint64_t seqno)
{
	size_t taglen;
	struct tls_mac_data mac;
	struct evp_aead_ctx_st *bssl;
	size_t ivlen;
	uint8_t iv[64];
	int ret, tls_size_out, i;


	bssl = (struct evp_aead_ctx_st *)tls->cipher;
	KASSERT(bssl != NULL, ("Null cipher"));
	counter_u64_add(sbtls_offload_boring_cbc, 1);
	taglen = bssl->aead->max_tag_len;
	mac.type =  hdr->tls_type;
	mac.tls_vmajor = hdr->tls_vmajor;
	mac.tls_vminor = hdr->tls_vminor;
	mac.seq = htobe64(seqno);
	mac.tls_length = 0;
	if (bssl->aead->nonce_len) {
		ivlen = bssl->aead->nonce_len;
		memcpy(iv, hdr + 1, ivlen);
	} else {
		ivlen = 0;
	}
	ret = bssl->aead->seal(bssl, outiov, iovcnt,
	    (uint8_t *) & iv, ivlen, iniov, iovcnt,
	    (uint8_t *) & mac, (sizeof(mac) - 2), trailer, &taglen);

	if (ret == 0)
		return (EFAULT);

	/* The iov chain on out may not be right sized to in */
	for (i = 0, tls_size_out = 0; i < iovcnt; i++) {
		tls_size_out += outiov[i].iov_len;
	}

	/*
	 * horrific hack to pass the taglen for this one pkt
	 * back to the higher level code without extending the API
	 * and adding args that GCM would have to deal with
	 */
	tls->taglen = taglen;

	/*
	 * move data in the output iovec back to the original
	 * layout
	 */
	sbtls_boring_cbc_fixup(tls, iniov, outiov, trailer, iovcnt);

	return (0);
}

static int
sbtls_try_boring(struct socket *so, struct tls_so_enable *en,
    struct sbtls_session **ptls)
{
	struct sbtls_session *tls;
	struct evp_aead_ctx_st *bssl;

	if (((en->crypt_algorithm == CRYPTO_AES_NIST_GMAC) ||
	    (en->crypt_algorithm == CRYPTO_AES_NIST_GCM_16)) &&
	    ((en->mac_algorithm == CRYPTO_AES_128_NIST_GMAC) ||
	    (en->mac_algorithm == CRYPTO_AES_256_NIST_GMAC))) {

		tls = sbtls_init_session(so, en, sizeof(*bssl));
		if (tls == NULL) {
			return (ENOMEM);
		}
		bssl = tls->cipher;
		if (en->mac_algorithm == CRYPTO_AES_128_NIST_GMAC)
			bssl->aead = EVP_aead_aes_128_gcm();
		else if (en->mac_algorithm == CRYPTO_AES_256_NIST_GMAC)
			bssl->aead = EVP_aead_aes_256_gcm();
		else
			panic("Unknown key size -- mac alg");

		tls->t_type = SBTLS_T_TYPE_BSSL;
		tls->sb_tls_crypt = sbtls_crypt_boringssl_aead;
		*ptls = tls;
		return (0);
	} else if (en->crypt_algorithm == CRYPTO_AES_CBC) {
		const EVP_AEAD *choice = NULL;

		if (en->mac_algorithm == CRYPTO_SHA2_256_HMAC) {
			if (en->key_size == 16) {
				choice = EVP_aead_aes_128_cbc_sha256_tls();
			} else if (en->key_size == 32) {
				choice = EVP_aead_aes_256_cbc_sha256_tls();
			}
		} else if (en->mac_algorithm == CRYPTO_SHA1_HMAC) {
			if (en->tls_vmajor != TLS_MAJOR_VER_ONE) {
				return (EINVAL);
			}
			if (en->key_size == 16) {
				if (en->tls_vminor == TLS_MINOR_VER_ZERO) {
					/* TLS 1.1 */
					choice = EVP_aead_aes_128_cbc_sha1_tls_implicit_iv();
				} else if (en->tls_vminor >= TLS_MINOR_VER_ONE) {
					/* TLS 1.2 and > */
					choice = EVP_aead_aes_128_cbc_sha1_tls();
				}
			} else if (en->key_size == 32) {
				if (en->tls_vminor == TLS_MINOR_VER_ZERO) {
					/* TLS 1.1 */
					choice = EVP_aead_aes_256_cbc_sha1_tls_implicit_iv();
				} else if (en->tls_vminor >= TLS_MINOR_VER_ONE) {
					/* TLS 1.2 and > */
					choice = EVP_aead_aes_256_cbc_sha1_tls();
				}
			}
		}
		/*
		 * At this point choice is set if we have a cipher that
		 * matches
		 */
		if (choice == NULL) {
			return (EOPNOTSUPP);
		}

		tls = sbtls_init_session(so, en, sizeof(*bssl));
		if (tls == NULL) {
			return (ENOMEM);
		}

		KASSERT(tls->sb_params.tls_hlen ==
		    sizeof(struct tls_record_layer) + choice->nonce_len,
		    ("TLS header length mismatch"));
		KASSERT(tls->sb_params.tls_tlen != choice->overhead,
		    ("TLS trailer length mismatch"));

		bssl = tls->cipher;
		bssl->aead = choice;
		tls->t_type = SBTLS_T_TYPE_BSSL;
		tls->sb_tls_crypt = sbtls_crypt_boringssl_cbc;
		*ptls = tls;
		return (0);
	} else {
		return (EOPNOTSUPP);
	}

}

static int
sbtls_setup_boring_cipher(struct sbtls_session *tls)
{
	int ret;
	struct evp_aead_ctx_st *bssl;
	uint8_t *key, *mal = NULL;
	struct fpu_kern_ctx *fpu_ctx;
	size_t keylen;


	bssl = (struct evp_aead_ctx_st *)tls->cipher;
	if (tls->sb_tls_crypt == sbtls_crypt_boringssl_cbc) {
		/* CBC has a merged key */
		keylen = tls->sb_params.hmac_key_len + tls->sb_params.crypt_key_len;
		if (tls->sb_params.hmac_key == NULL || tls->sb_params.crypt == NULL) {
			return (EINVAL);
		}
		    
		mal = malloc(keylen, M_TLSSOBUF, M_NOWAIT);
		if (mal == NULL) {
			return (ENOMEM);
		}
		memcpy(mal, tls->sb_params.hmac_key, tls->sb_params.hmac_key_len);
		memcpy(mal + tls->sb_params.hmac_key_len, tls->sb_params.crypt,
		    tls->sb_params.crypt_key_len);
		key = mal;
	} else {
		key = tls->sb_params.crypt;
		keylen = tls->sb_params.crypt_key_len;
		if (key == NULL) {
			return (EINVAL);
		}
	}
	fpu_ctx = fpu_kern_alloc_ctx(FPU_KERN_NOWAIT);
	if (fpu_ctx == NULL) {
		return (ENOMEM);
	}
	fpu_kern_enter(curthread, fpu_ctx, FPU_KERN_NORMAL);
	ret = EVP_AEAD_CTX_init_with_direction(bssl,
	    bssl->aead,
	    key,
	    keylen,
	    EVP_AEAD_DEFAULT_TAG_LENGTH,
	    evp_aead_seal);
	if (mal) {
		free(mal, M_TLSSOBUF);
	}
	fpu_kern_leave(curthread, fpu_ctx);
	fpu_kern_free_ctx(fpu_ctx);
	if (ret == 0) {
		return (EINVAL);
	} else {
		return (0);
	}
}

static void
sbtls_clean_boring(struct sbtls_session *tls, void *arg)
{
	EVP_AEAD_CTX_cleanup(arg);
}

SYSCTL_DECL(_kern_ipc_tls_counters);
SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, bsslaead_crypts, CTLFLAG_RD,
    &sbtls_offload_boring_aead, "Total number of BORING SSL TLS AEAD encrypts called");

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, bssl_cbc_crypts, CTLFLAG_RD,
    &sbtls_offload_boring_cbc, "Total number of BORING SSL TLS CBC encrypts called");

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, bssl_cbc_cp,
    CTLFLAG_RD, &sbtls_offload_boring_cbc_cp,
    "Total bytes copied fixing up CBC");
SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, bssl_cbc_ok,
    CTLFLAG_RD, &sbtls_offload_boring_cbc_ok,
    "Total bytes not copied fixing up CBC");



struct sbtls_crypto_backend bssl_backend  = {
	.name = "Boring",
	.prio = 10,
	.api_version = SBTLS_API_VERSION,
	.try = sbtls_try_boring,
	.setup_cipher = sbtls_setup_boring_cipher,
	.clean_cipher = sbtls_clean_boring,
};

static int
boringssl_init(void)
{
	sbtls_offload_boring_aead = counter_u64_alloc(M_WAITOK);
	sbtls_offload_boring_cbc = counter_u64_alloc(M_WAITOK);
	sbtls_offload_boring_cbc_cp = counter_u64_alloc(M_WAITOK);
	sbtls_offload_boring_cbc_ok = counter_u64_alloc(M_WAITOK);
	CRYPTO_library_init();
	return (sbtls_crypto_backend_register(&bssl_backend));
}

static int
boring_module_event_handler(module_t mod, int evt, void *arg)
{
	switch (evt) {
	case MOD_LOAD:
		return (boringssl_init());
	case MOD_UNLOAD:
		return (sbtls_crypto_backend_deregister(&bssl_backend));
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t boring_moduledata = {
	"boring",
	boring_module_event_handler,
	NULL
};



DECLARE_MODULE(boring, boring_moduledata, SI_SUB_PROTO_END, SI_ORDER_ANY);
