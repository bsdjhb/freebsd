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
#include <sys/sockbuf_tls.h>
#include <sys/filedesc.h>
#include <sys/sysctl.h>
#include <sys/counter.h>
#include <sys/uio.h>
#include <sys/module.h>
#include <opencrypto/xform.h>
#include <machine/fpu.h>

#include "aes_gcm.h"
#include "aes_cbc.h"

struct isa_gcm_struct {
	struct gcm_key_data key_data;
	struct gcm_context_data ctx_data;
	void (*gcm_pre) (const void *key, struct gcm_key_data *); /* Done once per key */
	void (*gcm_init) (const struct gcm_key_data *key_data,
	    struct gcm_context_data *context_data,
	    uint8_t *iv,
	    uint8_t const *aad,
	    uint64_t aad_len);	/* Done at start of crypt */
	void (*gcm_upd) (const struct gcm_key_data *key_data,
	    struct gcm_context_data *context_data,
	    uint8_t *out,
	    const uint8_t *in,
	    uint64_t len);	/* With each block of data */
	void (*gcm_upd_nt) (const struct gcm_key_data *key_data,
	    struct gcm_context_data *context_data,
	    uint8_t *out,
	    const uint8_t *in,
	    uint64_t len);	/* With each block of data */
	void (*gcm_final) (const struct gcm_key_data *key_data,
	    struct gcm_context_data *context_data,
	    uint8_t *tag,
	    uint64_t tag_len);	/* Pulls out the tag */
};


int sbtls_use_intel_isa_gcm = 1;

static counter_u64_t sbtls_offload_isa_aead;
static counter_u64_t intelisa_aligned_mem;
static counter_u64_t intelisa_aligned_mem_b;
static counter_u64_t intelisa_unaligned_mem;
static counter_u64_t intelisa_unaligned_mem_b;


static int
intel_isa_seal(struct isa_gcm_struct *isa,
    struct iovec *outiov, int numiovs,
    uint8_t * nd, int noncelen,
    struct iovec *iniov,
    uint8_t * ad, int adlen,
    uint8_t * tagout, size_t *taglen)
{

	int i;
	bool nt = true;
	bool misaligned_len, misaligned_start;
	int fixup = 0;
	uint8_t *in;
	uint8_t *out;
	uint64_t len;
	uint8_t iv[32];
	uint8_t const IVend[] = GCM_IV_END_MARK;
	
	if (noncelen > 28) {
		return (-1);
	}
	memcpy(iv, nd, noncelen);
	memcpy(&iv[noncelen], IVend, sizeof(IVend));
	isa->gcm_init(&isa->key_data, &isa->ctx_data, iv, ad, (size_t)adlen);
	for (i = 0; i < numiovs; i++) {
		in = iniov[i].iov_base;
		out = outiov[i].iov_base;
		len = iniov[i].iov_len;

		misaligned_start = ((uintptr_t)in & 0xf) != 0;
		misaligned_len = (len & 0xf) != 0;

		if (misaligned_start || misaligned_len) {
			/*
			 * Try to do as much of a page using
			 * non-temporals as we possibly can, and leave
			 * a ragged tail as a separate chunk.
			 */
			if (nt && !misaligned_start && len > 0xf) {
				len = len & ~0xf;
				fixup = iniov[i].iov_len - len;
			} else {
				nt = false;
			}
		}
fixup_done:
		if (nt) {
			isa->gcm_upd_nt(&isa->key_data, &isa->ctx_data, out, in, len);
			counter_u64_add(intelisa_aligned_mem, 1);
			counter_u64_add(intelisa_aligned_mem_b, len);
		} else {
			isa->gcm_upd(&isa->key_data, &isa->ctx_data, out, in, len);
			counter_u64_add(intelisa_unaligned_mem, 1);
			counter_u64_add(intelisa_unaligned_mem_b, len);
		}
		if (fixup) {
			in += len;
			out += len;
			len = fixup;
			fixup = 0;
			nt = false;
			goto fixup_done;
		}
	}
	isa->gcm_final(&isa->key_data, &isa->ctx_data, tagout, *taglen);
	return (0);
}

static int
sbtls_crypt_intelisa_aead(struct sbtls_session *tls,
    const struct tls_record_layer *hdr, uint8_t *trailer, struct iovec *iniov,
    struct iovec *outiov, int iovcnt, uint64_t seqno)
{
	struct isa_gcm_struct *isa;
	struct tls_aead_data ad;
	struct tls_nonce_data nd;
	size_t noncelen, adlen, taglen;
	int ret;
	uint16_t tls_comp_len;

	isa = (struct isa_gcm_struct *)tls->cipher;

	KASSERT(isa != NULL, ("Null cipher"));
	counter_u64_add(sbtls_offload_isa_aead, 1);
	taglen = SBTLS_INTELISA_AEAD_TAGLEN;

	/* Setup the nonce */
	memcpy(nd.fixed, tls->sb_params.iv, TLS_AEAD_GCM_LEN);
	memcpy(&nd.seq, hdr + 1, sizeof(nd.seq));
	noncelen = sizeof(nd);
	/* Setup the associated data */
	tls_comp_len = ntohs(hdr->tls_length) -
	    (SBTLS_INTELISA_AEAD_TAGLEN + sizeof(nd.seq));
	ad.type = hdr->tls_type;
	ad.tls_vmajor = hdr->tls_vmajor;
	ad.tls_vminor = hdr->tls_vminor;
	ad.tls_length = htons(tls_comp_len);
	memcpy(&ad.seq, &nd.seq, sizeof(uint64_t));
	adlen = sizeof(ad);
	ret = intel_isa_seal(isa, outiov, iovcnt,
	    (uint8_t *) & nd, noncelen, iniov,
	    (uint8_t *) & ad, adlen, trailer, &taglen);

	return(ret);
}


static int
sbtls_setup_isa_cipher(struct sbtls_session *tls)
{
	uint8_t *key;
	struct fpu_kern_ctx *fpu_ctx;
	struct isa_gcm_struct *isa;


	key = tls->sb_params.crypt;
	if (key == NULL) {
		return (EINVAL);
	}
	isa = (struct isa_gcm_struct *)tls->cipher;
	fpu_ctx = fpu_kern_alloc_ctx(FPU_KERN_NOWAIT);
	if (fpu_ctx == NULL) {
		return (ENOMEM);
	}
	fpu_kern_enter(curthread, fpu_ctx, FPU_KERN_NORMAL);
	isa->gcm_pre(key, &isa->key_data);
	fpu_kern_leave(curthread, fpu_ctx);
	fpu_kern_free_ctx(fpu_ctx);
	return (0);
}

static int
sbtls_try_intelisa(struct socket *so, struct tls_so_enable *en,
    struct sbtls_session **ptls)
{
	struct sbtls_session *tls;
	struct isa_gcm_struct *isa;

	if (sbtls_use_intel_isa_gcm &&
	    ((en->crypt_algorithm == CRYPTO_AES_NIST_GMAC) ||
	    (en->crypt_algorithm == CRYPTO_AES_NIST_GCM_16)) &&
	    ((en->mac_algorithm == CRYPTO_AES_128_NIST_GMAC) ||
	    (en->mac_algorithm == CRYPTO_AES_256_NIST_GMAC))) {
		tls = sbtls_init_session(so, en, sizeof (*isa));

		if (tls == NULL) {
			return (ENOMEM);
		}
		isa = tls->cipher;
		if (en->mac_algorithm == CRYPTO_AES_128_NIST_GMAC) {
			isa->gcm_pre = aes_gcm_pre_128;
			isa->gcm_init = aes_gcm_init_128;
			isa->gcm_upd = aes_gcm_enc_128_update;
			isa->gcm_upd_nt = aes_gcm_enc_128_update_nt;
			isa->gcm_final = aes_gcm_enc_128_finalize;
		} else if (en->mac_algorithm == CRYPTO_AES_256_NIST_GMAC) {
			isa->gcm_pre = aes_gcm_pre_256;
			isa->gcm_init = aes_gcm_init_256;
			isa->gcm_upd = aes_gcm_enc_256_update;
			isa->gcm_upd_nt = aes_gcm_enc_256_update_nt;
			isa->gcm_final = aes_gcm_enc_256_finalize;
		} else {
			panic("Unknown key size -- mac alg");
		}
		tls->t_type = SBTLS_T_TYPE_INTELISA_GCM;
		tls->sb_tls_crypt = sbtls_crypt_intelisa_aead;
		*ptls = tls;
		return (0);
	}
	return (EOPNOTSUPP);
}

SYSCTL_DECL(_kern_ipc_tls);
SYSCTL_DECL(_kern_ipc_tls_counters);

SYSCTL_INT(_kern_ipc_tls, OID_AUTO, isa_gcm, CTLFLAG_RW,
    &sbtls_use_intel_isa_gcm, 1,
    "Should we use the Intel ISA GCM if available");

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, isa_aead_crypts, CTLFLAG_RD,
    &sbtls_offload_isa_aead, "Total number of Intel ISA TLS AEAD encrypts called");

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, isa_unaligned_bytes,
   CTLFLAG_RD, &intelisa_unaligned_mem_b, "Byte cnt of intel isa unaligned");

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, isa_aligned_bytes,
   CTLFLAG_RD, &intelisa_aligned_mem_b, "Byte cnt of intel isa aligned");

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, isa_unaligned,
   CTLFLAG_RD, &intelisa_unaligned_mem, "Call cnt of intel isa unaligned");

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, isa_aligned,
   CTLFLAG_RD, &intelisa_aligned_mem, "Call cnt of intel isa aligned");


struct sbtls_crypto_backend intelisa_backend  = {
	.name = "Intel ISA-L",
	.prio = 20,
	.api_version = SBTLS_API_VERSION,
	.try = sbtls_try_intelisa,
	.setup_cipher = sbtls_setup_isa_cipher,
};

static int
intelisa_init(void)
{
	sbtls_offload_isa_aead = counter_u64_alloc(M_WAITOK);
	intelisa_aligned_mem = counter_u64_alloc(M_WAITOK);
	intelisa_aligned_mem_b = counter_u64_alloc(M_WAITOK);
	intelisa_unaligned_mem = counter_u64_alloc(M_WAITOK);
	intelisa_unaligned_mem_b = counter_u64_alloc(M_WAITOK);
	return (sbtls_crypto_backend_register(&intelisa_backend));
}

static int
intelisa_module_event_handler(module_t mod, int evt, void *arg)
{
	switch (evt) {
	case MOD_LOAD:
		return (intelisa_init());
	case MOD_UNLOAD:
		return (sbtls_crypto_backend_deregister(&intelisa_backend));
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t intelisa_moduledata = {
	"intelisa",
	intelisa_module_event_handler,
	NULL
};

DECLARE_MODULE(intelisa, intelisa_moduledata, SI_SUB_PROTO_END, SI_ORDER_ANY);
