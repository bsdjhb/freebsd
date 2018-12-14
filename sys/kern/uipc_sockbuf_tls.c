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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/refcount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockbuf_tls.h>
#include <sys/sysctl.h>
#include <sys/kthread.h>
#include <machine/fpu.h>
#include <machine/vmparam.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <sys/smp.h>
#include <sys/uio.h>
#include <vm/vm.h>
#include <vm/vm_pageout.h>
#include <sys/vmmeter.h>
#include <vm/vm_page.h>

#include "opt_rss.h"
#ifdef RSS
#include <net/netisr.h>
#include <net/rss_config.h>
static int sbtls_bind_threads = 1;
#else
static int sbtls_bind_threads;
#endif



#include <opencrypto/xform.h>
#ifndef EVP_AEAD_AES_GCM_TAG_LEN
#define EVP_AEAD_AES_GCM_TAG_LEN 16
#endif

static int sbtls_offload_disable = 1;
static struct proc *sbtls_proc = NULL;
static struct rmlock sbtls_backend_lock;

int sbtls_allow_unload;
LIST_HEAD(sbtls_backend_head, sbtls_crypto_backend) sbtls_backend_head =
    LIST_HEAD_INITIALIZER(sbtls_backend_head);
static uma_zone_t zone_tlssock;
static int sbtls_number_threads;
static int sbtls_maxlen = 16384;

SYSCTL_DECL(_kern_ipc);

SYSCTL_NODE(_kern_ipc, OID_AUTO, tls, CTLFLAG_RW, 0,
    "TLS offload IPC calls");
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, stats, CTLFLAG_RW, 0,
    "TLS offload stats");
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, counters, CTLFLAG_RW, 0,
    "TLS offload counters");

SYSCTL_INT(_kern_ipc_tls, OID_AUTO, allow_unload, CTLFLAG_RDTUN,
    &sbtls_allow_unload, 0, "Allow backend crypto modules to unload");

SYSCTL_INT(_kern_ipc_tls, OID_AUTO, bind_threads, CTLFLAG_RDTUN,
    &sbtls_bind_threads, 0,
    "Bind crypto threads to cores or domains at boot");

SYSCTL_INT(_kern_ipc_tls, OID_AUTO, maxlen, CTLFLAG_RWTUN,
    &sbtls_maxlen, 0, "Maximum TLS record size");

SYSCTL_INT(_kern_ipc_tls_stats, OID_AUTO, threads, CTLFLAG_RD,
    &sbtls_number_threads, 0,
    "Number of TLS threads in thread-pool");

SYSCTL_UINT(_kern_ipc_tls, OID_AUTO, disable, CTLFLAG_RW,
    &sbtls_offload_disable, 0,
    "Disable Support of KERNEL TLS offload");

static int sbtls_cbc_disable;

SYSCTL_UINT(_kern_ipc_tls, OID_AUTO, cbc_disable, CTLFLAG_RW,
    &sbtls_cbc_disable, 1,
    "Disable Support of AES CBC crypto");

static counter_u64_t sbtls_tasks_active;

SYSCTL_COUNTER_U64(_kern_ipc_tls, OID_AUTO, tasks_active, CTLFLAG_RD,
    &sbtls_tasks_active, "Number of active tasks");

static counter_u64_t sbtls_cnt_on;

SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, so_inqueue, CTLFLAG_RD,
    &sbtls_cnt_on, "Number of sockets in queue to tasks");

/* Sysctl counters */
static counter_u64_t sbtls_offload_total;
static counter_u64_t sbtls_offload_enable_calls;
static counter_u64_t sbtls_offload_active;
static counter_u64_t sbtls_offload_failed_crypto;

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, offload_total,
    CTLFLAG_RD, &sbtls_offload_total,
    "Total succesful TLS setups (parameters set)");
SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, enable_calls,
    CTLFLAG_RD, &sbtls_offload_enable_calls,
    "Total number of TLS enable calls made");
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, active, CTLFLAG_RD,
    &sbtls_offload_active, "Total Active TLS sessions");
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, failed_crypto, CTLFLAG_RD,
    &sbtls_offload_failed_crypto, "TotalTLS crypto failures");

MALLOC_DEFINE(M_TLSSOBUF, "tls_sobuf", "TLS Socket Buffer");


struct sbtls_wq {
	struct mtx			mtx;
	STAILQ_HEAD(, mbuf_ext_pgs)	head;
	int				running;
} __aligned(CACHE_LINE_SIZE);


static struct sbtls_wq *sbtls_wq;
static void sbtls_work_thread(void *ctx);



int
sbtls_crypto_backend_register(struct sbtls_crypto_backend *be)
{
	struct sbtls_crypto_backend *curr_be, *tmp;

	if (be->api_version != SBTLS_API_VERSION) {
		printf("API version mismatch (%d vs %d) for %s\n",
		    be->api_version, SBTLS_API_VERSION,
		    be->name);
		return EINVAL;
	}

	rm_wlock(&sbtls_backend_lock);
	printf("Registering crypto method: %s with prio %d\n",
	       be->name, be->prio);
	if (LIST_EMPTY(&sbtls_backend_head)) {
		LIST_INSERT_HEAD(&sbtls_backend_head, be, next);
	} else {
		LIST_FOREACH_SAFE(curr_be, &sbtls_backend_head, next, tmp) {
			if (curr_be->prio < be->prio) {
				LIST_INSERT_BEFORE(curr_be, be, next);
				break;
			}
			if (LIST_NEXT(curr_be, next) == NULL)
				LIST_INSERT_AFTER(curr_be, be, next);
		}
	}
	rm_wunlock(&sbtls_backend_lock);
	return 0;
}

int
sbtls_crypto_backend_deregister(struct sbtls_crypto_backend *be)
{
	struct sbtls_crypto_backend *tmp;
	int err = 0;

	/*
	 * Don't error if the backend isn't registered.  This permits
	 * MOD_UNLOAD handlers to use this function unconditionally.
	 */
	rm_wlock(&sbtls_backend_lock);
	LIST_FOREACH(tmp, &sbtls_backend_head, next) {
		if (tmp == be)
			break;
	}
	if (tmp == NULL) {
		rm_wunlock(&sbtls_backend_lock);
		return (0);
	}

	if (!sbtls_allow_unload) {
		rm_wunlock(&sbtls_backend_lock);
		printf("deregistering crypto method %s is not supported\n",
		    be->name);
		return (EBUSY);
	}

	if (be->use_count) {
		err = EBUSY;
	} else {
		LIST_REMOVE(be, next);
	}
	rm_wunlock(&sbtls_backend_lock);
	return (err);
}

static uint16_t
sbtls_get_cpu(struct socket *so)
{
	uint16_t cpuid;
	struct inpcb *inp;

	inp = sotoinpcb(so);
#ifdef	RSS
	cpuid = rss_hash2cpuid(inp->inp_flowid, inp->inp_flowtype);
	if (cpuid != NETISR_CPUID_NONE)
		return (cpuid);
#endif
	/*
	 * Just use the flowid to shard connections in a repeatable fashion.
	 * Note that some crypto backends rely on the serialization provided by
	 * having the same connection use the same queue.
	 */
	cpuid = inp->inp_flowid % (sbtls_number_threads);
	return (cpuid);

}


static void
sbtls_init(void *st __unused)
{
	int domain, error, i, j;
	cpuset_t mask;
	struct pcpu *pc;
	struct thread **sbtls_ctx;

	/*
	 * Initialize the task's to run the TLS work. We create a task
	 * per cpu. Each task is separate with a separate queue.
	 */

	/* Init counters */
	sbtls_tasks_active = counter_u64_alloc(M_WAITOK);
	sbtls_cnt_on = counter_u64_alloc(M_WAITOK);
	sbtls_offload_total = counter_u64_alloc(M_WAITOK);
	sbtls_offload_enable_calls = counter_u64_alloc(M_WAITOK);
	sbtls_offload_active = counter_u64_alloc(M_WAITOK);
	sbtls_offload_failed_crypto = counter_u64_alloc(M_WAITOK);

	rm_init(&sbtls_backend_lock, "sbtls crypto backend lock");

	sbtls_number_threads = mp_ncpus;

	sbtls_wq = malloc(sizeof(*sbtls_wq) * mp_ncpus, M_TLSSOBUF,
	    M_WAITOK | M_ZERO);

	zone_tlssock = uma_zcreate("sbtls_session",
	    sizeof(struct sbtls_session),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_CACHE, 0);

	sbtls_ctx = malloc((sizeof(struct thread *) * mp_ncpus),
	    M_TLSSOBUF, M_WAITOK | M_ZERO);

	error = kproc_kthread_add(sbtls_work_thread, &sbtls_wq[0],
	    &sbtls_proc, &sbtls_ctx[0],  0, 0, "TLS_proc", "tls_thr_0");

	if (error)
		panic("Can't start TLS_proc err:%d", error);

	for (i = 1; i < mp_ncpus; i++) {
		error = kthread_add(sbtls_work_thread, &sbtls_wq[i],
		    sbtls_proc, &sbtls_ctx[i], 0, 0, "tls_thr_%d", i);
		if (error)
			panic("Can't add TLS_thread %d err:%d", i, error);
	}
	/*
	 * Bind threads to cores.  If sbtls_bind_threads is > 1, then
	 * we bind to the NUMA domain.
	 */
	if (sbtls_bind_threads) {
		CPU_FOREACH(i) {
			CPU_ZERO(&mask);
			if (sbtls_bind_threads > 1) {
				pc = pcpu_find(i);
				domain = pc->pc_domain;
				CPU_FOREACH(j) {
					pc = pcpu_find(j);
					if (pc->pc_domain == domain)
						CPU_SET(j, &mask);
				}
			} else {
				CPU_SET(i, &mask);
			}
			error |= cpuset_setthread(sbtls_ctx[i]->td_tid,
			    &mask);
		}
		if (error) {
			printf("unable to bind crypto threads\n");
		}
	}
	printf("SBTLS: Initialized %d threads\n", sbtls_number_threads);
}

SYSINIT(sbtls, SI_SUB_SMP + 1, SI_ORDER_ANY, sbtls_init, NULL);



struct sbtls_session *
sbtls_init_session(struct socket *so, struct tls_so_enable *en, size_t size)
{
	static int warn_once = 0;
	struct sbtls_session *tls;
	void *cipher;

	tls = uma_zalloc(zone_tlssock, M_NOWAIT | M_ZERO);
	if (tls == NULL)
		return (NULL);

	cipher = malloc(size, M_TLSSOBUF, M_NOWAIT | M_ZERO);
	if (cipher == NULL) {
		uma_zfree(zone_tlssock, tls);
		return (NULL);
	}
	tls->cipher = cipher;
	refcount_init(&tls->refcount, 1);

	/* cache cpu index */
	tls->sb_tsk_instance = sbtls_get_cpu(so);

	tls->sb_params.crypt_algorithm = en->crypt_algorithm;
	tls->sb_params.mac_algorithm = en->mac_algorithm;
	tls->sb_params.tls_vmajor = en->tls_vmajor;
	tls->sb_params.tls_vminor = en->tls_vminor;

	/* Determine max size */
	if (tls->sb_params.tls_vmajor == TLS_MAJOR_VER_ONE) {
		/* 
		 *  note that 1.3 was supposed to go to 64K, but that 
		 * was shot down
		 */
		tls->sb_params.sb_maxlen = TLS_MAX_MSG_SIZE_V10_2;

	} else {
		/*
		 * Unknown play it safe and frag at V1.0-2 size
		 * (16k).
		 */
		if (warn_once == 0) {
			printf("Warning saw TLS version major:%d -- unknown size limited to 16k\n",
			    tls->sb_params.tls_vmajor);
			warn_once = 1;
		}
		tls->sb_params.sb_maxlen = TLS_MAX_MSG_SIZE_V10_2;
	}
	if (tls->sb_params.sb_maxlen > sbtls_maxlen)
		tls->sb_params.sb_maxlen = sbtls_maxlen;

	/* Set the header and trailer lengths. */
	tls->sb_params.tls_hlen = sizeof(struct tls_record_layer);
	switch (en->crypt_algorithm) {
	case CRYPTO_AES_NIST_GCM_16:
		tls->sb_params.tls_hlen += sizeof(uint64_t);
		tls->sb_params.tls_tlen = 16;
		tls->sb_params.tls_bs = 1;
		break;
	case CRYPTO_AES_CBC:
		switch (en->mac_algorithm) {
		case CRYPTO_SHA1_HMAC:
			if (en->tls_vmajor == TLS_MINOR_VER_ZERO) {
				/* Implicit IV, no nonce. */
			} else {
				tls->sb_params.tls_hlen += AES_BLOCK_LEN;
			}
			tls->sb_params.tls_tlen = AES_BLOCK_LEN +
			    SHA1_HASH_LEN;
			break;
		case CRYPTO_SHA2_256_HMAC:
			tls->sb_params.tls_hlen += AES_BLOCK_LEN;
			tls->sb_params.tls_tlen = AES_BLOCK_LEN +
			    SHA2_256_HASH_LEN;
			break;
		default:
			panic("invalid hmac");
		}
		tls->sb_params.tls_bs = AES_BLOCK_LEN;
		break;
	default:
		panic("invalid cipher");
	}

	KASSERT(tls->sb_params.tls_hlen <= MBUF_PEXT_HDR_LEN,
	    ("TLS header length too long: %d", tls->sb_params.tls_hlen));
	KASSERT(tls->sb_params.tls_tlen <= MBUF_PEXT_TRAIL_LEN,
	    ("TLS trailer length too long: %d", tls->sb_params.tls_tlen));
	counter_u64_add(sbtls_offload_active, 1);
	return (tls);
}

static void
sbtls_cleanup(struct sbtls_session *tls)
{
	void *cipher;

	if (NULL != (cipher = tls->cipher)) {
		counter_u64_add(sbtls_offload_active, -1);
		tls->cipher = NULL;
		if (tls->be != NULL && tls->be->clean_cipher != NULL)
			tls->be->clean_cipher(tls, cipher);
		free(cipher, M_TLSSOBUF);
	}
	if (tls->sb_params.hmac_key) {
		explicit_bzero(tls->sb_params.hmac_key,
		    tls->sb_params.hmac_key_len);
		free(tls->sb_params.hmac_key, M_TLSSOBUF);
		tls->sb_params.hmac_key = NULL;
		tls->sb_params.hmac_key_len = 0;
	}
	if (tls->sb_params.crypt) {
		explicit_bzero(tls->sb_params.crypt,
		    tls->sb_params.crypt_key_len);
		free(tls->sb_params.crypt, M_TLSSOBUF);
		tls->sb_params.crypt = NULL;
		tls->sb_params.crypt_key_len = 0;
	}
	if (tls->sb_params.iv) {
		explicit_bzero(tls->sb_params.iv, tls->sb_params.iv_len);
		free(tls->sb_params.iv, M_TLSSOBUF);
		tls->sb_params.iv = NULL;
		tls->sb_params.iv_len = 0;
	}
}

int
sbtls_crypt_tls_enable(struct socket *so, struct tls_so_enable *en)
{
	struct rm_priotracker prio;
	struct sbtls_crypto_backend *be;
	struct sbtls_session *tls;
	int error;

	if (sbtls_offload_disable) {
		return (ENOTSUP);
	}
	counter_u64_add(sbtls_offload_enable_calls, 1);
	if (so->so_proto->pr_protocol != IPPROTO_TCP) {
		/* We can only support TCP for now */
		return (EINVAL);
	}

	if (so->so_snd.sb_tls_info != NULL) {
		/* Already setup, you get to do it once per socket. */
		return (EALREADY);
	}

	if (en->crypt_algorithm == CRYPTO_AES_CBC && sbtls_cbc_disable)
		return (ENOTSUP);

	/* TLS requires ext pgs */
	if (mb_use_ext_pgs == 0)
		return (ENXIO);

	/* XXX: We could just rely on copyin to fault on NULL. */
	if ((en->hmac_key_len != 0 && en->hmac_key == NULL) ||
	    (en->crypt_key_len != 0 && en->crypt == NULL) ||
	    (en->iv_len != 0 && en->iv == NULL))
		return (EFAULT);

	/* Only TLS 1.0 - 1.2 are supported. */
	if (en->tls_vmajor != TLS_MAJOR_VER_ONE)
		return (EINVAL);
	if (en->tls_vminor < TLS_MINOR_VER_ZERO ||
	    en->tls_vminor > TLS_MINOR_VER_TWO)
		return (EINVAL);

	if (en->hmac_key_len < 0 || en->hmac_key_len > TLS_MAX_PARAM_SIZE)
		return (EINVAL);
	if (en->crypt_key_len < 0 || en->crypt_key_len > TLS_MAX_PARAM_SIZE)
		return (EINVAL);
	if (en->iv_len < 0 || en->iv_len > TLS_MAX_PARAM_SIZE)
		return (EINVAL);

	/* All supported algorithms require a cipher key. */
	if (en->crypt_key_len == 0)
		return (EINVAL);

	/* Common checks for supported algorithms. */
	switch (en->crypt_algorithm) {
	case CRYPTO_AES_NIST_GCM_16:
		/*
		 * mac_algorithm isn't used, but permit GMAC values
		 * for compatibility.
		 */
		switch (en->mac_algorithm) {
		case 0:
		case CRYPTO_AES_128_NIST_GMAC:
		case CRYPTO_AES_192_NIST_GMAC:
		case CRYPTO_AES_256_NIST_GMAC:
			break;
		default:
			return (EINVAL);
		}
		if (en->hmac_key_len != 0)
			return (EINVAL);
		if (en->iv_len != TLS_AEAD_GCM_LEN)
			return (EINVAL);
		break;
	case CRYPTO_AES_CBC:
		switch (en->mac_algorithm) {
		case CRYPTO_SHA1_HMAC:
		case CRYPTO_SHA2_256_HMAC:
			break;
		default:
			return (EINVAL);
		}
		if (en->hmac_key_len == 0)
			return (EINVAL);
		/* XXX: Checks on iv_len? */
	default:
		return (EINVAL);
	}

	/*
	 * Now lets find the algorithms if possible. The idea here is we
	 * prioritize what to use. 1) Hardware, if we have an offload card
	 * use it. 2) INTEL ISA lib which is faster than BoringSSL. 3)
	 * Finally if nothing else we try boring SSL.
	 * 
	 * As noted in the sbtls_try_hardware comments, that is more historic
	 * and needs to be re-written with async in mind as well as folding
	 * the SID/et.al. into its own structure. But that will come when we
	 * intergrate the intel QAT card.
	 */

	if (sbtls_allow_unload)
		rm_rlock(&sbtls_backend_lock, &prio);
	tls = NULL;
	LIST_FOREACH(be, &sbtls_backend_head, next) {
		if (be->try(so, en, &tls) == 0)
			break;
		KASSERT(tls == NULL,
		    ("sbtls backend try failed but created a session"));
	}
	if (tls != NULL) {
		if (sbtls_allow_unload)
			be->use_count++;
		tls->be = be;
		so->so_snd.sb_tls_info = tls;
	}
	if (sbtls_allow_unload)
		rm_runlock(&sbtls_backend_lock, &prio);
	if (tls == NULL)
		return (ENOTSUP);

	/* Now lets get in the keys and such */
	if (en->hmac_key_len != 0) {
		tls->sb_params.hmac_key_len = en->hmac_key_len;
		tls->sb_params.hmac_key = malloc(en->hmac_key_len,
		    M_TLSSOBUF, M_NOWAIT);
		if (tls->sb_params.hmac_key == NULL) {
			error = ENOMEM;
			goto out;
		}
		error = copyin_nofault(en->hmac_key, tls->sb_params.hmac_key,
		    en->hmac_key_len);
		if (error)
			goto out;
	}

	tls->sb_params.crypt_key_len = en->crypt_key_len;
	tls->sb_params.crypt = malloc(en->crypt_key_len, M_TLSSOBUF, M_NOWAIT);
	if (tls->sb_params.crypt == NULL) {
		error = ENOMEM;
		goto out;
	}
	error = copyin_nofault(en->crypt, tls->sb_params.crypt,
	    en->crypt_key_len);
	if (error)
		goto out;

	/*
	 * We allow these to be set as a number to indicate how many random
	 * bytes to send if iv is present, then its for an AEAD fixed part
	 * nonce.
	 */
	if (en->iv_len != 0) {
		tls->sb_params.iv = malloc(en->iv_len,
		    M_TLSSOBUF, M_NOWAIT);
		tls->sb_params.iv_len = en->iv_len;
		if (tls->sb_params.iv == NULL) {
			error = ENOMEM;
			goto out;
		}
		error = copyin_nofault(en->iv, tls->sb_params.iv,
		    en->iv_len);
		if (error)
			goto out;
	}
	error = tls->be->setup_cipher(tls);
	if (error)
		goto out;

	/* TODO: Possibly defer setting sb_tls_info to here. */
	so->so_snd.sb_tls_flags |= SB_TLS_ACTIVE;
	if (tls->sb_tls_crypt == NULL)
		so->so_snd.sb_tls_flags |= SB_TLS_IFNET;

	counter_u64_add(sbtls_offload_total, 1);

	return (0);

out:
	sbtlsdestroy(&so->so_snd);
	return (error);
}

void
sbtls_destroy(struct sbtls_session *tls)
{
	struct rm_priotracker prio;

	sbtls_cleanup(tls);
	if (tls->be != NULL && sbtls_allow_unload) {
		rm_rlock(&sbtls_backend_lock, &prio);
		tls->be->use_count--;
		rm_runlock(&sbtls_backend_lock, &prio);
	}
	uma_zfree(zone_tlssock, tls);
}

void
sbtlsdestroy(struct sockbuf *sb)
{
	struct sbtls_session *tls;

	tls = sb->sb_tls_info;
	sb->sb_tls_info = NULL;
	sb->sb_tls_flags = 0;
	if (tls != NULL)
		sbtls_free(tls);
}

void
sbtls_seq(struct sockbuf *sb, struct mbuf *m)
{
	struct mbuf_ext_pgs *pgs;
	struct tls_record_layer *tlshdr;
	uint64_t seqno;

	for (; m != NULL; m = m->m_next) {
		if (0 == (m->m_flags & M_NOMAP))
			panic("tls with normal mbuf\n");

		pgs = (void *)m->m_ext.ext_buf;
		pgs->seqno = sb->sb_tls_seqno;

		/*
		 * Store the sequence number in the TLS header as the
		 * nonce for GCM.
		 */
		if (pgs->tls->sb_params.crypt_algorithm ==
		    CRYPTO_AES_NIST_GCM_16) {
			tlshdr = (void *)pgs->hdr;
			seqno = htobe64(pgs->seqno);
			memcpy(tlshdr + 1, &seqno, sizeof(seqno));
		}
		sb->sb_tls_seqno++;
	}
}

int
sbtls_frame(struct mbuf **top, struct sbtls_session *tls, int *enq_cnt,
    uint8_t record_type)
{
	struct tls_record_layer *tlshdr;
	struct mbuf *m;
	struct mbuf_ext_pgs *pgs;
	uint16_t tls_len;
	int maxlen;

	maxlen = tls->sb_params.sb_maxlen;
	*enq_cnt = 0;
	for (m = *top; m != NULL; m = m->m_next) {
		/*
		 * We expect whoever constructed the chain
		 * to have put no more than maxlen in each
		 * mbuf.
		 */
		if (m->m_len > maxlen || m->m_len == 0)
			return (EINVAL);


		tls_len = m->m_len;

		/*
		 * we don't yet support inserting framing into
		 * normal mbuf chains.  For now, just panic if
		 * we see one.  Eventually, we'll be sticking
		 * a tls hdr mbuf at the start, which is why
		 * top is a pointer to a pointer
		 */
		KASSERT(((m->m_flags & M_NOMAP) == M_NOMAP),
		    ("Can't Frame %p: not nomap mbuf(top = %p)\n", m, *top));


		pgs = (void *)m->m_ext.ext_buf;

		/* Save a reference to the session. */
		pgs->tls = sbtls_hold(tls);

		pgs->hdr_len = tls->sb_params.tls_hlen;
		pgs->trail_len = tls->sb_params.tls_tlen;
		if (tls->sb_params.crypt_algorithm == CRYPTO_AES_CBC) {
			int bs, delta;

			/*
			 * CBC pads messages to a multiple of block
			 * size.  Try to figure out what the final
			 * trailer len will be.  Note that the padding
			 * calculation must include the digest len, as
			 * it is not always a multiple of the block
			 * size.  tls->sb_params.sb_tls_tlen is the
			 * max possible len (padding + digest), so
			 * what we're doing here is actually removing
			 * padding.
			 */
			bs = tls->sb_params.tls_bs;
			delta = (tls_len + tls->sb_params.tls_tlen) &
			    (bs - 1);
			pgs->trail_len -= delta;
		}
		m->m_len += pgs->hdr_len + pgs->trail_len;

		/* Populate the TLS header. */
		tlshdr = (void *)pgs->hdr;
		tlshdr->tls_vmajor = tls->sb_params.tls_vmajor;
		tlshdr->tls_vminor = tls->sb_params.tls_vminor;
		tlshdr->tls_type = record_type;
		tlshdr->tls_length = htons(m->m_len - sizeof(*tlshdr));

		/*
		 * For GCM, the sequence number is stored in the
		 * header by sbtls_seq().  For CBC, a random nonce is
		 * inserted for TLS 1.1+.
		 */
		if (tls->sb_params.crypt_algorithm == CRYPTO_AES_CBC &&
		    tls->sb_params.tls_vminor >= TLS_MINOR_VER_ONE)
			arc4rand(tlshdr + 1, AES_BLOCK_LEN, 0);

		if (tls->sb_tls_crypt != NULL) {
			/* mark mbuf not-ready, to be cleared when encrypted */
			m->m_flags |= M_NOTREADY;
			pgs->nrdy = pgs->npgs;
			*enq_cnt += pgs->npgs;
		}
	}
	return (0);
}


void
sbtls_enqueue_to_free(struct mbuf_ext_pgs *pgs)
{
	struct sbtls_wq *wq;
	int running;

	/* Mark it for freeing. */
	pgs->mbuf = NULL;
	wq = &sbtls_wq[pgs->tls->sb_tsk_instance];
	mtx_lock(&wq->mtx);
	STAILQ_INSERT_TAIL(&wq->head, pgs, stailq);
	running = wq->running;
	mtx_unlock(&wq->mtx);
	if (!running)
		wakeup(wq);
}

void
sbtls_enqueue(struct mbuf *m, struct socket *so, int page_count)
{
	struct mbuf_ext_pgs *pgs;
	struct sbtls_wq *wq;
	int running;

	KASSERT(((m->m_flags & (M_NOMAP | M_NOTREADY)) ==
		(M_NOMAP | M_NOTREADY)),
	    ("%p not unready & nomap mbuf\n", m));

	if (page_count == 0)
		panic("enq_cnt = 0\n");

	pgs = (void *)m->m_ext.ext_buf;

	KASSERT(pgs->tls->sb_tls_crypt != NULL, ("ifnet TLS mbuf"));

	pgs->enc_cnt = page_count;
	pgs->mbuf = m;

	/*
	 * Save a pointer to the socket.  The caller is responsible
	 * for taking an additional reference via soref().
	 */
	pgs->so = so;

	wq = &sbtls_wq[pgs->tls->sb_tsk_instance];
	mtx_lock(&wq->mtx);
	STAILQ_INSERT_TAIL(&wq->head, pgs, stailq);
	running = wq->running;
	mtx_unlock(&wq->mtx);
	if (!running)
		wakeup(wq);
	counter_u64_add(sbtls_cnt_on, 1);
}

static void
sbtls_boring_fixup(struct sbtls_session *tls, struct sockbuf *sb,
    struct mbuf *m, struct iovec *dst_iov, int *pgcnt)
{
	struct mbuf_ext_pgs *pgs;
	struct vm_page *pg;
	struct iovec *iov;
	int i, pg_delta, tag_delta, len, off;


	/*
	 * Boring CBC will shuffle data around in order to better
	 * align things.  We need to account for several different
	 * cases, where data can move into or out of the first or
	 * last segment.  We do not expect any middle segments to
	 * be impacted.
	 *
	 * Holding the sb lock is not required, when we are only
	 * changing the internal layout of the mbuf; we are not
	 * changing its length.  Because the mbuf is marked
	 * M_NOTREADY, and nothing in the socket buffer code that
	 * deals with M_NOTREADY can look inside one, changing the
	 * layout is safe.
	 *
	 * The exception is removing pages, which is reflected in
	 * decrease in ext_size and sb_mbcnt.  This does require
	 * the lock.
	 *
	 * Note that if the session is closed, we avoid fixing up
	 * the mbuf.  This is because we both don't care what's
	 * in the mbuf at this point (since it cannot be sent),
	 * and because sb_free() may have already run and accounted
	 * for the page we're about to remove when it decremented
	 * sb_mbcnt.
	 */

	pgs = (void *)m->m_ext.ext_buf;
	tag_delta = tls->taglen - pgs->trail_len;
	pgs->trail_len += tag_delta;
	off = pgs->first_pg_off;
	for (i = 0, iov = dst_iov; i < pgs->npgs; i++, iov++) {
		len = mbuf_ext_pg_len(pgs, i, off);
		off = 0;
		pg_delta = iov->iov_len - len;
		if (pg_delta == 0)
			continue;

		/* try to fix the mess boring has made */

		if (pgs->npgs == 1 && iov->iov_len == 0) {
			/*
			 *  if the only page is removed, then downgrade
			 * it to a normal mbuf
			 */

			SOCKBUF_LOCK(sb);
			mb_ext_pgs_downgrade(m);
			sb->sb_mbcnt -= PAGE_SIZE;
			SOCKBUF_UNLOCK(sb);
			/*
			 * must return here, as pgs has been freed
			 * Note: We must not decease pgcnt!  This
			 * is required so that sbready will ready the
			 * plain mbuf.
			 */
			return;
		} else if (i == pgs->npgs - 1) {
			/*
			 * Handle changes to the last page
			 */

			pgs->last_pg_len = iov->iov_len;
			if (pgs->last_pg_len == 0) {
				/* last segment entirely removed */
				SOCKBUF_LOCK(sb);
				*pgcnt = *pgcnt + 1;
				pg = PHYS_TO_VM_PAGE(pgs->pa[i]);
				pg->flags &= ~PG_ZERO;
				vm_page_free_toq(pg);
				vm_wire_sub(1);
				pgs->last_pg_len = PAGE_SIZE;
				pgs->npgs -= 1;
				pgs->nrdy -= 1;
				/*
				 * If this is the only page, then its
				 * length must reflect the 1st page off
				 */
				if (pgs->npgs == 1)
					pgs->last_pg_len -=
					    pgs->first_pg_off;
				sb->sb_mbcnt -= PAGE_SIZE;
				m->m_ext.ext_size -= PAGE_SIZE;
				SOCKBUF_UNLOCK(sb);
			}
		} else {
			/*
			 * Handle changes to the first page
			 */

			if (i != 0)
				panic("boring removed dat in the middle: %p %p %p %d %d?!?!\n",
				    m, pgs, dst_iov, pg_delta, i);
			if (iov->iov_len == 0) {
				/* first segment entirely removed */
				SOCKBUF_LOCK(sb);
				*pgcnt = *pgcnt + 1;
				pg = PHYS_TO_VM_PAGE(pgs->pa[i]);
				pg->flags &= ~PG_ZERO;
				vm_page_free_toq(pg);
				vm_wire_sub(1);
				pgs->first_pg_off = 0;
				pgs->npgs -= 1;
				pgs->nrdy -= 1;
				/* move remainder of pgs down */
				ovbcopy(&pgs->pa[1], &pgs->pa[0],
				    pgs->npgs * sizeof(pgs->pa[0]));

				/*
				 * back up loop index to look at the
				 * page we just moved into place, else
				 * it will be skipped over
				 */
				i--;

				sb->sb_mbcnt -= PAGE_SIZE;
				m->m_ext.ext_size -= PAGE_SIZE;
				SOCKBUF_UNLOCK(sb);
			} else {
				/*
				 * Remove data from the first segment:
				 *
				 * We have no way to express the length of
				 * the first segment except for the offset.
				 * However, boring reduces the length
				 * and leaves the offset the same.  The only
				 * way to recover is to copy the data so
				 * that it starts at the adjusted offset.
				 *
				 * Note: pg_delta is negative, that is why
				 * it is subtracted.
				 *
				 */
				ovbcopy(iov->iov_base,
				    (caddr_t)iov->iov_base - pg_delta,
				    iov->iov_len);
				pgs->first_pg_off = PAGE_SIZE - iov->iov_len;
			}
		}
	}
	MBUF_EXT_PGS_ASSERT_SANITY(pgs);
}

static __noinline void
sbtls_encrypt(struct mbuf_ext_pgs *pgs)
{
	uint64_t seqno;
	struct sbtls_session *tls;
	struct socket *so;
	struct mbuf *top, *m;
	vm_paddr_t parray[1+ btoc(TLS_MAX_MSG_SIZE_V10_2)];
	struct iovec src_iov[1 + btoc(TLS_MAX_MSG_SIZE_V10_2)];
	struct iovec dst_iov[1 + btoc(TLS_MAX_MSG_SIZE_V10_2)];
	vm_page_t pg;
	int off, len, npages, page_count, error, i, wire_adj;
	bool is_anon;
	bool boring = false;

	so = pgs->so;
	tls = pgs->tls;
	top = pgs->mbuf;
	KASSERT(tls != NULL, ("tls = NULL, top = %p, pgs = %p\n", top, pgs));
	KASSERT(so != NULL, ("so = NULL, top = %p, pgs = %p\n", top, pgs));
	pgs->so = NULL;
	pgs->mbuf = NULL;
	npages = 0;
	boring = (tls->t_type == SBTLS_T_TYPE_BSSL);
	/*
	 *  each TLS record is in a single mbuf.  Do
	 *  one at a time
	 */
	page_count = pgs->enc_cnt;
	error = 0;
	for (m = top; m != NULL && npages != page_count; m = m->m_next) {
		pgs = (void *)m->m_ext.ext_buf;

		KASSERT(pgs->tls == tls,
		    ("different TLS sessions in a single mbuf chain: %p vs %p",
		    tls, pgs->tls));
		KASSERT(((m->m_flags & (M_NOMAP | M_NOTREADY)) ==
			(M_NOMAP | M_NOTREADY)),
		    ("%p not unready & nomap mbuf (top = %p)\n", m, top));

		/*
		 * If this is not a file-backed page, it can
		 * be used for in-place encryption.
		 */
		is_anon = M_WRITABLE(m);

		off = pgs->first_pg_off;
		seqno = pgs->seqno;
		wire_adj = 0;
		for (i = 0; i < pgs->npgs; i++, off = 0) {
			len = mbuf_ext_pg_len(pgs, i, off);
			src_iov[i].iov_len = len;
			src_iov[i].iov_base =
			    (char *)(void *)PHYS_TO_DMAP(pgs->pa[i]) + off;

			if (is_anon) {
				dst_iov[i].iov_base = src_iov[i].iov_base;
				dst_iov[i].iov_len = src_iov[i].iov_len;
				continue;
			}
			/* allocate pages needed for encryption */
retry_page:
			pg = vm_page_alloc(NULL, 0, VM_ALLOC_SYSTEM |
			    VM_ALLOC_NOOBJ | VM_ALLOC_NODUMP);
			if (pg == NULL) {
				if (wire_adj)
					vm_wire_add(wire_adj);
				wire_adj = 0;
				vm_wait(NULL);
				goto retry_page;
			}
			wire_adj++;
			parray[i] = VM_PAGE_TO_PHYS(pg);
			dst_iov[i].iov_base =
			    (char *)(void *)PHYS_TO_DMAP(parray[i]) + off;
			dst_iov[i].iov_len = len;
		}

		npages += i;
		if (wire_adj)
			vm_wire_add(wire_adj);

		error = (*tls->sb_tls_crypt)(tls,
		    (struct tls_record_layer *)pgs->hdr,
		    pgs->trail, src_iov, dst_iov, i, seqno);
		if (error) {
			/* WTF can we do..? */
			counter_u64_add(sbtls_offload_failed_crypto, 1);
			break;
		}
		if (!is_anon) {
			/* Free the old pages that backed the mbuf */
			m->m_ext.ext_free(m);

			/* Replace them with the new pages just alloc'ed */
			for (i = 0; i < pgs->npgs; i++)
				pgs->pa[i] = parray[i];

			/*
			 * Switch the free routine to basic one.
			 */
			m->m_ext.ext_free = mb_free_mext_pgs;
		}
		if (boring) {
			int pgs_removed = 0;
			sbtls_boring_fixup(tls, &so->so_snd, m, dst_iov,
			    &pgs_removed);
			npages -= pgs_removed;
			page_count -= pgs_removed;
		}

		/* XXX: Not sure if this is really needed, but can't hurt? */
		pgs->tls = NULL;
		sbtls_free(tls);
	}

	CURVNET_SET(so->so_vnet);
	if (error == 0) {
		(void) (*so->so_proto->pr_usrreqs->pru_ready)(so, top, npages);
	} else {
		so->so_proto->pr_usrreqs->pru_abort(so);
		so->so_error = EIO;
		mb_free_notready(top, page_count);
	}

	SOCK_LOCK(so);
	sorele(so);
	CURVNET_RESTORE();
}

static void
sbtls_work_thread(void *ctx)
{
	struct sbtls_wq *wq = ctx;
	struct mbuf_ext_pgs *p, *n;
	struct sbtls_session *tls;


	STAILQ_INIT(&wq->head);
	fpu_kern_thread(0);
	mtx_init(&wq->mtx, "sbtls work queue lock", "tls_wqlock",
	    MTX_DEF);
	mtx_lock(&wq->mtx);

	while (1) {
		wq->running = 0;
		mtx_sleep(wq, &wq->mtx, 0, "sbtls wq", 0);
		wq->running = 1;
		while (NULL != (p = STAILQ_FIRST(&wq->head))) {
			/* pull the entire list off */
			STAILQ_INIT(&wq->head);
			mtx_unlock(&wq->mtx);
			/* encrypt or free each TLS record on the list */
			while (p != NULL) {
				n = STAILQ_NEXT(p, stailq);
				STAILQ_NEXT(p, stailq) = NULL;
				if (p->mbuf != NULL) {
					sbtls_encrypt(p);
					counter_u64_add(sbtls_cnt_on, -1);
				} else {
					/* records w/null mbuf are freed */
					tls = p->tls;
					sbtls_free(tls);
					uma_zfree(zone_extpgs, p);
				}
				p = n;
			}
			mtx_lock(&wq->mtx);
		}
	}
}
