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
#include <sys/taskqueue.h>
#include <sys/kthread.h>
#include <machine/fpu.h>
#include <machine/vmparam.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
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
static uint16_t sbtls_cpuid_lookup[MAXCPU];

SYSCTL_DECL(_kern_ipc);

SYSCTL_NODE(_kern_ipc, OID_AUTO, tls, CTLFLAG_RW, 0,
    "TLS offload IPC calls");
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, stats, CTLFLAG_RW, 0,
    "TLS offload stats");
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, counters, CTLFLAG_RW, 0,
    "TLS offload counters");

SYSCTL_INT(_kern_ipc_tls, OID_AUTO, allow_unload, CTLFLAG_RDTUN,
    &sbtls_allow_unload, 0, "Allow software crypto modules to unload");

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
    "Disable Support of AES-CBC crypto");

static counter_u64_t sbtls_tasks_active;

SYSCTL_COUNTER_U64(_kern_ipc_tls, OID_AUTO, tasks_active, CTLFLAG_RD,
    &sbtls_tasks_active, "Number of active tasks");

static counter_u64_t sbtls_cnt_on;

SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, so_inqueue, CTLFLAG_RD,
    &sbtls_cnt_on, "Number of TLS records in queue to tasks for SW crypto");

/* Sysctl counters */
static counter_u64_t sbtls_offload_total;
static counter_u64_t sbtls_offload_enable_calls;
static counter_u64_t sbtls_offload_active;
static counter_u64_t sbtls_offload_failed_crypto;
static counter_u64_t sbtls_switch_to_ifnet;
static counter_u64_t sbtls_switch_to_sw;
static counter_u64_t sbtls_switch_failed;
static counter_u64_t sbtls_sw_cbc;
static counter_u64_t sbtls_sw_gcm;
static counter_u64_t sbtls_ifnet_cbc;
static counter_u64_t sbtls_ifnet_gcm;

SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, offload_total,
    CTLFLAG_RD, &sbtls_offload_total,
    "Total successful TLS setups (parameters set)");
SYSCTL_COUNTER_U64(_kern_ipc_tls_counters, OID_AUTO, enable_calls,
    CTLFLAG_RD, &sbtls_offload_enable_calls,
    "Total number of TLS enable calls made");
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, active, CTLFLAG_RD,
    &sbtls_offload_active, "Total Active TLS sessions");
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, failed_crypto, CTLFLAG_RD,
    &sbtls_offload_failed_crypto, "Total TLS crypto failures");
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, switch_to_ifnet, CTLFLAG_RD,
    &sbtls_switch_to_ifnet, "TLS sessions switched from SW to ifnet");
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, switch_to_sw, CTLFLAG_RD,
    &sbtls_switch_to_sw, "TLS sessions switched from ifnet to SW");
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, switch_failed, CTLFLAG_RD,
    &sbtls_switch_failed, "TLS sessions unable to switch between SW and ifnet");

SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, sw, CTLFLAG_RD, 0,
    "Software TLS session stats");
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, ifnet, CTLFLAG_RD, 0,
    "Hardware (ifnet) TLS session stats");

SYSCTL_COUNTER_U64(_kern_ipc_tls_sw, OID_AUTO, cbc, CTLFLAG_RD, &sbtls_sw_cbc,
    "Active number of software TLS sessions using AES-CBC");
SYSCTL_COUNTER_U64(_kern_ipc_tls_sw, OID_AUTO, gcm, CTLFLAG_RD, &sbtls_sw_gcm,
    "Active number of software TLS sessions using AES-GCM");
SYSCTL_COUNTER_U64(_kern_ipc_tls_ifnet, OID_AUTO, cbc, CTLFLAG_RD,
    &sbtls_ifnet_cbc,
    "Active number of ifnet TLS sessions using AES-CBC");
SYSCTL_COUNTER_U64(_kern_ipc_tls_ifnet, OID_AUTO, gcm, CTLFLAG_RD,
    &sbtls_ifnet_gcm,
    "Active number of ifnet TLS sessions using AES-GCM");

static int sbtls_ifnet_permitted;

SYSCTL_UINT(_kern_ipc_tls_ifnet, OID_AUTO, permitted, CTLFLAG_RWTUN,
    &sbtls_ifnet_permitted, 1,
    "Whether to permit hardware (ifnet) TLS sessions: 0 = never, 1 = always, "
    "2 = defer to TCP stack flag");

MALLOC_DEFINE(M_TLSSOBUF, "tls_sobuf", "TLS Socket Buffer");


struct sbtls_wq {
	struct mtx			mtx;
	STAILQ_HEAD(, mbuf_ext_pgs)	head;
	int				running;
} __aligned(CACHE_LINE_SIZE);


static struct sbtls_wq *sbtls_wq;

static void sbtls_cleanup(struct sbtls_session *tls);
static void sbtls_reset_send_tag(void *context, int pending);
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
	cpuid = sbtls_cpuid_lookup[inp->inp_flowid % sbtls_number_threads];
	return (cpuid);

}


static void
sbtls_init(void *st __unused)
{
	int error, i;
	cpuset_t mask;
	struct pcpu *pc;
	struct thread *sbtls_td;

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
	sbtls_switch_to_ifnet = counter_u64_alloc(M_WAITOK);
	sbtls_switch_to_sw = counter_u64_alloc(M_WAITOK);
	sbtls_switch_failed = counter_u64_alloc(M_WAITOK);
	sbtls_ifnet_cbc = counter_u64_alloc(M_WAITOK);
	sbtls_ifnet_gcm = counter_u64_alloc(M_WAITOK);
	sbtls_sw_cbc = counter_u64_alloc(M_WAITOK);
	sbtls_sw_gcm = counter_u64_alloc(M_WAITOK);

	rm_init(&sbtls_backend_lock, "sbtls crypto backend lock");

	sbtls_wq = malloc(sizeof(*sbtls_wq) * (mp_maxid + 1), M_TLSSOBUF,
	    M_WAITOK | M_ZERO);

	zone_tlssock = uma_zcreate("sbtls_session",
	    sizeof(struct sbtls_session),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_CACHE, 0);

	CPU_FOREACH(i) {
		STAILQ_INIT(&sbtls_wq[i].head);
		mtx_init(&sbtls_wq[i].mtx, "sbtls work queue lock",
		    "tls_wqlock", MTX_DEF);
		error = kproc_kthread_add(sbtls_work_thread, &sbtls_wq[i],
		    &sbtls_proc, &sbtls_td, 0, 0, "TLS_proc", "tls_thr_%d", i);
		if (error)
			panic("Can't add TLS_thread %d err:%d", i, error);

		/*
		 * Bind threads to cores.  If sbtls_bind_threads is >
		 * 1, then we bind to the NUMA domain.
		 */
		if (sbtls_bind_threads) {
			if (sbtls_bind_threads > 1) {
				pc = pcpu_find(i);
				CPU_COPY(&cpuset_domain[pc->pc_domain], &mask);
			} else {
				CPU_SETOF(i, &mask);
			}
			error = cpuset_setthread(sbtls_td->td_tid, &mask);
			if (error)
				printf(
				    "Unable to bind KTLS thread for CPU %d.\n",
				    i);
		}
		sbtls_cpuid_lookup[sbtls_number_threads] = i;
		sbtls_number_threads++;
	}
	printf("SBTLS: Initialized %d threads\n", sbtls_number_threads);
}

SYSINIT(sbtls, SI_SUB_SMP + 1, SI_ORDER_ANY, sbtls_init, NULL);

static int
sbtls_create_session(struct socket *so, struct tls_so_enable *en,
    struct sbtls_session **tlsp)
{
	struct sbtls_session *tls;
	int error;

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
			/*
			 * TLS 1.0 requires an implicit IV.  TLS 1.1+
			 * all use explicit IVs.
			 */
			if (en->tls_vminor == TLS_MINOR_VER_ZERO) {
				if (en->iv_len != TLS_CBC_IMPLICIT_IV_LEN)
					return (EINVAL);
				break;
			}

			/* FALLTHROUGH */
		case CRYPTO_SHA2_256_HMAC:
		case CRYPTO_SHA2_384_HMAC:
			/* Ignore any supplied IV. */
			en->iv_len = 0;
			break;
		default:
			return (EINVAL);
		}
		if (en->hmac_key_len == 0)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}

	tls = uma_zalloc(zone_tlssock, M_WAITOK | M_ZERO);

	counter_u64_add(sbtls_offload_active, 1);

	refcount_init(&tls->refcount, 1);
	TASK_INIT(&tls->reset_tag_task, 0, sbtls_reset_send_tag, tls);

	/* cache cpu index */
	tls->sb_tsk_instance = sbtls_get_cpu(so);

	tls->sb_params.crypt_algorithm = en->crypt_algorithm;
	tls->sb_params.mac_algorithm = en->mac_algorithm;
	tls->sb_params.tls_vmajor = en->tls_vmajor;
	tls->sb_params.tls_vminor = en->tls_vminor;

	/* 
	 * Note that 1.3 was supposed to go to 64K, but that 
	 * was shot down.
	 */
	tls->sb_params.sb_maxlen = TLS_MAX_MSG_SIZE_V10_2;
	if (tls->sb_params.sb_maxlen > sbtls_maxlen)
		tls->sb_params.sb_maxlen = sbtls_maxlen;

	/* Set the header and trailer lengths. */
	tls->sb_params.tls_hlen = sizeof(struct tls_record_layer);
	switch (en->crypt_algorithm) {
	case CRYPTO_AES_NIST_GCM_16:
		tls->sb_params.tls_hlen += 8;
		tls->sb_params.tls_tlen = 16;
		tls->sb_params.tls_bs = 1;
		break;
	case CRYPTO_AES_CBC:
		switch (en->mac_algorithm) {
		case CRYPTO_SHA1_HMAC:
			if (en->tls_vminor == TLS_MINOR_VER_ZERO) {
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
		case CRYPTO_SHA2_384_HMAC:
			tls->sb_params.tls_hlen += AES_BLOCK_LEN;
			tls->sb_params.tls_tlen = AES_BLOCK_LEN +
			    SHA2_384_HASH_LEN;
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

	/* Now lets get in the keys and such */
	if (en->hmac_key_len != 0) {
		tls->sb_params.hmac_key_len = en->hmac_key_len;
		tls->sb_params.hmac_key = malloc(en->hmac_key_len,
		    M_TLSSOBUF, M_WAITOK);
		error = copyin(en->hmac_key, tls->sb_params.hmac_key,
		    en->hmac_key_len);
		if (error)
			goto out;
	}

	tls->sb_params.crypt_key_len = en->crypt_key_len;
	tls->sb_params.crypt = malloc(en->crypt_key_len, M_TLSSOBUF, M_WAITOK);
	error = copyin(en->crypt, tls->sb_params.crypt, en->crypt_key_len);
	if (error)
		goto out;

	/*
	 * This holds the implicit portion of the nonce for GCM and
	 * the initial implicit IV for TLS 1.0.  The explicit portions
	 * of the IV are generated in sbtls_frame() and sbtls_seq().
	 */
	if (en->iv_len != 0) {
		MPASS(en->iv_len <= sizeof(tls->sb_params.iv));
		tls->sb_params.iv_len = en->iv_len;
		error = copyin(en->iv, tls->sb_params.iv, en->iv_len);
		if (error)
			goto out;
	}

	*tlsp = tls;
	return (0);

out:
	sbtls_cleanup(tls);
	return (error);
}

static struct sbtls_session *
sbtls_clone_session(struct sbtls_session *tls)
{
	struct sbtls_session *tls_new;

	tls_new = uma_zalloc(zone_tlssock, M_WAITOK | M_ZERO);

	counter_u64_add(sbtls_offload_active, 1);

	refcount_init(&tls_new->refcount, 1);

	/* Copy fields from existing session. */
	tls_new->sb_params = tls->sb_params;
	tls_new->sb_tsk_instance = tls->sb_tsk_instance;

	/* Deep copy keys. */
	if (tls_new->sb_params.hmac_key != NULL) {
		tls_new->sb_params.hmac_key = malloc(
		    tls->sb_params.hmac_key_len, M_TLSSOBUF, M_WAITOK);
		memcpy(tls_new->sb_params.hmac_key, tls->sb_params.hmac_key,
		    tls->sb_params.hmac_key_len);
	}

	tls_new->sb_params.crypt = malloc(tls->sb_params.crypt_key_len,
	    M_TLSSOBUF, M_WAITOK);
	memcpy(tls_new->sb_params.crypt, tls->sb_params.crypt,
	    tls->sb_params.crypt_key_len);

	return (tls_new);
}

static void
sbtls_cleanup(struct sbtls_session *tls)
{

	counter_u64_add(sbtls_offload_active, -1);
	if (tls->sb_tls_free != NULL) {
		MPASS(tls->be != NULL);
		switch (tls->sb_params.crypt_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(sbtls_sw_cbc, -1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(sbtls_sw_gcm, -1);
			break;
		}
		tls->sb_tls_free(tls);
	} else if (tls->snd_tag != NULL) {
		switch (tls->sb_params.crypt_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(sbtls_ifnet_cbc, -1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(sbtls_ifnet_gcm, -1);
			break;
		}
		m_snd_tag_rele(tls->snd_tag);
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
	explicit_bzero(tls->sb_params.iv, sizeof(tls->sb_params.iv));
}

static int
sbtls_alloc_snd_tag(struct inpcb *inp, struct sbtls_session *tls, bool force,
    struct m_snd_tag **mstp)
{
	union if_snd_tag_alloc_params params;
	struct ifnet *ifp;
	struct rtentry *rt;
	struct tcpcb *tp;
	int error;

	INP_RLOCK(inp);
	if (inp->inp_flags2 & INP_FREED) {
		INP_RUNLOCK(inp);
		return (ECONNRESET);
	}
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_RUNLOCK(inp);
		return (ECONNRESET);
	}
	if (inp->inp_socket == NULL) {
		INP_RUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);

	/*
	 * Check administrative controls on ifnet TLS to determine if
	 * ifnet TLS should be denied.
	 *
	 * - Always permit 'force' requests.
	 * - sbtls_ifnet_permitted == 0: always deny.
	 * - sbtls_ifnet_permitted == 1: always permit.
	 * - sbtls_ifnet_permitted == 2: honor TCP stack flag.
	 */
	if (!force && (sbtls_ifnet_permitted == 0 ||
	    (sbtls_ifnet_permitted == 2 &&
	    (tp->t_fb->tfb_flags & TCP_FUNC_IFNET_TLS_OK) == 0))) {
		INP_RUNLOCK(inp);
		return (ENXIO);
	}

	/*
	 * XXX: Use the cached route in the inpcb to find the
	 * interface.  This should perhaps instead use
	 * rtalloc1_fib(dst, 0, 0, fibnum).
	 */
	rt = inp->inp_route.ro_rt;
	if (rt == NULL || rt->rt_ifp == NULL) {
		INP_RUNLOCK(inp);
		return (ENXIO);
	}
	ifp = rt->rt_ifp;
	if_ref(ifp);

	params.hdr.type = IF_SND_TAG_TYPE_TLS;
	params.hdr.flowid = inp->inp_flowid;
	params.hdr.flowtype = inp->inp_flowtype;
	params.tls.inp = inp;
	params.tls.tls = tls;
	INP_RUNLOCK(inp);

	if (ifp->if_snd_tag_alloc == NULL) {
		error = EOPNOTSUPP;
		goto out;
	}
	if ((ifp->if_capenable & IFCAP_NOMAP) == 0) {	
		error = EOPNOTSUPP;
		goto out;
	}
	if (inp->inp_vflag & INP_IPV6) {
		if ((ifp->if_capenable & IFCAP_TXTLS6) == 0) {
			error = EOPNOTSUPP;
			goto out;
		}
	} else {
		if ((ifp->if_capenable & IFCAP_TXTLS4) == 0) {
			error = EOPNOTSUPP;
			goto out;
		}
	}
	error = ifp->if_snd_tag_alloc(ifp, &params, mstp);
out:
	if_rele(ifp);
	return (error);
}

static int
sbtls_try_ifnet_tls(struct socket *so, struct sbtls_session *tls, bool force)
{
	struct m_snd_tag *mst;
	int error;

	error = sbtls_alloc_snd_tag(so->so_pcb, tls, force, &mst);
	if (error == 0) {
		tls->snd_tag = mst;
		switch (tls->sb_params.crypt_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(sbtls_ifnet_cbc, 1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(sbtls_ifnet_gcm, 1);
			break;
		}
	}
	return (error);
}

static int
sbtls_try_sw_tls(struct socket *so, struct sbtls_session *tls)
{
	struct rm_priotracker prio;
	struct sbtls_crypto_backend *be;

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
	LIST_FOREACH(be, &sbtls_backend_head, next) {
		if (be->try(so, tls) == 0)
			break;
		KASSERT(tls->cipher == NULL,
		    ("sbtls backend leaked a cipher pointer"));
	}
	if (be != NULL) {
		if (sbtls_allow_unload)
			be->use_count++;
		tls->be = be;
	}
	if (sbtls_allow_unload)
		rm_runlock(&sbtls_backend_lock, &prio);
	if (be == NULL)
		return (EOPNOTSUPP);
	switch (tls->sb_params.crypt_algorithm) {
	case CRYPTO_AES_CBC:
		counter_u64_add(sbtls_sw_cbc, 1);
		break;
	case CRYPTO_AES_NIST_GCM_16:
		counter_u64_add(sbtls_sw_gcm, 1);
		break;
	}
	return (0);
}

int
sbtls_crypt_tls_enable(struct socket *so, struct tls_so_enable *en)
{
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

	error = sbtls_create_session(so, en, &tls);
	if (error)
		return (error);

	error = sbtls_try_ifnet_tls(so, tls, false);
	if (error)
		error = sbtls_try_sw_tls(so, tls);

	if (error) {
		sbtls_cleanup(tls);
		return (error);
	}

	error = sblock(&so->so_snd, SBL_WAIT);
	if (error) {
		sbtls_cleanup(tls);
		return (error);
	}

	SOCKBUF_LOCK(&so->so_snd);
	so->so_snd.sb_tls_info = tls;
	if (tls->sb_tls_crypt == NULL)
		so->so_snd.sb_tls_flags |= SB_TLS_IFNET;
	SOCKBUF_UNLOCK(&so->so_snd);
	sbunlock(&so->so_snd);

	counter_u64_add(sbtls_offload_total, 1);

	return (0);
}

int
sbtls_get_tls_mode(struct socket *so)
{
	struct sbtls_session *tls;
	struct inpcb *inp;
	int mode;

	inp = so->so_pcb;
	INP_WLOCK_ASSERT(inp);
	SOCKBUF_LOCK(&so->so_snd);
	tls = so->so_snd.sb_tls_info;
	if (tls == NULL)
		mode = TCP_TLS_MODE_NONE;
	else if (tls->sb_tls_crypt != NULL)
		mode = TCP_TLS_MODE_SW;
	else
		mode = TCP_TLS_MODE_IFNET;
	SOCKBUF_UNLOCK(&so->so_snd);
	return (mode);
}

/*
 * Switch between SW and ifnet TLS sessions as requested.
 */
int
sbtls_set_tls_mode(struct socket *so, int mode)
{
	struct sbtls_session *tls, *tls_new;
	struct inpcb *inp;
	int error;

	MPASS(mode == TCP_TLS_MODE_SW || mode == TCP_TLS_MODE_IFNET);

	inp = so->so_pcb;
	INP_WLOCK_ASSERT(inp);
	SOCKBUF_LOCK(&so->so_snd);
	tls = so->so_snd.sb_tls_info;
	if (tls == NULL) {
		SOCKBUF_UNLOCK(&so->so_snd);
		return (0);
	}

	if ((tls->sb_tls_crypt != NULL && mode == TCP_TLS_MODE_SW) ||
	    (tls->sb_tls_crypt == NULL && mode == TCP_TLS_MODE_IFNET)) {
		SOCKBUF_UNLOCK(&so->so_snd);
		return (0);
	}

	tls = sbtls_hold(tls);
	SOCKBUF_UNLOCK(&so->so_snd);
	INP_WUNLOCK(inp);

	tls_new = sbtls_clone_session(tls);

	if (mode == TCP_TLS_MODE_IFNET)
		error = sbtls_try_ifnet_tls(so, tls_new, true);
	else
		error = sbtls_try_sw_tls(so, tls_new);
	if (error) {
		counter_u64_add(sbtls_switch_failed, 1);
		sbtls_free(tls_new);
		sbtls_free(tls);
		INP_WLOCK(inp);
		return (error);
	}

	error = sblock(&so->so_snd, SBL_WAIT);
	if (error) {
		counter_u64_add(sbtls_switch_failed, 1);
		sbtls_free(tls_new);
		sbtls_free(tls);
		INP_WLOCK(inp);
		return (error);
	}

	/*
	 * If we raced with another session change, keep the existing
	 * session.
	 */
	if (tls != so->so_snd.sb_tls_info) {
		counter_u64_add(sbtls_switch_failed, 1);
		sbunlock(&so->so_snd);
		sbtls_free(tls_new);
		sbtls_free(tls);
		INP_WLOCK(inp);
		return (EBUSY);
	}

	SOCKBUF_LOCK(&so->so_snd);
	so->so_snd.sb_tls_info = tls_new;
	if (tls_new->sb_tls_crypt == NULL)
		so->so_snd.sb_tls_flags |= SB_TLS_IFNET;
	SOCKBUF_UNLOCK(&so->so_snd);
	sbunlock(&so->so_snd);

	/*
	 * Drop two references on 'tls'.  The first is for the
	 * sbtls_hold() above.  The second drops the reference from
	 * the socket buffer.
	 */
	KASSERT(tls->refcount >= 2, ("too few references on old session"));
	sbtls_free(tls);
	sbtls_free(tls);

	if (mode == TCP_TLS_MODE_IFNET)
		counter_u64_add(sbtls_switch_to_ifnet, 1);
	else
		counter_u64_add(sbtls_switch_to_sw, 1);

	INP_WLOCK(inp);
	return (0);
}

void
sbtls_tcp_stack_changed(struct socket *so)
{
	struct inpcb *inp;
	struct tcpcb *tp;
	int mode;

	inp = so->so_pcb;
	INP_WLOCK_ASSERT(inp);

	/*
	 * If the TCP stack has changed and we are honoring the stack
	 * flag, check the stack flag to determine what mode the
	 * session should be using with the new stack.
	 */
	if (sbtls_ifnet_permitted != 2)
		return;

	tp = intotcpcb(inp);
	if (tp->t_fb->tfb_flags & TCP_FUNC_IFNET_TLS_OK)
		mode = TCP_TLS_MODE_IFNET;
	else
		mode = TCP_TLS_MODE_SW;
	(void)sbtls_set_tls_mode(so, mode);
}

/*
 * Try to allocate a new TLS send tag.  This task is scheduled when
 * ip_output detects a route change while trying to transmit a packet
 * holding a TLS record.  If a new tag is allocated, replace the tag
 * in the TLS session.  Subsequent packets on the connection will use
 * the new tag.  If a new tag cannot be allocated, drop the
 * connection.
 */
static void
sbtls_reset_send_tag(void *context, int pending)
{
	struct epoch_tracker et;
	struct sbtls_session *tls;
	struct m_snd_tag *old, *new;
	struct inpcb *inp;
	struct tcpcb *tp;
	int error;

	MPASS(pending == 1);

	tls = context;
	inp = tls->inp;

	error = sbtls_alloc_snd_tag(inp, tls, true, &new);

	if (error == 0) {
		old = tls->snd_tag;
		tls->snd_tag = new;

		INP_RLOCK(inp);
		mtx_pool_lock(mtxpool_sleep, tls);
		tls->reset_pending = false;
		mtx_pool_unlock(mtxpool_sleep, tls);
		if (!in_pcbrele_rlocked(inp))
			INP_RUNLOCK(inp);

		m_snd_tag_rele(old);

		/*
		 * XXX: Should we kick tcp_output explicitly now that
		 * the send tag is fixed or just rely on timers?
		 */
	} else {
		INP_INFO_RLOCK_ET(&V_tcbinfo, et);
		INP_WLOCK(inp);
		if (in_pcbrele_wlocked(inp)) {
			if (!(inp->inp_flags & INP_TIMEWAIT) &&
			    !(inp->inp_flags & INP_DROPPED)) {
				tp = intotcpcb(inp);
				tp = tcp_drop(tp, ECONNABORTED);
				if (tp != NULL)
					INP_WUNLOCK(inp);
			} else
				INP_WUNLOCK(inp);
		}
		INP_INFO_RUNLOCK_ET(&V_tcbinfo, et);

		/*
		 * Leave reset_pending true to avoid future tasks while
		 * the socket goes away.
		 */
	}

	sbtls_free(tls);
}

int
sbtls_output_eagain(struct inpcb *inp, struct sbtls_session *tls)
{

	if (inp == NULL)
		return (ENOBUFS);

	INP_LOCK_ASSERT(inp);

	/*
	 * See if we should schedule a task to update the send tag for
	 * this session.
	 */
	mtx_pool_lock(mtxpool_sleep, tls);
	if (!tls->reset_pending) {
		(void) sbtls_hold(tls);
		in_pcbref(inp);
		tls->inp = inp;
		tls->reset_pending = true;
		taskqueue_enqueue(taskqueue_thread, &tls->reset_tag_task);
	}
	mtx_pool_unlock(mtxpool_sleep, tls);
	return (ENOBUFS);
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

		pgs = m->m_ext.ext_pgs;
		pgs->seqno = sb->sb_tls_seqno;

		/*
		 * Store the sequence number in the TLS header as the
		 * explicit part of the IV for GCM.
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


		pgs = m->m_ext.ext_pgs;

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

	pgs = m->m_ext.ext_pgs;

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

	so = pgs->so;
	tls = pgs->tls;
	top = pgs->mbuf;
	KASSERT(tls != NULL, ("tls = NULL, top = %p, pgs = %p\n", top, pgs));
	KASSERT(so != NULL, ("so = NULL, top = %p, pgs = %p\n", top, pgs));
	pgs->so = NULL;
	pgs->mbuf = NULL;
	npages = 0;
	/*
	 *  each TLS record is in a single mbuf.  Do
	 *  one at a time
	 */
	page_count = pgs->enc_cnt;
	error = 0;
	for (m = top; m != NULL && npages != page_count; m = m->m_next) {
		pgs = m->m_ext.ext_pgs;

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
		    (const struct tls_record_layer *)pgs->hdr,
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

		/*
		 * Drop a reference to the session now that it is no
		 * longer needed.  Existing code depends on encrypted
		 * records having no associated session vs
		 * yet-to-be-encrypted records having an associated
		 * session.
		 */
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
	STAILQ_HEAD(, mbuf_ext_pgs) local_head;

	fpu_kern_thread(0);
	mtx_lock(&wq->mtx);
	for (;;) {
		while (STAILQ_EMPTY(&wq->head)) {
			wq->running = 0;
			mtx_sleep(wq, &wq->mtx, 0, "sbtls wq", 0);
			wq->running = 1;
		}

		STAILQ_INIT(&local_head);
		STAILQ_CONCAT(&local_head, &wq->head);
		mtx_unlock(&wq->mtx);

		STAILQ_FOREACH_SAFE(p, &local_head, stailq, n) {
			/* encrypt or free each TLS record on the list */
			if (p->mbuf != NULL) {
				sbtls_encrypt(p);
				counter_u64_add(sbtls_cnt_on, -1);
			} else {
				/* records w/null mbuf are freed */
				tls = p->tls;
				sbtls_free(tls);
				uma_zfree(zone_extpgs, p);
			}
		}

		mtx_lock(&wq->mtx);
	}
}
