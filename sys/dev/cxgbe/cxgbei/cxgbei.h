/*-
 * Copyright (c) 2012, 2015 Chelsio Communications, Inc.
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

#ifndef __CXGBEI_OFLD_H__
#define __CXGBEI_OFLD_H__

#include <dev/iscsi/icl.h>

enum {
	CWT_SLEEPING	= 1,
	CWT_RUNNING	= 2,
	CWT_STOP	= 3,
	CWT_STOPPED	= 4,
};

struct cxgbei_worker_thread_softc {
	struct mtx	cwt_lock;
	struct cv	cwt_cv;
	volatile int	cwt_state;

	TAILQ_HEAD(, icl_cxgbei_conn) rx_head;
} __aligned(CACHE_LINE_SIZE);

#define CXGBEI_CONN_SIGNATURE 0x56788765

enum {
	RXF_ACTIVE	= 1 << 0,	/* In the worker thread's queue */
};

struct cxgbei_cmp {
	LIST_ENTRY(cxgbei_cmp) link;

	uint32_t tt;		/* Transfer tag. */

	uint32_t next_buffer_offset;
	uint32_t last_datasn;
};
LIST_HEAD(cxgbei_cmp_head, cxgbei_cmp);

struct icl_cxgbei_conn {
	struct icl_conn ic;

	/* cxgbei specific stuff goes here. */
	uint32_t icc_signature;
	int ulp_submode;
	struct adapter *sc;
	struct toepcb *toep;

	/* Receive related. */
	u_int rx_flags;				/* protected by so_rcv lock */
	u_int cwt;
	STAILQ_HEAD(, icl_pdu) rcvd_pdus;	/* protected by so_rcv lock */
	TAILQ_ENTRY(icl_cxgbei_conn) rx_link;	/* protected by cwt lock */

	struct cxgbei_cmp_head *cmp_table;	/* protected by cmp_lock */
	struct mtx cmp_lock;
	unsigned long cmp_hash_mask;
};

static inline struct icl_cxgbei_conn *
ic_to_icc(struct icl_conn *ic)
{

	return (__containerof(ic, struct icl_cxgbei_conn, ic));
}

/* PDU flags and signature. */
enum {
	ICPF_RX_HDR	= 1 << 0, /* PDU header received. */
	ICPF_RX_FLBUF	= 1 << 1, /* PDU payload received in a freelist. */
	ICPF_RX_DDP	= 1 << 2, /* PDU payload DDP'd. */
	ICPF_RX_STATUS	= 1 << 3, /* Rx status received. */

	CXGBEI_PDU_SIGNATURE = 0x12344321
};

struct icl_cxgbei_pdu {
	struct icl_pdu ip;

	/* cxgbei specific stuff goes here. */
	uint32_t icp_signature;
	uint32_t icp_seq;	/* For debug only */
	u_int icp_flags;

	u_int ref_cnt;
	icl_pdu_cb cb;
	int error;
};

static inline struct icl_cxgbei_pdu *
ip_to_icp(struct icl_pdu *ip)
{

	return (__containerof(ip, struct icl_cxgbei_pdu, ip));
}

struct cxgbei_data {
	u_int max_tx_data_len;
	u_int max_rx_data_len;

	u_int ddp_threshold;
	struct ppod_region pr;

	struct sysctl_ctx_list ctx;	/* from uld_activate to deactivate */
};

#define CXGBEI_MAX_ISO_PAYLOAD	65535

#define	CXGBEI_TRACE_PDU(icc, action, ip) do {				\
	struct iscsi_bhs *_bhs = (ip)->ip_bhs;				\
	u_int _tid = (icc)->toep->tid;					\
	uint32_t _datalen = _bhs->bhs_data_segment_len[0] << 16 |	\
	    _bhs->bhs_data_segment_len[1] << 8 |			\
	    _bhs->bhs_data_segment_len[0];				\
									\
	switch (_bhs->bhs_opcode & ~ISCSI_BHS_OPCODE_IMMEDIATE) {	\
	case ISCSI_BHS_OPCODE_NOP_OUT:					\
	{								\
		struct iscsi_bhs_nop_out *_bhsno = (void *)_bhs;	\
									\
		CTR5(KTR_CXGBE, "%s: tid %u " action " NOP-OUT "	\
		    "datalen %u cmdsn %u expstatsn %u", __func__, _tid,	\
		    _datalen, be32toh(_bhsno->bhsno_cmdsn),		\
		    be32toh(_bhsno->bhsno_expstatsn));			\
		(void)_bhsno;						\
		break;							\
	}								\
	case ISCSI_BHS_OPCODE_SCSI_COMMAND:				\
	{								\
		struct iscsi_bhs_scsi_command *_bhssc = (void *)_bhs;	\
									\
		CTR5(KTR_CXGBE, "%s: tid %u " action " COMMAND "	\
		    "datalen %u cmdsn %u expstatsn %u", __func__, _tid,	\
		    _datalen, be32toh(_bhssc->bhssc_cmdsn),		\
		    be32toh(_bhssc->bhssc_expstatsn));			\
		(void)_bhssc;						\
		break;							\
	}								\
	case ISCSI_BHS_OPCODE_SCSI_DATA_OUT:				\
	{								\
		struct iscsi_bhs_data_out *_bhsdo = (void *)_bhs;	\
									\
		CTR5(KTR_CXGBE, "%s: tid %u " action " DATA-OUT "	\
		    "datalen %u datasn %u expstatsn %u", __func__, _tid,\
		    _datalen, be32toh(_bhsdo->bhsdo_datasn),		\
		    be32toh(_bhsdo->bhsdo_expstatsn));			\
		(void)_bhsdo;						\
		break;							\
	}								\
	case ISCSI_BHS_OPCODE_NOP_IN:					\
	{								\
		struct iscsi_bhs_nop_in *_bhsni = (void *)_bhs;		\
									\
		CTR5(KTR_CXGBE, "%s: tid %u " action " NOP-IN "		\
		    "datalen %u statsn %u expcmdsn %u", __func__, _tid,	\
		    _datalen, be32toh(_bhsni->bhsni_statsn),		\
		    be32toh(_bhsni->bhsni_expcmdsn));			\
		(void)_bhsni;						\
		break;							\
	}								\
	case ISCSI_BHS_OPCODE_SCSI_RESPONSE:				\
	{								\
		struct iscsi_bhs_scsi_response *_bhssr = (void *)_bhs;	\
									\
		CTR6(KTR_CXGBE, "%s: tid %u " action " RESPONSE "	\
		    "datalen %u statsn %u expcmdsn %u expdatasn %u",	\
		    __func__, _tid, _datalen,				\
		    be32toh(_bhssr->bhssr_statsn),			\
		    be32toh(_bhssr->bhssr_expcmdsn),			\
		    be32toh(_bhssr->bhssr_expdatasn));			\
		(void)_bhssr;						\
		break;							\
	}								\
	case ISCSI_BHS_OPCODE_SCSI_DATA_IN:				\
	{								\
		struct iscsi_bhs_data_in *_bhsdi = (void *)_bhs;	\
									\
		CTR6(KTR_CXGBE, "%s: tid %u " action " DATA-IN "	\
		    "datalen %u datasn %u statsn %u expcmdsn %u",	\
		    __func__, _tid, _datalen,				\
		    be32toh(_bhsdi->bhsdi_datasn),			\
		    be32toh(_bhsdi->bhsdi_statsn),			\
		    be32toh(_bhsdi->bhsdi_expcmdsn));			\
		(void)_bhsdi;						\
		break;							\
	}								\
	case ISCSI_BHS_OPCODE_R2T:					\
	{								\
		struct iscsi_bhs_r2t *_bhsr2t = (void *)_bhs;		\
									\
		CTR6(KTR_CXGBE, "%s: tid %u " action " R2T statsn %u "	\
		    "datalen %u expcmdsn %u r2tsn %u", __func__, _tid,	\
		    _datalen, be32toh(_bhsr2t->bhsr2t_statsn),		\
		    be32toh(_bhsr2t->bhsr2t_expcmdsn),			\
		    be32toh(_bhsr2t->bhsr2t_r2tsn));			\
		(void)_bhsr2t;						\
		break;							\
	}								\
	default:							\
		CTR4(KTR_CXGBE, "%s: tid %u " action " opcode 0x%02x "	\
		    "datalen %u", __func__, _tid, _bhs->bhs_opcode,	\
		    _datalen);						\
	}								\
	(void)_tid;							\
	(void)_datalen;							\
} while (0)

/* cxgbei.c */
u_int cxgbei_select_worker_thread(struct icl_cxgbei_conn *);

/* icl_cxgbei.c */
int icl_cxgbei_mod_load(void);
int icl_cxgbei_mod_unload(void);
struct icl_pdu *icl_cxgbei_new_pdu(int);
void icl_cxgbei_new_pdu_set_conn(struct icl_pdu *, struct icl_conn *);
void icl_cxgbei_conn_pdu_free(struct icl_conn *, struct icl_pdu *);
struct cxgbei_cmp *cxgbei_find_cmp(struct icl_cxgbei_conn *, uint32_t);

#endif
