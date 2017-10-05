/*-
 * Copyright (c) 2017 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <np@FreeBSD.org>
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

#include "opt_inet.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/toecore.h>

#ifdef TCP_OFFLOAD
#include "common/common.h"
#include "common/t4_tcb.h"
#include "tom/t4_tom.h"
#include "tom/t4_tls.h"

/*
 * TODO:
 * - socket options
 * - transmit TLS records via CPL_TX_TLS_SFO
 * - how to receive TLS data?
 */

/* Clear TF_RX_QUIESCE to re-enable receive. */
static void
t4_clear_rx_quiesce(struct toepcb *toep)
{
	struct adapter *sc = td_adapter(toep->td);

	t4_set_tcb_field(sc, toep->ctrlq, toep->tid, W_TCB_T_FLAGS,
	    V_TF_RX_QUIESCE(1), 0, 0, 0, toep->ofld_rxq->iq.abs_id);
}

static void
tls_clr_ofld_mode(struct toepcb *toep)
{
	struct adapter *sc = td_adapter(toep->td);

	/* XXX: Stop handshake timer. */

	/* Operate in PDU extraction mode only. */
	t4_set_tcb_field(sc, toep->ctrlq, toep->tid, W_TCB_ULP_RAW,
	    V_TCB_ULP_RAW(V_TF_TLS_ENABLE(1)),
	    V_TCB_ULP_RAW(V_TF_TLS_ENABLE(1)), 0, 0, toep->ofld_rxq->iq.abs_id);
	t4_clear_rx_quiesce(toep);
}

static void
tls_clr_quiesce(struct toepcb *toep)
{

	/* XXX: Stop handshake timer. */

	t4_clear_rx_quiesce(toep);
}

int
t4_ctloutput_tls(struct socket *so, struct sockopt *sopt)
{
	struct inpcb *inp;
	struct tcpcb *tp;
	struct toepcb *toep;
	int error, optval;

	error = 0;
	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("tcp_ctloutput: inp == NULL"));
	INP_WLOCK(inp);
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);
	toep = tp->t_toe;
	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case TCP_TLSOM_CLR_TLS_TOM:
			tls_clr_ofld_mode(toep);
			INP_WUNLOCK(inp);
			break;
		case TCP_TLSOM_CLR_QUIES:
			tls_clr_quiesce(toep);
			INP_WUNLOCK(inp);
			break;
		case TCP_TLSOM_SET_TLS_CONTEXT:
			/* FALLTHROUGH */
		default:
			INP_WUNLOCK(inp);
			error = EOPNOTSUPP;
			break;
		}
		break;
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case TCP_TLSOM_GET_TLS_TOM:
			optval = is_tls_offload(toep);
			INP_WUNLOCK(inp);
			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;
		default:
			INP_WUNLOCK(inp);
			error = EOPNOTSUPP;
			break;
		}
		break;
	}
	return (error);
}

void
tls_init_toep(struct toepcb *toep)
{
}

void
tls_uninit_toep(struct toepcb *toep)
{
}
#endif	/* TCP_OFFLOAD */
