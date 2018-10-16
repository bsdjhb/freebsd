/*	$FreeBSD$	*/
/*	$OpenBSD: cryptosoft.h,v 1.10 2002/04/22 23:10:09 deraadt Exp $	*/

/*-
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 */

#ifndef _CRYPTO_CRYPTOSOFT_H_
#define _CRYPTO_CRYPTOSOFT_H_

/* Software session entry */
struct swcr_auth {
	uint8_t		*sw_ictx;
	uint8_t		*sw_octx;
	struct auth_hash *sw_axf;
	uint16_t	sw_klen;
	uint16_t	sw_mlen;
	uint16_t	sw_octx_len;
};

struct swcr_encdec {
	uint8_t		*sw_kschedule;
	struct enc_xform *sw_exf;
};

struct swcr_compdec {
	struct comp_algo *sw_cxf;
};

struct swcr_session {
	struct mtx	swcr_lock;
	int	(*swcr_process)(struct swcr_session *, struct cryptop *);

	struct swcr_auth swcr_auth;
	struct swcr_encdec swcr_encdec;
	struct swcr_compdec swcr_compdec;
};

#ifdef _KERNEL
extern u_int8_t hmac_ipad_buffer[];
extern u_int8_t hmac_opad_buffer[];
#endif /* _KERNEL */

#endif /* _CRYPTO_CRYPTO_H_ */
