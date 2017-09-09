/*	$NetBSD: ptrace.h,v 1.2 2001/02/23 21:23:52 reinoud Exp $	*/
/* $FreeBSD$ */

#ifndef _MACHINE_PTRACE_H_
#define _MACHINE_PTRACE_H_

#define	__HAVE_PTRACE_MACHDEP

/* Must match mcontext_vfp_t. */
struct vfpreg {
	__uint64_t	vfp_reg[32];
	__uint32_t	vfp_scr;
};

#define	PT_GETVFPREGS	(PT_FIRSTMACH + 0)
#define	PT_SETVFPREGS	(PT_FIRSTMACH + 1)

#endif /* !_MACHINE_PTRACE_H */

