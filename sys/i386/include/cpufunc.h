/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1993 The Regents of the University of California.
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
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
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
 */

/*
 * Functions to provide access to special i386 instructions.
 * This in included in sys/systm.h, and that file should be
 * used in preference to this.
 */

#ifndef _MACHINE_CPUFUNC_H_
#define	_MACHINE_CPUFUNC_H_

static __inline void
breakpoint(void)
{
	__asm __volatile("int $3");
}

static __inline void
cpuid_count(u_int ax, u_int cx, u_int *p)
{
	__asm __volatile(
	    "pushl\t%%ebx\n\t"
	    "cpuid\n\t"
	    "movl\t%%ebx,%1\n\t"
	    "popl\t%%ebx"
	    : "=a" (p[0]), "=DS" (p[1]), "=c" (p[2]), "=d" (p[3])
	    :  "0" (ax), "c" (cx));
}

static __inline void
do_cpuid(u_int ax, u_int *p)
{
	cpuid_count(ax, 0, p);
}

static __inline void
lfence(void)
{
	__asm __volatile("lfence" : : : "memory");
}

static __inline void
mfence(void)
{
	__asm __volatile("mfence" : : : "memory");
}

static __inline void
sfence(void)
{
	__asm __volatile("sfence" : : : "memory");
}

static __inline u_char
inb(u_int port)
{
	u_char	data;

	__asm __volatile("inb %w1, %0" : "=a" (data) : "Nd" (port));
	return (data);
}

static __inline u_int
inl(u_int port)
{
	u_int	data;

	__asm __volatile("inl %w1, %0" : "=a" (data) : "Nd" (port));
	return (data);
}

static __inline void
insb(u_int port, void *addr, size_t count)
{
	__asm __volatile("cld; rep; insb"
			 : "+D" (addr), "+c" (count)
			 : "d" (port)
			 : "memory");
}

static __inline void
insw(u_int port, void *addr, size_t count)
{
	__asm __volatile("cld; rep; insw"
			 : "+D" (addr), "+c" (count)
			 : "d" (port)
			 : "memory");
}

static __inline void
insl(u_int port, void *addr, size_t count)
{
	__asm __volatile("cld; rep; insl"
			 : "+D" (addr), "+c" (count)
			 : "d" (port)
			 : "memory");
}

static __inline u_short
inw(u_int port)
{
	u_short	data;

	__asm __volatile("inw %w1, %0" : "=a" (data) : "Nd" (port));
	return (data);
}

static __inline void
outb(u_int port, u_char data)
{
	__asm __volatile("outb %0, %w1" : : "a" (data), "Nd" (port));
}

static __inline void
outl(u_int port, u_int data)
{
	__asm __volatile("outl %0, %w1" : : "a" (data), "Nd" (port));
}

static __inline void
outsb(u_int port, const void *addr, size_t count)
{
	__asm __volatile("cld; rep; outsb"
			 : "+S" (addr), "+c" (count)
			 : "d" (port));
}

static __inline void
outsw(u_int port, const void *addr, size_t count)
{
	__asm __volatile("cld; rep; outsw"
			 : "+S" (addr), "+c" (count)
			 : "d" (port));
}

static __inline void
outsl(u_int port, const void *addr, size_t count)
{
	__asm __volatile("cld; rep; outsl"
			 : "+S" (addr), "+c" (count)
			 : "d" (port));
}

static __inline void
outw(u_int port, u_short data)
{
	__asm __volatile("outw %0, %w1" : : "a" (data), "Nd" (port));
}

static __inline void
ia32_pause(void)
{
	__asm __volatile("pause");
}

static __inline u_int
read_eflags(void)
{
	u_int	ef;

	__asm __volatile("pushfl; popl %0" : "=r" (ef));
	return (ef);
}

static __inline uint64_t
rdtsc(void)
{
	uint64_t rv;

	__asm __volatile("rdtsc" : "=A" (rv));
	return (rv);
}

static __inline uint64_t
rdtscp(void)
{
	uint64_t rv;

	__asm __volatile("rdtscp" : "=A" (rv) : : "ecx");
	return (rv);
}

static __inline uint64_t
rdtscp_aux(uint32_t *aux)
{
	uint64_t rv;

	__asm __volatile("rdtscp" : "=A" (rv), "=c" (*aux));
	return (rv);
}

static __inline uint32_t
rdtsc32(void)
{
	uint32_t rv;

	__asm __volatile("rdtsc" : "=a" (rv) : : "edx");
	return (rv);
}

static __inline uint32_t
rdtscp32(void)
{
	uint32_t rv;

	__asm __volatile("rdtscp" : "=a" (rv) : : "ecx", "edx");
	return (rv);
}

static __inline void
write_eflags(u_int ef)
{
	__asm __volatile("pushl %0; popfl" : : "r" (ef));
}

static __inline uint32_t
rdpkru(void)
{
	uint32_t res;

	__asm __volatile("rdpkru" :  "=a" (res) : "c" (0) : "edx");
	return (res);
}

static __inline void
wrpkru(uint32_t mask)
{

	__asm __volatile("wrpkru" :  : "a" (mask),  "c" (0), "d" (0));
}

#endif /* !_MACHINE_CPUFUNC_H_ */
