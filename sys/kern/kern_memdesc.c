/*-
 * Copyright (c) 2023 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>
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

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/mbuf.h>
#include <sys/memdesc.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <machine/bus.h>

static void
phys_copyback(vm_paddr_t pa, int off, int size, const void *src)
{
	u_int page_off;
	char *p;

	KASSERT(PMAP_HAS_DMAP, ("direct-map required"));

	page_off = pa & PAGE_MASK;
	p = (char *)PHYS_TO_DMAP(trunc_page(pa));

	/*
	 * Assumes physically contiguous pages are virtually
	 * contiguous in the direct map.
	 */
	memcpy(p + page_off + off, src, size);
}

static void
vlist_copyback(struct bus_dma_segment *vlist, int sglist_cnt, int off,
    int size, const void *src)
{
	const char *p;
	int todo;

	while (vlist->ds_len <= off) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		off -= vlist->ds_len;
		vlist++;
		sglist_cnt--;
	}

	p = src;
	while (size > 0) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		todo = size;
		if (todo > vlist->ds_len - off)
			todo = vlist->ds_len - off;

		memcpy((char *)(uintptr_t)vlist->ds_addr + off, p, todo);
		off = 0;
		vlist++;
		sglist_cnt--;
		size -= todo;
		p += todo;
	}
}

static void
plist_copyback(struct bus_dma_segment *plist, int sglist_cnt, int off,
    int size, const void *src)
{
	const char *p;
	int todo;

	while (plist->ds_len <= off) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		off -= plist->ds_len;
		plist++;
		sglist_cnt--;
	}

	p = src;
	while (size > 0) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		todo = size;
		if (todo > plist->ds_len - off)
			todo = plist->ds_len - off;

		phys_copyback(plist->ds_addr, off, todo, p);
		off = 0;
		plist++;
		sglist_cnt--;
		size -= todo;
		p += todo;
	}
}

static void
vmpages_copyback(vm_page_t *m, int off, int size, const void *src)
{
	struct iovec iov[1];
	struct uio uio;
	int error __diagused;

	iov[0].iov_base = __DECONST(void *, src);
	iov[0].iov_len = size;
	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = size;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	error = uiomove_fromphys(m, off, size, &uio);
	KASSERT(error == 0 && uio.uio_resid == 0, ("copy failed"));
}

static void
bio_copyback(struct bio *bio, int off, int size, const void *src)
{
	KASSERT(off + size <= bio->bio_bcount, ("copy out of bounds"));

	if ((bio->bio_flags & BIO_VLIST) != 0) {
		vlist_copyback((bus_dma_segment_t *)bio->bio_data,
		    bio->bio_ma_n, off, size, src);
		return;
	}

	if ((bio->bio_flags & BIO_UNMAPPED) != 0) {
		vmpages_copyback(bio->bio_ma, bio->bio_ma_offset + off, size,
		    src);
		return;
	}

	memcpy(bio->bio_data + off, src, size);
}

void
memdesc_copyback(struct memdesc *mem, int off, int size, const void *src)
{
	switch (mem->md_type) {
	case MEMDESC_VADDR:
		KASSERT(off + size <= mem->md_opaque, ("copy out of bounds"));
		memcpy((char *)mem->u.md_vaddr + off, src, size);
		break;
	case MEMDESC_PADDR:
		KASSERT(off + size <= mem->md_opaque, ("copy out of bounds"));
		phys_copyback(mem->u.md_paddr, off, size, src);
		break;
	case MEMDESC_VLIST:
		vlist_copyback(mem->u.md_list, mem->md_opaque, off, size, src);
		break;
	case MEMDESC_PLIST:
		plist_copyback(mem->u.md_list, mem->md_opaque, off, size, src);
		break;
	case MEMDESC_BIO:
		bio_copyback(mem->u.md_bio, off, size, src);
		break;
	case MEMDESC_UIO:
		panic("Use uiomove instead");
		break;
	case MEMDESC_MBUF:
		m_copyback(mem->u.md_mbuf, off, size, src);
		break;
	default:
		__assert_unreachable();
	}
}

static void
phys_copydata(vm_paddr_t pa, int off, int size, void *dst)
{
	u_int page_off;
	const char *p;

	KASSERT(PMAP_HAS_DMAP, ("direct-map required"));

	page_off = pa & PAGE_MASK;
	p = (const char *)PHYS_TO_DMAP(trunc_page(pa));

	/*
	 * Assumes physically contiguous pages are virtually
	 * contiguous in the direct map.
	 */
	memcpy(dst, p + page_off + off, size);
}

static void
vlist_copydata(struct bus_dma_segment *vlist, int sglist_cnt, int off,
    int size, void *dst)
{
	char *p;
	int todo;

	while (vlist->ds_len <= off) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		off -= vlist->ds_len;
		vlist++;
		sglist_cnt--;
	}

	p = dst;
	while (size > 0) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		todo = size;
		if (todo > vlist->ds_len - off)
			todo = vlist->ds_len - off;

		memcpy(p, (char *)(uintptr_t)vlist->ds_addr + off, todo);
		off = 0;
		vlist++;
		sglist_cnt--;
		size -= todo;
		p += todo;
	}
}

static void
plist_copydata(struct bus_dma_segment *plist, int sglist_cnt, int off,
    int size, void *dst)
{
	char *p;
	int todo;

	while (plist->ds_len <= off) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		off -= plist->ds_len;
		plist++;
		sglist_cnt--;
	}

	p = dst;
	while (size > 0) {
		KASSERT(sglist_cnt > 1, ("out of sglist entries"));

		todo = size;
		if (todo > plist->ds_len - off)
			todo = plist->ds_len - off;

		phys_copydata(plist->ds_addr, off, todo, p);
		off = 0;
		plist++;
		sglist_cnt--;
		size -= todo;
		p += todo;
	}
}

static void
vmpages_copydata(vm_page_t *m, int off, int size, void *dst)
{
	struct iovec iov[1];
	struct uio uio;
	int error __diagused;

	iov[0].iov_base = dst;
	iov[0].iov_len = size;
	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = size;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	error = uiomove_fromphys(m, off, size, &uio);
	KASSERT(error == 0 && uio.uio_resid == 0, ("copy failed"));
}

static void
bio_copydata(struct bio *bio, int off, int size, void *dst)
{
	KASSERT(off + size <= bio->bio_bcount, ("copy out of bounds"));

	if ((bio->bio_flags & BIO_VLIST) != 0) {
		vlist_copydata((bus_dma_segment_t *)bio->bio_data,
		    bio->bio_ma_n, off, size, dst);
		return;
	}

	if ((bio->bio_flags & BIO_UNMAPPED) != 0) {
		vmpages_copydata(bio->bio_ma, bio->bio_ma_offset + off, size,
		    dst);
		return;
	}

	memcpy(dst, bio->bio_data + off, size);
}

void
memdesc_copydata(struct memdesc *mem, int off, int size, void *dst)
{
	switch (mem->md_type) {
	case MEMDESC_VADDR:
		KASSERT(off + size <= mem->md_opaque, ("copy out of bounds"));
		memcpy(dst, (const char *)mem->u.md_vaddr + off, size);
		break;
	case MEMDESC_PADDR:
		KASSERT(off + size <= mem->md_opaque, ("copy out of bounds"));
		phys_copydata(mem->u.md_paddr, off, size, dst);
		break;
	case MEMDESC_VLIST:
		vlist_copydata(mem->u.md_list, mem->md_opaque, off, size, dst);
		break;
	case MEMDESC_PLIST:
		plist_copydata(mem->u.md_list, mem->md_opaque, off, size, dst);
		break;
	case MEMDESC_BIO:
		bio_copydata(mem->u.md_bio, off, size, dst);
		break;
	case MEMDESC_UIO:
		panic("Use uiomove instead");
		break;
	case MEMDESC_MBUF:
		m_copydata(mem->u.md_mbuf, off, size, dst);
		break;
	default:
		__assert_unreachable();
	}
}
