# $FreeBSD$

CXGBE = ${.CURDIR}/../../../dev/cxgbe
.PATH: ${CXGBE}

KMOD=	ccr

SRCS=	t4_crypto.c
SRCS+=	bus_if.h
SRCS+=	device_if.h
#SRCS+=	opt_inet.h
#SRCS+=	opt_inet6.h
SRCS+=	pci_if.h

CFLAGS+= -I${CXGBE}

MFILES=	kern/bus_if.m kern/device_if.m dev/pci/pci_if.m

.include <bsd.kmod.mk>
