#ifndef __QPI_H__
#define	__QPI_H__

#include <sys/cdefs.h>
#include <sys/linker_set.h>
#include <sys/queue.h>

/* A single DIMM slot in a QPI system. */
struct dimm {
	int	socket;
	int	channel;
	int	id;
	long	ccount;
	long	ucount;
	TAILQ_ENTRY(dimm) link;
};

struct qpi_dimm_labeler {
	int	(*probe)(void);
	const char *(*dimm_label)(struct dimm *);
};

#define	QPI_DIMM_LABELER(x)	DATA_SET(qpi_dimm_labelers, x)

#endif /* __QPI_H__ */
