/*
 * Parse ECC error info for Nehalem CPUs.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <machine/cpufunc.h>
#include <x86/mca.h>
#include <machine/specialreg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecc.h"

/* Fields in MISC for QPI MC8-MC11. */
#define	QPI_MC8_MISC_RTID	0x00000000000000ff
#define	QPI_MC8_MISC_DIMM	0x0000000000030000
#define	QPI_MC8_MISC_CHANNEL	0x00000000000c0000
#define	QPI_MC8_MISC_ECC_SYNDROME 0xffffffff00000000

struct dimm {
	int	socket;
	int	channel;
	int	id;
	long	ccount;
	long	ucount;
	TAILQ_ENTRY(dimm) link;
};

static TAILQ_HEAD(, dimm) dimms = TAILQ_HEAD_INITIALIZER(dimms);
static int socket_divisor = 1;
static int cpu_model;

/* Figure out how to map APIC IDs to sockets. */
static void
socket_probe(void)
{
	u_int regs[4];

	do_cpuid(1, regs);
	if (regs[3] & CPUID_HTT)
		socket_divisor = (regs[1] & CPUID_HTT_CORES) >> 16;
}

static struct dimm *
dimm_find(int socket, int channel, int id)
{
	struct dimm *d;

	TAILQ_FOREACH(d, &dimms, link) {
		if (d->socket == socket && d->channel == channel && d->id == id)
			return (d);
	}

	d = malloc(sizeof(*d));
	d->socket = socket;
	d->channel = channel;
	d->id = id;
	d->ccount = 0;
	d->ucount = 0;
	TAILQ_INSERT_TAIL(&dimms, d, link);
	return (d);
}

static int
qpi_probe(const char *vendor, int family, int model)
{

	if (strcmp(vendor, "GenuineIntel") != 0)
		return (0);
	if (family != 6)
		return (0);
	switch (model) {
	case 0x1a:	/* Nehalem */
	case 0x2a:	/* Sandybridge */
	case 0x2c:	/* Westmere-EP */
	case 0x2d:	/* Romley */
	case 0x2f:	/* E7 */
	case 0x3e:	/* Romley V2 */
		break;
	default:
		return (0);
	}

	socket_probe();
	cpu_model = model;
	return (100);
}

static int
qpi_handle_event(struct mca_record *mr)
{
	struct dimm *d;
	uint16_t mca_error;

	mca_error = mr->mr_status & MC_STATUS_MCA_ERROR;

	/* Memory controller error. */
	if (mr->mr_bank >= 8 && (mca_error & 0xef80) == 0x0080) {
		d = dimm_find(mr->mr_apic_id / socket_divisor,
		    (mr->mr_misc & QPI_MC8_MISC_CHANNEL) >> 18,
		    (mr->mr_misc & QPI_MC8_MISC_DIMM) >> 16);
		if (mr->mr_status & MC_STATUS_UC)
			d->ucount++;
		else
			d->ccount += (mr->mr_status & MC_STATUS_COR_COUNT) >> 38;
		return (1);
	}

	return (0);
}

/* XXX: This is a hack, should use motherboard name from smbios instead. */
static const char *
qpi_dimm_label(struct dimm *d)
{
	static char buf[64];

	switch (cpu_model) {
	case 0x2d:
	case 0x3e:
		/* X9 boards */
		snprintf(buf, sizeof(buf), "P%d-DIMM%c%d", d->socket + 1,
		    d->socket * 4 + d->id + 'A', d->channel + 1);
		break;
	default:
		/* X8 boards */
		snprintf(buf, sizeof(buf), "P%d-DIMM%d%c", d->socket + 1,
		    d->channel + 1, d->id + 'A');
		break;
	}
	return (buf);
}

static void
qpi_summary(void)
{
	struct dimm *d;

	TAILQ_FOREACH(d, &dimms, link) {
		if (d->ccount != 0)
			printf("%s: %ld corrected error%s\n", qpi_dimm_label(d),
			    d->ccount, d->ccount != 1 ? "s" : "");
		if (d->ucount != 0)
			printf("%s: %ld uncorrected error%s\n",
			    qpi_dimm_label(d), d->ucount,
			    d->ucount != 1 ? "s" : "");
	}
}

struct mca_handler qpi = {
	&qpi_probe,
	&qpi_handle_event,
	&qpi_summary
};

MCA_HANDLER(qpi);
