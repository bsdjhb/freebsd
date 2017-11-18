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
#include "qpi.h"

/*
 * Fields in MISC for QPI memory controller memory channel errors.
 *
 * The SDM claims this is only used for model 0x1a (Nehalem) but it
 * seems to be used with other CPUs.  The SDM claims that memory
 * controller errors are logged as bus errors in newer CPU models, but
 * in practice ECC errors are logged as memory channel errors on newer
 * CPUs.
 *
 * The model 0x1a section notes that these errors are only logged in
 * bank 8.  Errors from other CPU models have been observed in banks
 * 7 and 11.
 */
#define	QPI_MC8_MISC_RTID	0x00000000000000ff
#define	QPI_MC8_MISC_DIMM	0x0000000000030000
#define	QPI_MC8_MISC_CHANNEL	0x00000000000c0000
#define	QPI_MC8_MISC_ECC_SYNDROME 0xffffffff00000000

SET_DECLARE(qpi_dimm_labelers, struct qpi_dimm_labeler);

static TAILQ_HEAD(, dimm) dimms = TAILQ_HEAD_INITIALIZER(dimms);
static int socket_divisor = 1;

/*
 * XXX: This backend assumes that there is one set of DIMM banks per
 * physical processor socket.  This may not be true on COD machines.
 */

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

	/* Ignore pre-Nehalem CPU models. */
	if (model < 0x1a || model == 0x1d)
		return (0);

	socket_probe();
	return (100);
}

static int
qpi_handle_event(struct mca_record *mr)
{
	struct dimm *d;
	uint16_t mca_error;

	mca_error = mr->mr_status & MC_STATUS_MCA_ERROR;

	/*
	 * Memory channel error in a memory controller bank.
	 *
	 * Some CPUs log memory write errors which do not have an
	 * associated address and which have a MISC value which does
	 * not seem to match any of the MISC formats described in the
	 * SDM.  Ignore those errors for now.
	 *
	 * This assumes MSR_ERROR_CONTROL.1 is not set.  We could
	 * perhaps infer the alternate decoding when this bit is set
	 * by checking for the valid bits in the top two bits of MISC.
	 */
	if (mr->mr_bank >= 7 && (mca_error & 0xef80) == 0x0080 &&
	    mr->mr_status & MC_STATUS_ADDRV) {
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

static const char *
qpi_default_dimm_label(struct dimm *d)
{
	static char buf[64];

	snprintf(buf, sizeof(buf), "Socket %d ID %d Channel %d", d->socket,
	    d->id, d->channel);
	return (buf);
}

static struct qpi_dimm_labeler *
find_labeler(void)
{
	struct qpi_dimm_labeler *best_l, **l;
	int best_score, score;

	best_l = NULL;
	best_score = -1;
	SET_FOREACH(l, qpi_dimm_labelers) {
		score = (*l)->probe();
		if (score <= 0)
			continue;
		if (best_l == NULL || score > best_score) {
			best_l = *l;
			best_score = score;
		}
	}
	return (best_l);
}

static const char *
qpi_dimm_label(struct dimm *d)
{
	static const char *(*label_func)(struct dimm *) = NULL;

	if (label_func == NULL) {
		struct qpi_dimm_labeler *l;

		l = find_labeler();
		if (l != NULL)
			label_func = l->dimm_label;
		else
			label_func = qpi_default_dimm_label;
	}
	return (label_func(d));
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
