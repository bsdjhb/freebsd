/*
 * Parse ECC error info for Core2 CPUs.
 */

#include <sys/types.h>
#include <x86/mca.h>
#include <machine/specialreg.h>
#include <stdio.h>
#include <string.h>

#include "ecc.h"

static int corrected, uncorrected;

static int
core2_probe(const char *vendor, int family, int model)
{

	if (strcmp(vendor, "GenuineIntel") != 0)
		return (0);
	if (family == 6 && (model == 0x0f || model == 0x17 || model == 0x1d))
		return (100);
	return (0);
}

static int
core2_handle_event(struct mca_record *mr)
{
	uint16_t mca_error;

	mca_error = mr->mr_status & MC_STATUS_MCA_ERROR;

	/* Generic L2 cache errors seem to be ECC errors. */
	/* GCACHE L2 ERR error */
	if ((mca_error & 0xefff) == 0x010a) {
		if (mr->mr_status & MC_STATUS_UC)
			uncorrected++;
		else
			corrected++;
		return (1);
	}

	/*
	 * Sometimes a non-error event is posted, perhaps when a
	 * stream of errors stops?
	 */
	if (mca_error == 0x0000)
		return (1);

	return (0);
}

static void
core2_summary(void)
{

	if (corrected != 0)
		printf("%d corrected ECC error%s\n", corrected,
		    corrected != 1 ? "s" : "");
	if (uncorrected != 0)
		printf("%d uncorrected ECC error%s\n", uncorrected,
		    uncorrected != 1 ? "s" : "");
}

struct mca_handler core2 = {
	&core2_probe,
	&core2_handle_event,
	&core2_summary
};

MCA_HANDLER(core2);
