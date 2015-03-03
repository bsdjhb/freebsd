/*
 * Generic handling for threshold-based error reporting.  Other backends
 * use this handler.
 */

#include <sys/types.h>
#include <x86/mca.h>
#include <machine/specialreg.h>
#include <stdio.h>
#include <string.h>

#include "ecc.h"

static int yellow, green;

int
threshold_handle_event(struct mca_record *mr)
{
	int status;

	if (!(mr->mr_mcg_cap & MCG_CAP_TES_P))
		return (0);
	status = (mr->mr_status & MC_STATUS_TES_STATUS) >> 53;
	switch (status) {
	case 1:
		green++;
		return (1);
	case 2:
		yellow++;
		return (1);
	default:
		return (0);
	}
}

void
threshold_summary(void)
{

	if (green != 0)
		printf("%d green corrected error%s\n", green,
		    green != 1 ? "s": "");
	if (yellow != 0)
		printf("%d yellow corrected error%s\n", yellow,
		    yellow != 1 ? "s": "");
}
