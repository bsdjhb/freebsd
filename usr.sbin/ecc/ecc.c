/*
 * Generate a summary of ECC events on a machine based on machine
 * check events.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <machine/cpufunc.h>
#include <x86/mca.h>
#include <machine/specialreg.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ecc.h"

SET_DECLARE(mca_handlers, struct mca_handler);

static char vendor[20];
static int family, model;
static int bizarre;

static void
usage(void)
{

	fprintf(stderr, "usage: ecc [-M core] [-N system]\n");
	exit(1);
}

static struct mca_handler *
find_handler(void)
{
	struct mca_handler *best_h, **mh;
	u_int regs[4];
	u_int cpu_id;
	int best_score, score;

	do_cpuid(0, regs);
	((u_int *)vendor)[0] = regs[1];
	((u_int *)vendor)[1] = regs[3];
	((u_int *)vendor)[2] = regs[2];
	vendor[12] = 0;

	do_cpuid(1, regs);
	cpu_id = regs[0];
	family = CPUID_TO_FAMILY(cpu_id);
	model = CPUID_TO_MODEL(cpu_id);

	best_h = NULL;
	best_score = -1;
	SET_FOREACH(mh, mca_handlers) {
		score = (*mh)->probe(vendor, family, model);
		if (score <= 0)
			continue;
		if (best_h == NULL || score > best_score) {
			best_h = *mh;
			best_score = score;
		}
	}
	return (best_h);
}

static void
fetch_events_live(struct mca_record **records, int *countp)
{
	struct mca_record *mr;
	int mib[4];
	size_t len;
	int count, i;

	len = sizeof(count);
	if (sysctlbyname("hw.mca.count", &count, &len, NULL, 0) < 0)
		err(1, "sysctl(hw.mca.count)");

	len = 4;
	if (sysctlnametomib("hw.mca.records", mib, &len) < 0)
		err(1, "sysctl(hw.mca.records)");

	mr = calloc(count, sizeof(struct mca_record));
	for (i = 0; i < count; i++) {
		mib[3] = i;
		len = sizeof(struct mca_record);
		if (sysctl(mib, 4, &mr[i], &len, NULL, 0) < 0) {
			warn("sysctl(hw.mca.records.%d)", i);
			continue;
		}
	}
	*records = mr;
	*countp = count;
}

static void
walk_events(struct mca_handler *h, struct mca_record *mr, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (h != NULL && h->handle_event(&mr[i]))
			continue;
		if (threshold_handle_event(&mr[i]))
			continue;
		bizarre++;
	}
}

int
main(int ac, char **av)
{
	struct mca_handler *h;
	struct mca_record *records;
	char ch, *mflag, *nflag;
	int count;

	mflag = NULL;
	nflag = NULL;
	while ((ch = getopt(ac, av, "M:N:")) != -1) {
		switch (ch) {
		case 'M':
			mflag = optarg;
			break;
		case 'N':
			nflag = optarg;
			break;
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;
	if (ac > 1)
		usage();

	h = find_handler();
	if (mflag != NULL || nflag != NULL)
		fetch_events_kvm(mflag, nflag, &records, &count);
	else
		fetch_events_live(&records, &count);
	walk_events(h, records, count);
	if (h != NULL)
		h->summary();
	else if (bizarre != 0)
		printf("Unsupported CPU: %s %xh_%xh\n", vendor, family, model);
	threshold_summary();
	if (bizarre != 0)
		printf("%d non-ECC error%s\n", bizarre, bizarre != 1 ? "s" :
		    "");
	return (0);
}
