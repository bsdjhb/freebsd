/*-
 * Fetch a list of MCA records from a kernel crash dump.
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <x86/mca.h>
#include <machine/specialreg.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <stdlib.h>
#include <strings.h>

#include "ecc.h"

struct mca_record_internal {
	struct mca_record rec;
	int		logged;
	STAILQ_ENTRY(mca_internal) link;
};

static struct nlist nl[] = {
#define	X_MCA_RECORDS		0
	{ .n_name = "_mca_records" },
	{ .n_name = NULL },
};

static int
kread(kvm_t *kvm, void *kvm_pointer, void *buf, size_t size, size_t offset)
{
	ssize_t ret;

	ret = kvm_read(kvm, (unsigned long)kvm_pointer + offset, buf, size);
	if (ret < 0 || (size_t)ret != size)
		return (-1);
	return (0);
}

static int
kread_symbol(kvm_t *kvm, int index, void *buf, size_t size)
{
	ssize_t ret;

	ret = kvm_read(kvm, nl[index].n_value, buf, size);
	if (ret < 0 || (size_t)ret != size)
		return (-1);
	return (0);
}

void
fetch_events_kvm(char *mflag, char *nflag, struct mca_record **recordsp,
    int *countp)
{
	struct mca_record *mr, *records;
	char errbuf[_POSIX2_LINE_MAX];
	kvm_t *kvm;
	size_t record_size, link_offset;
	int count;

	if (mflag == NULL)
		errx(1, "kernel option requires core option");

	kvm = kvm_openfiles(nflag, mflag, NULL, O_RDONLY, errbuf);
	if (kvm == NULL)
		errx(1, "kvm_openfiles: %s", errbuf);
	if (kvm_nlist(kvm, nl) != 0)
		errx(1, "kvm_nlist: %s", kvm_geterr(kvm));

	/* stqh_first is the first pointer at this address. */
	if (kread_symbol(kvm, X_MCA_RECORDS, &mr, sizeof(mr)) < 0)
		errx(1, "kvm_read(mca_records) failed");
	record_size = sizeof(struct mca_record);
	link_offset = __offsetof(struct mca_record_internal,
	    link.stqe_next);

	count = 0;
	records = NULL;
	while (mr != NULL) {
		records = reallocf(records, (count + 1) *
		    sizeof(struct mca_record));
		bzero(&records[count], sizeof(struct mca_record));
		if (kread(kvm, mr, &records[count], record_size, 0) < 0)
			break;
		count++;
		if (kread(kvm, mr, &mr, sizeof(mr), link_offset) < 0)
			break;
	}

	*countp = count;
	*recordsp = records;
}
