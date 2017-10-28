/*
 * QPI DIMM labelers for SuperMicro motherboards.
 */

#include <sys/types.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <regex.h>
#include <smbios.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "qpi.h"

/*
 * XXX: These are legacy namers that predate support for parsing DIMM names
 * from SMBIOS.  They are possibly redundant with the full SMBIOS namer.
 */
static int
qpi_x8_namer_probe(void)
{
	u_int regs[4];

	do_cpuid(1, regs);
	switch (CPUID_TO_MODEL(regs[0])) {
	case 0x1a:	/* Nehalem */
	case 0x2a:	/* Sandybridge */
	case 0x2c:	/* Westmere-EP */
	case 0x2f:	/* E7 */
		return (1);
	default:
		return (0);
	}
}

static const char *
qpi_x8_namer_label(struct dimm *d)
{
	static char buf[64];

	snprintf(buf, sizeof(buf), "P%d-DIMM%d%c", d->socket + 1,
	    d->channel + 1, d->id + 'A');
	return (buf);
}

static struct qpi_dimm_labeler qpi_sm_x8 = {
	&qpi_x8_namer_probe,
	&qpi_x8_namer_label
};

QPI_DIMM_LABELER(qpi_sm_x8);

static int
qpi_x9_namer_probe(void)
{
	u_int regs[4];

	do_cpuid(1, regs);
	switch (CPUID_TO_MODEL(regs[0])) {
	case 0x2d:	/* Romley */
	case 0x3e:	/* Romley V2 */
		return (1);
	default:
		return (0);
	}
}

static const char *
qpi_x9_namer_label(struct dimm *d)
{
	static char buf[64];

	snprintf(buf, sizeof(buf), "P%d-DIMM%c%d", d->socket + 1,
	    d->socket * 4 + d->id + 'A', d->channel + 1);
	return (buf);
}

static struct qpi_dimm_labeler qpi_sm_x9 = {
	&qpi_x9_namer_probe,
	&qpi_x9_namer_label
};

QPI_DIMM_LABELER(qpi_sm_x9);

/*
 * This namer handles SuperMicro boards which use the pattern
 * 'P<a>_Node<b>_Channel<c>_Dimm<d>' in the Bank Locator string of
 * SMBIOS memory device entries.  Currently this namer assumes that
 * 'a' matches the socket, 'c' matches the id, and 'd' matches the
 * channel.
 */
static smbios_handle_t smbios_handle;
static regex_t smbios_regex;

static enum smbios_cb_retval
qpi_sm_probe_callback(smbios_handle_t handle,
    struct smbios_structure_header *hdr, void *arg)
{
	struct smbios_memory_device *md;
	const char *str;
	int *matchesp;

	if (hdr->type != SMBIOS_MEMORY_DEVICE)
		return (SMBIOS_CONTINUE);

	matchesp = arg;
	if (hdr->length < offsetof(struct smbios_memory_device, memory_type))
		goto bad;

	md = (struct smbios_memory_device *)hdr;
	if (smbios_find_string(handle, hdr, md->device_locator) == NULL)
		goto bad;

	str = smbios_find_string(handle, hdr, md->bank_locator);
	if (str == NULL)
		goto bad;

	if (regexec(&smbios_regex, str, 0, NULL, 0) != 0)
		goto bad;

	*matchesp += 1;
	return (SMBIOS_CONTINUE);

bad:
	*matchesp = 0;
	return (SMBIOS_STOP);
}

static int
qpi_sm_smbios_probe(void)
{
	int matches;

	matches = 0;
	if (smbios_open(&smbios_handle) != 0)
		return (-1);

	if (regcomp(&smbios_regex,
	    "^P([0-9]+)_Node0_Channel([0-9]+)_Dimm([0-9]+)$", REG_EXTENDED) != 0)
		goto bad;
	smbios_walk_table(smbios_handle, qpi_sm_probe_callback, &matches);
	if (matches != 0)
		return (10);

	regfree(&smbios_regex);
bad:
	smbios_close(smbios_handle);
	return (0);
}

struct sm_find_dimm_data {
	struct dimm *d;
	const char *label;
};
	
static enum smbios_cb_retval
qpi_sm_find_dimm(smbios_handle_t handle,
    struct smbios_structure_header *hdr, void *arg)
{
	struct sm_find_dimm_data *fdd;
	struct smbios_memory_device *md;
	regmatch_t matches[smbios_regex.re_nsub + 1];
	const char *str;
	
	if (hdr->type != SMBIOS_MEMORY_DEVICE)
		return (SMBIOS_CONTINUE);

	md = (struct smbios_memory_device *)hdr;
	str = smbios_find_string(handle, hdr, md->bank_locator);
	if (str == NULL)
		return (SMBIOS_STOP);

	if (regexec(&smbios_regex, str, smbios_regex.re_nsub + 1, matches,
	    0) != 0)
		return (SMBIOS_STOP);

	/* P<a> */
	if (strtol(str + matches[1].rm_so, NULL, 0) != fdd->d->socket)
		return (SMBIOS_CONTINUE);

	/* Channel<c> */
	if (strtol(str + matches[2].rm_so, NULL, 0) != fdd->d->id)
		return (SMBIOS_CONTINUE);

	/* Dimm<d> */
	if (strtol(str + matches[3].rm_so, NULL, 0) != fdd->d->channel)
		return (SMBIOS_CONTINUE);

	fdd->label = smbios_find_string(handle, hdr, md->device_locator);
	return (SMBIOS_STOP);
}

static const char *
qpi_sm_smbios_label(struct dimm *d)
{
	struct sm_find_dimm_data fdd;

	fdd.label = NULL;
	fdd.d = d;
	smbios_walk_table(smbios_handle, qpi_sm_find_dimm, &fdd);
	return (fdd.label);
}

static struct qpi_dimm_labeler qpi_sm_smbios = {
	&qpi_sm_smbios_probe,
	&qpi_sm_smbios_label
};

QPI_DIMM_LABELER(qpi_sm_smbios);
