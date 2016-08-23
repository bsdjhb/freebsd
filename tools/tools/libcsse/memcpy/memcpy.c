#include <sys/param.h>
#include <sys/signal.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define	SSE2_ALIGNED	0x0001
#define	SSE2_UNALIGNED	0x0002
#define	AVX_256		0x0004
#define	ERMS		0x0008

static struct name_table {
	const char *name;
	int value;
} variant_table[] = {
	{ "sse2_aligned", SSE2_ALIGNED },
	{ "sse2_unaligned", SSE2_UNALIGNED },
	{ "sse2", SSE2_ALIGNED | SSE2_UNALIGNED },
	{ "avx_256", AVX_256 },
	{ "avx", AVX_256 },
	{ "erms", ERMS },
};

static int variants;

extern void *memcpy_sse2_aligned(void *dst, const void *src, size_t len);
extern void *memcpy_sse2_unaligned(void *dst, const void *src, size_t len);
extern void *memcpy_avx_256(void *dst, const void *src, size_t len);
extern void *memcpy_erms(void *dst, const void *src, size_t len);

static void
set_variants(void)
{
	u_int regs[4];

	variants = SSE2_ALIGNED | SSE2_UNALIGNED | ERMS;
	do_cpuid(1, regs);
	if ((regs[2] & (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX)) ==
	    (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX))
		variants |= AVX_256;
}

#define	TRIAL(fname, suffix, TEST) do {					\
	FILE *fp;							\
	int i;								\
									\
	for (i = 0; i < trials; i++) {					\
		samples[i] = rdtsc();					\
		TEST;							\
	}								\
	samples[trials] = rdtsc();					\
	fp = fopen(fname suffix, "w");					\
	for (i = 0; i < trials; i++)					\
		fprintf(fp, "%ld\n", samples[i + 1] - samples[i]);	\
	fclose(fp);							\
} while (0)

#define	TRIALS(suffix, args) do {					\
	TRIAL("builtin", suffix, memcpy args);				\
	if (variants & SSE2_ALIGNED)					\
		TRIAL("sse2_aligned", suffix,				\
		    memcpy_sse2_aligned args);				\
	if (variants & SSE2_UNALIGNED)					\
		TRIAL("sse2_unaligned", suffix,				\
		    memcpy_sse2_unaligned args);			\
	if (variants & AVX_256)						\
		TRIAL("avx_256", suffix, memcpy_avx_256 args);		\
	if (variants & ERMS)						\
		TRIAL("erms", suffix, memcpy_erms args);		\
} while (0)

static void
benchmarks(void)
{
	char *p1, *p2;
	uint64_t *samples;
	size_t size;
	int trials;

	size = getpagesize();
	trials = 1000;

	samples = calloc(trials + 1, sizeof(uint64_t));
	p1 = calloc(size, 1);
	p2 = calloc(size, 1);

	TRIALS("_page", (p2, p1, size));
	TRIALS("_overlap", (p1 + 16, p1, size - 16));
	TRIALS("_short", (p2, p1, 15));
	TRIALS("_short2", (p2, p1, 32));
	TRIALS("_short3", (p2, p1, 48));
	TRIALS("_offset", (p2 + 4, p1, 128));
	TRIALS("_offset2", (p2 + 7, p1 + 7, 97));
}

static sig_atomic_t info;

static void
handler(int sig)
{

	info = 1;
}

struct page_pair {
	char *p1;
	char *p2;
} control, test, data;

static bool
run_test(void *src, void *dst, size_t len)
{
	int i, todo, variant;

	/* Always fill the raw data buffers with specific data. */
	for (i = 0; i < getpagesize(); i++)
		data.p1[i] = i;
	for (i = 0; i < getpagesize(); i++)
		data.p2[i] = ~i;

	/* Run plain memcpy first. */
	memcpy(dst, src, len);

	/* Save off buffers from plain memcpy in 'control'. */
	memcpy(control.p1, data.p1, getpagesize());
	memcpy(control.p2, data.p2, getpagesize());

	todo = variants;
	while (todo != 0) {
		/* Re-fill raw data buffers. */
		for (i = 0; i < getpagesize(); i++)
			data.p1[i] = i;
		for (i = 0; i < getpagesize(); i++)
			data.p2[i] = ~i;

		/* Test memcpy. */
		if (todo & SSE2_ALIGNED) {
			memcpy_sse2_aligned(dst, src, len);
			variant = SSE2_ALIGNED;
		} else if (todo & SSE2_UNALIGNED) {
			memcpy_sse2_unaligned(dst, src, len);
			variant = SSE2_UNALIGNED;
		} else if (todo & AVX_256) {
			memcpy_avx_256(dst, src, len);
			variant = AVX_256;
		} else if (todo & ERMS) {
			memcpy_erms(dst, src, len);
			variant = ERMS;
		}			

		/* Save off buffers from test memcpy in 'test'. */
		memcpy(test.p1, data.p1, getpagesize());
		memcpy(test.p2, data.p2, getpagesize());

		/* Verify results are identical. */
		if (memcmp(control.p1, test.p1, getpagesize()) != 0 ||
		    memcmp(control.p2, test.p2, getpagesize()) != 0) {
			printf("%s: ", variant == SSE2_ALIGNED ? "sse2_aligned" :
			    variant == SSE2_UNALIGNED ? "sse2_unaligned" :
			    variant == AVX_256 ? "avx_256" :
			    variant == ERMS ? "erms" : "???");
			return (false);
		}
		todo &= ~variant;
	}
	return (true);
}

static void
tests(void)
{
	int si, di, len, cap;

	control.p1 = malloc(getpagesize());
	control.p2 = malloc(getpagesize());
	test.p1 = malloc(getpagesize());
	test.p2 = malloc(getpagesize());
	data.p1 = malloc(getpagesize());
	data.p2 = malloc(getpagesize());

	signal(SIGINFO, handler);

	/* Non-overlapping tests. */
	for (si = 0; si < 128; si++) {
		for (di = 0; di < 128; di++) {
			cap = getpagesize() - si;
			if (getpagesize() - di < cap)
				cap = getpagesize() - di;
			for (len = 1; len < cap; len++) {
				if (!run_test(data.p1 + si, data.p2 + di, len)) {
					printf("normal failed: si %d di %d"
					    " len %d\n", si, di, len);
					abort();
				}
				if (info) {
					printf("normal: si %d di %d len %d\n",
					    si, di, len);
					info = 0;
				}
			}
		}
	}

	/* Overlapping tests. */
	for (si = 0; si < 128; si++) {
		for (di = 0; di < 128; di++) {
			cap = getpagesize() - si;
			if (getpagesize() - di < cap)
				cap = getpagesize() - di;
			for (len = 1; len < cap; len++) {
				if (!run_test(data.p1 + si, data.p1 + di, len)) {
					printf("overlap failed: si %d di %d"
					    " len %d\n", si, di, len);
					abort();
				}
				if (info) {
					printf("overlap: si %d di %d len %d\n",
					    si, di, len);
					info = 0;
				}
			}
		}
	}
}

static void
usage(void)
{
	fprintf(stderr, "Usage: memcpy [-t] [-v variant[,variant...]]\n");
	exit(1);
}

static void
parse_variants(const char *arg)
{
	char *str, *cp;
	unsigned i;

	str = strdup(arg);
	cp = strtok(str, ",");
	while (cp != NULL) {
		for (i = 0; i < nitems(variant_table); i++) {
			if (strcasecmp(cp, variant_table[i].name) == 0) {
				variants |= variant_table[i].value;
				goto next;
			}
		}
		errx(1, "Invalid variant %s", cp);
	next:
		cp = strtok(NULL, ",");
	}
	free(str);
}

int
main(int ac, char **av)
{
	enum { BENCHMARKS, TESTS } mode = BENCHMARKS;
	int ch;

	while ((ch = getopt(ac, av, "tv:")) != -1) {
		switch (ch) {
		case 't':
			mode = TESTS;
			break;
		case 'v':
			parse_variants(optarg);
			break;
		default:
			usage();
		}
	}

	ac -= optind;
	av += optind;

	if (ac != 0)
		usage();

	if (variants == 0)
		set_variants();

	switch (mode) {
	case BENCHMARKS:
		benchmarks();
		break;
	case TESTS:
		tests();
		break;
	}
	return (0);	
}
