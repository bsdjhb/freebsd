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

#define SSE2_ALIGNED	0x0001
#define	SSE2_UNALIGNED	0x0002
#define	SSSE3_ALIGNED	0x0004
#define	SSSE3_UNALIGNED	0x0008
#define	AVX_128		0x0010
#define	AVX_256		0x0020
#define	AVX2_256	0x0040
#define	ERMS		0x0080

static struct name_table {
	const char *name;
	int value;
} variant_table[] = {
	{ "sse2_aligned", SSE2_ALIGNED },
	{ "sse2_unaligned", SSE2_UNALIGNED },
	{ "sse2", SSE2_ALIGNED | SSE2_UNALIGNED },
	{ "ssse3_aligned", SSSE3_ALIGNED },
	{ "ssse3_unaligned", SSSE3_UNALIGNED },
	{ "ssse3", SSSE3_ALIGNED | SSSE3_UNALIGNED },
	{ "avx_128", AVX_128 },
	{ "avx_256", AVX_256 },
	{ "avx", AVX_128 | AVX_256 },
	{ "avx2_256", AVX2_256 },
	{ "avx2", AVX2_256 },
	{ "erms", ERMS },
};

static int variants;

extern void *memset_sse2_aligned(void *dst, int c, size_t length);
extern void *memset_sse2_unaligned(void *dst, int c, size_t length);
extern void *memset_ssse3_aligned(void *dst, int c, size_t length);
extern void *memset_ssse3_unaligned(void *dst, int c, size_t length);
extern void *memset_avx_128(void *dst, int c, size_t length);
extern void *memset_avx_256(void *dst, int c, size_t length);
extern void *memset_avx2_256(void *dst, int c, size_t length);
extern void *memset_erms(void *dst, int c, size_t length);

static void
set_variants(void)
{
	u_int regs[4];

	variants = SSE2_ALIGNED | SSE2_UNALIGNED | ERMS;
	do_cpuid(1, regs);
	if (regs[2] & CPUID2_SSSE3)
		variants |= SSSE3_ALIGNED | SSSE3_UNALIGNED;
	if ((regs[2] & (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX)) ==
	    (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX)) {
		variants |= AVX_128 | AVX_256;
		do_cpuid(0, regs);
		if (regs[0] >= 7) {
			cpuid_count(7, 0, regs);
			if (regs[1] & CPUID_STDEXT_AVX2)
				variants |= AVX2_256;
		}
	}
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
	TRIAL("builtin", suffix, memset args);				\
	if (variants & SSE2_ALIGNED)					\
		TRIAL("sse2_aligned", suffix,				\
		    memset_sse2_aligned args);				\
	if (variants & SSE2_UNALIGNED)					\
		TRIAL("sse2_unaligned", suffix,				\
		    memset_sse2_unaligned args);			\
	if (variants & SSSE3_ALIGNED)					\
		TRIAL("ssse3_aligned", suffix,				\
		    memset_ssse3_aligned args);				\
	if (variants & SSSE3_UNALIGNED)					\
		TRIAL("ssse3_unaligned", suffix,			\
		    memset_ssse3_unaligned args);			\
	if (variants & AVX_128)						\
		TRIAL("avx_128", suffix, memset_avx_128 args);		\
	if (variants & AVX_256)						\
		TRIAL("avx_256", suffix, memset_avx_256 args);		\
	if (variants & AVX2_256)					\
		TRIAL("avx2_256", suffix, memset_avx2_256 args);	\
	if (variants & ERMS)						\
		TRIAL("erms", suffix, memset_erms args);		\
} while (0)

static void
benchmarks(void)
{
	char *p1;
	uint64_t *samples;
	size_t size;
	int trials;

	size = getpagesize();
	trials = 1000;

	samples = calloc(trials + 1, sizeof(uint64_t));
	p1 = calloc(size, 1);

	TRIALS("_page", (p1, 0xa5, size));
	TRIALS("_short", (p1, 0xa5, 15));
	TRIALS("_short2", (p1, 0xa5, 32));
	TRIALS("_short3", (p1, 0xa5, 48));
	TRIALS("_offset", (p1 + 4, 0, 128));
	TRIALS("_offset2", (p1 + 7, 0, 97));
}

static sig_atomic_t info;

static void
handler(int sig)
{

	info = 1;
}

char *control, *test, *data;

static bool
run_test(void *dst, size_t len)
{
	int i, todo, variant;

	/* Always fill the raw data buffer with specific data. */
	for (i = 0; i < getpagesize(); i++)
		data[i] = 0xff;

	/* Run plain memset first. */
	memset(dst, 0xa5, len);

	/* Save off buffer from plain memset in 'control'. */
	memcpy(control, data, getpagesize());

	todo = variants;
	while (todo != 0) {
		/* Re-fill raw data buffers */
		for (i = 0; i < getpagesize(); i++)
			data[i] = 0xff;

		/* Test memset. */
		if (todo & SSE2_ALIGNED) {
			memset_sse2_aligned(dst, 0xa5, len);
			variant = SSE2_ALIGNED;
		} else if (todo & SSE2_UNALIGNED) {
			memset_sse2_unaligned(dst, 0xa5, len);
			variant = SSE2_UNALIGNED;
		} else if (todo & SSSE3_ALIGNED) {
			memset_ssse3_aligned(dst, 0xa5, len);
			variant = SSSE3_ALIGNED;
		} else if (todo & SSSE3_UNALIGNED) {
			memset_ssse3_unaligned(dst, 0xa5, len);
			variant = SSSE3_UNALIGNED;
		} else if (todo & AVX_128) {
			memset_avx_128(dst, 0xa5, len);
			variant = AVX_128;
		} else if (todo & AVX_256) {
			memset_avx_256(dst, 0xa5, len);
			variant = AVX_256;
		} else if (todo & AVX2_256) {
			memset_avx2_256(dst, 0xa5, len);
			variant = AVX2_256;
		} else if (todo & ERMS) {
			memset_erms(dst, 0xa5, len);
			variant = ERMS;
		}			

		/* Save off buffer from test memset in 'test'. */
		memcpy(test, data, getpagesize());

		/* Verify results are identical. */
		if (memcmp(control, test, getpagesize()) != 0) {
			printf("%s: ", variant == SSE2_ALIGNED ? "sse2_aligned" :
			    variant == SSE2_UNALIGNED ? "sse2_unaligned" :
			    variant == SSSE3_ALIGNED ? "ssse3_aligned" :
			    variant == SSSE3_UNALIGNED ? "ssse3_unaligned" :
			    variant == AVX_128 ? "avx_128" :
			    variant == AVX_256 ? "avx_256" :
			    variant == AVX2_256 ? "avx2_256" :
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
	int si, len, cap;

	control = malloc(getpagesize());
	test = malloc(getpagesize());
	data = malloc(getpagesize());

	signal(SIGINFO, handler);

	for (si = 0; si < 256; si++) {
		cap = getpagesize() - si;
		for (len = 1; len < cap; len++) {
			if (!run_test(data + si, len)) {
				printf("memset failed: si %d len %d\n", si, len);
				abort();
			}
			if (info) {
				printf("memset: si %d len %d\n", si, len);
				info = 0;
			}
		}
	}
}

static void
usage(void)
{
	fprintf(stderr, "Usage: memset [-t] [-v variant[,variant...]]\n");
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
