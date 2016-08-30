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
#define	SSE42		0x0004
//#define	AVX_256		0x0004
#define	ERMS		0x0008

static struct name_table {
	const char *name;
	int value;
} variant_table[] = {
	{ "sse2_aligned", SSE2_ALIGNED },
	{ "sse2_unaligned", SSE2_UNALIGNED },
	{ "sse2", SSE2_ALIGNED | SSE2_UNALIGNED },
	{ "sse42", SSE42 },
//	{ "avx_256", AVX_256 },
//	{ "avx", AVX_256 },
	{ "erms", ERMS },
};

static int variants;

extern int memcmp_sse2_aligned(void *dst, const void *src, size_t len);
extern int memcmp_sse2_unaligned(void *dst, const void *src, size_t len);
extern int memcmp_sse42(void *dst, const void *src, size_t len);
//extern int memcmp_avx_256(void *dst, const void *src, size_t len);
extern int memcmp_erms(void *dst, const void *src, size_t len);
extern int memcmp_stock(void *dst, const void *src, size_t len);

static void
set_variants(void)
{
	u_int regs[4];

	variants = SSE2_ALIGNED | SSE2_UNALIGNED | ERMS;
	do_cpuid(1, regs);
	if (regs[2] & CPUID2_SSE42)
		variants |= SSE42;
#if 0
	if ((regs[2] & (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX)) ==
	    (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX))
		variants |= AVX_256;
#endif
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

#define	TEMP \
	if (variants & AVX_256)						\
		TRIAL("avx_256", suffix, memcmp_avx_256 args);		\

#define	TRIALS(suffix, args) do {					\
	TRIAL("builtin", suffix, memcmp_stock args);			\
	if (variants & SSE2_ALIGNED)					\
		TRIAL("sse2_aligned", suffix,				\
		    memcmp_sse2_aligned args);				\
	if (variants & SSE2_UNALIGNED)					\
		TRIAL("sse2_unaligned", suffix,				\
		    memcmp_sse2_unaligned args);			\
	if (variants & SSE42)						\
		TRIAL("sse42", suffix, memcmp_sse42 args);		\
	if (variants & ERMS)						\
		TRIAL("erms", suffix, memcmp_erms args);		\
} while (0)

static void
benchmarks(void)
{
	unsigned char *p1, *p2;
	uint64_t *samples;
	size_t size;
	int trials;

	size = getpagesize();
	trials = 1000;

	samples = calloc(trials + 1, sizeof(uint64_t));
	p1 = calloc(size, 1);
	p2 = calloc(size, 1);

	TRIALS("_page", (p2, p1, size));
	TRIALS("_short", (p2, p1, 15));
	TRIALS("_short2", (p2, p1, 32));
	TRIALS("_short3", (p2, p1, 48));
	TRIALS("_offset", (p2 + 4, p1, 128));
	TRIALS("_offset2", (p2 + 7, p1 + 7, 97));
	p1[size - 6] = 1;
	TRIALS("_dpage", (p2, p1, size));
	TRIALS("_dshort", (p2 + size - 16, p1 + size - 16, 15));
	TRIALS("_dshort2", (p2 + size - 32, p2 + size - 32, 32));
	TRIALS("_dshort3", (p2 + size - 48, p2 + size - 48, 48));
	TRIALS("_doffset", (p2 + size - 132, p2 + size - 128, 128));
	TRIALS("_doffset2", (p2 + size - 131, p2 + size - 131, 131));
}

static sig_atomic_t info;

static void
handler(int sig)
{

	info = 1;
}

static void
run_test(unsigned char *p1, unsigned char *p2, size_t len, size_t same)
{
	int i, todo, variant;
	int control, test;

	/* Always fill the raw data buffers with specific data. */
	for (i = 0; i < len; i++)
		p1[i] = i;
	memcpy(p2, p1, same);
	for (i = same; i < len; i++)
		p2[i] = ~i;

	/* Run plain memcmp first. */
	control = memcmp(p1, p2, len);
	if (same == len) {
		if (control != 0) {
			printf("memcmp: equal match %u vs 0\n", control);
			abort();
		}
	} else {
		if (control != p1[same] - p2[same]) {
			printf("memcmp: control %u vs expected %u\n", control,
			    p1[same] - p2[same]);
			abort();
		}
	}

	todo = variants;
	while (todo != 0) {
		/* Test memcpy. */
		if (todo & SSE2_ALIGNED) {
			test = memcmp_sse2_aligned(p1, p2, len);
			variant = SSE2_ALIGNED;
		} else if (todo & SSE2_UNALIGNED) {
			test = memcmp_sse2_unaligned(p1, p2, len);
			variant = SSE2_UNALIGNED;
		} else if (todo & SSE42) {
			test = memcmp_sse42(p1, p2, len);
			variant = SSE42;
#if 0
		} else if (todo & AVX_256) {
			test = memcmp_avx_256(p1, p2, len);
			variant = AVX_256;
#endif
		} else if (todo & ERMS) {
			test = memcmp_erms(p1, p2, len);
			variant = ERMS;
		}			

		/* Verify results are identical. */
		if (test != control) {
			printf("memcmp_%s: failed: same %zu len %zu: %u vs %u\n",
			    variant == SSE2_ALIGNED ? "sse2_aligned" :
			    variant == SSE2_UNALIGNED ? "sse2_unaligned" :
			    variant == SSE42 ? "sse42" :
#if 0
			    variant == AVX_256 ? "avx_256" :
#endif
			    variant == ERMS ? "erms" : "???",
			    same, len, test, control);
			abort();
		}
		todo &= ~variant;
	}
}

static void
tests(void)
{
	unsigned char *p1, *p2;
	int si, di, len, cap, same;

	p1 = malloc(getpagesize());
	p2 = malloc(getpagesize());

	signal(SIGINFO, handler);

	for (si = 0; si < 128; si++) {
		for (di = 0; di < 128; di++) {
			cap = getpagesize() - si;
			if (getpagesize() - di < cap)
				cap = getpagesize() - di;
			for (len = 1; len < cap; len++) {
				for (same = 0; same < len; same++) {
					run_test(p1 + si, p2 + di, len, same);
					if (info) {
						printf(
				    "memcmp: si %d di %d len %d same %d\n",
						    si, di, len, same);
						info = 0;
					}
				}
			}
		}
	}
}

static void
usage(void)
{
	fprintf(stderr, "Usage: memcmp [-t] [-v variant[,variant...]]\n");
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
