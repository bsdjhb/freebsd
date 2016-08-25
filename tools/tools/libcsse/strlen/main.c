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

#define	SSE2		0x0001
#define	SSE42		0x0002
#define	AVX		0x0004
#define	AVX2		0x0010
#define	ERMS		0x0020

static struct name_table {
	const char *name;
	int value;
} variant_table[] = {
	{ "sse2", SSE2 },
	{ "sse4.2", SSE42 },
	{ "avx", AVX },
	{ "avx2", AVX2 },
	{ "erms", ERMS },
};

static int variants;

extern size_t strlen_sse2(const char *s);
extern size_t strlen_sse42(const char *s);
extern size_t strlen_avx(const char *s);
extern size_t strlen_avx2(const char *s);
extern size_t strlen_erms(const char *s);
extern size_t strlen_mi(const char *s);

static void
set_variants(void)
{
	u_int regs[4];

	variants = SSE2 | ERMS;
	do_cpuid(1, regs);
	if (regs[2] & CPUID2_SSE42)
		variants |= SSE42;
	if ((regs[2] & (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX)) ==
	    (CPUID2_XSAVE | CPUID2_OSXSAVE | CPUID2_AVX)) {
		variants |= AVX;
		do_cpuid(0, regs);
		if (regs[0] >= 7) {
			cpuid_count(7, 0, regs);
			if (regs[1] & CPUID_STDEXT_AVX2)
				variants |= AVX2;
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
	TRIAL("builtin", suffix, (void)strlen_mi args);			\
	if (variants & SSE2)						\
		TRIAL("sse2", suffix, strlen_sse2 args);		\
	if (variants & SSE42)						\
		TRIAL("sse42", suffix, strlen_sse42 args);		\
	if (variants & AVX)						\
		TRIAL("avx", suffix, strlen_avx args);			\
	if (variants & AVX2)						\
		TRIAL("avx2", suffix, strlen_avx2 args);		\
	if (variants & ERMS)						\
		TRIAL("erms", suffix, strlen_erms args);		\
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

	memset(p1, 0xa5, size - 1);
	TRIALS("_page", (p1));

	p1[47] = '\0';
	TRIALS("_short3", (p1));

	p1[31] = '\0';
	TRIALS("_short2", (p1));

	p1[14] = '\0';
	TRIALS("_short", (p1));

	memset(p1, 0xa5, 48);
	p1[127 + 4] = '\0';
	TRIALS("_offset", (p1 + 4));

	p1[96 + 7] = '\0';
	TRIALS("_offset2", (p1 + 7));
}

static sig_atomic_t info;

static void
handler(int sig)
{

	info = 1;
}

char *data;

static void
run_test(size_t offset, size_t len)
{
	size_t control, i, test;
	int todo, variant;

	/* Fill the buffer with data. */
	for (i = 0; i < (size_t)getpagesize(); i++) {
		if (i < offset)
			/*
			 * Prefill the header with zeros to ensure
			 * they are ignored.
			 */
			data[i] = '\0';
		else if (i >= offset + len && (i - (offset + len)) % 2 == 0)
			data[i] = '\0';
		else
			data[i] = i % 254 + 1;
	}

	/* Plain strlen. */
	control = strlen(data + offset);
	if (control != len) {
		printf("strlen: control length %zu vs %zu\n", control, len);
		abort();
	}

	todo = variants;
	while (todo != 0) {
		/* Test strlen. */
		if (todo & SSE2) {
			test = strlen_sse2(data + offset);
			variant = SSE2;
		} else if (todo & SSE42) {
			test = strlen_sse42(data + offset);
			variant = SSE42;
		} else if (todo & AVX) {
			test = strlen_avx(data + offset);
			variant = AVX;
		} else if (todo & AVX2) {
			test = strlen_avx2(data + offset);
			variant = AVX2;
		} else if (todo & ERMS) {
			test = strlen_erms(data + offset);
			variant = ERMS;
		}
		
		/* Verify results are identical. */
		if (test != control) {
			printf("strlen%s failed: si %zu len %zu: %zu vs %zu\n",
			    variant == SSE2 ? "sse2" :
			    variant == SSE42 ? "sse42" :
			    variant == AVX ? "avx" :
			    variant == AVX2 ? "avx2" :
			    variant == ERMS ? "erms" : "???",
			    offset, len, test, control);
			abort();
		}
	}
}

static void
tests(void)
{
	int si, len, cap;

	data = malloc(getpagesize());

	signal(SIGINFO, handler);

	for (si = 0; si < 256; si++) {
		cap = getpagesize() - si;
		for (len = 0; len < cap - 1; len++) {
			run_test(si, len);
			if (info) {
				printf("strlen: si %d len %d\n", si, len);
				info = 0;
			}
		}
	}
}

static void
usage(void)
{

	fprintf(stderr, "Usage: strlen [-t] [-v variant[,variant...]]\n");
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
