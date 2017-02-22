/*-
 * Copyright (c) 2004 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 * $FreeBSD$
 */

/*
 * A different tool for checking hardware crypto support.  Whereas
 * cryptotest is focused on simple performance numbers, this tool is
 * focused on correctness.  For each crypto operation, it performs the
 * operation once in software via OpenSSL and a second time via
 * OpenCrypto and compares the results.
 *
 * cryptocheck [-vz] [-a algorithm] [-d dev] [size ...]
 *
 * Options:
 *	-v	Verbose.
 *	-z	Run all algorithms on a variety of buffer sizes.
 *
 * Supported algorithms:
 *	all		Run all tests
 *	hmac		Run all hmac tests
 *	sha1		sha1 hmac
 *	sha256		256-bit sha2 hmac
 *	sha384		384-bit sha2 hmac
 *	sha512		512-bit	sha2 hmac
 *	aes		128-bit aes cbc
 *	aes192		192-bit	aes cbc
 *	aes256		256-bit aes cbc
 *	aes-ctr		128-bit aes ctr
 *	aes-ctr192	192-bit aes ctr
 *	aes-ctr256	256-bit aes ctr
 *	aes-xts		128-bit aes xts
 *	aes-xts256	256-bit aes xts
 */

#include <sys/param.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <libutil.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/hmac.h>

#include <crypto/cryptodev.h>

struct alg {
	const char *name;
	int alg;
	enum { T_NONE, T_HMAC, T_BLKCIPHER } type;
	const EVP_CIPHER *(*evp_cipher)(void);
	const EVP_MD *(*evp_md)(void);
		
} algs[] = {
	{ .name = "all", .alg = 0, .type = T_NONE },
	{ .name = "hmac", .alg = 0, .type = T_HMAC },
	{ .name = "sha1", .alg = CRYPTO_SHA1_HMAC, .type = T_HMAC,
	  .evp_md = EVP_sha1 },
	{ .name = "sha256", .alg = CRYPTO_SHA2_256_HMAC, .type = T_HMAC,
	  .evp_md = EVP_sha256 },
	{ .name = "sha384", .alg = CRYPTO_SHA2_384_HMAC, .type = T_HMAC,
	  .evp_md = EVP_sha384 },
	{ .name = "sha512", .alg = CRYPTO_SHA2_512_HMAC, .type = T_HMAC,
	  .evp_md = EVP_sha512 },
	{ .name = "blkcipher", .alg = 0, .type = T_BLKCIPHER },
	{ .name = "aes", .alg = CRYPTO_AES_CBC, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_128_cbc },
	{ .name = "aes192", .alg = CRYPTO_AES_CBC, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_192_cbc },
	{ .name = "aes256", .alg = CRYPTO_AES_CBC, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_256_cbc },
	{ .name = "aes-ctr", .alg = CRYPTO_AES_ICM, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_128_ctr },
	{ .name = "aes-ctr192", .alg = CRYPTO_AES_ICM, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_192_ctr },
	{ .name = "aes-ctr256", .alg = CRYPTO_AES_ICM, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_256_ctr },
	{ .name = "aes-xts", .alg = CRYPTO_AES_XTS, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_128_xts },
	{ .name = "aes-xts256", .alg = CRYPTO_AES_XTS, .type = T_BLKCIPHER,
	  .evp_cipher = EVP_aes_256_xts },
};

static bool verbose;
static int crid;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: cryptocheck [-z] [-a algorithm] [-d dev] [size ...]\n");
	exit(1);
}

static struct alg *
find_alg(const char *name)
{
	u_int i;

	for (i = 0; i < nitems(algs); i++)
		if (strcasecmp(algs[i].name, name) == 0)
			return (&algs[i]);
	return (NULL);
}

static int
devcrypto(void)
{
	static int fd = -1;

	if (fd < 0) {
		fd = open("/dev/crypto", O_RDWR | O_CLOEXEC, 0);
		if (fd < 0)
			err(1, "/dev/crypto");
	}
	return (fd);
}

static int
crlookup(const char *devname)
{
	struct crypt_find_op find;

	if (strncmp(devname, "soft", 4) == 0)
		return CRYPTO_FLAG_SOFTWARE;

	find.crid = -1;
	strlcpy(find.name, devname, sizeof(find.name));
	if (ioctl(devcrypto(), CIOCFINDDEV, &find) == -1)
		err(1, "ioctl(CIOCFINDDEV)");
	return (find.crid);
}

const char *
crfind(int crid)
{
	static struct crypt_find_op find;

	if (crid == CRYPTO_FLAG_SOFTWARE)
		return ("soft");
	else if (crid == CRYPTO_FLAG_HARDWARE)
		return ("unknown");

	bzero(&find, sizeof(find));
	find.crid = crid;
	if (ioctl(devcrypto(), CRIOFINDDEV, &find) == -1)
		err(1, "ioctl(CIOCFINDDEV): crid %d", crid);
	return (find.name);
}

static int
crget(void)
{
	int fd;

	if (ioctl(devcrypto(), CRIOGET, &fd) == -1)
		err(1, "ioctl(CRIOGET)");
	if (fcntl(fd, F_SETFD, 1) == -1)
		err(1, "fcntl(F_SETFD) (crget)");
	return fd;
}

static char
rdigit(void)
{
	const char a[] = {
		0x10,0x54,0x11,0x48,0x45,0x12,0x4f,0x13,0x49,0x53,0x14,0x41,
		0x15,0x16,0x4e,0x55,0x54,0x17,0x18,0x4a,0x4f,0x42,0x19,0x01
	};
	return 0x20+a[random()%nitems(a)];
}

static char *
alloc_buffer(size_t len)
{
	char *buf;
	size_t i;

	buf = malloc(len);
	for (i = 0; i < len; i++)
		buf[i] = rdigit();
	return (buf);
}

static bool
ocf_hmac(struct alg *alg, const char *buffer, size_t size, const char *key,
    size_t key_len, char *digest, int *cridp)
{
	struct session2_op sop;
	struct crypt_op cop;
	int fd;

	memset(&sop, 0, sizeof(sop));
	memset(&cop, 0, sizeof(cop));
	sop.crid = crid;
	sop.mackeylen = key_len;
	sop.mackey = (char *)key;
	sop.mac = alg->alg;
	fd = crget();
	if (ioctl(fd, CIOCGSESSION2, &sop) < 0) {
		warn("cryptodev %s HMAC not supported for device %s",
		    alg->name, crfind(crid));
		close(fd);
		return (false);
	}

	cop.ses = sop.ses;
	cop.op = 0;
	cop.len = size;
	cop.src = (char *)buffer;
	cop.dst = NULL;
	cop.mac = digest;
	cop.iv = NULL;

	if (ioctl(fd, CIOCCRYPT, &cop) < 0)
		err(1, "ioctl(CIOCCRYPT)");

	if (ioctl(fd, CIOCFSESSION, &sop.ses) < 0)
		warn("ioctl(CIOCFSESSION)");

	close(fd);
	*cridp = sop.crid;
	return (true);
}

static void
run_hmac_test(struct alg *alg, size_t size)
{
	const EVP_MD *md;
	char *key, *buffer;
	u_int key_len, digest_len;
	int crid;
	char control_digest[EVP_MAX_MD_SIZE], test_digest[EVP_MAX_MD_SIZE];

	memset(control_digest, 0x3c, sizeof(control_digest));
	memset(test_digest, 0x3c, sizeof(test_digest));

	md = alg->evp_md();
	key_len = EVP_MD_size(md);
	assert(EVP_MD_size(md) <= sizeof(control_digest));

	key = alloc_buffer(key_len);
	buffer = alloc_buffer(size);

	/* OpenSSL HMAC. */
	digest_len = sizeof(control_digest);
	if (HMAC(md, key, key_len, (u_char *)buffer, size,
	    (u_char *)control_digest, &digest_len) == NULL)
		errx(1, "OpenSSL %s (%zu) HMAC failed: %s", alg->name,
		    size, ERR_error_string(ERR_get_error(), NULL));

	/* cryptodev HMAC. */
	if (ocf_hmac(alg, buffer, size, key, key_len, test_digest, &crid)) {
		if (memcmp(control_digest, test_digest,
		    sizeof(control_digest)) != 0) {
			if (memcmp(control_digest, test_digest,
			    EVP_MD_size(md)) == 0)
				printf("%s (%zu) mismatch in trailer:\n",
				    alg->name, size);
			else
				printf("%s (%zu) mismatch:\n", alg->name, size);
			printf("control:\n");
			hexdump(control_digest, sizeof(control_digest), NULL,
			    0);
			printf("test (cryptodev device %s):\n", crfind(crid));
			hexdump(test_digest, sizeof(test_digest), NULL, 0);
		} else if (verbose)
			printf("%s (%zu) matched (cryptodev device %s)\n",
			    alg->name, size, crfind(crid));
	}

	free(buffer);
	free(key);
}

static size_t
openssl_cipher(struct alg *alg, const EVP_CIPHER *cipher, const char *key,
    const char *iv, const char *input, size_t size, char *output, int enc)
{
	EVP_CIPHER_CTX *ctx;
	int outl, total;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		errx(1, "OpenSSL %s (%zu) ctx new failed: %s", alg->name,
		    size, ERR_error_string(ERR_get_error(), NULL));
	if (EVP_CipherInit_ex(ctx, cipher, NULL, (const u_char *)key,
	    (const u_char *)iv, enc) != 1)
		errx(1, "OpenSSL %s (%zu) ctx init failed: %s", alg->name,
		    size, ERR_error_string(ERR_get_error(), NULL));
	if (EVP_CipherUpdate(ctx, (u_char *)output, &outl,
	    (const u_char *)input, size) != 1)
		errx(1, "OpenSSL %s (%zu) cipher update failed: %s", alg->name,
		    size, ERR_error_string(ERR_get_error(), NULL));
	total = outl;
	if (EVP_CipherFinal_ex(ctx, (u_char *)output + outl, &outl) != 1)
		errx(1, "OpenSSL %s (%zu) cipher final failed: %s", alg->name,
		    size, ERR_error_string(ERR_get_error(), NULL));
	EVP_CIPHER_CTX_free(ctx);
	total += outl;
	return (total);
}

static bool
ocf_cipher(struct alg *alg, const char *key, size_t key_len,
    const char *iv, const char *input, char *output, size_t size, int enc,
    int *cridp)
{
	struct session2_op sop;
	struct crypt_op cop;
	int fd;

	memset(&cop, 0, sizeof(cop));
	sop.crid = crid;
	sop.keylen = key_len;
	sop.key = (char *)key;
	sop.cipher = alg->alg;
	fd = crget();
	if (ioctl(fd, CIOCGSESSION2, &sop) < 0) {
		warn("cryptodev %s block cipher not supported for device %s",
		    alg->name, crfind(crid));
		close(fd);
		return (false);
	}

	cop.ses = sop.ses;
	cop.op = enc ? COP_ENCRYPT : COP_DECRYPT;
	cop.len = size;
	cop.src = (char *)input;
	cop.dst = output;
	cop.mac = NULL;
	cop.iv = (char *)iv;

	if (ioctl(fd, CIOCCRYPT, &cop) < 0)
		err(1, "ioctl(CIOCCRYPT)");

	if (ioctl(fd, CIOCFSESSION, &sop.ses) < 0)
		warn("ioctl(CIOCFSESSION)");

	close(fd);
	*cridp = sop.crid;
	return (true);
}

static void
run_blkcipher_test(struct alg *alg, size_t size)
{
	const EVP_CIPHER *cipher;
	char *buffer, *cleartext, *ciphertext;
	char *iv, *key;
	u_int block_size, iv_len, key_len;
	size_t buffer_size, out_size;
	int crid;

	cipher = alg->evp_cipher();
	block_size = EVP_CIPHER_block_size(cipher);
	if (size % block_size != 0) {
		if (verbose)
			printf(
			    "%s (%zu): invalid buffer size (block size %d)\n",
			    alg->name, size, EVP_CIPHER_block_size(cipher));
		return;
	}
			    
	key_len = EVP_CIPHER_key_length(cipher);
	iv_len = EVP_CIPHER_iv_length(cipher);
	buffer_size = size + block_size * 2;

	key = alloc_buffer(key_len);
	iv = alloc_buffer(iv_len);
	cleartext = alloc_buffer(size);
	buffer = malloc(buffer_size);
	ciphertext = malloc(buffer_size);

	/* OpenSSL cipher. */
	memset(ciphertext, 0x3c, buffer_size);
	out_size = openssl_cipher(alg, cipher, key, iv, cleartext, size,
	    ciphertext, 1);
	if (out_size > buffer_size)
		errx(1, "OpenSSL %s (%zu) cipher size too large: %zu vs %zu",
		    alg->name, size, out_size, buffer_size);
	if (memcmp(cleartext, ciphertext, size) == 0)
		errx(1, "OpenSSL %s (%zu): cipher text unchanged", alg->name,
		    size);
	memset(buffer, 0x3c, buffer_size);
	out_size = openssl_cipher(alg, cipher, key, iv, ciphertext, out_size,
	    buffer, 0);
	if (out_size != size)
		errx(1, "OpenSSL %s (%zu) cipher size mismatch: %zu",
		    alg->name, size, out_size);
	if (memcmp(cleartext, buffer, size) != 0) {
		printf("OpenSSL %s (%zu): cipher mismatch:", alg->name, size);
		printf("original:\n");
		hexdump(cleartext, size, NULL, 0);
		printf("decrypted:\n");
		hexdump(buffer, size, NULL, 0);
		exit(1);
	}

	/* OCF encrypt. */
	memset(buffer, 0x3c, buffer_size);
	if (!ocf_cipher(alg, key, key_len, iv, cleartext, buffer, size, 1,
	    &crid))
		goto out;
	if (memcmp(ciphertext, buffer, buffer_size) != 0) {
		printf("%s (%zu) encryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(ciphertext, buffer_size, NULL, 0);
		printf("test (cryptodev device %s):\n", crfind(crid));
		hexdump(buffer, buffer_size, NULL, 0);
		goto out;
	}
	
	/* OCF decrypt. */
	memset(buffer, 0x3c, buffer_size);
	if (!ocf_cipher(alg, key, key_len, iv, ciphertext, buffer, size, 0,
	    &crid))
		goto out;
	if (memcmp(cleartext, buffer, size) != 0) {
		printf("%s (%zu) decryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(cleartext, size, NULL, 0);
		printf("test (cryptodev device %s):\n", crfind(crid));
		hexdump(buffer, size, NULL, 0);
	} else if (verbose)
		printf("%s (%zu) matched (cryptodev device %s)\n",
		    alg->name, size, crfind(crid));
	
out:
	free(ciphertext);
	free(buffer);
	free(cleartext);
	free(iv);
	free(key);
}

static void
run_test(struct alg *alg, size_t size)
{

	switch (alg->type) {
	case T_HMAC:
		run_hmac_test(alg, size);
		break;
	case T_BLKCIPHER:
		run_blkcipher_test(alg, size);
		break;
	case T_NONE:
		assert(false);
	}
}

static void
run_test_sizes(struct alg *alg, size_t *sizes, u_int nsizes)
{
	u_int i;

	for (i = 0; i < nsizes; i++)
		run_test(alg, sizes[i]);
}

int
main(int ac, char **av)
{
	struct alg *alg;
	size_t sizes[128];
	u_int i, nsizes;
	bool testall;
	int ch;

	alg = NULL;
	crid = CRYPTO_FLAG_HARDWARE;
	testall = false;
	verbose = false;
	while ((ch = getopt(ac, av, "a:d:vz")) != -1)
		switch (ch) {
		case 'a':
			alg = find_alg(optarg);
			if (alg == NULL)
				errx(1, "Invalid algorithm %s", optarg);
			break;
		case 'd':
			crid = crlookup(optarg);
			break;
		case 'v':
			verbose = true;
			break;
		case 'z':
			testall = true;
			break;
		default:
			usage();
		}
	ac -= optind;
	av += optind;
	nsizes = 0;
	while (ac > 0) {
		char *cp;

		if (nsizes >= nitems(sizes)) {
			warnx("Too many sizes, ignoring extras");
			break;
		}
		sizes[nsizes] = strtol(av[0], &cp, 0);
		if (*cp != '\0')
			errx(1, "Bad size %s", av[0]);
		nsizes++;
		ac--;
		av++;
	}

	if (alg == NULL)
		errx(1, "Algorithm required");
	if (nsizes == 0) {
		sizes[0] = 8;
		nsizes++;
		if (testall) {
			while (sizes[nsizes - 1] < 32 * 1024) {
				assert(nsizes < nitems(sizes));
				sizes[nsizes] = sizes[nsizes - 1] * 2;
				nsizes++;
			}
		}
	}

	if (alg->alg == 0) {
		for (i = 0; i < nitems(algs); i++) {
			if (algs[i].alg == 0)
				continue;
			if (alg->type == T_NONE || alg->type == algs[i].type)
				run_test_sizes(&algs[i], sizes, nsizes);
		}
	} else
		run_test_sizes(alg, sizes, nsizes);
	return (0);
}
