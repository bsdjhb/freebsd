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
 * A tool for testing the /dev/crypto OpenSSL engine.  This tool is
 * similar to cryptocheck, but rather using /dev/crypto directly,
 * it compares the results from OpenSSL's software operation to the
 * results from the /dev/crypto OpenSSL engine.
 *
 * sslcheck [-vz] [-A aad length] [-a algorithm] [-d dev] [size ...]
 *
 * Options:
 *	-v	Verbose.
 *	-z	Run all algorithms on a variety of buffer sizes.
 *
 * Supported algorithms:
 *	all		Run all tests
 *	hmac		Run all hmac tests
 *	blkcipher	Run all block cipher tests
 *	authenc		Run all authenticated encryption tests
 *	aead		Run all authenticated encryption with associated data
 *			tests
 *
 * HMACs:
 *	sha1		sha1 hmac
 *	sha256		256-bit sha2 hmac
 *	sha384		384-bit sha2 hmac
 *	sha512		512-bit	sha2 hmac
 *
 * Block Ciphers:
 *	aes-cbc		128-bit aes cbc
 *	aes-cbc192	192-bit	aes cbc
 *	aes-cbc256	256-bit aes cbc
 *	aes-ctr		128-bit aes ctr
 *	aes-ctr192	192-bit aes ctr
 *	aes-ctr256	256-bit aes ctr
 *	aes-xts		128-bit aes xts
 *	aes-xts256	256-bit aes xts
 *
 * Authenticated Encryption:
 *	<block cipher>+<hmac>
 *
 * Authenticated Encryption with Associated Data:
 *	aes-gcm		128-bit aes gcm
 *	aes-gcm192	192-bit aes gcm
 *	aes-gcm256	256-bit aes gcm
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

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include <crypto/cryptodev.h>

struct alg {
	const char *name;
	enum { T_HMAC, T_BLKCIPHER, /*T_AUTHENC,*/ T_GCM } type;
	enum { CBC, CTR, XTS, GCM } iv_type;
	const EVP_CIPHER *(*evp_cipher)(void);
	const EVP_MD *(*evp_md)(void);
} algs[] = {
	{ .name = "sha1", .type = T_HMAC, .evp_md = EVP_sha1 },
	{ .name = "sha256", .type = T_HMAC, .evp_md = EVP_sha256 },
	{ .name = "sha384", .type = T_HMAC, .evp_md = EVP_sha384 },
	{ .name = "sha512", .type = T_HMAC, .evp_md = EVP_sha512 },
	{ .name = "aes-cbc", .type = T_BLKCIPHER, .iv_type = CBC,
	  .evp_cipher = EVP_aes_128_cbc },
	{ .name = "aes-cbc192", .type = T_BLKCIPHER, .iv_type = CBC,
	  .evp_cipher = EVP_aes_192_cbc },
	{ .name = "aes-cbc256", .type = T_BLKCIPHER, .iv_type = CBC,
	  .evp_cipher = EVP_aes_256_cbc },
	{ .name = "aes-ctr", .type = T_BLKCIPHER, .iv_type = CTR,
	  .evp_cipher = EVP_aes_128_ctr },
	{ .name = "aes-ctr192", .type = T_BLKCIPHER, .iv_type = CTR,
	  .evp_cipher = EVP_aes_192_ctr },
	{ .name = "aes-ctr256", .type = T_BLKCIPHER, .iv_type = CTR,
	  .evp_cipher = EVP_aes_256_ctr },
	{ .name = "aes-xts", .type = T_BLKCIPHER, .iv_type = XTS,
	  .evp_cipher = EVP_aes_128_xts },
	{ .name = "aes-xts256", .type = T_BLKCIPHER, .iv_type = XTS,
	  .evp_cipher = EVP_aes_256_xts },
	{ .name = "aes-gcm", .type = T_GCM, .iv_type = GCM,
	  .evp_cipher = EVP_aes_128_gcm },
	{ .name = "aes-gcm192", .type = T_GCM, .iv_type = GCM,
	  .evp_cipher = EVP_aes_192_gcm },
	{ .name = "aes-gcm256", .type = T_GCM, .iv_type = GCM,
	  .evp_cipher = EVP_aes_256_gcm },
};

static bool verbose;
static size_t aad_len;
static ENGINE *crypto_eng;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: sslcheck [-z] [-a algorithm] [-d dev] [size ...]\n");
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

#ifdef notyet
static struct alg *
build_authenc(struct alg *cipher, struct alg *hmac)
{
	static struct alg authenc;
	char *name;

	assert(cipher->type == T_BLKCIPHER);
	assert(hmac->type == T_HMAC);
	memset(&authenc, 0, sizeof(authenc));
	asprintf(&name, "%s+%s", cipher->name, hmac->name);
	authenc.name = name;
	authenc.type = T_AUTHENC;
	authenc.evp_cipher = cipher->evp_cipher;
	authenc.evp_md = hmac->evp_md;
	return (&authenc);
}

static struct alg *
build_authenc_name(const char *name)
{
	struct alg *cipher, *hmac;
	const char *hmac_name;
	char *cp, *cipher_name;

	cp = strchr(name, '+');
	cipher_name = strndup(name, cp - name);
	hmac_name = cp + 1;
	cipher = find_alg(cipher_name);
	free(cipher_name);
	if (cipher == NULL)
		errx(1, "Invalid cipher %s", cipher_name);
	hmac = find_alg(hmac_name);
	if (hmac == NULL)
		errx(1, "Invalid hash %s", hmac_name);
	return (build_authenc(cipher, hmac));
}
#endif

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

static char *
generate_iv(size_t len, struct alg *alg)
{
	char *iv;

	iv = alloc_buffer(len);
	switch (alg->iv_type) {
	case CTR:
		/* Clear the low 32 bits of the IV to hold the counter. */
		iv[len - 4] = 0;
		iv[len - 3] = 0;
		iv[len - 2] = 0;
		iv[len - 1] = 0;
		break;
	case XTS:
		/*
		 * Clear the low 64-bits to only store a 64-bit block
		 * number.
		 */
		iv[len - 8] = 0;
		iv[len - 7] = 0;
		iv[len - 6] = 0;
		iv[len - 5] = 0;
		iv[len - 4] = 0;
		iv[len - 3] = 0;
		iv[len - 2] = 0;
		iv[len - 1] = 0;
		break;
	default:
		break;
	}
	return (iv);
}

static const char *
engine_name(ENGINE *eng)
{

	if (eng == NULL)
		return ("<none>");
	return (ENGINE_get_id(eng));
}

static bool
openssl_hmac(ENGINE *eng, struct alg *alg, const EVP_MD *md, const char *key,
    u_int key_len, const char *buffer, size_t size, char *digest,
    u_int *digest_len)
{
	HMAC_CTX ctx;

	HMAC_CTX_init(&ctx);
	if (HMAC_Init_ex(&ctx, key, key_len, md, eng) != 1) {
		warnx("%s (%zu) hmac init failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
		HMAC_CTX_cleanup(&ctx);
		return (false);
	}
	if (HMAC_Update(&ctx, (const u_char *)buffer, size) != 1)
		errx(1, "%s (%zu) hmac update failed for engine %s: %s",
		    alg->name, size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	if (HMAC_Final(&ctx, (u_char *)digest, digest_len) != 1)
		errx(1, "%s (%zu) hmac final failed for engine %s: %s",
		    alg->name, size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	HMAC_CTX_cleanup(&ctx);
	return (true);
}

static void
run_hmac_test(struct alg *alg, size_t size)
{
	const EVP_MD *md;
	char *key, *buffer;
	u_int key_len, digest_len;
	char control_digest[EVP_MAX_MD_SIZE], test_digest[EVP_MAX_MD_SIZE];

	memset(control_digest, 0x3c, sizeof(control_digest));
	memset(test_digest, 0x3c, sizeof(test_digest));

	md = alg->evp_md();
	key_len = EVP_MD_size(md);
	assert(EVP_MD_size(md) <= sizeof(control_digest));

	key = alloc_buffer(key_len);
	buffer = alloc_buffer(size);

	/* Software HMAC. */
	digest_len = sizeof(control_digest);
	if (!openssl_hmac(NULL, alg, md, key, key_len, buffer, size,
	    control_digest, &digest_len))
		exit(1);

	/* Engine HMAC. */
	digest_len = sizeof(test_digest);
	if (!openssl_hmac(crypto_eng, alg, md, key, key_len, buffer, size,
	    test_digest, &digest_len))
		goto out;
	if (memcmp(control_digest, test_digest, sizeof(control_digest)) != 0) {
		if (memcmp(control_digest, test_digest, EVP_MD_size(md)) == 0)
			printf("%s (%zu) mismatch in trailer:\n",
			    alg->name, size);
		else
			printf("%s (%zu) mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(control_digest, sizeof(control_digest), NULL, 0);
		printf("test:\n");
		hexdump(test_digest, sizeof(test_digest), NULL, 0);
		goto out;
	}

	if (verbose)
		printf("%s (%zu) matched\n", alg->name, size);

out:
	free(buffer);
	free(key);
}

static bool
openssl_cipher(ENGINE *eng, struct alg *alg, const EVP_CIPHER *cipher,
    const char *key, const char *iv, const char *input, char *output,
    size_t size, int enc)
{
	EVP_CIPHER_CTX *ctx;
	int outl, total;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		errx(1, "%s (%zu) ctx new failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	if (EVP_CipherInit_ex(ctx, cipher, eng, (const u_char *)key,
	    (const u_char *)iv, enc) != 1) {
		warnx("%s (%zu) ctx init failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_free(ctx);
		return (false);
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (EVP_CipherUpdate(ctx, (u_char *)output, &outl,
	    (const u_char *)input, size) != 1)
		errx(1, "%s (%zu) cipher update failed for engine %s: %s",
		    alg->name, size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	total = outl;
	if (EVP_CipherFinal_ex(ctx, (u_char *)output + outl, &outl) != 1)
		errx(1, "%s (%zu) cipher final failed for engine %s: %s",
		    alg->name, size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	total += outl;
	if (total != size)
		errx(1, "OpenSSL %s (%zu) cipher size mismatch: %d", alg->name,
		    size, total);
	EVP_CIPHER_CTX_free(ctx);
	return (true);
}

static void
run_blkcipher_test(struct alg *alg, size_t size)
{
	const EVP_CIPHER *cipher;
	char *buffer, *cleartext, *ciphertext;
	char *iv, *key;
	u_int iv_len, key_len;

	cipher = alg->evp_cipher();
	if (size % EVP_CIPHER_block_size(cipher) != 0) {
		if (verbose)
			printf(
			    "%s (%zu): invalid buffer size (block size %d)\n",
			    alg->name, size, EVP_CIPHER_block_size(cipher));
		return;
	}

	key_len = EVP_CIPHER_key_length(cipher);
	iv_len = EVP_CIPHER_iv_length(cipher);

	key = alloc_buffer(key_len);
	iv = generate_iv(iv_len, alg);
	cleartext = alloc_buffer(size);
	buffer = malloc(size);
	ciphertext = malloc(size);

	/* Software cipher. */
	if (!openssl_cipher(NULL, alg, cipher, key, iv, cleartext, ciphertext,
	    size, 1))
		exit(1);
	if (size > 0 && memcmp(cleartext, ciphertext, size) == 0)
		errx(1, "software %s (%zu): cipher text unchanged", alg->name,
		    size);
	if (!openssl_cipher(NULL, alg, cipher, key, iv, ciphertext, buffer,
	    size, 0))
		exit(1);
	if (memcmp(cleartext, buffer, size) != 0) {
		printf("software %s (%zu): cipher mismatch:", alg->name, size);
		printf("original:\n");
		hexdump(cleartext, size, NULL, 0);
		printf("decrypted:\n");
		hexdump(buffer, size, NULL, 0);
		exit(1);
	}

	/* Engine encrypt. */
	if (!openssl_cipher(crypto_eng, alg, cipher, key, iv, cleartext,
	    buffer, size, 1))
		goto out;
	if (memcmp(ciphertext, buffer, size) != 0) {
		printf("%s (%zu) encryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(ciphertext, size, NULL, 0);
		printf("test:\n");
		hexdump(buffer, size, NULL, 0);
		goto out;
	}
	
	/* Engine decrypt. */
	if (!openssl_cipher(crypto_eng, alg, cipher, key, iv, ciphertext,
	    buffer, size, 0))
		goto out;
	if (memcmp(cleartext, buffer, size) != 0) {
		printf("%s (%zu) decryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(cleartext, size, NULL, 0);
		printf("test:\n");
		hexdump(buffer, size, NULL, 0);
		goto out;
	}

	if (verbose)
		printf("%s (%zu) matched\n", alg->name, size);

out:
	free(ciphertext);
	free(buffer);
	free(cleartext);
	free(iv);
	free(key);
}

#ifdef notyet
/*
 * OpenSSL's API doesn't really support chained operations in a single
 * go, nor does its engine interface.
 */
static void
run_authenc_test(struct alg *alg, size_t size)
{
	const EVP_CIPHER *cipher;
	const EVP_MD *md;
	char *aad, *buffer, *cleartext, *ciphertext;
	char *iv, *auth_key, *cipher_key;
	u_int iv_len, auth_key_len, cipher_key_len, digest_len;
	int crid;
	char control_digest[EVP_MAX_MD_SIZE], test_digest[EVP_MAX_MD_SIZE];

	cipher = alg->evp_cipher();
	if (size % EVP_CIPHER_block_size(cipher) != 0) {
		if (verbose)
			printf(
			    "%s (%zu): invalid buffer size (block size %d)\n",
			    alg->name, size, EVP_CIPHER_block_size(cipher));
		return;
	}

	memset(control_digest, 0x3c, sizeof(control_digest));
	memset(test_digest, 0x3c, sizeof(test_digest));

	md = alg->evp_md();
			    
	cipher_key_len = EVP_CIPHER_key_length(cipher);
	iv_len = EVP_CIPHER_iv_length(cipher);
	auth_key_len = EVP_MD_size(md);

	cipher_key = alloc_buffer(cipher_key_len);
	iv = generate_iv(iv_len, alg);
	auth_key = alloc_buffer(auth_key_len);
	cleartext = alloc_buffer(aad_len + size);
	buffer = malloc(aad_len + size);
	ciphertext = malloc(aad_len + size);

	/* OpenSSL encrypt + HMAC. */
	if (aad_len != 0)
		memcpy(ciphertext, cleartext, aad_len);
	openssl_cipher(alg, cipher, cipher_key, iv, cleartext + aad_len,
	    ciphertext + aad_len, size, 1);
	if (size > 0 && memcmp(cleartext + aad_len, ciphertext + aad_len,
	    size) == 0)
		errx(1, "OpenSSL %s (%zu): cipher text unchanged", alg->name,
		    size);
	digest_len = sizeof(control_digest);
	if (HMAC(md, auth_key, auth_key_len, (u_char *)ciphertext,
	    aad_len + size, (u_char *)control_digest, &digest_len) == NULL)
		errx(1, "OpenSSL %s (%zu) HMAC failed: %s", alg->name,
		    size, ERR_error_string(ERR_get_error(), NULL));

	/* OCF encrypt + HMAC. */
	if (!ocf_authenc(alg, cipher_key, cipher_key_len, iv, iv_len, auth_key,
	    auth_key_len, aad_len != 0 ? cleartext : NULL, aad_len,
	    cleartext + aad_len, buffer + aad_len, size, test_digest, 1, &crid))
		goto out;
	if (memcmp(ciphertext + aad_len, buffer + aad_len, size) != 0) {
		printf("%s (%zu) encryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(ciphertext + aad_len, size, NULL, 0);
		printf("test (cryptodev device %s):\n", crfind(crid));
		hexdump(buffer + aad_len, size, NULL, 0);
		goto out;
	}
	if (memcmp(control_digest, test_digest, sizeof(control_digest)) != 0) {
		if (memcmp(control_digest, test_digest, EVP_MD_size(md)) == 0)
			printf("%s (%zu) enc hash mismatch in trailer:\n",
			    alg->name, size);
		else
			printf("%s (%zu) enc hash mismatch:\n", alg->name,
			    size);
		printf("control:\n");
		hexdump(control_digest, sizeof(control_digest), NULL, 0);
		printf("test (cryptodev device %s):\n", crfind(crid));
		hexdump(test_digest, sizeof(test_digest), NULL, 0);
		goto out;
	}
	
	/* OCF HMAC + decrypt. */
	memset(test_digest, 0x3c, sizeof(test_digest));
	if (!ocf_authenc(alg, cipher_key, cipher_key_len, iv, iv_len, auth_key,
	    auth_key_len, aad_len != 0 ? ciphertext : NULL, aad_len,
	    ciphertext + aad_len, buffer + aad_len, size, test_digest, 0,
	    &crid))
		goto out;
	if (memcmp(control_digest, test_digest, sizeof(control_digest)) != 0) {
		if (memcmp(control_digest, test_digest, EVP_MD_size(md)) == 0)
			printf("%s (%zu) dec hash mismatch in trailer:\n",
			    alg->name, size);
		else
			printf("%s (%zu) dec hash mismatch:\n", alg->name,
			    size);
		printf("control:\n");
		hexdump(control_digest, sizeof(control_digest), NULL, 0);
		printf("test (cryptodev device %s):\n", crfind(crid));
		hexdump(test_digest, sizeof(test_digest), NULL, 0);
		goto out;
	}
	if (memcmp(cleartext + aad_len, buffer + aad_len, size) != 0) {
		printf("%s (%zu) decryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(cleartext, size, NULL, 0);
		printf("test (cryptodev device %s):\n", crfind(crid));
		hexdump(buffer, size, NULL, 0);
		goto out;
	}

	if (verbose)
		printf("%s (%zu) matched (cryptodev device %s)\n",
		    alg->name, size, crfind(crid));

out:
	free(ciphertext);
	free(buffer);
	free(cleartext);
	free(auth_key);
	free(iv);
	free(cipher_key);
}
#endif

static bool
openssl_gcm_encrypt(ENGINE *eng, struct alg *alg, const EVP_CIPHER *cipher,
    const char *key, const char *iv, const char *aad, size_t aad_len,
    const char *input, char *output, size_t size, char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int outl, total;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		errx(1, "%s (%zu) ctx new failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	if (EVP_EncryptInit_ex(ctx, cipher, eng, (const u_char *)key,
	    (const u_char *)iv) != 1) {
		warnx("%s (%zu) ctx init failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_free(ctx);
		return (false);
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (aad != NULL) {
		if (EVP_EncryptUpdate(ctx, NULL, &outl, (const u_char *)aad,
		    aad_len) != 1)
			errx(1, "%s (%zu) aad update failed for engine %s: %s",
			    alg->name, size, engine_name(eng),
			    ERR_error_string(ERR_get_error(), NULL));
	}
	if (EVP_EncryptUpdate(ctx, (u_char *)output, &outl,
	    (const u_char *)input, size) != 1)
		errx(1, "%s (%zu) encrypt update failed for engine %s: %s",
		    alg->name, size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	total = outl;
	if (EVP_EncryptFinal_ex(ctx, (u_char *)output + outl, &outl) != 1)
		errx(1, "%s (%zu) encrypt final failed for engine %s: %s",
		    alg->name, size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	total += outl;
	if (total != size)
		errx(1, "%s (%zu) encrypt size mismatch for engine %s: %d",
		    alg->name, size, engine_name(eng), total);
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GMAC_HASH_LEN,
	    tag) != 1)
		errx(1, "%s (%zu) get tag failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	EVP_CIPHER_CTX_free(ctx);
	return (true);
}

static bool
openssl_gcm_decrypt(ENGINE *eng, struct alg *alg, const EVP_CIPHER *cipher,
    const char *key, const char *iv, const char *aad, size_t aad_len,
    const char *input, char *output, size_t size, char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int outl, total;
	bool valid;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		errx(1, "%s (%zu) ctx new failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	if (EVP_DecryptInit_ex(ctx, cipher, eng, (const u_char *)key,
	    (const u_char *)iv) != 1) {
		warnx("%s (%zu) ctx init failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
		EVP_CIPHER_CTX_free(ctx);
		return (false);
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (aad != NULL) {
		if (EVP_DecryptUpdate(ctx, NULL, &outl, (const u_char *)aad,
		    aad_len) != 1)
			errx(1, "%s (%zu) aad update failed for engine %s: %s",
			    alg->name, size, engine_name(eng),
			    ERR_error_string(ERR_get_error(), NULL));
	}
	if (EVP_DecryptUpdate(ctx, (u_char *)output, &outl,
	    (const u_char *)input, size) != 1)
		errx(1, "%s (%zu) decrypt update failed for engine %s: %s",
		    alg->name, size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	total = outl;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GMAC_HASH_LEN,
	    tag) != 1)
		errx(1, "%s (%zu) set tag failed for engine %s: %s", alg->name,
		    size, engine_name(eng),
		    ERR_error_string(ERR_get_error(), NULL));
	valid = (EVP_DecryptFinal_ex(ctx, (u_char *)output + outl, &outl) == 1);
	total += outl;
	if (total != size)
		errx(1, "%s (%zu) decrypt size mismatch for engine %s: %d",
		    alg->name, size, engine_name(eng), total);
	EVP_CIPHER_CTX_free(ctx);
	if (!valid)
		warnx("%s (%zu) decrypt failed validation for engine %s",
		    alg->name, size, engine_name(eng));
	return (valid);
}

static void
run_gcm_test(struct alg *alg, size_t size)
{
	const EVP_CIPHER *cipher;
	char *aad, *buffer, *cleartext, *ciphertext;
	char *iv, *key;
	u_int iv_len, key_len;
	char control_tag[AES_GMAC_HASH_LEN], test_tag[AES_GMAC_HASH_LEN];

	cipher = alg->evp_cipher();
	if (size % EVP_CIPHER_block_size(cipher) != 0) {
		if (verbose)
			printf(
			    "%s (%zu): invalid buffer size (block size %d)\n",
			    alg->name, size, EVP_CIPHER_block_size(cipher));
		return;
	}

	memset(control_tag, 0x3c, sizeof(control_tag));
	memset(test_tag, 0x3c, sizeof(test_tag));

	key_len = EVP_CIPHER_key_length(cipher);
	iv_len = EVP_CIPHER_iv_length(cipher);

	key = alloc_buffer(key_len);
	iv = generate_iv(iv_len, alg);
	cleartext = alloc_buffer(size);
	buffer = malloc(size);
	ciphertext = malloc(size);
	if (aad_len != 0)
		aad = alloc_buffer(aad_len);
	else
		aad = NULL;

	/* Software encrypt */
	if (!openssl_gcm_encrypt(NULL, alg, cipher, key, iv, aad, aad_len,
	    cleartext, ciphertext, size, control_tag))
		exit(1);

	/* Engine encrypt. */
	if (!openssl_gcm_encrypt(crypto_eng, alg, cipher, key, iv, aad,
	    aad_len, cleartext, buffer, size, test_tag))
		goto out;
	if (memcmp(ciphertext, buffer, size) != 0) {
		printf("%s (%zu) encryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(ciphertext, size, NULL, 0);
		printf("test:\n");
		hexdump(buffer, size, NULL, 0);
		goto out;
	}
	if (memcmp(control_tag, test_tag, sizeof(control_tag)) != 0) {
		printf("%s (%zu) enc tag mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(control_tag, sizeof(control_tag), NULL, 0);
		printf("test:\n");
		hexdump(test_tag, sizeof(test_tag), NULL, 0);
		goto out;
	}

	/* Engine decrypt */
	if (!openssl_gcm_decrypt(crypto_eng, alg, cipher, key, iv, aad,
	    aad_len, ciphertext, buffer, size, control_tag))
		goto out;
	if (memcmp(cleartext, buffer, size) != 0) {
		printf("%s (%zu) decryption mismatch:\n", alg->name, size);
		printf("control:\n");
		hexdump(cleartext, size, NULL, 0);
		printf("test:\n");
		hexdump(buffer, size, NULL, 0);
		goto out;
	}

	if (verbose)
		printf("%s (%zu) matched\n", alg->name, size);

out:
	free(aad);
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
#ifdef notyet
	case T_AUTHENC:
		run_authenc_test(alg, size);
		break;
#endif
	case T_GCM:
		run_gcm_test(alg, size);
		break;
	}
}

static void
run_test_sizes(struct alg *alg, size_t *sizes, u_int nsizes)
{
	u_int i;

	for (i = 0; i < nsizes; i++)
		run_test(alg, sizes[i]);
}

static void
run_hmac_tests(size_t *sizes, u_int nsizes)
{
	u_int i;

	for (i = 0; i < nitems(algs); i++)
		if (algs[i].type == T_HMAC)
			run_test_sizes(&algs[i], sizes, nsizes);
}

static void
run_blkcipher_tests(size_t *sizes, u_int nsizes)
{
	u_int i;

	for (i = 0; i < nitems(algs); i++)
		if (algs[i].type == T_BLKCIPHER)
			run_test_sizes(&algs[i], sizes, nsizes);
}

#ifdef notyet
static void
run_authenc_tests(size_t *sizes, u_int nsizes)
{
	struct alg *authenc, *cipher, *hmac;
	u_int i, j;

	for (i = 0; i < nitems(algs); i++) {
		cipher = &algs[i];
		if (cipher->type != T_BLKCIPHER)
			continue;
		for (j = 0; j < nitems(algs); j++) {
			hmac = &algs[j];
			if (hmac->type != T_HMAC)
				continue;
			authenc = build_authenc(cipher, hmac);
			run_test_sizes(authenc, sizes, nsizes);
			free((char *)authenc->name);
		}
	}
}
#endif

static void
run_aead_tests(size_t *sizes, u_int nsizes)
{
	u_int i;

	for (i = 0; i < nitems(algs); i++)
		if (algs[i].type == T_GCM)
			run_test_sizes(&algs[i], sizes, nsizes);
}

int
main(int ac, char **av)
{
	const char *algname, *device;
	struct alg *alg;
	size_t sizes[128];
	u_int i, nsizes;
	bool testall;
	int ch;

	algname = NULL;
	device = NULL;
	testall = false;
	verbose = false;
	while ((ch = getopt(ac, av, "A:a:d:vz")) != -1)
		switch (ch) {
		case 'A':
			aad_len = atoi(optarg);
			break;
		case 'a':
			algname = optarg;
			break;
		case 'd':
			device = optarg;
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

	if (algname == NULL)
		errx(1, "Algorithm required");
	if (nsizes == 0) {
		sizes[0] = 16;
		nsizes++;
		if (testall) {
			while (sizes[nsizes - 1] * 2 < 240 * 1024) {
				assert(nsizes < nitems(sizes));
				sizes[nsizes] = sizes[nsizes - 1] * 2;
				nsizes++;
			}
			if (sizes[nsizes - 1] < 240 * 1024) {
				assert(nsizes < nitems(sizes));
				sizes[nsizes] = 240 * 1024;
				nsizes++;
			}
		}
	}

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	ENGINE_load_cryptodev();
	crypto_eng = ENGINE_by_id("cryptodev");
	if (crypto_eng == NULL)
		errx(1, "Unable to load cryptodev engine: %s",
		    ERR_error_string(ERR_get_error(), NULL));
	if (ENGINE_init(crypto_eng) != 1)
		errx(1, "Unable to init cryptodev engine: %s",
		    ERR_error_string(ERR_get_error(), NULL));
	if (device != NULL) {
		if (strcasecmp(device, "soft") == 0) {
			if (ENGINE_ctrl_cmd(crypto_eng, "CRID",
			    CRYPTO_FLAG_SOFTWARE, NULL, NULL, 0) == 0)
				warn("Failed to set device to \"soft\"");
		} else {
			if (ENGINE_ctrl_cmd_string(crypto_eng, "CRID", device,
			    0) == 0)
				warn("Failed to set device to \"%s\"", device);
		}
	}

	if (strcasecmp(algname, "hmac") == 0)
		run_hmac_tests(sizes, nsizes);
	else if (strcasecmp(algname, "blkcipher") == 0)
		run_blkcipher_tests(sizes, nsizes);
#ifdef notyet
	else if (strcasecmp(algname, "authenc") == 0)
		run_authenc_tests(sizes, nsizes);
#endif
	else if (strcasecmp(algname, "aead") == 0)
		run_aead_tests(sizes, nsizes);
	else if (strcasecmp(algname, "all") == 0) {
		run_hmac_tests(sizes, nsizes);
		run_blkcipher_tests(sizes, nsizes);
#ifdef notyet
		run_authenc_tests(sizes, nsizes);
#endif
		run_aead_tests(sizes, nsizes);
#ifdef notyet
	} else if (strchr(algname, '+') != NULL) {
		alg = build_authenc_name(algname);
		run_test_sizes(alg, sizes, nsizes);
#endif
	} else {
		alg = find_alg(algname);
		if (alg == NULL)
			errx(1, "Invalid algorithm %s", algname);
		run_test_sizes(alg, sizes, nsizes);
	}

	ENGINE_finish(crypto_eng);
	ENGINE_free(crypto_eng);
	ENGINE_cleanup();
	return (0);
}
