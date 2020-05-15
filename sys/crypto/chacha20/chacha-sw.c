/* This file is in the public domain. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <crypto/chacha20/chacha.h>
#include <opencrypto/xform_enc.h>

static int
chacha20_xform_setkey(void **sched, const uint8_t *key, int len)
{
	struct chacha_ctx *ctx;

	if (len != CHACHA_MINKEYLEN && len != 32)
		return (EINVAL);

	ctx = malloc(sizeof(*ctx), M_CRYPTO_DATA, M_NOWAIT | M_ZERO);
	*sched = (void *)ctx;
	if (ctx == NULL)
		return (ENOMEM);

	chacha_keysetup(ctx, key, len * 8);
	return (0);
}

static void
chacha20_xform_reinit(void *key, const u_int8_t *iv)
{
	struct chacha_ctx *ctx;

	ctx = key;
	chacha_ivsetup(ctx, iv + 8, iv);
}

static void
chacha20_xform_zerokey(void *sched)
{

	zfree(sched, M_CRYPTO_DATA);
}

static void
chacha20_xform_crypt(void *cctx, const uint8_t *in, uint8_t *out)
{
	struct chacha_ctx *ctx;

	ctx = cctx;
	chacha_encrypt_bytes(ctx, in, out, 1);
}

static void
chacha20_xform_crypt_multi(void *vctx, const uint8_t *in, uint8_t *out,
    size_t len)
{
	struct chacha_ctx *ctx;

	ctx = vctx;
	chacha_encrypt_bytes(ctx, in, out, len);
}

struct enc_xform enc_xform_chacha20 = {
	.type = CRYPTO_CHACHA20,
	.name = "chacha20",
	.blocksize = 1,
	.ivsize = CHACHA_NONCELEN + CHACHA_CTRLEN,
	.minkey = CHACHA_MINKEYLEN,
	.maxkey = 32,
	.encrypt = chacha20_xform_crypt,
	.decrypt = chacha20_xform_crypt,
	.setkey = chacha20_xform_setkey,
	.zerokey = chacha20_xform_zerokey,
	.reinit = chacha20_xform_reinit,
	.encrypt_multi = chacha20_xform_crypt_multi,
	.decrypt_multi = chacha20_xform_crypt_multi,
};
