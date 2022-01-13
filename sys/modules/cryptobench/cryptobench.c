#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/sx.h>

#include <crypto/chacha20_poly1305.h>

#include <opencrypto/cryptodev.h>

#define	SHORT_LEN		64
#define	LONG_LEN		16384

static MALLOC_DEFINE(M_CRYPTOBENCH, "cryptobench", "cryptobench");

static struct sx lock;
SX_SYSINIT(crypto_bench, &lock, "crypto bench");

static bool unloading;
static char *short_plain, *short_cipher;
static char *long_plain, *long_cipher;
static char *key, *nonce;

static char *ocf_driver;
static crypto_session_t ocf_session;

SYSCTL_NODE(_kern_crypto, OID_AUTO, bench, CTLFLAG_RD, NULL, "cryptobench");

static u_int iterations = 10000;
SYSCTL_UINT(_kern_crypto_bench, OID_AUTO, iterations, CTLFLAG_RW, &iterations,
    0, "Number of iterations per test");

static void
encrypt_buffer_direct(const char *src, char *dst, size_t len, const char *key,
    const char *nonce)
{
	chacha20_poly1305_encrypt(dst, src, len, NULL, 0, nonce, 8, key);
}

static int
null_callback(struct cryptop *crp)
{
	return (0);
}

static void
encrypt_buffer_ocf(const char *src, char *dst, size_t len, const char *key,
    const char *nonce)
{
	struct cryptop crp;

	crypto_initreq(&crp, ocf_session);
	crypto_use_buf(&crp, __DECONST(char *, src), len);
	crypto_use_output_buf(&crp, dst, len + POLY1305_HASH_LEN);
	memcpy(crp.crp_iv, nonce, 8);
	crp.crp_cipher_key = key;
	crp.crp_payload_length = len;
	crp.crp_digest_start = len;
	crp.crp_flags = CRYPTO_F_CBIMM | CRYPTO_F_IV_SEPARATE;
	crp.crp_op = CRYPTO_OP_ENCRYPT | CRYPTO_OP_COMPUTE_DIGEST;
	crp.crp_callback = null_callback;
	(void)crypto_dispatch(&crp);
	crypto_destroyreq(&crp);
}

static int
create_session(const char *name)
{
	struct crypto_session_params csp;
	crypto_session_t ses;
	int crid, error;

	crid = crypto_find_driver(name);
	if (crid < 0)
		return (ENOENT);
	if ((crypto_getcaps(crid) & CRYPTOCAP_F_SYNC) == 0)
		return (EINVAL);

	memset(&csp, 0, sizeof(csp));
	csp.csp_mode = CSP_MODE_AEAD;
	csp.csp_cipher_alg = CRYPTO_CHACHA20_POLY1305;
	csp.csp_cipher_klen = CHACHA20_POLY1305_KEY;
	csp.csp_ivlen = 8;
	csp.csp_flags = CSP_F_SEPARATE_OUTPUT;
	error = crypto_newsession(&ses, &csp, crid);
	if (error != 0)
		return (error);

	crypto_freesession(ocf_session);
	free(ocf_driver, M_CRYPTOBENCH);
	ocf_driver = strdup(name, M_CRYPTOBENCH);
	ocf_session = ses;
	return (0);
}

static int
sysctl_driver_name(SYSCTL_HANDLER_ARGS)
{
	char *new;
	int error;

	sx_xlock(&lock);
	if (unloading || ocf_driver == NULL)
		error = SYSCTL_OUT(req, "", 1);
	else
		error = SYSCTL_OUT(req, ocf_driver, strlen(ocf_driver) + 1);
	if (error != 0 || req->newptr == NULL)
		goto out;

	if (unloading) {
		error = ENXIO;
		goto out;
	}
	new = malloc(req->newlen + 1, M_CRYPTOBENCH, M_WAITOK);
	error = SYSCTL_IN(req, new, req->newlen);
	if (error != 0) {
		free(new, M_CRYPTOBENCH);
		goto out;
	}
	new[req->newlen] = '\0';
	error = create_session(new);
	free(new, M_CRYPTOBENCH);
out:
	sx_xunlock(&lock);
	return (error);
}
SYSCTL_PROC(_kern_crypto_bench, OID_AUTO, driver, CTLTYPE_STRING |
    CTLFLAG_MPSAFE | CTLFLAG_RW, NULL, 0, sysctl_driver_name, "A",
    "OCF driver name");

static uint64_t
test_direct(const char *src, char *dst, size_t len)
{
	uint64_t start, stop;
	u_int i;

	start = rdtsc();
	__compiler_membar();
	for (i = 0; i < iterations; i++)
		encrypt_buffer_direct(src, dst, len, key, nonce);
	__compiler_membar();
	stop = rdtsc();
	return (stop - start);
}

static uint64_t
test_ocf(const char *src, char *dst, size_t len)
{
	uint64_t start, stop;
	u_int i;

	start = rdtsc();
	__compiler_membar();
	for (i = 0; i < iterations; i++)
		encrypt_buffer_ocf(src, dst, len, key, nonce);
	__compiler_membar();
	stop = rdtsc();
	return (stop - start);
}

static int
sysctl_test_direct_short(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;

	sx_slock(&lock);
	if (unloading) {
		sx_sunlock(&lock);
		return (ENXIO);
	}
	val = test_direct(short_plain, short_cipher, SHORT_LEN);
	sx_sunlock(&lock);
	return (sysctl_handle_64(oidp, &val, 0, req));
}
SYSCTL_PROC(_kern_crypto_bench, OID_AUTO, test_direct_short, CTLTYPE_U64 |
    CTLFLAG_MPSAFE | CTLFLAG_RD | CTLFLAG_SKIP, NULL, 0,
    sysctl_test_direct_short, "QU", "");

static int
sysctl_test_direct_long(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;

	sx_slock(&lock);
	if (unloading) {
		sx_sunlock(&lock);
		return (ENXIO);
	}
	val = test_direct(long_plain, long_cipher, LONG_LEN);
	sx_sunlock(&lock);
	return (sysctl_handle_64(oidp, &val, 0, req));
}
SYSCTL_PROC(_kern_crypto_bench, OID_AUTO, test_direct_long, CTLTYPE_U64 |
    CTLFLAG_MPSAFE | CTLFLAG_RD | CTLFLAG_SKIP, NULL, 0,
    sysctl_test_direct_long, "QU", "");

static int
sysctl_test_ocf_short(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;

	sx_slock(&lock);
	if (unloading || ocf_session == NULL) {
		sx_sunlock(&lock);
		return (ENXIO);
	}
	val = test_ocf(short_plain, short_cipher, SHORT_LEN);
	sx_sunlock(&lock);
	return (sysctl_handle_64(oidp, &val, 0, req));
}
SYSCTL_PROC(_kern_crypto_bench, OID_AUTO, test_ocf_short, CTLTYPE_U64 |
    CTLFLAG_MPSAFE | CTLFLAG_RD | CTLFLAG_SKIP, NULL, 0,
    sysctl_test_ocf_short, "QU", "");

static int
sysctl_test_ocf_long(SYSCTL_HANDLER_ARGS)
{
	uint64_t val;

	sx_slock(&lock);
	if (unloading || ocf_session == NULL) {
		sx_sunlock(&lock);
		return (ENXIO);
	}
	val = test_ocf(long_plain, long_cipher, LONG_LEN);
	sx_sunlock(&lock);
	return (sysctl_handle_64(oidp, &val, 0, req));
}
SYSCTL_PROC(_kern_crypto_bench, OID_AUTO, test_ocf_long, CTLTYPE_U64 |
    CTLFLAG_MPSAFE | CTLFLAG_RD | CTLFLAG_SKIP, NULL, 0, sysctl_test_ocf_long,
    "QU", "");

static int
mod_event(module_t mod, int type, void *dummy __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		error = create_session("cryptosoft0");
		if (error)
			break;
		short_plain = malloc(SHORT_LEN, M_CRYPTOBENCH, M_WAITOK);
		short_cipher = malloc(SHORT_LEN + POLY1305_HASH_LEN,
		    M_CRYPTOBENCH, M_WAITOK);
		long_plain = malloc(LONG_LEN, M_CRYPTOBENCH, M_WAITOK);
		long_cipher = malloc(LONG_LEN + POLY1305_HASH_LEN,
		    M_CRYPTOBENCH, M_WAITOK);
		key = malloc(CHACHA20_POLY1305_KEY, M_CRYPTOBENCH, M_WAITOK);
		nonce = malloc(8, M_CRYPTOBENCH, M_WAITOK);
		arc4random_buf(short_plain, SHORT_LEN);
		arc4random_buf(long_plain, LONG_LEN);
		arc4random_buf(key, CHACHA20_POLY1305_KEY);
		arc4random_buf(nonce, 8);
		break;
	case MOD_UNLOAD:
		sx_xlock(&lock);
		unloading = true;
		sx_xunlock(&lock);
		free(nonce, M_CRYPTOBENCH);
		free(key, M_CRYPTOBENCH);
		free(long_cipher, M_CRYPTOBENCH);
		free(long_plain, M_CRYPTOBENCH);
		free(short_cipher, M_CRYPTOBENCH);
		free(short_plain, M_CRYPTOBENCH);
		crypto_freesession(ocf_session);
		free(ocf_driver, M_CRYPTOBENCH);
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static moduledata_t cryptobench_mod = {
	"cryptobench",
	mod_event
};
DECLARE_MODULE(cryptobench, cryptobench_mod, SI_SUB_LAST, SI_ORDER_ANY);

MODULE_VERSION(cryptobench, 1);
MODULE_DEPEND(cryptobench, crypto, 1, 1, 1);
