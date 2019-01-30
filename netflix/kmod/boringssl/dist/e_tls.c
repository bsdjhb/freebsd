/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */
#ifndef _KERNEL
#include <limits.h>
#include <string.h>
#endif
#include "openssl/modes.h"
#include "openssl/aead.h"
#include "openssl/cipher.h"
#include "openssl/err.h"
#include "openssl/hmac.h"
#include "openssl/mem.h"
#include "openssl/sha_open.h"
#include "openssl/type_check.h"
#include "openssl/internal_crypto.h"
#include "openssl/internal_cipher.h"
#include "openssl/internal_digest.h"


typedef struct {
  EVP_CIPHER_CTX cipher_ctx;
  HMAC_CTX hmac_ctx;
  /* mac_key is the portion of the key used for the MAC. It is retained
   * separately for the constant-time CBC code. */
  uint8_t mac_key[EVP_MAX_MD_SIZE];
  uint8_t mac_key_len;
  /* implicit_iv is one iff this is a pre-TLS-1.1 CBC cipher without an explicit
   * IV. */
  char implicit_iv;
} AEAD_TLS_CTX;

static void aead_tls_cleanup(EVP_AEAD_CTX *ctx)
{
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;
  if (tls_ctx) {
	  EVP_CIPHER_CTX_cleanup(&tls_ctx->cipher_ctx);
	  HMAC_CTX_cleanup(&tls_ctx->hmac_ctx);
	  OPENSSL_cleanse(&tls_ctx->mac_key, sizeof(tls_ctx->mac_key));
	  OPENSSL_free(tls_ctx);
  }
  ctx->aead_state = NULL;
}

static int aead_tls_init(EVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len,
                         size_t tag_len, enum evp_aead_direction_t dir,
                         const EVP_CIPHER *cipher, const EVP_MD *md,
                         char implicit_iv)
{
	int ret1, ret2;
	if (tag_len != EVP_AEAD_DEFAULT_TAG_LENGTH &&
	    tag_len != EVP_MD_size(md)) {
		return 0;
	}

	if (key_len != EVP_AEAD_key_length(ctx->aead)) {
		return 0;
	}

	size_t mac_key_len = EVP_MD_size(md);
	size_t enc_key_len = EVP_CIPHER_key_length(cipher);
	/* Although EVP_rc4() is a variable-length cipher, the default key size is
	 * correct for TLS. */

	AEAD_TLS_CTX *tls_ctx = OPENSSL_malloc(sizeof(AEAD_TLS_CTX));
	if (tls_ctx == NULL) {
		return 0;
	}
	EVP_CIPHER_CTX_init(&tls_ctx->cipher_ctx);
	HMAC_CTX_init(&tls_ctx->hmac_ctx);
	memcpy(tls_ctx->mac_key, key, mac_key_len);
	tls_ctx->mac_key_len = (uint8_t)mac_key_len;
	tls_ctx->implicit_iv = implicit_iv;

	ctx->aead_state = tls_ctx;
	ret1 = EVP_CipherInit_ex(&tls_ctx->cipher_ctx, cipher, NULL, &key[mac_key_len],
				 implicit_iv ? &key[mac_key_len + enc_key_len] : NULL,
				 dir == evp_aead_seal);
	ret2 = HMAC_Init_ex(&tls_ctx->hmac_ctx, key, mac_key_len, md, NULL);
	if (!ret1 || !ret2) {
		aead_tls_cleanup(ctx);
		return 0;
	}
	EVP_CIPHER_CTX_set_padding(&tls_ctx->cipher_ctx, 0);
	return 1;
}


int
aead_block_size(const struct evp_aead_ctx_st *ctx)
{
  int bs;
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;
  bs = EVP_CIPHER_CTX_block_size(&tls_ctx->cipher_ctx);
  return(bs);
}

static int aead_tls_seal(const struct evp_aead_ctx_st *ctx,
			 struct iovec *iovout, int out_iov_cnt,
                         const uint8_t *nonce, size_t nonce_len,
			 struct iovec *iovin, int in_iov_cnt,
                         const uint8_t *ad, size_t ad_len,
			 uint8_t *tagout, size_t *tagsize)
{
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;
  uint8_t *out;
  uint8_t *in;
  size_t in_len, t_len, tag_len_out;
  int len;
  int i;
  uint8_t ad_extra[2];
  uint8_t mac[EVP_MAX_MD_SIZE];
  unsigned mac_len;
  HMAC_CTX hmac_ctx;
  
  if (!tls_ctx->cipher_ctx.encrypt) {
    /* Unlike a normal AEAD, a TLS AEAD may only be used in one direction. */
    return 0;
  }
  for (i=0, t_len=0; i< out_iov_cnt; i++) {
	  t_len += iovin[i].iov_len;
  }
  if (nonce_len != EVP_AEAD_nonce_length(ctx->aead)) {
    return 0;
  }

  if (ad_len != 13 - 2 /* length bytes */) {
    return 0;
  }

  /* To allow for CBC mode which changes cipher length, |ad| doesn't include the
   * length for legacy ciphers. */
  ad_extra[0] = (uint8_t)(t_len >> 8);
  ad_extra[1] = (uint8_t)(t_len & 0xff);
  /* Compute the MAC. This must be first in case the operation is being done
   * in-place. */
  HMAC_CTX_init(&hmac_ctx);
  if (!HMAC_CTX_copy_ex(&hmac_ctx, &tls_ctx->hmac_ctx) ||
      !HMAC_Update(&hmac_ctx, ad, ad_len) ||
      !HMAC_Update(&hmac_ctx, ad_extra, sizeof(ad_extra))) {
	      HMAC_CTX_cleanup(&hmac_ctx);
	      return 0;
  }
  for(i=0; i<in_iov_cnt; i++) {
	  in = iovin[i].iov_base;
	  in_len = iovin[i].iov_len;
	  if (!HMAC_Update(&hmac_ctx, in, in_len)) {
		  HMAC_CTX_cleanup(&hmac_ctx);
		  return 0;
	  }
  }
  if (!HMAC_Final(&hmac_ctx, mac, &mac_len)) {
	  HMAC_CTX_cleanup(&hmac_ctx);
	  return 0;
  }
  HMAC_CTX_cleanup(&hmac_ctx);
  /* Configure the explicit IV. */
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE &&
      !tls_ctx->implicit_iv &&
      !EVP_EncryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, NULL, nonce)) {
    return 0;
  }

  /* Encrypt input. */
  for(i=0; i<in_iov_cnt; i++) {  
	  in = iovin[i].iov_base;
	  out = iovout[i].iov_base;
	  in_len = iovin[i].iov_len;
	  if (!EVP_EncryptUpdate(&tls_ctx->cipher_ctx, out, &len, in,
				 (int)in_len)) {
		  return 0;
	  }
	  iovout[i].iov_len = len;
  }

  /* Feed the MAC into the cipher. */
  if (!EVP_EncryptUpdate(&tls_ctx->cipher_ctx, tagout, &len, mac,
                         (int)mac_len)) {
    return 0;
  }
  tag_len_out = len;
  unsigned block_size = EVP_CIPHER_CTX_block_size(&tls_ctx->cipher_ctx);
  if (block_size > 1) {

    /* Compute padding and feed that into the cipher. */
    uint8_t padding[256];
    unsigned padding_len = block_size - ((t_len + mac_len) % block_size);
    memset(padding, padding_len - 1, padding_len);
    if (!EVP_EncryptUpdate(&tls_ctx->cipher_ctx, tagout + tag_len_out, &len,
			   padding,
                           (int)padding_len)) {
      return 0;
    }
    /* Increase the size of tag_len_out by padding */
    tag_len_out += len;
  }
  if (!EVP_EncryptFinal_ex(&tls_ctx->cipher_ctx, tagout + tag_len_out, &len)) {
    return 0;
  }
  /* Add in the final as well */
  tag_len_out += len;
  *tagsize = tag_len_out;
  return 1;
}

static int aead_tls_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                         size_t *out_len, size_t max_out_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *in, size_t in_len,
                         const uint8_t *ad, size_t ad_len) {
  AEAD_TLS_CTX *tls_ctx = (AEAD_TLS_CTX *)ctx->aead_state;

  if (tls_ctx->cipher_ctx.encrypt) {
    /* Unlike a normal AEAD, a TLS AEAD may only be used in one direction. */
    return 0;

  }

  if (in_len < HMAC_size(&tls_ctx->hmac_ctx)) {
    return 0;
  }

  if (max_out_len < in_len) {
    /* This requires that the caller provide space for the MAC, even though it
     * will always be removed on return. */
    return 0;
  }

  if (nonce_len != EVP_AEAD_nonce_length(ctx->aead)) {
    return 0;
  }

  if (ad_len != 13 - 2 /* length bytes */) {
    return 0;
  }

  if (in_len > INT_MAX) {
    /* EVP_CIPHER takes int as input. */
    return 0;
  }

  /* Configure the explicit IV. */
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE &&
      !tls_ctx->implicit_iv &&
      !EVP_DecryptInit_ex(&tls_ctx->cipher_ctx, NULL, NULL, NULL, nonce)) {
    return 0;
  }

  /* Decrypt to get the plaintext + MAC + padding. */
  size_t total = 0;
  int len;
  if (!EVP_DecryptUpdate(&tls_ctx->cipher_ctx, out, &len, in, (int)in_len)) {
    return 0;
  }
  total += len;
  if (!EVP_DecryptFinal_ex(&tls_ctx->cipher_ctx, out + total, &len)) {
    return 0;
  }
  total += len;

  /* Remove CBC padding. Code from here on is timing-sensitive with respect to
   * |padding_ok| and |data_plus_mac_len| for CBC ciphers. */
  int padding_ok;
  unsigned data_plus_mac_len, data_len;
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE) {
    padding_ok = EVP_tls_cbc_remove_padding(
        &data_plus_mac_len, out, total,
        EVP_CIPHER_CTX_block_size(&tls_ctx->cipher_ctx),
        (unsigned)HMAC_size(&tls_ctx->hmac_ctx));
    /* Publicly invalid. This can be rejected in non-constant time. */
    if (padding_ok == 0) {
      return 0;
    }
  } else {
    padding_ok = 1;
    data_plus_mac_len = total;
    /* |data_plus_mac_len| = |total| = |in_len| at this point. |in_len| has
     * already been checked against the MAC size at the top of the function. */
  }
  data_len = data_plus_mac_len - HMAC_size(&tls_ctx->hmac_ctx);

  /* At this point, |padding_ok| is 1 or -1. If 1, the padding is valid and the
   * first |data_plus_mac_size| bytes after |out| are the plaintext and
   * MAC. Either way, |data_plus_mac_size| is large enough to extract a MAC. */

  /* To allow for CBC mode which changes cipher length, |ad| doesn't include the
   * length for legacy ciphers. */
  uint8_t ad_fixed[13];
  memcpy(ad_fixed, ad, 11);
  ad_fixed[11] = (uint8_t)(data_len >> 8);
  ad_fixed[12] = (uint8_t)(data_len & 0xff);
  ad_len += 2;

  /* Compute the MAC and extract the one in the record. */
  uint8_t mac[EVP_MAX_MD_SIZE];
  size_t mac_len;
  uint8_t record_mac_tmp[EVP_MAX_MD_SIZE];
  uint8_t *record_mac;
  if (EVP_CIPHER_CTX_mode(&tls_ctx->cipher_ctx) == EVP_CIPH_CBC_MODE &&
      EVP_tls_cbc_record_digest_supported(tls_ctx->hmac_ctx.md)) {
    if (!EVP_tls_cbc_digest_record(tls_ctx->hmac_ctx.md, mac, &mac_len,
                                   ad_fixed, out, data_plus_mac_len, total,
                                   tls_ctx->mac_key, tls_ctx->mac_key_len)) {
      return 0;
    }

    record_mac = record_mac_tmp;
    EVP_tls_cbc_copy_mac(record_mac, mac_len, out, data_plus_mac_len, total);
  } else {
    /* We should support the constant-time path for all CBC-mode ciphers
     * implemented. */

    HMAC_CTX hmac_ctx;
    HMAC_CTX_init(&hmac_ctx);
    unsigned mac_len_u;
    if (!HMAC_CTX_copy_ex(&hmac_ctx, &tls_ctx->hmac_ctx) ||
        !HMAC_Update(&hmac_ctx, ad_fixed, ad_len) ||
        !HMAC_Update(&hmac_ctx, out, data_len) ||
        !HMAC_Final(&hmac_ctx, mac, &mac_len_u)) {
      HMAC_CTX_cleanup(&hmac_ctx);
      return 0;
    }
    mac_len = mac_len_u;
    HMAC_CTX_cleanup(&hmac_ctx);

    record_mac = &out[data_len];
  }

  /* Perform the MAC check and the padding check in constant-time. It should be
   * safe to simply perform the padding check first, but it would not be under a
   * different choice of MAC location on padding failure. See
   * EVP_tls_cbc_remove_padding. */
  unsigned good = constant_time_eq_int(CRYPTO_memcmp(record_mac, mac, mac_len),
                                       0);
  good &= constant_time_eq_int(padding_ok, 1);
  if (!good) {
    return 0;
  }

  /* End of timing-sensitive code. */

  *out_len = data_len;
  return 1;
}


static int aead_aes_128_cbc_sha1_tls_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                          size_t key_len, size_t tag_len,
                                          enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_aes_128_cbc(),
                       EVP_sha1(), 0);
}

static int aead_aes_128_cbc_sha1_tls_implicit_iv_init(
    EVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len, size_t tag_len,
    enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_aes_128_cbc(),
                       EVP_sha1(), 1);
}

static int aead_aes_128_cbc_sha256_tls_init(EVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len,
                                            enum evp_aead_direction_t dir)

{
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_aes_128_cbc(),
                       EVP_sha256(), 0);
}

static int aead_aes_256_cbc_sha1_tls_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                          size_t key_len, size_t tag_len,
                                          enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_aes_256_cbc(),
                       EVP_sha1(), 0);
}

static int aead_aes_256_cbc_sha1_tls_implicit_iv_init(
    EVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len, size_t tag_len,
    enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_aes_256_cbc(),
                       EVP_sha1(), 1);
}

static int aead_aes_256_cbc_sha256_tls_init(EVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len,
                                            enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_aes_256_cbc(),
                       EVP_sha256(), 0);
}

static int aead_aes_256_cbc_sha384_tls_init(EVP_AEAD_CTX *ctx,
                                            const uint8_t *key, size_t key_len,
                                            size_t tag_len,
                                            enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_aes_256_cbc(),
                       EVP_sha384(), 0);
}

static int aead_des_ede3_cbc_sha1_tls_init(EVP_AEAD_CTX *ctx,
                                           const uint8_t *key, size_t key_len,
                                           size_t tag_len,
                                           enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_des_ede3_cbc(),
                       EVP_sha1(), 0);
}

static int aead_des_ede3_cbc_sha1_tls_implicit_iv_init(
    EVP_AEAD_CTX *ctx, const uint8_t *key, size_t key_len, size_t tag_len,
    enum evp_aead_direction_t dir) {
  return aead_tls_init(ctx, key, key_len, tag_len, dir, EVP_des_ede3_cbc(),
                       EVP_sha1(), 1);
}

static const EVP_AEAD aead_aes_128_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 16, /* key len (SHA1 + AES128) */
    16,                     /* nonce len (IV) */
    16 + SHA_DIGEST_LENGTH, /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_aes_128_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                   /* get_rc4_state */
};

static const EVP_AEAD aead_aes_128_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 16 + 16, /* key len (SHA1 + AES128 + IV) */
    0,                           /* nonce len */
    16 + SHA_DIGEST_LENGTH,      /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,           /* max tag length */
    NULL, /* init */
    aead_aes_128_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                        /* get_rc4_state */
};

static const EVP_AEAD aead_aes_128_cbc_sha256_tls = {
    SHA256_DIGEST_LENGTH + 16, /* key len (SHA256 + AES128) */
    16,                        /* nonce len (IV) */
    16 + SHA256_DIGEST_LENGTH, /* overhead (padding + SHA256) */
    SHA_DIGEST_LENGTH,         /* max tag length */
    NULL, /* init */
    aead_aes_128_cbc_sha256_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                      /* get_rc4_state */
};

static const EVP_AEAD aead_aes_256_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 32, /* key len (SHA1 + AES256) */
    16,                     /* nonce len (IV) */
    16 + SHA_DIGEST_LENGTH, /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                   /* get_rc4_state */
};

static const EVP_AEAD aead_aes_256_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 32 + 16, /* key len (SHA1 + AES256 + IV) */
    0,                           /* nonce len */
    16 + SHA_DIGEST_LENGTH,      /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,           /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                        /* get_rc4_state */
};

static const EVP_AEAD aead_aes_256_cbc_sha256_tls = {
    SHA256_DIGEST_LENGTH + 32, /* key len (SHA256 + AES256) */
    16,                        /* nonce len (IV) */
    16 + SHA256_DIGEST_LENGTH, /* overhead (padding + SHA256) */
    SHA_DIGEST_LENGTH,         /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha256_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                      /* get_rc4_state */
};

static const EVP_AEAD aead_aes_256_cbc_sha384_tls = {
    SHA384_DIGEST_LENGTH + 32, /* key len (SHA384 + AES256) */
    16,                        /* nonce len (IV) */
    16 + SHA384_DIGEST_LENGTH, /* overhead (padding + SHA384) */
    SHA_DIGEST_LENGTH,         /* max tag length */
    NULL, /* init */
    aead_aes_256_cbc_sha384_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                      /* get_rc4_state */
};

static const EVP_AEAD aead_des_ede3_cbc_sha1_tls = {
    SHA_DIGEST_LENGTH + 24, /* key len (SHA1 + 3DES) */
    8,                      /* nonce len (IV) */
    8 + SHA_DIGEST_LENGTH,  /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,      /* max tag length */
    NULL, /* init */
    aead_des_ede3_cbc_sha1_tls_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                   /* get_rc4_state */
};

static const EVP_AEAD aead_des_ede3_cbc_sha1_tls_implicit_iv = {
    SHA_DIGEST_LENGTH + 24 + 8, /* key len (SHA1 + 3DES + IV) */
    0,                          /* nonce len */
    8 + SHA_DIGEST_LENGTH,      /* overhead (padding + SHA1) */
    SHA_DIGEST_LENGTH,          /* max tag length */
    NULL, /* init */
    aead_des_ede3_cbc_sha1_tls_implicit_iv_init,
    aead_tls_cleanup,
    aead_tls_seal,
    aead_tls_open,
    NULL,                       /* get_rc4_state */
};

const EVP_AEAD *EVP_aead_aes_128_cbc_sha1_tls(void) {
  return &aead_aes_128_cbc_sha1_tls;
}

const EVP_AEAD *EVP_aead_aes_128_cbc_sha1_tls_implicit_iv(void) {
  return &aead_aes_128_cbc_sha1_tls_implicit_iv;
}

const EVP_AEAD *EVP_aead_aes_128_cbc_sha256_tls(void) {
	return &aead_aes_128_cbc_sha256_tls;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha1_tls(void) {
  return &aead_aes_256_cbc_sha1_tls;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha1_tls_implicit_iv(void) {
  return &aead_aes_256_cbc_sha1_tls_implicit_iv;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha256_tls(void) {
  return &aead_aes_256_cbc_sha256_tls;
}

const EVP_AEAD *EVP_aead_aes_256_cbc_sha384_tls(void) {
  return &aead_aes_256_cbc_sha384_tls;
}

const EVP_AEAD *EVP_aead_des_ede3_cbc_sha1_tls(void) {
  return &aead_des_ede3_cbc_sha1_tls;
}

const EVP_AEAD *EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv(void) {
  return &aead_des_ede3_cbc_sha1_tls_implicit_iv;
}
