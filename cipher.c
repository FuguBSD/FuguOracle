/*
 * Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * The cipher shim. This file holds every call into libsecp256k1 and
 * into libcrypto (ARCH-LAYOUT-1), and it answers the wire protocol
 * with the semantics of libwally (PROTO-TWEAK, PROTO-ENCRYPT).
 *
 * Each secret lives in a stack buffer, and each exit path clears it
 * under one goto out (SEC-MEMORY-1, SEC-MEMORY-2). Each tag
 * comparison runs in constant time (SEC-MEMORY-3).
 */

#include <sys/types.h>

#include <endian.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef REGRESS
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>

#include "cipher.h"

/* The tag of the BIP341 tweak, without its NUL byte (PROTO-TWEAK-2). */
#define TAPTWEAK	"TapTweak"

static secp256k1_context	*context(void);
static int			 hmac_evp(const EVP_MD *, const uint8_t *,
				    size_t, const uint8_t *, size_t,
				    uint8_t *, size_t);
static int			 aes_cbc(const uint8_t *, const uint8_t *,
				    int, const uint8_t *, size_t, uint8_t *,
				    size_t, size_t *);
static int			 ecdh_secret(const uint8_t *, const uint8_t *,
				    uint8_t *);
static size_t			 padded(size_t);
static int			 tweak_input(const uint8_t *, uint32_t,
				    uint8_t *);
static int			 tweak_scalar(const uint8_t *,
				    const uint8_t *, uint32_t, uint8_t *);

/*
 * The library context. The shim blinds it, because each request runs
 * the static key d and the request key d' through it (SEC-RANDOM-3).
 * The 32 blinding bytes come from arc4random_buf(3) here, and not
 * from the seam of cipher_random(). The blinding changes no answer,
 * and a draw outside the seam keeps the draw order that the
 * byte-identity test needs (SEC-RANDOM-2, TEST-ACCEPT-2). One process
 * serves one request, so the context lives to the exit of the
 * program.
 */
static secp256k1_context *
context(void)
{
	static secp256k1_context	*ctx;
	uint8_t				 seed[32];

	if (ctx != NULL)
		return ctx;
	if ((ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)) == NULL)
		return NULL;
	arc4random_buf(seed, sizeof(seed));
	if (secp256k1_context_randomize(ctx, seed) != 1) {
		secp256k1_context_destroy(ctx);
		ctx = NULL;
	}
	explicit_bzero(seed, sizeof(seed));
	return ctx;
}

/* The length of the PKCS#7 padded form of a plaintext. */
static size_t
padded(size_t len)
{
	return len - (len % CIPHER_BLOCK_LEN) + CIPHER_BLOCK_LEN;
}

/*
 * One HMAC of the message under the key, with the digest that the
 * caller names. out_len states the digest length that the caller
 * expects.
 */
static int
hmac_evp(const EVP_MD *md, const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len)
{
	unsigned int	 len = 0;

	if (key_len > INT_MAX)
		return -1;
	if (HMAC(md, key, (int)key_len, msg, msg_len, out, &len) == NULL)
		return -1;
	if (len != out_len) {
		explicit_bzero(out, out_len);
		return -1;
	}
	return 0;
}

/*
 * One AES-256-CBC operation with PKCS#7 padding. The EVP layer writes
 * the padded length on an encryption, and at most the input length on
 * a decryption, so out_size covers both in one test. A failure clears
 * the whole output buffer, because it can hold a part of a plaintext.
 */
static int
aes_cbc(const uint8_t *key, const uint8_t *iv, int encrypt,
    const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size,
    size_t *out_len)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	int		 len, total;
	int		 rc = -1;

	*out_len = 0;
	if (in_len > INT_MAX || out_size > INT_MAX)
		goto out;
	if (out_size < (encrypt ? padded(in_len) : in_len))
		goto out;
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		goto out;
	if (EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv,
	    encrypt) != 1)
		goto out;
	if (EVP_CipherUpdate(ctx, out, &len, in, (int)in_len) != 1)
		goto out;
	total = len;
	if (EVP_CipherFinal_ex(ctx, out + total, &len) != 1)
		goto out;
	total += len;
	*out_len = (size_t)total;
	rc = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	if (rc != 0)
		explicit_bzero(out, out_size);
	return rc;
}

void
cipher_random(void *buf, size_t len)
{
#ifdef REGRESS
	/*
	 * The regress build reads each draw of the seam from the file
	 * that FUGUORACLE_RANDOM names, in draw order (SEC-RANDOM-2).
	 * The context blinding of SEC-RANDOM-3 draws outside the
	 * seam. The service build holds no such path. A missing or a
	 * short file is a fault of the test, and the program stops
	 * on it.
	 */
	static int	 fd = -1;
	const char	*path;
	uint8_t		*out = buf;
	ssize_t		 n;

	if (fd == -1) {
		if ((path = getenv("FUGUORACLE_RANDOM")) == NULL)
			errx(1, "FUGUORACLE_RANDOM names no file");
		if ((fd = open(path, O_RDONLY)) == -1)
			err(1, "%s", path);
	}
	while (len > 0) {
		n = read(fd, out, len);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			err(1, "the fixed random source");
		}
		if (n == 0)
			errx(1, "the fixed random source holds too few bytes");
		out += n;
		len -= (size_t)n;
	}
#else
	arc4random_buf(buf, len);
#endif
}

int
cipher_sha256(const uint8_t *msg, size_t msg_len, uint8_t *out)
{
	if (SHA256(msg, msg_len, out) == NULL)
		return -1;
	return 0;
}

int
cipher_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg,
    size_t msg_len, uint8_t *out)
{
	return hmac_evp(EVP_sha256(), key, key_len, msg, msg_len, out,
	    CIPHER_HASH_LEN);
}

/*
 * The tweak input m = H(HMAC(key = cke, msg = replay_counter)) of one
 * request (PROTO-TWEAK-1). The counter travels in little-endian byte
 * order. cke holds CIPHER_PUBKEY_LEN bytes, and out takes
 * CIPHER_HASH_LEN bytes.
 */
static int
tweak_input(const uint8_t *cke, uint32_t counter, uint8_t *out)
{
	uint32_t	 le;
	uint8_t		 mac[CIPHER_HASH_LEN];
	int		 rc = -1;

	le = htole32(counter);
	if (cipher_hmac_sha256(cke, CIPHER_PUBKEY_LEN, (const uint8_t *)&le,
	    sizeof(le), mac) != 0)
		goto out;
	if (cipher_sha256(mac, sizeof(mac), out) != 0)
		goto out;
	rc = 0;
out:
	explicit_bzero(mac, sizeof(mac));
	if (rc != 0)
		explicit_bzero(out, CIPHER_HASH_LEN);
	return rc;
}

#ifdef REGRESS
/*
 * The tweak input alone, for the known-answer test of PROTO-TWEAK-1.
 * The service reads m inside the tweak only, so the regress build
 * holds this entry point (ARCH-LAYOUT-5).
 */
int
cipher_tweak_input(const uint8_t *cke, uint32_t counter, uint8_t *out)
{
	return tweak_input(cke, counter, out);
}
#endif

/*
 * The scalar t of one request, for the x-only server key that the
 * caller serialized (PROTO-TWEAK-2). The private side and the public
 * side of the tweak add the same scalar, so they share this step.
 * xonly holds CIPHER_XONLY_LEN bytes, and out takes CIPHER_HASH_LEN
 * bytes.
 */
static int
tweak_scalar(const uint8_t *xonly, const uint8_t *cke, uint32_t counter,
    uint8_t *out)
{
	secp256k1_context	*ctx;
	uint8_t			 tagged[CIPHER_XONLY_LEN + CIPHER_HASH_LEN];
	int			 rc = -1;

	if ((ctx = context()) == NULL)
		goto out;

	/* The tagged hash covers the x-only key and m (PROTO-TWEAK-1). */
	memcpy(tagged, xonly, CIPHER_XONLY_LEN);
	if (tweak_input(cke, counter, tagged + CIPHER_XONLY_LEN) != 0)
		goto out;
	if (secp256k1_tagged_sha256(ctx, out, (const uint8_t *)TAPTWEAK,
	    sizeof(TAPTWEAK) - 1, tagged, sizeof(tagged)) != 1)
		goto out;
	rc = 0;
out:
	explicit_bzero(tagged, sizeof(tagged));
	if (rc != 0)
		explicit_bzero(out, CIPHER_HASH_LEN);
	return rc;
}

int
cipher_tweak_key(const uint8_t *priv, const uint8_t *cke, uint32_t counter,
    uint8_t *out)
{
	secp256k1_context	*ctx;
	secp256k1_keypair	 keypair;
	secp256k1_xonly_pubkey	 xonly;
	uint8_t			 serialized[CIPHER_XONLY_LEN];
	uint8_t			 tweak[CIPHER_HASH_LEN];
	int			 rc = -1;

	memset(&keypair, 0, sizeof(keypair));
	if ((ctx = context()) == NULL)
		goto out;

	/*
	 * The tweak is the tagged hash of the x-only public key and
	 * m, and the keypair call negates d for an odd Y
	 * (PROTO-TWEAK-2).
	 */
	if (secp256k1_keypair_create(ctx, &keypair, priv) != 1)
		goto out;
	if (secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &keypair) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_serialize(ctx, serialized, &xonly) != 1)
		goto out;
	if (tweak_scalar(serialized, cke, counter, tweak) != 0)
		goto out;
	if (secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak) != 1)
		goto out;
	if (secp256k1_keypair_sec(ctx, out, &keypair) != 1)
		goto out;
	rc = 0;
out:
	explicit_bzero(&keypair, sizeof(keypair));
	explicit_bzero(serialized, sizeof(serialized));
	explicit_bzero(tweak, sizeof(tweak));
	if (rc != 0)
		explicit_bzero(out, CIPHER_KEY_LEN);
	return rc;
}

#ifdef REGRESS
/*
 * The public tweak answers a client, because the service holds d
 * (PROTO-TWEAK-4). The regress build compiles it, and the service
 * program carries no client-side curve code (ARCH-LAYOUT-2,
 * ARCH-LAYOUT-4, ARCH-LAYOUT-5).
 */
int
cipher_tweak_pubkey(const uint8_t *pub, const uint8_t *cke, uint32_t counter,
    uint8_t *out, int *parity)
{
	secp256k1_context	*ctx;
	secp256k1_pubkey	 pubkey, tweaked;
	secp256k1_xonly_pubkey	 xonly;
	uint8_t			 serialized[CIPHER_XONLY_LEN];
	uint8_t			 tweak[CIPHER_HASH_LEN];
	int			 rc = -1;

	*parity = -1;
	memset(&pubkey, 0, sizeof(pubkey));
	memset(&tweaked, 0, sizeof(tweaked));
	if ((ctx = context()) == NULL)
		goto out;

	/*
	 * A client holds P, not d, so it adds the scalar to the
	 * x-only key of P. The answer is d' * G, and its Y parity
	 * belongs to the answer (PROTO-TWEAK-4).
	 */
	if (secp256k1_ec_pubkey_parse(ctx, &pubkey, pub,
	    CIPHER_PUBKEY_LEN) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL,
	    &pubkey) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_serialize(ctx, serialized, &xonly) != 1)
		goto out;
	if (tweak_scalar(serialized, cke, counter, tweak) != 0)
		goto out;
	if (secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked, &xonly,
	    tweak) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, parity,
	    &tweaked) != 1)
		goto out;
	if (secp256k1_xonly_pubkey_serialize(ctx, out, &xonly) != 1)
		goto out;
	rc = 0;
out:
	explicit_bzero(serialized, sizeof(serialized));
	explicit_bzero(tweak, sizeof(tweak));
	if (rc != 0) {
		explicit_bzero(out, CIPHER_XONLY_LEN);
		*parity = -1;
	}
	return rc;
}
#endif

/*
 * The ECDH secret of one private key and one public key. The default
 * hash function of the library is the SHA-256 of the compressed
 * shared point (PROTO-ENCRYPT-1). out holds CIPHER_HASH_LEN bytes.
 */
static int
ecdh_secret(const uint8_t *priv, const uint8_t *pub, uint8_t *out)
{
	secp256k1_context	*ctx;
	secp256k1_pubkey	 pubkey;
	int			 rc = -1;

	memset(&pubkey, 0, sizeof(pubkey));
	if ((ctx = context()) == NULL)
		goto out;
	if (secp256k1_ec_pubkey_parse(ctx, &pubkey, pub,
	    CIPHER_PUBKEY_LEN) != 1)
		goto out;
	if (secp256k1_ecdh(ctx, out, &pubkey, priv, NULL, NULL) != 1)
		goto out;
	rc = 0;
out:
	if (rc != 0)
		explicit_bzero(out, CIPHER_HASH_LEN);
	return rc;
}

#ifdef REGRESS
/*
 * The ECDH secret alone, for the known-answer test of
 * PROTO-ENCRYPT-1. The service reads the two envelope keys only, so
 * the regress build holds this entry point (ARCH-LAYOUT-5).
 */
int
cipher_ecdh_secret(const uint8_t *priv, const uint8_t *pub, uint8_t *out)
{
	return ecdh_secret(priv, pub, out);
}
#endif

int
cipher_ecdh_keys(const uint8_t *priv, const uint8_t *pub, const char *label,
    uint8_t *enc_key, uint8_t *mac_key)
{
	uint8_t	 shared[CIPHER_HASH_LEN];
	uint8_t	 keys[CIPHER_KEY_LEN + CIPHER_KEY_LEN];
	int	 rc = -1;

	/* The HMAC-SHA512 of the label splits the secret (PROTO-ENCRYPT-2). */
	if (ecdh_secret(priv, pub, shared) != 0)
		goto out;
	if (hmac_evp(EVP_sha512(), shared, sizeof(shared),
	    (const uint8_t *)label, strlen(label), keys, sizeof(keys)) != 0)
		goto out;
	memcpy(enc_key, keys, CIPHER_KEY_LEN);
	memcpy(mac_key, keys + CIPHER_KEY_LEN, CIPHER_KEY_LEN);
	rc = 0;
out:
	explicit_bzero(shared, sizeof(shared));
	explicit_bzero(keys, sizeof(keys));
	if (rc != 0) {
		explicit_bzero(enc_key, CIPHER_KEY_LEN);
		explicit_bzero(mac_key, CIPHER_KEY_LEN);
	}
	return rc;
}

int
cipher_envelope_open(const uint8_t *enc_key, const uint8_t *mac_key,
    const uint8_t *env, size_t env_len, uint8_t *out, size_t out_size,
    size_t *out_len)
{
	uint8_t		 tag[CIPHER_TAG_LEN];
	size_t		 ct_len;
	int		 rc = -1;

	*out_len = 0;
	if (env_len < CIPHER_ENVELOPE_OVERHEAD + CIPHER_BLOCK_LEN)
		goto out;
	ct_len = env_len - CIPHER_ENVELOPE_OVERHEAD;
	if (ct_len % CIPHER_BLOCK_LEN != 0)
		goto out;

	/*
	 * The tag covers the IV and the ciphertext, and it answers
	 * before the decryption starts (PROTO-ENCRYPT-3).
	 */
	if (cipher_hmac_sha256(mac_key, CIPHER_KEY_LEN, env,
	    CIPHER_IV_LEN + ct_len, tag) != 0)
		goto out;
	if (timingsafe_bcmp(tag, env + CIPHER_IV_LEN + ct_len,
	    CIPHER_TAG_LEN) != 0)
		goto out;
	if (aes_cbc(enc_key, env, 0, env + CIPHER_IV_LEN, ct_len, out,
	    out_size, out_len) != 0)
		goto out;
	rc = 0;
out:
	explicit_bzero(tag, sizeof(tag));
	return rc;
}

int
cipher_envelope_seal(const uint8_t *enc_key, const uint8_t *mac_key,
    const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_size,
    size_t *out_len)
{
	size_t	 ct_len;
	int	 rc = -1;

	*out_len = 0;
	if (pt_len > INT_MAX)
		return -1;
	if (out_size < CIPHER_IV_LEN + padded(pt_len) + CIPHER_TAG_LEN)
		return -1;

	/* The IV of each envelope is fresh (PROTO-ENCRYPT-4). */
	cipher_random(out, CIPHER_IV_LEN);
	if (aes_cbc(enc_key, out, 1, pt, pt_len, out + CIPHER_IV_LEN,
	    out_size - CIPHER_IV_LEN - CIPHER_TAG_LEN, &ct_len) != 0)
		goto out;
	if (cipher_hmac_sha256(mac_key, CIPHER_KEY_LEN, out,
	    CIPHER_IV_LEN + ct_len, out + CIPHER_IV_LEN + ct_len) != 0)
		goto out;
	*out_len = CIPHER_IV_LEN + ct_len + CIPHER_TAG_LEN;
	rc = 0;
out:
	if (rc != 0)
		explicit_bzero(out, out_size);
	return rc;
}

int
cipher_recover_pubkey(const uint8_t *msghash, const uint8_t *sig,
    uint8_t *out)
{
	secp256k1_context			*ctx;
	secp256k1_ecdsa_recoverable_signature	 rsig;
	secp256k1_pubkey			 pubkey;
	size_t					 len = CIPHER_PUBKEY_LEN;
	int					 recid;
	int					 rc = -1;

	memset(&rsig, 0, sizeof(rsig));
	memset(&pubkey, 0, sizeof(pubkey));
	if ((ctx = context()) == NULL)
		goto out;

	/* The header byte of the libwally form holds the recovery id. */
	recid = (sig[0] - 27) & 3;
	if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig,
	    sig + 1, recid) != 1)
		goto out;
	if (secp256k1_ecdsa_recover(ctx, &pubkey, &rsig, msghash) != 1)
		goto out;
	if (secp256k1_ec_pubkey_serialize(ctx, out, &len, &pubkey,
	    SECP256K1_EC_COMPRESSED) != 1)
		goto out;
	if (len != CIPHER_PUBKEY_LEN)
		goto out;
	rc = 0;
out:
	explicit_bzero(&rsig, sizeof(rsig));
	explicit_bzero(&pubkey, sizeof(pubkey));
	if (rc != 0)
		explicit_bzero(out, CIPHER_PUBKEY_LEN);
	return rc;
}

int
cipher_record_open(const uint8_t *key, const uint8_t *enc, size_t enc_len,
    uint8_t *out, size_t out_size, size_t *out_len)
{
	size_t	 ct_len;
	int	 rc = -1;

	*out_len = 0;
	if (enc_len < CIPHER_IV_LEN + CIPHER_BLOCK_LEN)
		goto out;
	ct_len = enc_len - CIPHER_IV_LEN;
	if (ct_len % CIPHER_BLOCK_LEN != 0)
		goto out;
	rc = aes_cbc(key, enc, 0, enc + CIPHER_IV_LEN, ct_len, out,
	    out_size, out_len);
out:
	if (rc != 0)
		explicit_bzero(out, out_size);
	return rc;
}

int
cipher_record_seal(const uint8_t *key, const uint8_t *pt, size_t pt_len,
    uint8_t *out, size_t out_size, size_t *out_len)
{
	size_t	 ct_len;
	int	 rc = -1;

	*out_len = 0;
	if (pt_len > INT_MAX)
		return -1;
	if (out_size < CIPHER_IV_LEN + padded(pt_len))
		return -1;

	/* The IV of each record write is fresh (STORE-RECORD-5). */
	cipher_random(out, CIPHER_IV_LEN);
	if (aes_cbc(key, out, 1, pt, pt_len, out + CIPHER_IV_LEN,
	    out_size - CIPHER_IV_LEN, &ct_len) != 0)
		goto out;
	*out_len = CIPHER_IV_LEN + ct_len;
	rc = 0;
out:
	if (rc != 0)
		explicit_bzero(out, out_size);
	return rc;
}
