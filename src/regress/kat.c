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
 * The known-answer tests of the cipher shim (TEST-KAT-1). Each test
 * reads the vectors that libwally wrote, and each answer of the shim
 * must equal the vector.
 *
 * The program writes the fixed random source first, and it names it
 * in FUGUORACLE_RANDOM. The draws then follow the order of that file:
 * the request seal, the response seal, the record seal, and the two
 * reads of the seam test. A test that draws must therefore keep its
 * place in main().
 *
 * The program prints nothing when every test passes.
 */

#include <sys/types.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cipher.h"
#include "vectors/vectors.h"

/* The largest vector is the 229-byte envelope of the set_pin request. */
#define BLOB_MAX	256

/* The cke and the replay counter in front of an envelope. */
#define HEADER_LEN	(CIPHER_PUBKEY_LEN + 4)

struct blob {
	uint8_t	 b[BLOB_MAX];
	size_t	 len;
};

static void	 blob(struct blob *, const char *);
static void	 dump(const char *, const uint8_t *, size_t);
static void	 same(const char *, const uint8_t *, size_t,
		     const struct blob *);
static void	 ok(const char *, int);
static void	 parity_is(const char *, int, int);
static void	 zeroed(const char *, const uint8_t *, size_t);
static void	 untouched(const char *, const uint8_t *, size_t, uint8_t);
static void	 m_is(const char *, const char *, uint32_t, const char *);
static void	 keys(const char *, uint32_t, const char *, uint8_t *,
		     uint8_t *, uint8_t *);
static void	 tweaked(const char *, const char *, uint32_t, const char *,
		     int);

static int	 failures;

/* The bytes of one hex vector. */
static void
blob(struct blob *out, const char *hex)
{
	size_t		 i, len;
	unsigned int	 byte;

	len = strlen(hex);
	if (len % 2 != 0 || len / 2 > BLOB_MAX)
		errx(1, "a vector holds %zu digits", len);
	memset(out->b, 0, sizeof(out->b));
	for (i = 0; i < len / 2; i++) {
		if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
			errx(1, "a vector holds no hex digit");
		out->b[i] = (uint8_t)byte;
	}
	out->len = len / 2;
}

/* One labeled line of hex, for a failure report. */
static void
dump(const char *label, const uint8_t *bytes, size_t len)
{
	size_t	 i;

	fprintf(stderr, "    %s ", label);
	for (i = 0; i < len; i++)
		fprintf(stderr, "%02x", bytes[i]);
	fprintf(stderr, "\n");
}

/* The answer of the shim equals the vector. */
static void
same(const char *name, const uint8_t *got, size_t got_len,
    const struct blob *want)
{
	if (got_len == want->len && memcmp(got, want->b, got_len) == 0)
		return;
	warnx("%s: the value differs", name);
	dump("got ", got, got_len);
	dump("want", want->b, want->len);
	failures++;
}

/* One condition of a test holds. */
static void
ok(const char *name, int cond)
{
	if (cond)
		return;
	warnx("%s: the test failed", name);
	failures++;
}

/* The parity bit of the shim equals the vector. */
static void
parity_is(const char *name, int got, int want)
{
	if (got == want)
		return;
	warnx("%s: the parity is %d, not %d", name, got, want);
	failures++;
}

/* A buffer holds no byte of a secret (SEC-MEMORY-2). */
static void
zeroed(const char *name, const uint8_t *buf, size_t len)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		if (buf[i] != 0) {
			warnx("%s: the buffer holds byte %zu", name, i);
			failures++;
			return;
		}
}

/* A call left the fill byte of a buffer in place. */
static void
untouched(const char *name, const uint8_t *buf, size_t len, uint8_t fill)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		if (buf[i] != fill) {
			warnx("%s: the buffer lost byte %zu", name, i);
			failures++;
			return;
		}
}

/*
 * The tweak input m of one request (PROTO-TWEAK-1). The shim derives
 * m, and the tweak of the key reads the same derivation, so a wrong
 * counter byte order in the shim fails here.
 */
static void
m_is(const char *name, const char *cke_hex, uint32_t counter,
    const char *m_hex)
{
	struct blob	 cke, want;
	uint8_t		 m[CIPHER_HASH_LEN];

	blob(&cke, cke_hex);
	blob(&want, m_hex);
	ok(name, cipher_tweak_input(cke.b, counter, m) == 0);
	same(name, m, sizeof(m), &want);
}

/*
 * The request key d' of one transcript request, and the two envelope
 * keys of one direction. dprime, enc and mac each take a key.
 */
static void
keys(const char *cke_hex, uint32_t counter, const char *label,
    uint8_t *dprime, uint8_t *enc, uint8_t *mac)
{
	struct blob	 priv, cke;

	blob(&priv, V_STATIC_PRIV);
	blob(&cke, cke_hex);
	ok("the tweak of the static key",
	    cipher_tweak_key(priv.b, cke.b, counter, dprime) == 0);
	ok("the envelope keys",
	    cipher_ecdh_keys(dprime, cke.b, label, enc, mac) == 0);
}

/*
 * The request public key Q' of one request, from the static public
 * key P (PROTO-TWEAK-4). A client holds P only, and it must reach the
 * x-only key and the parity bit of this vector.
 */
static void
tweaked(const char *name, const char *cke_hex, uint32_t counter,
    const char *qprime_hex, int qprime_parity)
{
	struct blob	 pub, cke, want;
	uint8_t		 qprime[CIPHER_XONLY_LEN];
	int		 parity = -1;

	blob(&pub, V_STATIC_PUB);
	blob(&cke, cke_hex);
	blob(&want, qprime_hex);
	ok(name, cipher_tweak_pubkey(pub.b, cke.b, counter, qprime,
	    &parity) == 0);
	same(name, qprime, sizeof(qprime), &want);
	parity_is(name, parity, qprime_parity);
}

/* The tweak of the static key (PROTO-TWEAK-1, PROTO-TWEAK-2). */
static void
t_tweak(void)
{
	struct blob	 priv, cke, want;
	uint8_t		 dprime[CIPHER_KEY_LEN];

	blob(&priv, V_STATIC_PRIV);
	blob(&cke, V_TWEAK_CKE);
	blob(&want, V_TWEAK_DPRIME);
	m_is("the tweak input", V_TWEAK_CKE, V_TWEAK_COUNTER, V_TWEAK_M);
	ok("tweak", cipher_tweak_key(priv.b, cke.b, V_TWEAK_COUNTER,
	    dprime) == 0);
	same("tweak", dprime, sizeof(dprime), &want);
	tweaked("the tweaked key", V_TWEAK_CKE, V_TWEAK_COUNTER,
	    V_TWEAK_QPRIME, V_TWEAK_QPRIME_PARITY);
}

/* The ECDH secret and its split, for both labels (PROTO-ENCRYPT-2). */
static void
t_kdf(void)
{
	struct blob	 priv, cke, want;
	uint8_t		 shared[CIPHER_HASH_LEN];
	uint8_t		 enc[CIPHER_KEY_LEN], mac[CIPHER_KEY_LEN];

	blob(&priv, V_TWEAK_DPRIME);
	blob(&cke, V_TWEAK_CKE);

	/* The one secret that both labels split (PROTO-ENCRYPT-5). */
	blob(&want, V_TWEAK_SHARED);
	ok("the shared secret", cipher_ecdh_secret(priv.b, cke.b, shared) == 0);
	same("the shared secret", shared, sizeof(shared), &want);

	ok("request keys", cipher_ecdh_keys(priv.b, cke.b,
	    CIPHER_LABEL_REQUEST, enc, mac) == 0);
	blob(&want, V_TWEAK_REQUEST_ENC_KEY);
	same("request enc_key", enc, sizeof(enc), &want);
	blob(&want, V_TWEAK_REQUEST_MAC_KEY);
	same("request mac_key", mac, sizeof(mac), &want);

	ok("response keys", cipher_ecdh_keys(priv.b, cke.b,
	    CIPHER_LABEL_RESPONSE, enc, mac) == 0);
	blob(&want, V_TWEAK_RESPONSE_ENC_KEY);
	same("response enc_key", enc, sizeof(enc), &want);
	blob(&want, V_TWEAK_RESPONSE_MAC_KEY);
	same("response mac_key", mac, sizeof(mac), &want);
}

/* The open of one request of the transcript. */
static void
open_request(const char *name, const char *cke_hex, uint32_t counter,
    const char *dprime_hex, const char *env_hex, const char *payload_hex)
{
	struct blob	 env, want;
	uint8_t		 dprime[CIPHER_KEY_LEN];
	uint8_t		 enc[CIPHER_KEY_LEN], mac[CIPHER_KEY_LEN];
	uint8_t		 out[BLOB_MAX];
	size_t		 len;

	keys(cke_hex, counter, CIPHER_LABEL_REQUEST, dprime, enc, mac);
	blob(&want, dprime_hex);
	same(name, dprime, sizeof(dprime), &want);

	blob(&env, env_hex);
	blob(&want, payload_hex);
	ok(name, cipher_envelope_open(enc, mac, env.b, env.len, out,
	    sizeof(out), &len) == 0);
	same(name, out, len, &want);
}

/*
 * The transcript pair of one client key: a set_pin request, then a
 * get_pin request with a higher replay counter. The two payload forms
 * of PROTO-PAYLOAD-1 travel in them.
 */
static void
t_open(void)
{
	struct blob	 payload;

	ok("the counter of the get_pin request is higher",
	    V_GET_COUNTER > V_SET_COUNTER);

	blob(&payload, V_SET_PAYLOAD);
	ok("the set_pin payload holds 129 bytes", payload.len == 129);
	m_is("the set_pin tweak input", V_SET_CKE, V_SET_COUNTER, V_SET_M);
	open_request("set_pin open", V_SET_CKE, V_SET_COUNTER, V_SET_DPRIME,
	    V_SET_ENC, V_SET_PAYLOAD);
	tweaked("the set_pin tweaked key", V_SET_CKE, V_SET_COUNTER,
	    V_SET_QPRIME, V_SET_QPRIME_PARITY);

	blob(&payload, V_GET_PAYLOAD);
	ok("the get_pin payload holds 97 bytes", payload.len == 97);
	m_is("the get_pin tweak input", V_GET_CKE, V_GET_COUNTER, V_GET_M);
	open_request("get_pin open", V_GET_CKE, V_GET_COUNTER, V_GET_DPRIME,
	    V_GET_ENC, V_GET_PAYLOAD);
	tweaked("the get_pin tweaked key", V_GET_CKE, V_GET_COUNTER,
	    V_GET_QPRIME, V_GET_QPRIME_PARITY);
}

/*
 * A changed envelope answers -1. A wrong tag and a wrong length each
 * leave the buffer of the caller in place, because the open answers
 * before the decryption (PROTO-ENCRYPT-3). A bad padding fails after
 * the decryption, so that failure clears the buffer.
 */
static void
t_reject(void)
{
	struct blob	 env;
	uint8_t		 dprime[CIPHER_KEY_LEN];
	uint8_t		 enc[CIPHER_KEY_LEN], mac[CIPHER_KEY_LEN];
	uint8_t		 out[BLOB_MAX];
	size_t		 len;

	keys(V_GET_CKE, V_GET_COUNTER, CIPHER_LABEL_REQUEST, dprime, enc,
	    mac);

	blob(&env, V_GET_ENC);
	env.b[env.len - 1] ^= 0x01;
	memset(out, 0xa5, sizeof(out));
	ok("a wrong tag", cipher_envelope_open(enc, mac, env.b, env.len, out,
	    sizeof(out), &len) == -1);
	ok("a wrong tag writes no length", len == 0);
	untouched("a wrong tag", out, sizeof(out), 0xa5);

	blob(&env, V_GET_ENC);
	env.b[CIPHER_IV_LEN] ^= 0x01;
	ok("a changed ciphertext", cipher_envelope_open(enc, mac, env.b,
	    env.len, out, sizeof(out), &len) == -1);

	/*
	 * A wrong length answers before the tag step, so it leaves
	 * the buffer of the caller in place. Each case fills the
	 * buffer first, so the test reads a byte of its own.
	 */
	blob(&env, V_GET_ENC);
	memset(out, 0xa5, sizeof(out));
	ok("a short envelope", cipher_envelope_open(enc, mac, env.b,
	    CIPHER_ENVELOPE_OVERHEAD, out, sizeof(out), &len) == -1);
	ok("a short envelope writes no length", len == 0);
	untouched("a short envelope", out, sizeof(out), 0xa5);

	memset(out, 0xa5, sizeof(out));
	ok("a ciphertext beside the block", cipher_envelope_open(enc, mac,
	    env.b, env.len - 1, out, sizeof(out), &len) == -1);
	ok("a ciphertext beside the block writes no length", len == 0);
	untouched("a ciphertext beside the block", out, sizeof(out), 0xa5);

	/*
	 * A tag that answers, and a padding that does not. The change
	 * of the last byte of the second last block breaks the last
	 * pad byte, and a fresh tag covers the change. The decryption
	 * runs and writes a part of the plaintext, so the failure
	 * clears the buffer.
	 */
	blob(&env, V_GET_ENC);
	env.b[env.len - CIPHER_TAG_LEN - CIPHER_BLOCK_LEN - 1] ^= 0x01;
	ok("a bad padding", cipher_hmac_sha256(mac, CIPHER_KEY_LEN, env.b,
	    env.len - CIPHER_TAG_LEN, env.b + env.len - CIPHER_TAG_LEN) == 0);
	memset(out, 0xa5, sizeof(out));
	ok("a bad padding", cipher_envelope_open(enc, mac, env.b, env.len,
	    out, sizeof(out), &len) == -1);
	ok("a bad padding writes no length", len == 0);
	zeroed("a bad padding", out, sizeof(out));
}

/* The client public key of the signed payload hash (PROTO-PAYLOAD-4). */
static void
t_recover(void)
{
	struct blob	 msghash, payload, want;
	uint8_t		 pubkey[CIPHER_PUBKEY_LEN];

	blob(&want, V_CLIENT_PUB);

	blob(&msghash, V_SET_MSGHASH);
	blob(&payload, V_SET_PAYLOAD);
	ok("set_pin recovery", cipher_recover_pubkey(msghash.b,
	    payload.b + payload.len - CIPHER_SIG_LEN, pubkey) == 0);
	same("set_pin recovery", pubkey, sizeof(pubkey), &want);

	blob(&msghash, V_GET_MSGHASH);
	blob(&payload, V_GET_PAYLOAD);
	ok("get_pin recovery", cipher_recover_pubkey(msghash.b,
	    payload.b + payload.len - CIPHER_SIG_LEN, pubkey) == 0);
	same("get_pin recovery", pubkey, sizeof(pubkey), &want);

	/* Another signature never recovers the key of this client. */
	payload.b[payload.len - 1] ^= 0x01;
	ok("a changed signature recovers another key",
	    cipher_recover_pubkey(msghash.b,
	    payload.b + payload.len - CIPHER_SIG_LEN, pubkey) == -1 ||
	    memcmp(pubkey, want.b, sizeof(pubkey)) != 0);
}

/* The two hash functions, and the signed message of the transcript. */
static void
t_hash(void)
{
	struct blob	 msg, key, env, pin, entropy, want;
	uint8_t		 out[CIPHER_HASH_LEN];
	uint8_t		 get_message[HEADER_LEN + CIPHER_KEY_LEN];
	uint8_t		 set_message[HEADER_LEN + 2 * CIPHER_KEY_LEN];

	blob(&msg, V_HASH_MESSAGE);
	blob(&want, V_HASH_SHA256);
	ok("sha256", cipher_sha256(msg.b, msg.len, out) == 0);
	same("sha256", out, sizeof(out), &want);

	blob(&key, V_HMAC_KEY);
	blob(&want, V_HMAC_SHA256);
	ok("hmac_sha256", cipher_hmac_sha256(key.b, key.len, msg.b, msg.len,
	    out) == 0);
	same("hmac_sha256", out, sizeof(out), &want);

	/*
	 * The envelope of the get_pin request opens with its cke and
	 * its counter, and those bytes lead the signed message. The
	 * 97-byte form carries no entropy, so the message holds 69
	 * bytes (PROTO-PAYLOAD-3).
	 */
	blob(&env, V_GET_ENVELOPE);
	blob(&pin, V_PIN_SECRET);
	blob(&want, V_GET_MSGHASH);
	memcpy(get_message, env.b, HEADER_LEN);
	memcpy(get_message + HEADER_LEN, pin.b, CIPHER_KEY_LEN);
	ok("the get_pin signed message", cipher_sha256(get_message,
	    sizeof(get_message), out) == 0);
	same("the get_pin signed message", out, sizeof(out), &want);

	/*
	 * The 129-byte form of the set_pin request adds the entropy
	 * after the pin_secret, so its signed message holds 101 bytes
	 * (PROTO-PAYLOAD-3).
	 */
	blob(&env, V_SET_ENVELOPE);
	blob(&pin, V_PIN_SECRET);
	blob(&entropy, V_ENTROPY);
	blob(&want, V_SET_MSGHASH);
	memcpy(set_message, env.b, HEADER_LEN);
	memcpy(set_message + HEADER_LEN, pin.b, CIPHER_KEY_LEN);
	memcpy(set_message + HEADER_LEN + CIPHER_KEY_LEN, entropy.b,
	    CIPHER_KEY_LEN);
	ok("the set_pin signed message", cipher_sha256(set_message,
	    sizeof(set_message), out) == 0);
	same("the set_pin signed message", out, sizeof(out), &want);
}

/*
 * The seal of the get_pin request and of its answer, each with an IV
 * from the seam (PROTO-ENCRYPT-4). The answer is block aligned, so a
 * full pad block follows it.
 */
static void
t_seal(void)
{
	struct blob	 payload, want;
	uint8_t		 dprime[CIPHER_KEY_LEN];
	uint8_t		 enc[CIPHER_KEY_LEN], mac[CIPHER_KEY_LEN];
	uint8_t		 out[BLOB_MAX];
	size_t		 len;

	keys(V_GET_CKE, V_GET_COUNTER, CIPHER_LABEL_REQUEST, dprime, enc,
	    mac);
	blob(&payload, V_GET_PAYLOAD);
	blob(&want, V_GET_ENC);
	ok("request seal", cipher_envelope_seal(enc, mac, payload.b,
	    payload.len, out, sizeof(out), &len) == 0);
	same("request seal", out, len, &want);

	keys(V_GET_CKE, V_GET_COUNTER, CIPHER_LABEL_RESPONSE, dprime, enc,
	    mac);
	blob(&payload, V_RESPONSE_PAYLOAD);
	blob(&want, V_RESPONSE_ENC);
	ok("response seal", cipher_envelope_seal(enc, mac, payload.b,
	    payload.len, out, sizeof(out), &len) == 0);
	same("response seal", out, len, &want);
	ok("the response envelope holds 96 bytes", len == 96);
}

/* The record cipher of the 69-byte plaintext (STORE-RECORD). */
static void
t_record(void)
{
	struct blob	 key, enc, want;
	uint8_t		 out[BLOB_MAX];
	uint8_t		 small[CIPHER_BLOCK_LEN];
	size_t		 len;

	blob(&key, V_RECORD_KEY);
	blob(&enc, V_RECORD_ENC);
	blob(&want, V_RECORD_PLAIN);
	ok("the enc field holds 96 bytes", enc.len == 96);
	ok("the record plaintext holds 69 bytes", want.len == 69);

	ok("record open", cipher_record_open(key.b, enc.b, enc.len, out,
	    sizeof(out), &len) == 0);
	same("record open", out, len, &want);

	ok("record seal", cipher_record_seal(key.b, want.b, want.len, out,
	    sizeof(out), &len) == 0);
	same("record seal", out, len, &enc);
	ok("the padded ciphertext holds 80 bytes",
	    len == CIPHER_IV_LEN + 80);

	/*
	 * A failure of the open clears the output buffer, because a
	 * caller can reuse a buffer that holds an earlier plaintext.
	 */
	ok("record open", cipher_record_open(key.b, enc.b, enc.len, out,
	    sizeof(out), &len) == 0);
	ok("a short enc field", cipher_record_open(key.b, enc.b,
	    CIPHER_IV_LEN, out, sizeof(out), &len) == -1);
	zeroed("a short enc field", out, sizeof(out));

	ok("record open", cipher_record_open(key.b, enc.b, enc.len, out,
	    sizeof(out), &len) == 0);
	ok("an enc field beside the block", cipher_record_open(key.b, enc.b,
	    enc.len - 1, out, sizeof(out), &len) == -1);
	zeroed("an enc field beside the block", out, sizeof(out));

	memset(small, 0xa5, sizeof(small));
	ok("a small output buffer", cipher_record_open(key.b, enc.b, enc.len,
	    small, sizeof(small), &len) == -1);
	zeroed("a small output buffer", small, sizeof(small));
}

/*
 * The seam answers the bytes of the file in order (SEC-RANDOM-2). The
 * three seals above drew the first three values, so the tail of the
 * file follows here, in two reads.
 */
static void
t_seam(void)
{
	struct blob	 want;
	uint8_t		 out[CIPHER_IV_LEN];

	blob(&want, V_SEAM_TAIL);
	cipher_random(out, 5);
	cipher_random(out + 5, sizeof(out) - 5);
	same("the seam", out, sizeof(out), &want);
}

int
main(void)
{
	struct blob	 source;
	char		 path[] = "kat.random.XXXXXXXXXX";
	int		 fd;

	blob(&source, V_RANDOM_SOURCE);
	if ((fd = mkstemp(path)) == -1)
		err(1, "mkstemp");
	if (write(fd, source.b, source.len) != (ssize_t)source.len)
		err(1, "%s", path);
	if (close(fd) == -1)
		err(1, "%s", path);
	if (setenv("FUGUORACLE_RANDOM", path, 1) == -1)
		err(1, "setenv");

	t_tweak();
	t_kdf();
	t_open();
	t_reject();
	t_recover();
	t_hash();
	t_seal();
	t_record();
	t_seam();

	if (unlink(path) == -1)
		err(1, "%s", path);
	if (failures != 0)
		errx(1, "%d known-answer test(s) failed", failures);
	return 0;
}
