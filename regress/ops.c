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
 * The tests of the oracle operations (OPS-SET, OPS-GET, OPS-JUNK).
 * The program holds a client of its own: it builds each request
 * envelope with the shim, and it reads each response envelope with
 * it. The client signs with cipher_sign_recoverable(), which the
 * service never calls.
 *
 * Two requests come from the committed transcript of vectors.h,
 * which libwally wrote. They prove the signed message of
 * PROTO-PAYLOAD-3 and the recovery of PROTO-PAYLOAD-4 against the
 * upstream semantics: another signed message recovers another key,
 * and the request then addresses another record.
 *
 * The program writes the fixed random source first, and it names it
 * in FUGUORACLE_RANDOM (SEC-RANDOM-2). Each draw of the run comes
 * from that file, in order: the IV of a client seal, and then the
 * draws of the service. The tests therefore pin the draw table of
 * TEST-ACCEPT-2. Each test names the draws that it expects, and it
 * reads the answer of the service for each one. A draw that moves, a
 * draw that is absent, and a draw that is new each fail here.
 *
 * The tests read and write real record files under the PINS_DIR of
 * the regress build, and each case empties that directory first. The
 * tests derive the record keys and the record layout from the text
 * of the specification, and not from pindb.c.
 *
 * The program prints nothing when every test passes.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cipher.h"
#include "oracle.h"
#include "pindb.h"
#include "vectors.h"

/* The offset of the encrypted part of a request (PROTO-ENVELOPE). */
#define ENV_ENC_OFF	(CIPHER_PUBKEY_LEN + 4)

/* The longest envelope of a test: the 129-byte payload form. */
#define ENV_MAX		256

/* The two payload forms of PROTO-PAYLOAD. */
#define PAYLOAD_SHORT	(CIPHER_KEY_LEN + CIPHER_SIG_LEN)
#define PAYLOAD_LONG	(CIPHER_KEY_LEN + CIPHER_KEY_LEN + CIPHER_SIG_LEN)

/* The envelope of each payload form (PROTO-ENVELOPE). */
#define ENV_SHORT	197	/* the 97-byte form */
#define ENV_LONG	229	/* the 129-byte form */

/* The offsets of the record file and of its plaintext (STORE-RECORD). */
#define R_HMAC		1
#define R_ENC		33
#define R_ENC_LEN	96
#define P_HASH		0
#define P_KEY		32
#define P_COUNT		64
#define P_REPLAY	65

/* The bytes of the fixed random source of the run. */
#define SOURCE_LEN	16384

/* The chain writes whole hash blocks, so the source holds no tail. */
_Static_assert(SOURCE_LEN % CIPHER_HASH_LEN == 0,
    "the source length must be a multiple of the hash");

/* The seed of that source. The chain of it fills SOURCE_LEN bytes. */
#define SOURCE_SEED	"fuguoracle ops tests"

static uint8_t	 priv[CIPHER_KEY_LEN];		/* the static key d */
static uint8_t	 spub[CIPHER_PUBKEY_LEN];	/* the static key P */
static uint8_t	 owner[CIPHER_KEY_LEN];		/* the client private key */
static uint8_t	 owner_pub[CIPHER_PUBKEY_LEN];	/* the client public key */
static uint8_t	 secret[CIPHER_KEY_LEN];	/* the correct pin_secret */
static uint8_t	 wrong[CIPHER_KEY_LEN];		/* a wrong pin_secret */
static uint8_t	 entropy[CIPHER_KEY_LEN];	/* the client entropy */
static uint8_t	 cke_priv[CIPHER_KEY_LEN];	/* the ephemeral client key */
static uint8_t	 cke[CIPHER_PUBKEY_LEN];
static uint8_t	 source[SOURCE_LEN];		/* the fixed random source */
static size_t	 used;				/* the bytes drawn from it */
static int	 failures;

static void	 ok(const char *, int);
static void	 ok2(const char *, const char *, int);
static size_t	 hexbytes(const char *, uint8_t *, size_t);
static void	 draw(uint8_t *, size_t);
static void	 record_keys(uint8_t *, uint8_t *);
static void	 record_file(char *, size_t);
static size_t	 record_bytes(uint8_t *, size_t);
static void	 record_put(const uint8_t *, size_t);
static void	 retag(uint8_t *);
static int	 record_state(struct pindb_record *);
static void	 reset(void);
static void	 client_keys(const uint8_t *, const uint8_t *, uint32_t,
		     const char *, uint8_t *, uint8_t *);
static size_t	 seal_request(uint32_t, const uint8_t *, size_t, uint8_t *,
		     size_t);
static size_t	 request(uint32_t, const uint8_t *, int, uint8_t *, size_t);
static void	 answer(const uint8_t *, const uint8_t *, uint32_t,
		     const struct oracle_response *, uint8_t *);
static enum oracle_decision handle(const char *, enum oracle_op,
		     const uint8_t *, size_t, struct oracle_response *,
		     enum oracle_outcome *);
static void	 responds(const char *, enum oracle_op, const uint8_t *, size_t,
		     struct oracle_response *, enum oracle_outcome);
static void	 fails(const char *, enum oracle_op, const uint8_t *, size_t,
		     enum oracle_decision, enum oracle_outcome);
static void	 storage_iv_is(const char *, const uint8_t *);
static void	 response_iv_is(const char *, const struct oracle_response *,
		     const uint8_t *);
static void	 key_is(const char *, const uint8_t *, const uint8_t *);
static void	 junk_is(const char *, const struct oracle_response *,
		     uint32_t, const uint8_t *, const uint8_t *);
static void	 provision(uint8_t *);
static void	 random_source(char *, size_t);

/* One condition of a test holds. */
static void
ok(const char *name, int cond)
{
	if (cond)
		return;
	warnx("%s: the test failed", name);
	failures++;
}

/* One condition of a named case holds. */
static void
ok2(const char *prefix, const char *name, int cond)
{
	if (cond)
		return;
	warnx("%s, %s: the test failed", prefix, name);
	failures++;
}

/* The bytes of one hex value, and its length. */
static size_t
hexbytes(const char *hex, uint8_t *out, size_t size)
{
	size_t		 i, len;
	unsigned int	 byte;

	len = strlen(hex);
	if (len % 2 != 0 || len / 2 > size)
		errx(1, "a value holds %zu digits", len);
	for (i = 0; i < len / 2; i++) {
		if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
			errx(1, "a value holds no hex digit");
		out[i] = (uint8_t)byte;
	}
	return len / 2;
}

/*
 * The next len bytes of the fixed source, in draw order. out takes
 * them, or it is NULL for a draw that the case does not read, such
 * as the IV of a client seal.
 */
static void
draw(uint8_t *out, size_t len)
{
	if (used + len > sizeof(source))
		errx(1, "the fixed source holds too few bytes");
	if (out != NULL)
		memcpy(out, source + used, len);
	used += len;
}

/* The two record keys of the test client (STORE-KEYS-1). */
static void
record_keys(uint8_t *storage, uint8_t *auth)
{
	uint8_t	 data_key[CIPHER_KEY_LEN];
	uint8_t	 hash[CIPHER_HASH_LEN];

	ok("the record key", cipher_hmac_sha256(priv, sizeof(priv),
	    (const uint8_t *)"pin_data", 8, data_key) == 0);
	ok("the key hash",
	    cipher_sha256(owner_pub, sizeof(owner_pub), hash) == 0);
	ok("the storage key", cipher_hmac_sha256(data_key, sizeof(data_key),
	    owner_pub, sizeof(owner_pub), storage) == 0);
	ok("the authentication key", cipher_hmac_sha256(data_key,
	    sizeof(data_key), hash, sizeof(hash), auth) == 0);
	explicit_bzero(data_key, sizeof(data_key));
}

/* The record path of the test client (STORE-KEYS-3). */
static void
record_file(char *out, size_t size)
{
	uint8_t	 hash[CIPHER_HASH_LEN];
	char	 hex[2 * CIPHER_HASH_LEN + 1];
	size_t	 i;
	int	 n;

	ok("the hash of the client key",
	    cipher_sha256(owner_pub, sizeof(owner_pub), hash) == 0);
	for (i = 0; i < sizeof(hash); i++)
		snprintf(hex + 2 * i, 3, "%02x", hash[i]);
	n = snprintf(out, size, "%s/%s.pin", PINS_DIR, hex);
	if (n < 0 || (size_t)n >= size)
		errx(1, "the record path is too long");
}

/* The bytes of the record file, or zero when no record is present. */
static size_t
record_bytes(uint8_t *out, size_t size)
{
	char	 path[PATH_MAX];
	ssize_t	 n;
	size_t	 len = 0;
	int	 fd;

	record_file(path, sizeof(path));
	if ((fd = open(path, O_RDONLY)) == -1) {
		if (errno != ENOENT)
			err(1, "%s", path);
		return 0;
	}
	while (len < size) {
		if ((n = read(fd, out + len, size - len)) == -1)
			err(1, "%s", path);
		if (n == 0)
			break;
		len += (size_t)n;
	}
	if (close(fd) == -1)
		err(1, "%s", path);
	return len;
}

/* The bytes of a case into the record file. */
static void
record_put(const uint8_t *raw, size_t len)
{
	char	 path[PATH_MAX];
	int	 fd;

	record_file(path, sizeof(path));
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1)
		err(1, "%s", path);
	if (write(fd, raw, len) != (ssize_t)len)
		err(1, "%s", path);
	if (close(fd) == -1)
		err(1, "%s", path);
}

/* The authenticator of a changed record (STORE-RECORD). */
static void
retag(uint8_t *raw)
{
	uint8_t	 storage[CIPHER_KEY_LEN], auth[CIPHER_KEY_LEN];
	uint8_t	 msg[1 + R_ENC_LEN];

	record_keys(storage, auth);
	msg[0] = raw[0];
	memcpy(msg + 1, raw + R_ENC, R_ENC_LEN);
	ok("the new authenticator", cipher_hmac_sha256(auth, sizeof(auth),
	    msg, sizeof(msg), raw + R_HMAC) == 0);
	explicit_bzero(storage, sizeof(storage));
	explicit_bzero(auth, sizeof(auth));
}

/*
 * The four fields of the record file, read with the keys of
 * STORE-KEYS-1 and the layout of STORE-RECORD. The call answers -1
 * when no record is present. Each answer clears the padding of the
 * structure, so two answers compare byte for byte.
 */
static int
record_state(struct pindb_record *rec)
{
	uint8_t		 raw[PINDB_RECORD_LEN + 1];
	uint8_t		 storage[CIPHER_KEY_LEN], auth[CIPHER_KEY_LEN];
	uint8_t		 plain[R_ENC_LEN - CIPHER_IV_LEN];
	uint32_t	 le;
	size_t		 len, plain_len;
	int		 rc = -1;

	memset(rec, 0, sizeof(*rec));
	if ((len = record_bytes(raw, sizeof(raw))) == 0)
		return -1;
	ok("the record file holds 129 bytes", len == PINDB_RECORD_LEN);
	if (len != PINDB_RECORD_LEN)
		return -1;
	record_keys(storage, auth);
	ok("the enc field opens", cipher_record_open(storage, raw + R_ENC,
	    R_ENC_LEN, plain, sizeof(plain), &plain_len) == 0);
	ok("the record plaintext holds 69 bytes",
	    plain_len == PINDB_PLAIN_LEN);
	if (plain_len == PINDB_PLAIN_LEN) {
		memcpy(rec->hash_pin_secret, plain + P_HASH,
		    sizeof(rec->hash_pin_secret));
		memcpy(rec->aes_key, plain + P_KEY, sizeof(rec->aes_key));
		rec->count = plain[P_COUNT];
		memcpy(&le, plain + P_REPLAY, sizeof(le));
		rec->replay_counter = letoh32(le);
		rc = 0;
	}
	explicit_bzero(storage, sizeof(storage));
	explicit_bzero(auth, sizeof(auth));
	explicit_bzero(plain, sizeof(plain));
	return rc;
}

/* An empty record directory, before one case. */
static void
reset(void)
{
	DIR		*dir;
	struct dirent	*ent;
	char		 path[PATH_MAX];

	if (mkdir(PINS_DIR, 0700) == -1 && errno != EEXIST)
		err(1, "%s", PINS_DIR);
	if ((dir = opendir(PINS_DIR)) == NULL)
		err(1, "%s", PINS_DIR);
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", PINS_DIR,
		    ent->d_name) < 0)
			errx(1, "%s", PINS_DIR);
		if (unlink(path) == -1)
			err(1, "%s", path);
	}
	closedir(dir);
}

/*
 * The two envelope keys of one direction, from the side of the
 * client. A client holds the static public key P only, so it adds
 * the tweak to the x-only key of P, and it keeps the parity bit
 * (PROTO-TWEAK-4).
 */
static void
client_keys(const uint8_t *ephemeral, const uint8_t *pub, uint32_t counter,
    const char *label, uint8_t *enc, uint8_t *mac)
{
	uint8_t	 xonly[CIPHER_XONLY_LEN];
	uint8_t	 qprime[CIPHER_PUBKEY_LEN];
	int	 parity = -1;

	ok("the tweaked public key of the client",
	    cipher_tweak_pubkey(spub, pub, counter, xonly, &parity) == 0);
	ok("the parity of the tweaked public key",
	    parity == 0 || parity == 1);
	qprime[0] = (uint8_t)(2 + parity);
	memcpy(qprime + 1, xonly, sizeof(xonly));
	ok("the envelope keys of the client",
	    cipher_ecdh_keys(ephemeral, qprime, label, enc, mac) == 0);
	explicit_bzero(xonly, sizeof(xonly));
	explicit_bzero(qprime, sizeof(qprime));
}

/*
 * One request envelope of the client: the cke, the replay counter,
 * and the sealed payload (PROTO-ENVELOPE). The seal draws its IV
 * through the seam, so each call moves the fixed source by
 * CIPHER_IV_LEN bytes.
 */
static size_t
seal_request(uint32_t counter, const uint8_t *payload, size_t plen,
    uint8_t *out, size_t size)
{
	uint8_t		 enc[CIPHER_KEY_LEN], mac[CIPHER_KEY_LEN];
	uint32_t	 le;
	size_t		 len = 0;

	client_keys(cke_priv, cke, counter, CIPHER_LABEL_REQUEST, enc, mac);
	memcpy(out, cke, CIPHER_PUBKEY_LEN);
	le = htole32(counter);
	memcpy(out + CIPHER_PUBKEY_LEN, &le, sizeof(le));
	ok("the seal of the request",
	    cipher_envelope_seal(enc, mac, payload, plen, out + ENV_ENC_OFF,
	    size - ENV_ENC_OFF, &len) == 0);
	draw(NULL, CIPHER_IV_LEN);
	explicit_bzero(enc, sizeof(enc));
	explicit_bzero(mac, sizeof(mac));
	return ENV_ENC_OFF + len;
}

/*
 * The request of one client operation: the pin_secret, the entropy
 * of the 129-byte form, and the signature of the message of
 * PROTO-PAYLOAD-3.
 */
static size_t
request(uint32_t counter, const uint8_t *pin_secret, int with_entropy,
    uint8_t *out, size_t size)
{
	uint8_t		 payload[PAYLOAD_LONG];
	uint8_t		 msg[ENV_ENC_OFF + 2 * CIPHER_KEY_LEN];
	uint8_t		 msghash[CIPHER_HASH_LEN];
	uint32_t	 le;
	size_t		 extra, plen;

	extra = with_entropy ? CIPHER_KEY_LEN : 0;
	memcpy(payload, pin_secret, CIPHER_KEY_LEN);
	if (with_entropy)
		memcpy(payload + CIPHER_KEY_LEN, entropy, CIPHER_KEY_LEN);

	memcpy(msg, cke, CIPHER_PUBKEY_LEN);
	le = htole32(counter);
	memcpy(msg + CIPHER_PUBKEY_LEN, &le, sizeof(le));
	memcpy(msg + ENV_ENC_OFF, payload, CIPHER_KEY_LEN + extra);
	ok("the signed message of the client",
	    cipher_sha256(msg, ENV_ENC_OFF + CIPHER_KEY_LEN + extra,
	    msghash) == 0);
	ok("the signature of the client", cipher_sign_recoverable(owner,
	    msghash, payload + CIPHER_KEY_LEN + extra) == 0);
	plen = CIPHER_KEY_LEN + extra + CIPHER_SIG_LEN;
	return seal_request(counter, payload, plen, out, size);
}

/* The key of one response envelope, as the client reads it. */
static void
answer(const uint8_t *ephemeral, const uint8_t *pub, uint32_t counter,
    const struct oracle_response *res, uint8_t *key)
{
	uint8_t	 enc[CIPHER_KEY_LEN], mac[CIPHER_KEY_LEN];
	uint8_t	 plain[ORACLE_RESPONSE_LEN];
	size_t	 len = 0;

	memset(key, 0, CIPHER_KEY_LEN);
	client_keys(ephemeral, pub, counter, CIPHER_LABEL_RESPONSE, enc, mac);
	ok("the open of the response", cipher_envelope_open(enc, mac,
	    res->env, res->len, plain, sizeof(plain), &len) == 0);
	ok("the response plaintext holds 32 bytes", len == CIPHER_KEY_LEN);
	if (len == CIPHER_KEY_LEN)
		memcpy(key, plain, CIPHER_KEY_LEN);
	explicit_bzero(enc, sizeof(enc));
	explicit_bzero(mac, sizeof(mac));
	explicit_bzero(plain, sizeof(plain));
}

/*
 * One request through the state machine. Every 200 answer holds the
 * same envelope length, and no other answer holds an envelope
 * (PROTO-RESPONSE-2, OPS-JUNK-2).
 */
static enum oracle_decision
handle(const char *name, enum oracle_op op, const uint8_t *env, size_t len,
    struct oracle_response *res, enum oracle_outcome *outcome)
{
	enum oracle_decision	 decision;

	decision = oracle_handle(priv, op, env, len, res, outcome);
	if (decision == ORACLE_RESPOND)
		ok2(name, "the response envelope holds 96 bytes",
		    res->len == ORACLE_RESPONSE_LEN);
	else
		ok2(name, "a failed request answers no envelope",
		    res->len == 0);
	return decision;
}

/* One request answers a 200 with the outcome class of the case. */
static void
responds(const char *name, enum oracle_op op, const uint8_t *env, size_t len,
    struct oracle_response *res, enum oracle_outcome want)
{
	enum oracle_outcome	 outcome = ORACLE_OUT_ERROR;
	enum oracle_decision	 decision;

	decision = handle(name, op, env, len, res, &outcome);
	ok2(name, "the request answers a response",
	    decision == ORACLE_RESPOND);
	ok2(name, "the outcome class of the request", outcome == want);
}

/* One request answers the failure decision of the case. */
static void
fails(const char *name, enum oracle_op op, const uint8_t *env, size_t len,
    enum oracle_decision want_decision, enum oracle_outcome want_outcome)
{
	struct oracle_response	 res;
	enum oracle_outcome	 outcome = ORACLE_OUT_OK_SET;
	enum oracle_decision	 decision;

	decision = handle(name, op, env, len, &res, &outcome);
	ok2(name, "the decision of the request", decision == want_decision);
	ok2(name, "the outcome class of the request", outcome ==
	    want_outcome);
}

/* The record write of the case drew the storage IV of the table. */
static void
storage_iv_is(const char *name, const uint8_t *want)
{
	uint8_t	 raw[PINDB_RECORD_LEN + 1];

	if (record_bytes(raw, sizeof(raw)) != PINDB_RECORD_LEN) {
		ok2(name, "the draw table: the record of the storage IV", 0);
		return;
	}
	ok2(name, "the draw table: the storage IV",
	    memcmp(raw + R_ENC, want, CIPHER_IV_LEN) == 0);
}

/* The response seal of the case drew the response IV of the table. */
static void
response_iv_is(const char *name, const struct oracle_response *res,
    const uint8_t *want)
{
	ok2(name, "the draw table: the response IV",
	    res->len == ORACLE_RESPONSE_LEN &&
	    memcmp(res->env, want, CIPHER_IV_LEN) == 0);
}

/* Two keys hold the same bytes. */
static void
key_is(const char *name, const uint8_t *got, const uint8_t *want)
{
	ok2(name, "the key of the answer",
	    memcmp(got, want, CIPHER_KEY_LEN) == 0);
}

/*
 * The junk answer of the case holds HMAC(key = random32, msg =
 * pin_secret), with the random32 of the draw table (OPS-JUNK-1). The
 * request of the case comes from the client of this program.
 */
static void
junk_is(const char *name, const struct oracle_response *res, uint32_t counter,
    const uint8_t *random32, const uint8_t *pin_secret)
{
	uint8_t	 want[CIPHER_KEY_LEN], got[CIPHER_KEY_LEN];

	ok2(name, "the junk key of the draw table",
	    cipher_hmac_sha256(random32, CIPHER_KEY_LEN, pin_secret,
	    CIPHER_KEY_LEN, want) == 0);
	answer(cke_priv, cke, counter, res, got);
	ok2(name, "the draw table: the junk key",
	    memcmp(got, want, sizeof(want)) == 0);
	explicit_bzero(want, sizeof(want));
	explicit_bzero(got, sizeof(got));
}

/*
 * A fresh record of the test client. The call empties the record
 * directory, and it runs the set_pin request of the transcript. want
 * takes the answer of that request, and each later correct PIN must
 * answer it again (OPS-GET-4). The record then holds no strike and
 * the counter zero.
 */
static void
provision(uint8_t *want)
{
	struct oracle_response	 res;
	uint8_t			 env[ENV_MAX];
	uint8_t			 random32[CIPHER_KEY_LEN];
	uint8_t			 new_key[CIPHER_KEY_LEN];
	size_t			 len;

	reset();
	len = hexbytes(V_SET_ENVELOPE, env, sizeof(env));
	draw(random32, sizeof(random32));	/* server_random32 */
	draw(NULL, CIPHER_IV_LEN);		/* the storage IV */
	draw(NULL, CIPHER_IV_LEN);		/* the response IV */
	responds("the record of a case", ORACLE_OP_SET, env, len, &res,
	    ORACLE_OUT_OK_SET);
	ok("the key share of the record",
	    cipher_hmac_sha256(random32, sizeof(random32), entropy,
	    sizeof(entropy), new_key) == 0);
	ok("the answer of the record", cipher_hmac_sha256(new_key,
	    sizeof(new_key), secret, sizeof(secret), want) == 0);
	explicit_bzero(random32, sizeof(random32));
	explicit_bzero(new_key, sizeof(new_key));
}

/*
 * The client of this program signs like libwally (PROTO-PAYLOAD-2,
 * PROTO-PAYLOAD-3). The test builds the signed message of the
 * transcript from the envelope and the payload of it. That message
 * equals the committed hash, and the signature of it equals the
 * committed signature, byte for byte.
 *
 * The signature draws no random byte, so this test moves the fixed
 * source by nothing.
 */
static void
t_signature(void)
{
	uint8_t	 env[ENV_MAX];
	uint8_t	 payload[PAYLOAD_LONG];
	uint8_t	 msg[ENV_ENC_OFF + 2 * CIPHER_KEY_LEN];
	uint8_t	 msghash[CIPHER_HASH_LEN], want[CIPHER_HASH_LEN];
	uint8_t	 sig[CIPHER_SIG_LEN];

	hexbytes(V_SET_ENVELOPE, env, sizeof(env));
	hexbytes(V_SET_PAYLOAD, payload, sizeof(payload));
	memcpy(msg, env, ENV_ENC_OFF);
	memcpy(msg + ENV_ENC_OFF, payload, 2 * CIPHER_KEY_LEN);
	ok("the signed message of the transcript",
	    cipher_sha256(msg, sizeof(msg), msghash) == 0);
	hexbytes(V_SET_MSGHASH, want, sizeof(want));
	ok("the signed message equals the vector",
	    memcmp(msghash, want, sizeof(want)) == 0);
	ok("the signature of the transcript message",
	    cipher_sign_recoverable(owner, msghash, sig) == 0);
	ok("the client signs like libwally",
	    memcmp(sig, payload + 2 * CIPHER_KEY_LEN, sizeof(sig)) == 0);
}

/*
 * The transcript of libwally: a set_pin request, then a get_pin
 * request with a higher replay counter. Each request carries the
 * signature of a client that the service never sees, so another
 * signed message would address another record (PROTO-PAYLOAD-3,
 * PROTO-PAYLOAD-4).
 *
 * The draws follow the first two rows of the draw table
 * (TEST-ACCEPT-2).
 */
static void
t_transcript(void)
{
	struct oracle_response	 res;
	struct pindb_record	 rec;
	uint8_t			 env[ENV_MAX];
	uint8_t			 tcke_priv[CIPHER_KEY_LEN];
	uint8_t			 tcke[CIPHER_PUBKEY_LEN];
	uint8_t			 random32[CIPHER_KEY_LEN];
	uint8_t			 storage_iv[CIPHER_IV_LEN];
	uint8_t			 response_iv[CIPHER_IV_LEN];
	uint8_t			 new_key[CIPHER_KEY_LEN];
	uint8_t			 want[CIPHER_KEY_LEN], got[CIPHER_KEY_LEN];
	uint8_t			 hash[CIPHER_HASH_LEN];
	size_t			 len;

	reset();
	len = hexbytes(V_SET_ENVELOPE, env, sizeof(env));
	ok("the set_pin envelope of the transcript holds 229 bytes",
	    len == ENV_LONG);

	/* The draws of a set_pin success, in order. */
	draw(random32, sizeof(random32));
	draw(storage_iv, sizeof(storage_iv));
	draw(response_iv, sizeof(response_iv));
	responds("the set_pin of the transcript", ORACLE_OP_SET, env, len,
	    &res, ORACLE_OUT_OK_SET);
	storage_iv_is("the set_pin of the transcript", storage_iv);
	response_iv_is("the set_pin of the transcript", &res, response_iv);

	/* The key share mixes the two entropies (OPS-SET-3). */
	ok("the key share of the set_pin",
	    cipher_hmac_sha256(random32, sizeof(random32), entropy,
	    sizeof(entropy), new_key) == 0);
	ok("the answer of the set_pin", cipher_hmac_sha256(new_key,
	    sizeof(new_key), secret, sizeof(secret), want) == 0);
	hexbytes(V_SET_CKE_PRIV, tcke_priv, sizeof(tcke_priv));
	hexbytes(V_SET_CKE, tcke, sizeof(tcke));
	answer(tcke_priv, tcke, V_SET_COUNTER, &res, got);
	key_is("the set_pin of the transcript", got, want);

	/* The record of OPS-SET-4, under the recovered client key. */
	ok("the set_pin writes the record", record_state(&rec) == 0);
	ok("the hash of the pin_secret",
	    cipher_sha256(secret, sizeof(secret), hash) == 0);
	ok("the record holds the hash of the pin_secret",
	    memcmp(rec.hash_pin_secret, hash, sizeof(hash)) == 0);
	ok("the record holds the new key share",
	    memcmp(rec.aes_key, new_key, sizeof(new_key)) == 0);
	ok("the record of a set_pin holds no strike", rec.count == 0);
	ok("the record of a set_pin holds the counter zero",
	    rec.replay_counter == 0);

	/* The draws of a get_pin with the correct PIN, in order. */
	len = hexbytes(V_GET_ENVELOPE, env, sizeof(env));
	ok("the get_pin envelope of the transcript holds 197 bytes",
	    len == ENV_SHORT);
	draw(storage_iv, sizeof(storage_iv));
	draw(response_iv, sizeof(response_iv));
	responds("the get_pin of the transcript", ORACLE_OP_GET, env, len,
	    &res, ORACLE_OUT_OK_GET);
	storage_iv_is("the get_pin of the transcript", storage_iv);
	response_iv_is("the get_pin of the transcript", &res, response_iv);

	/* The two operations answer the same key (OPS-GET-4). */
	hexbytes(V_GET_CKE_PRIV, tcke_priv, sizeof(tcke_priv));
	hexbytes(V_GET_CKE, tcke, sizeof(tcke));
	answer(tcke_priv, tcke, V_GET_COUNTER, &res, got);
	key_is("the get_pin of the transcript", got, want);
	ok("the get_pin keeps the record", record_state(&rec) == 0);
	ok("the record keeps the key share",
	    memcmp(rec.aes_key, new_key, sizeof(new_key)) == 0);
	ok("the record of a correct PIN holds no strike", rec.count == 0);
	ok("the record holds the counter of the client",
	    rec.replay_counter == V_GET_COUNTER);
}

/*
 * The service answers a request of the client of this program, and
 * that client reads the answer. The signature of the client recovers
 * the key of the transcript, so both clients address one record.
 */
static void
t_client(void)
{
	struct oracle_response	 res;
	uint8_t			 env[ENV_MAX];
	uint8_t			 want[CIPHER_KEY_LEN], got[CIPHER_KEY_LEN];
	size_t			 len;

	provision(want);
	len = request(1, secret, 1, env, sizeof(env));
	ok("the request of the client holds 229 bytes", len == ENV_LONG);
	draw(NULL, CIPHER_IV_LEN);	/* the storage IV */
	draw(NULL, CIPHER_IV_LEN);	/* the response IV */
	responds("the request of the client", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_OK_GET);
	answer(cke_priv, cke, 1, &res, got);
	key_is("the request of the client", got, want);
}

/*
 * get_pin takes both payload forms and reads no entropy, and set_pin
 * takes the 129-byte form only (OPS-GET-1, OPS-SET-1).
 */
static void
t_forms(void)
{
	struct oracle_response	 res;
	struct pindb_record	 before, after;
	uint8_t			 env[ENV_MAX];
	uint8_t			 want[CIPHER_KEY_LEN], got[CIPHER_KEY_LEN];
	size_t			 len;

	provision(want);

	/* The 129-byte form on get_pin, with the entropy that it ignores. */
	len = request(1, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_IV_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the 129-byte form on get_pin", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_OK_GET);
	answer(cke_priv, cke, 1, &res, got);
	key_is("the 129-byte form on get_pin", got, want);

	/* The 97-byte form on get_pin answers the same key. */
	len = request(2, secret, 0, env, sizeof(env));
	ok("the 97-byte form holds 197 bytes", len == ENV_SHORT);
	draw(NULL, CIPHER_IV_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the 97-byte form on get_pin", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_OK_GET);
	answer(cke_priv, cke, 2, &res, got);
	key_is("the 97-byte form on get_pin", got, want);

	/* The 97-byte form on set_pin is an internal failure. */
	ok("the record before the 97-byte set_pin", record_state(&before) == 0);
	len = request(3, secret, 0, env, sizeof(env));
	fails("the 97-byte form on set_pin", ORACLE_OP_SET, env, len,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);
	ok("the record after the 97-byte set_pin", record_state(&after) == 0);
	ok("the failed set_pin keeps the record",
	    memcmp(&before, &after, sizeof(before)) == 0);
}

/*
 * A set_pin with a stale counter and a set_pin with an equal counter
 * are internal failures, and neither one changes the record
 * (OPS-SET-2, OPS-SET-7).
 */
static void
t_set_replay(void)
{
	struct oracle_response	 res;
	struct pindb_record	 before, after;
	uint8_t			 env[ENV_MAX];
	uint8_t			 want[CIPHER_KEY_LEN];
	size_t			 len;

	provision(want);

	/* A get_pin lifts the stored counter to 4. */
	len = request(4, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_IV_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the get_pin before a stale set_pin", ORACLE_OP_GET, env, len,
	    &res, ORACLE_OUT_OK_GET);
	ok("the record before a stale set_pin", record_state(&before) == 0);
	ok("the stored counter of the record", before.replay_counter == 4);

	/* A stale counter, and then an equal counter. */
	len = request(3, secret, 1, env, sizeof(env));
	fails("a stale counter on set_pin", ORACLE_OP_SET, env, len,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);
	len = request(4, secret, 1, env, sizeof(env));
	fails("an equal counter on set_pin", ORACLE_OP_SET, env, len,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);
	ok("the record after a stale set_pin", record_state(&after) == 0);
	ok("a failed set_pin keeps the record",
	    memcmp(&before, &after, sizeof(before)) == 0);

	/* A higher counter passes, and it writes a new key share. */
	len = request(5, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_KEY_LEN);	/* server_random32 */
	draw(NULL, CIPHER_IV_LEN);	/* the storage IV */
	draw(NULL, CIPHER_IV_LEN);	/* the response IV */
	responds("a higher counter on set_pin", ORACLE_OP_SET, env, len, &res,
	    ORACLE_OUT_OK_SET);
	ok("the record of the new set_pin", record_state(&after) == 0);
	ok("the new set_pin writes a new key share",
	    memcmp(before.aes_key, after.aes_key, sizeof(after.aes_key)) != 0);
	ok("the new set_pin clears the stored counter",
	    after.replay_counter == 0);
}

/*
 * A wrong PIN twice, then the correct PIN: two junk answers, then
 * the real key, and then a record without a strike (OPS-GET-5).
 *
 * The draws follow the third row of the draw table: the storage IV
 * of the strike, then the junk key, then the response IV.
 */
static void
t_wrong_pin(void)
{
	struct oracle_response	 first, second, third;
	struct pindb_record	 rec;
	uint8_t			 env[ENV_MAX];
	uint8_t			 storage_iv[CIPHER_IV_LEN];
	uint8_t			 random32[CIPHER_KEY_LEN];
	uint8_t			 response_iv[CIPHER_IV_LEN];
	uint8_t			 want[CIPHER_KEY_LEN], got[CIPHER_KEY_LEN];
	size_t			 len;

	provision(want);

	len = request(1, wrong, 1, env, sizeof(env));
	draw(storage_iv, sizeof(storage_iv));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("the first wrong PIN", ORACLE_OP_GET, env, len, &first,
	    ORACLE_OUT_JUNK);
	storage_iv_is("the first wrong PIN", storage_iv);
	response_iv_is("the first wrong PIN", &first, response_iv);
	junk_is("the first wrong PIN", &first, 1, random32, wrong);
	ok("the first wrong PIN writes one strike", record_state(&rec) == 0);
	ok("the count of the first wrong PIN", rec.count == 1);
	ok("the counter of the first wrong PIN", rec.replay_counter == 1);

	len = request(2, wrong, 1, env, sizeof(env));
	draw(storage_iv, sizeof(storage_iv));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("the second wrong PIN", ORACLE_OP_GET, env, len, &second,
	    ORACLE_OUT_JUNK);
	storage_iv_is("the second wrong PIN", storage_iv);
	response_iv_is("the second wrong PIN", &second, response_iv);
	junk_is("the second wrong PIN", &second, 2, random32, wrong);
	ok("the second wrong PIN writes one strike", record_state(&rec) == 0);
	ok("the count of the second wrong PIN", rec.count == 2);

	/* Two junk answers hold one length, and they differ. */
	ok("two junk answers hold the same length", first.len == second.len);
	ok("two junk answers differ",
	    memcmp(first.env, second.env, first.len) != 0);

	/* The correct PIN answers the real key, and it clears the count. */
	len = request(3, secret, 1, env, sizeof(env));
	draw(storage_iv, sizeof(storage_iv));
	draw(response_iv, sizeof(response_iv));
	responds("the correct PIN after two strikes", ORACLE_OP_GET, env, len,
	    &third, ORACLE_OUT_OK_GET);
	storage_iv_is("the correct PIN after two strikes", storage_iv);
	response_iv_is("the correct PIN after two strikes", &third,
	    response_iv);
	answer(cke_priv, cke, 3, &third, got);
	key_is("the correct PIN after two strikes", got, want);
	ok("the correct PIN keeps the record", record_state(&rec) == 0);
	ok("the correct PIN clears the count", rec.count == 0);
	ok("the correct PIN stores the counter", rec.replay_counter == 3);
}

/*
 * A wrong PIN three times: junk, junk, then the wipe, and then junk
 * for every later request (OPS-GET-6). The third strike draws its
 * storage IV before the junk key, like a strike that stores.
 */
static void
t_third_strike(void)
{
	struct oracle_response	 res;
	struct pindb_record	 rec;
	uint8_t			 env[ENV_MAX];
	uint8_t			 raw[PINDB_RECORD_LEN + 1];
	uint8_t			 random32[CIPHER_KEY_LEN];
	uint8_t			 response_iv[CIPHER_IV_LEN];
	uint8_t			 want[CIPHER_KEY_LEN];
	uint32_t		 counter;
	size_t			 len;

	provision(want);

	for (counter = 1; counter <= 2; counter++) {
		len = request(counter, wrong, 1, env, sizeof(env));
		draw(NULL, CIPHER_IV_LEN);
		draw(NULL, CIPHER_KEY_LEN);
		draw(NULL, CIPHER_IV_LEN);
		responds("a strike before the wipe", ORACLE_OP_GET, env, len,
		    &res, ORACLE_OUT_JUNK);
	}
	ok("the record before the wipe", record_state(&rec) == 0);
	ok("the count before the wipe", rec.count == 2);

	/* The third strike destroys the key share (OPS-WIPE). */
	len = request(3, wrong, 1, env, sizeof(env));
	draw(NULL, CIPHER_IV_LEN);	/* the storage IV of the wipe */
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("the third strike", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	response_iv_is("the third strike", &res, response_iv);
	junk_is("the third strike", &res, 3, random32, wrong);
	ok("the third strike removes the record",
	    record_bytes(raw, sizeof(raw)) == 0);

	/* Every later request answers junk, also with the correct PIN. */
	len = request(4, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the correct PIN after the wipe", ORACLE_OP_GET, env, len,
	    &res, ORACLE_OUT_JUNK);
	ok("the wiped record stays absent",
	    record_bytes(raw, sizeof(raw)) == 0);

	len = request(5, wrong, 1, env, sizeof(env));
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("a wrong PIN after the wipe", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
}

/*
 * A stale counter and an equal counter take the junk path, and
 * neither one moves the count (OPS-GET-2). The draws follow the
 * fourth row of the draw table: the junk key, then the response IV,
 * and no storage IV.
 */
static void
t_get_replay(void)
{
	struct oracle_response	 res;
	struct pindb_record	 before, after;
	uint8_t			 env[ENV_MAX];
	uint8_t			 random32[CIPHER_KEY_LEN];
	uint8_t			 response_iv[CIPHER_IV_LEN];
	uint8_t			 want[CIPHER_KEY_LEN];
	size_t			 len;

	provision(want);

	/* One correct PIN lifts the stored counter to 2. */
	len = request(2, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_IV_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the get_pin before a replay", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_OK_GET);
	ok("the record before a replay", record_state(&before) == 0);
	ok("the counter before a replay", before.replay_counter == 2);

	/* An equal counter. */
	len = request(2, secret, 1, env, sizeof(env));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("an equal counter", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	response_iv_is("an equal counter", &res, response_iv);
	junk_is("an equal counter", &res, 2, random32, secret);

	/* A stale counter. */
	len = request(1, secret, 1, env, sizeof(env));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("a stale counter", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	response_iv_is("a stale counter", &res, response_iv);
	junk_is("a stale counter", &res, 1, random32, secret);

	ok("the record after a replay", record_state(&after) == 0);
	ok("a replay keeps the record",
	    memcmp(&before, &after, sizeof(before)) == 0);
}

/*
 * A missing record and a corrupt record take the junk path
 * (OPS-GET-2). The draws follow the fourth row of the draw table,
 * and no case writes a record.
 */
static void
t_missing_and_corrupt(void)
{
	struct oracle_response	 res;
	uint8_t			 env[ENV_MAX];
	uint8_t			 raw[PINDB_RECORD_LEN + 1];
	uint8_t			 random32[CIPHER_KEY_LEN];
	uint8_t			 response_iv[CIPHER_IV_LEN];
	uint8_t			 want[CIPHER_KEY_LEN];
	size_t			 len;

	/* A missing record. */
	reset();
	len = request(1, secret, 1, env, sizeof(env));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("a missing record", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	response_iv_is("a missing record", &res, response_iv);
	junk_is("a missing record", &res, 1, random32, secret);
	ok("a missing record stays absent",
	    record_bytes(raw, sizeof(raw)) == 0);

	/* A record of the wrong length. */
	provision(want);
	record_put((const uint8_t *)"a short record", 14);
	len = request(2, secret, 1, env, sizeof(env));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("a record of the wrong length", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	response_iv_is("a record of the wrong length", &res, response_iv);
	junk_is("a record of the wrong length", &res, 2, random32, secret);
	ok("a corrupt record keeps its length",
	    record_bytes(raw, sizeof(raw)) == 14);

	/* A record with a wrong authenticator. */
	provision(want);
	ok("the record of the authenticator case",
	    record_bytes(raw, sizeof(raw)) == PINDB_RECORD_LEN);
	raw[R_HMAC] ^= 0x80;
	record_put(raw, PINDB_RECORD_LEN);
	len = request(3, secret, 1, env, sizeof(env));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("a record with a wrong authenticator", ORACLE_OP_GET, env,
	    len, &res, ORACLE_OUT_JUNK);
	response_iv_is("a record with a wrong authenticator", &res,
	    response_iv);
	junk_is("a record with a wrong authenticator", &res, 3, random32,
	    secret);

	/*
	 * A record of another version. The authenticator covers the
	 * version byte, so the case writes a new authenticator over
	 * the changed record (STORE-RECORD-4).
	 */
	provision(want);
	ok("the record of the version case",
	    record_bytes(raw, sizeof(raw)) == PINDB_RECORD_LEN);
	raw[0] = PINDB_VERSION + 1;
	retag(raw);
	record_put(raw, PINDB_RECORD_LEN);
	len = request(4, secret, 1, env, sizeof(env));
	draw(random32, sizeof(random32));
	draw(response_iv, sizeof(response_iv));
	responds("a record of another version", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	response_iv_is("a record of another version", &res, response_iv);
	junk_is("a record of another version", &res, 4, random32, secret);
}

/*
 * Every junk answer holds one envelope length, and two junk answers
 * differ (OPS-JUNK-1, OPS-JUNK-2). The two requests of the pair hold
 * the same bytes, so the fresh draw of the junk key is the one
 * difference of the two answers.
 */
static void
t_junk(void)
{
	struct oracle_response	 res, first, second;
	uint8_t			 env[ENV_MAX];
	uint8_t			 raw[PINDB_RECORD_LEN + 1];
	uint8_t			 want[CIPHER_KEY_LEN];
	uint8_t			 one[CIPHER_KEY_LEN], two[CIPHER_KEY_LEN];
	size_t			 len, class_len[4];
	int			 i;

	provision(want);

	/* A wrong PIN, and then a replay of the same record. */
	len = request(1, wrong, 1, env, sizeof(env));
	draw(NULL, CIPHER_IV_LEN);
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the junk of a wrong PIN", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	class_len[0] = res.len;

	len = request(1, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the junk of a replay", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	class_len[1] = res.len;

	/* A corrupt record. */
	provision(want);
	ok("the record of the junk case",
	    record_bytes(raw, sizeof(raw)) == PINDB_RECORD_LEN);
	raw[R_ENC] ^= 0x01;
	record_put(raw, PINDB_RECORD_LEN);
	len = request(2, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the junk of a corrupt record", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	class_len[2] = res.len;

	/* A missing record. */
	reset();
	len = request(3, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the junk of a missing record", ORACLE_OP_GET, env, len, &res,
	    ORACLE_OUT_JUNK);
	class_len[3] = res.len;

	for (i = 0; i < 4; i++)
		ok("every junk answer holds 96 bytes",
		    class_len[i] == ORACLE_RESPONSE_LEN);

	/*
	 * One request, twice. The bytes of the two requests are
	 * equal, so a junk key that is not fresh would answer twice
	 * with one envelope.
	 */
	len = request(4, secret, 1, env, sizeof(env));
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the first junk of the pair", ORACLE_OP_GET, env, len, &first,
	    ORACLE_OUT_JUNK);
	draw(NULL, CIPHER_KEY_LEN);
	draw(NULL, CIPHER_IV_LEN);
	responds("the second junk of the pair", ORACLE_OP_GET, env, len,
	    &second, ORACLE_OUT_JUNK);
	ok("the two junk answers hold the same length",
	    first.len == second.len);
	answer(cke_priv, cke, 4, &first, one);
	answer(cke_priv, cke, 4, &second, two);
	ok("the junk key of each answer is fresh",
	    memcmp(one, two, sizeof(one)) != 0);
}

/*
 * A short envelope and a ciphertext beside the block are client
 * errors (PROTO-ENVELOPE-1, PROTO-ENVELOPE-2). Each one answers
 * before the tweak, so neither one reaches the record.
 */
static void
t_envelope(void)
{
	uint8_t	 env[ENV_MAX];
	uint8_t	 raw[PINDB_RECORD_LEN + 1];
	uint8_t	 want[CIPHER_KEY_LEN];
	size_t	 len;

	provision(want);
	len = request(1, secret, 1, env, sizeof(env));
	ok("the envelope of the case", len == ENV_LONG);

	fails("an envelope of 100 bytes", ORACLE_OP_GET, env, 100,
	    ORACLE_REJECT, ORACLE_OUT_REJECT);
	fails("a ciphertext of 17 bytes", ORACLE_OP_GET, env, 102,
	    ORACLE_REJECT, ORACLE_OUT_REJECT);

	/*
	 * An envelope of 85 bytes holds no ciphertext block. The
	 * block test alone accepts that length, so this case answers
	 * the length rule of PROTO-ENVELOPE-1 alone.
	 */
	fails("an envelope without a ciphertext", ORACLE_OP_GET, env, 85,
	    ORACLE_REJECT, ORACLE_OUT_REJECT);

	/*
	 * An envelope of 101 bytes passes the two tests of the
	 * envelope, and it fails at the tag of the truncated
	 * ciphertext. The two rejects above therefore answer the
	 * length and the block, and not a short buffer.
	 */
	fails("an envelope of 101 bytes", ORACLE_OP_GET, env, 101,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);
	ok("a rejected request keeps the record",
	    record_bytes(raw, sizeof(raw)) == PINDB_RECORD_LEN);
}

/*
 * An I/O failure of the load is an internal failure, and it is the
 * one get_pin failure after the payload extraction that answers no
 * junk key (D-10, OPS-GET-7). The service cannot count the attempt,
 * so it must not answer it.
 *
 * A directory at the record path gives that failure: the open(2)
 * passes, and the read(2) of a directory answers EISDIR on OpenBSD.
 */
static void
t_io(void)
{
	uint8_t	 env[ENV_MAX];
	char	 path[PATH_MAX];
	size_t	 len;

	reset();
	record_file(path, sizeof(path));
	if (mkdir(path, 0700) == -1)
		err(1, "%s", path);
	len = request(1, secret, 1, env, sizeof(env));
	fails("an I/O failure on get_pin", ORACLE_OP_GET, env, len,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);
	len = request(2, secret, 1, env, sizeof(env));
	fails("an I/O failure on set_pin", ORACLE_OP_SET, env, len,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);
	if (rmdir(path) == -1)
		err(1, "%s", path);
}

/*
 * A failure up to and through the payload extraction is an internal
 * failure, and never junk (PROTO-HTTP-8, PROTO-PAYLOAD-5). The junk
 * path needs the pin_secret and the recovered key, so it cannot
 * answer these failures.
 */
static void
t_extraction(void)
{
	uint8_t	 env[ENV_MAX];
	uint8_t	 payload[PAYLOAD_LONG];
	uint8_t	 want[CIPHER_KEY_LEN];
	size_t	 len;

	provision(want);

	/* A changed tag fails the MAC test of the envelope. */
	len = request(1, secret, 1, env, sizeof(env));
	env[len - 1] ^= 0x01;
	fails("a changed tag", ORACLE_OP_GET, env, len, ORACLE_FAILURE,
	    ORACLE_OUT_ERROR);

	/* A payload of another length (PROTO-PAYLOAD-1). */
	memset(payload, 0x5a, sizeof(payload));
	len = seal_request(2, payload, PAYLOAD_SHORT + 1, env, sizeof(env));
	fails("a payload of another length", ORACLE_OP_GET, env, len,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);

	/* A signature that no key recovers (PROTO-PAYLOAD-4). */
	memcpy(payload, secret, CIPHER_KEY_LEN);
	memcpy(payload + CIPHER_KEY_LEN, entropy, CIPHER_KEY_LEN);
	memset(payload + 2 * CIPHER_KEY_LEN, 0xff, CIPHER_SIG_LEN);
	len = seal_request(3, payload, PAYLOAD_LONG, env, sizeof(env));
	fails("a signature without a key", ORACLE_OP_GET, env, len,
	    ORACLE_FAILURE, ORACLE_OUT_ERROR);
}

/*
 * The fixed random source of the run. The seam of the regress build
 * reads it in draw order, and each test names the draws that it
 * expects. The source holds the hash chain of SOURCE_SEED, so two
 * runs read the same bytes through the seam (SEC-RANDOM-2). A draw
 * outside the seam, such as the one of mkstemp(3), stays random.
 */
static void
random_source(char *path, size_t size)
{
	uint8_t	 block[CIPHER_HASH_LEN];
	size_t	 i;
	int	 n, fd;

	n = snprintf(path, size, "ops.random.XXXXXXXXXX");
	if (n < 0 || (size_t)n >= size)
		errx(1, "the source path is too long");
	if (cipher_sha256((const uint8_t *)SOURCE_SEED,
	    sizeof(SOURCE_SEED) - 1, block) != 0)
		errx(1, "the seed of the source");
	for (i = 0; i + sizeof(block) <= sizeof(source); i += sizeof(block)) {
		memcpy(source + i, block, sizeof(block));
		if (cipher_sha256(block, sizeof(block), block) != 0)
			errx(1, "the chain of the source");
	}
	if ((fd = mkstemp(path)) == -1)
		err(1, "mkstemp");
	if (write(fd, source, sizeof(source)) != (ssize_t)sizeof(source))
		err(1, "%s", path);
	if (close(fd) == -1)
		err(1, "%s", path);
	if (setenv("FUGUORACLE_RANDOM", path, 1) == -1)
		err(1, "setenv");
}

int
main(void)
{
	char	 path[PATH_MAX];

	random_source(path, sizeof(path));
	hexbytes(V_STATIC_PRIV, priv, sizeof(priv));
	hexbytes(V_STATIC_PUB, spub, sizeof(spub));
	hexbytes(V_CLIENT_PRIV, owner, sizeof(owner));
	hexbytes(V_CLIENT_PUB, owner_pub, sizeof(owner_pub));
	hexbytes(V_PIN_SECRET, secret, sizeof(secret));
	hexbytes(V_ENTROPY, entropy, sizeof(entropy));
	hexbytes(V_TWEAK_CKE_PRIV, cke_priv, sizeof(cke_priv));
	hexbytes(V_TWEAK_CKE, cke, sizeof(cke));

	/* A wrong PIN of the client, which no vector needs. */
	if (cipher_sha256((const uint8_t *)"a wrong pin_secret", 18,
	    wrong) != 0)
		errx(1, "the wrong pin_secret");

	t_signature();
	t_transcript();
	t_client();
	t_forms();
	t_set_replay();
	t_wrong_pin();
	t_third_strike();
	t_get_replay();
	t_missing_and_corrupt();
	t_junk();
	t_envelope();
	t_extraction();
	t_io();

	if (unlink(path) == -1)
		err(1, "%s", path);
	if (failures != 0)
		errx(1, "%d operation test(s) failed", failures);
	return 0;
}
