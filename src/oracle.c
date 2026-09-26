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
 * The oracle operations. This file holds the request envelope, the
 * two payload forms, the set_pin rules, the get_pin rules and the
 * junk path. It calls the shim of cipher.h and the store of pindb.h,
 * and it includes no library header (ARCH-LAYOUT-1, ARCH-LAYOUT-2).
 *
 * The order of the checks is the order of the protocol. Every
 * failure up to and through the payload extraction answers an error
 * decision (PROTO-HTTP-8). After the extraction, a get_pin failure
 * takes the junk path, and only an I/O failure and a persist failure
 * answer an error (D-10, OPS-GET-7). Every set_pin failure answers
 * an error (OPS-SET-7).
 *
 * The draws follow the order of the draw table (TEST-ACCEPT-2): the
 * server entropy of a set_pin, then the storage IV of a record
 * write, then the junk key, then the response IV.
 *
 * Each secret lives in a stack buffer, and each exit path clears it
 * under one goto out (SEC-MEMORY-1, SEC-MEMORY-2). The comparison of
 * the PIN hash runs in constant time (SEC-MEMORY-3).
 */

#include <sys/types.h>

#include <endian.h>
#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "oracle.h"
#include "pindb.h"

/* The fields in front of the encrypted part (PROTO-ENVELOPE). */
#define ENV_COUNTER_OFF	CIPHER_PUBKEY_LEN
#define ENV_COUNTER_LEN	4
#define ENV_ENC_OFF	(ENV_COUNTER_OFF + ENV_COUNTER_LEN)

/* The two payload forms of PROTO-PAYLOAD. */
#define PAYLOAD_SHORT	(CIPHER_KEY_LEN + CIPHER_SIG_LEN)
#define PAYLOAD_LONG	(CIPHER_KEY_LEN + CIPHER_KEY_LEN + CIPHER_SIG_LEN)

/*
 * The room of the payload buffer. The EVP layer writes at most the
 * length of the ciphertext, so the buffer takes one block above the
 * longest form. A longer ciphertext fails in the shim, and a
 * plaintext of another length fails the test of PROTO-PAYLOAD-1.
 * Both answers are an internal failure.
 */
#define PAYLOAD_MAX	(PAYLOAD_LONG + CIPHER_BLOCK_LEN)

/* The signed message of PROTO-PAYLOAD-3, at its longest. */
#define SIGNED_MAX	(ENV_ENC_OFF + CIPHER_KEY_LEN + CIPHER_KEY_LEN)

/* The count at which a wrong PIN destroys the key share (OPS-GET-6). */
#define STRIKE_LAST	(PINDB_STRIKES - 1)

/* The fields of one request, after the payload extraction. */
struct request {
	const uint8_t	*priv;		/* the static key d */
	const uint8_t	*pin_secret;	/* CIPHER_KEY_LEN bytes */
	const uint8_t	*entropy;	/* CIPHER_KEY_LEN bytes, or NULL */
	uint8_t		 pin_pubkey[CIPHER_PUBKEY_LEN];
	uint32_t	 counter;
};

static int			 junk_key(const uint8_t *, uint8_t *);
static enum oracle_decision	 set_pin(const struct request *, uint8_t *,
				    enum oracle_outcome *);
static enum oracle_decision	 get_pin(const struct request *, uint8_t *,
				    enum oracle_outcome *);

/*
 * The junk answer of one request: HMAC(key = random32, msg =
 * pin_secret), with a fresh draw (OPS-JUNK-1). out takes
 * CIPHER_KEY_LEN bytes, and a failure clears it.
 */
static int
junk_key(const uint8_t *pin_secret, uint8_t *out)
{
	uint8_t	 random32[CIPHER_KEY_LEN];
	int	 rc;

	cipher_random(random32, sizeof(random32));
	rc = cipher_hmac_sha256(random32, sizeof(random32), pin_secret,
	    CIPHER_KEY_LEN, out);
	explicit_bzero(random32, sizeof(random32));
	return rc;
}

/*
 * The set_pin operation (OPS-SET). key takes the response key of
 * CIPHER_KEY_LEN bytes. Every failure answers ORACLE_FAILURE,
 * because a client cannot detect a junk key on this flow
 * (OPS-SET-7).
 */
static enum oracle_decision
set_pin(const struct request *req, uint8_t *key, enum oracle_outcome *outcome)
{
	struct pindb_record	 rec;
	uint8_t			 server_random32[CIPHER_KEY_LEN];
	uint8_t			 new_key[CIPHER_KEY_LEN];
	enum pindb_result	 res;
	enum oracle_decision	 decision = ORACLE_FAILURE;

	*outcome = ORACLE_OUT_ERROR;
	memset(&rec, 0, sizeof(rec));
	memset(server_random32, 0, sizeof(server_random32));
	memset(new_key, 0, sizeof(new_key));

	/*
	 * A missing record is normal, and every other failure of the
	 * load is an internal failure. The client counter must pass
	 * the stored counter of an existing record (OPS-SET-2).
	 */
	res = pindb_load(req->priv, req->pin_pubkey, &rec);
	if (res != PINDB_OK && res != PINDB_MISSING)
		goto out;
	if (res == PINDB_OK && req->counter <= rec.replay_counter)
		goto out;

	/* The key share mixes the two entropies (OPS-SET-3). */
	cipher_random(server_random32, sizeof(server_random32));
	if (cipher_hmac_sha256(server_random32, sizeof(server_random32),
	    req->entropy, CIPHER_KEY_LEN, new_key) != 0)
		goto out;

	/*
	 * The record holds the hash of the pin_secret and no other
	 * value of it (OPS-SET-4, OPS-SET-6). The stored counter
	 * starts at zero, and the risk table records that property.
	 */
	memset(&rec, 0, sizeof(rec));
	if (cipher_sha256(req->pin_secret, CIPHER_KEY_LEN,
	    rec.hash_pin_secret) != 0)
		goto out;
	memcpy(rec.aes_key, new_key, sizeof(rec.aes_key));
	rec.count = 0;
	rec.replay_counter = 0;
	if (pindb_store(req->priv, req->pin_pubkey, &rec) != PINDB_OK)
		goto out;

	/* The answer of OPS-SET-5, after the record persists. */
	if (cipher_hmac_sha256(new_key, sizeof(new_key), req->pin_secret,
	    CIPHER_KEY_LEN, key) != 0)
		goto out;
	*outcome = ORACLE_OUT_OK_SET;
	decision = ORACLE_RESPOND;
out:
	explicit_bzero(&rec, sizeof(rec));
	explicit_bzero(server_random32, sizeof(server_random32));
	explicit_bzero(new_key, sizeof(new_key));
	if (decision != ORACLE_RESPOND)
		explicit_bzero(key, CIPHER_KEY_LEN);
	return decision;
}

/*
 * The get_pin operation (OPS-GET). key takes the response key of
 * CIPHER_KEY_LEN bytes, real or junk. An I/O failure of the load and
 * every persist failure answer ORACLE_FAILURE, and every other
 * failure takes the junk path (D-10, OPS-GET-7).
 */
static enum oracle_decision
get_pin(const struct request *req, uint8_t *key, enum oracle_outcome *outcome)
{
	struct pindb_record	 rec;
	uint8_t			 hash[CIPHER_HASH_LEN];
	uint8_t			 aes_key[CIPHER_KEY_LEN];
	enum pindb_result	 res;
	enum oracle_decision	 decision = ORACLE_FAILURE;

	*outcome = ORACLE_OUT_ERROR;
	memset(&rec, 0, sizeof(rec));
	memset(hash, 0, sizeof(hash));
	memset(aes_key, 0, sizeof(aes_key));

	/*
	 * An I/O failure of the load answers an error, because the
	 * service cannot count the attempt. A missing record, a
	 * corrupt record and a failure of the shim take the junk
	 * path (OPS-GET-2, OPS-GET-7).
	 */
	res = pindb_load(req->priv, req->pin_pubkey, &rec);
	if (res == PINDB_IO)
		goto out;
	if (res != PINDB_OK)
		goto junk;

	/* A replay violation takes the junk path, and it moves no count. */
	if (req->counter <= rec.replay_counter)
		goto junk;
	if (cipher_sha256(req->pin_secret, CIPHER_KEY_LEN, hash) != 0)
		goto junk;

	if (timingsafe_bcmp(hash, rec.hash_pin_secret, sizeof(hash)) == 0) {
		/*
		 * The correct PIN clears the count and stores the
		 * client counter. The record persists before the
		 * answer (OPS-GET-4, OPS-GET-7).
		 */
		memcpy(aes_key, rec.aes_key, sizeof(aes_key));
		rec.count = 0;
		rec.replay_counter = req->counter;
		if (pindb_store(req->priv, req->pin_pubkey, &rec) != PINDB_OK)
			goto out;
		if (cipher_hmac_sha256(aes_key, sizeof(aes_key),
		    req->pin_secret, CIPHER_KEY_LEN, key) != 0)
			goto junk;
		*outcome = ORACLE_OUT_OK_GET;
		decision = ORACLE_RESPOND;
		goto out;
	}

	/*
	 * A wrong PIN burns one attempt. The third strike destroys
	 * the key share instead (OPS-GET-5, OPS-GET-6). The record
	 * changes before the answer, and each write draws its
	 * storage IV before the junk key (TEST-ACCEPT-2).
	 */
	if (rec.count < STRIKE_LAST) {
		rec.count++;
		rec.replay_counter = req->counter;
		if (pindb_store(req->priv, req->pin_pubkey, &rec) != PINDB_OK)
			goto out;
	} else {
		if (pindb_wipe(req->priv, req->pin_pubkey, &rec) != PINDB_OK)
			goto out;
	}

junk:
	/*
	 * The junk answer needs no record and no key share. A
	 * failure of it answers an error, because the service then
	 * holds no payload for a response. That failure is the same
	 * on the real path, so it tells a caller nothing (D-10).
	 */
	if (junk_key(req->pin_secret, key) != 0)
		goto out;
	*outcome = ORACLE_OUT_JUNK;
	decision = ORACLE_RESPOND;
out:
	explicit_bzero(&rec, sizeof(rec));
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(aes_key, sizeof(aes_key));
	if (decision != ORACLE_RESPOND)
		explicit_bzero(key, CIPHER_KEY_LEN);
	return decision;
}

enum oracle_decision
oracle_handle(const uint8_t *priv, enum oracle_op op, const uint8_t *env,
    size_t env_len, struct oracle_response *res, enum oracle_outcome *outcome)
{
	struct request		 req;
	uint8_t			 dprime[CIPHER_KEY_LEN];
	uint8_t			 enc_key[CIPHER_KEY_LEN];
	uint8_t			 mac_key[CIPHER_KEY_LEN];
	uint8_t			 payload[PAYLOAD_MAX];
	uint8_t			 signed_msg[SIGNED_MAX];
	uint8_t			 msghash[CIPHER_HASH_LEN];
	uint8_t			 key[CIPHER_KEY_LEN];
	uint32_t		 le;
	size_t			 len = 0, entropy_len = 0;
	int			 lock = -1;
	enum oracle_decision	 decision = ORACLE_FAILURE;

	memset(&req, 0, sizeof(req));
	memset(dprime, 0, sizeof(dprime));
	memset(enc_key, 0, sizeof(enc_key));
	memset(mac_key, 0, sizeof(mac_key));
	memset(payload, 0, sizeof(payload));
	memset(signed_msg, 0, sizeof(signed_msg));
	memset(msghash, 0, sizeof(msghash));
	memset(key, 0, sizeof(key));
	memset(res, 0, sizeof(*res));
	*outcome = ORACLE_OUT_ERROR;

	/*
	 * The envelope length and the block alignment answer first
	 * (PROTO-ENVELOPE-1, PROTO-ENVELOPE-2). A violation of
	 * either one is a client error. The shortest envelope holds
	 * one block of ciphertext, so the block test counts from
	 * that length, and it needs no other guard.
	 */
	if (env_len < ORACLE_ENVELOPE_MIN ||
	    (env_len - ORACLE_ENVELOPE_MIN) % CIPHER_BLOCK_LEN != 0) {
		*outcome = ORACLE_OUT_REJECT;
		decision = ORACLE_REJECT;
		goto out;
	}

	/* The request key d' and the two request keys of the envelope. */
	memcpy(&le, env + ENV_COUNTER_OFF, sizeof(le));
	req.priv = priv;
	req.counter = letoh32(le);
	if (cipher_tweak_key(priv, env, req.counter, dprime) != 0)
		goto out;
	if (cipher_ecdh_keys(dprime, env, CIPHER_LABEL_REQUEST, enc_key,
	    mac_key) != 0)
		goto out;
	if (cipher_envelope_open(enc_key, mac_key, env + ENV_ENC_OFF,
	    env_len - ENV_ENC_OFF, payload, sizeof(payload), &len) != 0)
		goto out;

	/*
	 * The payload holds one of the two forms, and set_pin needs
	 * the entropy of the longer one (PROTO-PAYLOAD-1,
	 * OPS-SET-1). get_pin takes both forms, and it reads no
	 * entropy (OPS-GET-1).
	 */
	if (len == PAYLOAD_LONG) {
		req.entropy = payload + CIPHER_KEY_LEN;
		entropy_len = CIPHER_KEY_LEN;
	} else if (len == PAYLOAD_SHORT && op == ORACLE_OP_GET) {
		req.entropy = NULL;
		entropy_len = 0;
	} else
		goto out;
	req.pin_secret = payload;

	/*
	 * The signed message covers the cke, the replay counter, the
	 * pin_secret and the entropy, in the bytes of the wire
	 * (PROTO-PAYLOAD-3). The recovered key addresses the record,
	 * and a failure of the recovery is an internal failure
	 * (PROTO-PAYLOAD-4, PROTO-PAYLOAD-5).
	 */
	memcpy(signed_msg, env, ENV_ENC_OFF);
	memcpy(signed_msg + ENV_ENC_OFF, payload, CIPHER_KEY_LEN + entropy_len);
	if (cipher_sha256(signed_msg, ENV_ENC_OFF + CIPHER_KEY_LEN +
	    entropy_len, msghash) != 0)
		goto out;
	if (cipher_recover_pubkey(msghash, payload + CIPHER_KEY_LEN +
	    entropy_len, req.pin_pubkey) != 0)
		goto out;

	/*
	 * One global lock covers the load, the decision and the
	 * store of the request (STORE-ATOMIC-1). A failure of it is
	 * an I/O failure, and the service must not answer an attempt
	 * that it cannot count (OPS-GET-7).
	 */
	if ((lock = pindb_lock()) == -1)
		goto out;
	if (op == ORACLE_OP_SET)
		decision = set_pin(&req, key, outcome);
	else
		decision = get_pin(&req, key, outcome);
	if (decision != ORACLE_RESPOND)
		goto out;

	/*
	 * The response travels under the same shared secret, with
	 * the response label (PROTO-ENCRYPT-5). The plaintext is one
	 * 32-byte key, and the envelope holds 96 bytes
	 * (PROTO-RESPONSE-1, PROTO-RESPONSE-2).
	 */
	if (cipher_ecdh_keys(dprime, env, CIPHER_LABEL_RESPONSE, enc_key,
	    mac_key) != 0 ||
	    cipher_envelope_seal(enc_key, mac_key, key, sizeof(key), res->env,
	    sizeof(res->env), &res->len) != 0 ||
	    res->len != ORACLE_RESPONSE_LEN) {
		decision = ORACLE_FAILURE;
		*outcome = ORACLE_OUT_ERROR;
	}
out:
	pindb_unlock(lock);
	explicit_bzero(&req, sizeof(req));
	explicit_bzero(dprime, sizeof(dprime));
	explicit_bzero(enc_key, sizeof(enc_key));
	explicit_bzero(mac_key, sizeof(mac_key));
	explicit_bzero(payload, sizeof(payload));
	explicit_bzero(signed_msg, sizeof(signed_msg));
	explicit_bzero(msghash, sizeof(msghash));
	explicit_bzero(key, sizeof(key));
	if (decision != ORACLE_RESPOND) {
		explicit_bzero(res->env, sizeof(res->env));
		res->len = 0;
	}
	return decision;
}
