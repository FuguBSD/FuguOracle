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
 * The state machine of the service: bytes in, bytes out. One call
 * takes the operation and the decoded request envelope, and it
 * answers a decision and an outcome class.
 *
 * The call reads no HTTP variable, and it writes no status line. The
 * caller maps the decision to a status (PROTO-HTTP), and it logs the
 * outcome class (SEC-LOGGING-2).
 */

#ifndef ORACLE_H
#define ORACLE_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"

/* The two operations of the wire protocol (PROTO-HTTP). */
enum oracle_op {
	ORACLE_OP_SET,
	ORACLE_OP_GET
};

/*
 * The decision of one request. ORACLE_REJECT answers a length
 * violation of the envelope, and ORACLE_FAILURE answers an internal
 * failure. The failure table of PROTO-HTTP holds the status of each
 * one.
 */
enum oracle_decision {
	ORACLE_RESPOND,
	ORACLE_REJECT,
	ORACLE_FAILURE
};

/* The outcome class of one request (SEC-LOGGING-2). */
enum oracle_outcome {
	ORACLE_OUT_OK_SET,
	ORACLE_OUT_OK_GET,
	ORACLE_OUT_JUNK,
	ORACLE_OUT_REJECT,
	ORACLE_OUT_ERROR
};

/*
 * The bytes of a response envelope: the IV, the ciphertext of one
 * 32-byte key, and the tag (PROTO-RESPONSE-2).
 */
#define ORACLE_RESPONSE_LEN	(CIPHER_IV_LEN + 48 + CIPHER_TAG_LEN)

/* The shortest request envelope: 33 + 4 + 16 + 16 + 32. */
#define ORACLE_ENVELOPE_MIN	(CIPHER_PUBKEY_LEN + 4 + \
				    CIPHER_ENVELOPE_OVERHEAD + CIPHER_BLOCK_LEN)

/* The envelope of a 200 response. */
struct oracle_response {
	uint8_t	 env[ORACLE_RESPONSE_LEN];
	size_t	 len;
};

/*
 * oracle_handle(priv, op, env, env_len, res, outcome):
 *	The answer of one request. priv holds the static key d of
 *	CIPHER_KEY_LEN bytes, and env holds the decoded request
 *	envelope of env_len bytes (PROTO-ENVELOPE). The caller reads
 *	the key of d from the key file, because a path is a
 *	compile-time constant of that caller (D-06, PROG-CGI-4).
 *
 *	The call answers ORACLE_RESPOND, and it then writes the
 *	response envelope of ORACLE_RESPONSE_LEN bytes to res. Each
 *	other answer clears res. The outcome class of the answer
 *	lands in outcome, on every path.
 *
 *	The junk path answers ORACLE_RESPOND with ORACLE_OUT_JUNK,
 *	and its envelope holds the same length as a real answer
 *	(OPS-JUNK-2).
 */
enum oracle_decision	oracle_handle(const uint8_t *, enum oracle_op,
			    const uint8_t *, size_t, struct oracle_response *,
			    enum oracle_outcome *);

#endif /* ORACLE_H */
