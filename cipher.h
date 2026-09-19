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
 * The shim API. cipher.c holds the library calls behind it, and no
 * other source includes a library header (ARCH-LAYOUT-1,
 * ARCH-LAYOUT-2).
 *
 * Every function but cipher_random() returns 0, or -1 on a failure.
 * A failure leaves no plaintext and no key in an output buffer.
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stddef.h>
#include <stdint.h>

#define CIPHER_KEY_LEN		32	/* a private key or a derived key */
#define CIPHER_PUBKEY_LEN	33	/* a public key, SEC1 compressed */
#define CIPHER_XONLY_LEN	32	/* a public key, x-only */
#define CIPHER_HASH_LEN		32	/* a SHA-256 or HMAC-SHA256 value */
#define CIPHER_SIG_LEN		65	/* a recoverable signature */
#define CIPHER_BLOCK_LEN	16	/* the AES block */
#define CIPHER_IV_LEN		16	/* the CBC initialization vector */
#define CIPHER_TAG_LEN		32	/* the HMAC-SHA256 tag */

/* The bytes that an envelope adds to its ciphertext (PROTO-ENVELOPE). */
#define CIPHER_ENVELOPE_OVERHEAD	(CIPHER_IV_LEN + CIPHER_TAG_LEN)

/*
 * The two direction labels of PROTO-ENCRYPT. The NUL byte of the
 * string is not part of the label.
 */
#define CIPHER_LABEL_REQUEST	"blind_oracle_request"
#define CIPHER_LABEL_RESPONSE	"blind_oracle_response"

/*
 * cipher_random(buf, len):
 *	Fill buf with len random bytes (SEC-RANDOM-1). Every draw of
 *	the program comes through this one seam (SEC-RANDOM-2).
 */
void	cipher_random(void *, size_t);

/*
 * cipher_sha256(msg, msg_len, out):
 *	The SHA-256 of a message. out holds CIPHER_HASH_LEN bytes.
 */
int	cipher_sha256(const uint8_t *, size_t, uint8_t *);

/*
 * cipher_hmac_sha256(key, key_len, msg, msg_len, out):
 *	The HMAC-SHA256 of a message under a key. out holds
 *	CIPHER_HASH_LEN bytes.
 */
int	cipher_hmac_sha256(const uint8_t *, size_t, const uint8_t *, size_t,
	    uint8_t *);

/*
 * cipher_tweak_key(priv, cke, counter, out):
 *	The request private key d' of PROTO-TWEAK. priv is the static
 *	key d, of CIPHER_KEY_LEN bytes, cke is a public key of
 *	CIPHER_PUBKEY_LEN bytes, and counter is the replay counter.
 *	out holds CIPHER_KEY_LEN bytes.
 */
int	cipher_tweak_key(const uint8_t *, const uint8_t *, uint32_t,
	    uint8_t *);

/*
 * cipher_tweak_pubkey(pub, cke, counter, out, parity):
 *	The request public key Q' of PROTO-TWEAK, from the static
 *	public key P. pub holds CIPHER_PUBKEY_LEN bytes, out takes the
 *	x-only key of CIPHER_XONLY_LEN bytes, and parity takes 0 for
 *	an even Y and 1 for an odd Y. A client needs both answers,
 *	because the ECDH step hashes the compressed point. A failure
 *	writes -1 to parity.
 */
int	cipher_tweak_pubkey(const uint8_t *, const uint8_t *, uint32_t,
	    uint8_t *, int *);

/*
 * cipher_ecdh_keys(priv, pub, label, enc_key, mac_key):
 *	The two envelope keys of PROTO-ENCRYPT, from the ECDH secret
 *	of priv and pub under a direction label. label is one of
 *	CIPHER_LABEL_REQUEST and CIPHER_LABEL_RESPONSE. enc_key and
 *	mac_key each hold CIPHER_KEY_LEN bytes.
 */
int	cipher_ecdh_keys(const uint8_t *, const uint8_t *, const char *,
	    uint8_t *, uint8_t *);

/*
 * cipher_envelope_open(enc_key, mac_key, env, env_len, out, out_size,
 *     out_len):
 *	The plaintext of an envelope. The tag check runs before the
 *	decryption (PROTO-ENCRYPT-3), and a wrong tag leaves out
 *	untouched. out_size counts at least env_len minus
 *	CIPHER_ENVELOPE_OVERHEAD bytes, because the EVP layer needs
 *	the room of the ciphertext. out_len takes the plaintext
 *	length.
 */
int	cipher_envelope_open(const uint8_t *, const uint8_t *,
	    const uint8_t *, size_t, uint8_t *, size_t, size_t *);

/*
 * cipher_envelope_seal(enc_key, mac_key, pt, pt_len, out, out_size,
 *     out_len):
 *	The envelope of a plaintext, with a fresh IV from the seam
 *	(PROTO-ENCRYPT-4). out_size counts at least pt_len rounded up
 *	to the next CIPHER_BLOCK_LEN plus CIPHER_ENVELOPE_OVERHEAD
 *	bytes. out_len takes the envelope length.
 */
int	cipher_envelope_seal(const uint8_t *, const uint8_t *,
	    const uint8_t *, size_t, uint8_t *, size_t, size_t *);

/*
 * cipher_recover_pubkey(msghash, sig, out):
 *	The public key of the signer of a message hash
 *	(PROTO-PAYLOAD-4). msghash holds CIPHER_HASH_LEN bytes, sig
 *	holds CIPHER_SIG_LEN bytes, and out takes CIPHER_PUBKEY_LEN
 *	bytes.
 */
int	cipher_recover_pubkey(const uint8_t *, const uint8_t *, uint8_t *);

/*
 * cipher_record_open(key, enc, enc_len, out, out_size, out_len):
 *	The plaintext of a record enc field (STORE-RECORD). The field
 *	holds the IV and the ciphertext, and it carries no tag: the
 *	record authenticator covers it. out_size counts at least
 *	enc_len minus CIPHER_IV_LEN bytes, and out_len takes the
 *	plaintext length.
 */
int	cipher_record_open(const uint8_t *, const uint8_t *, size_t,
	    uint8_t *, size_t, size_t *);

/*
 * cipher_record_seal(key, pt, pt_len, out, out_size, out_len):
 *	The enc field of a record, with a fresh IV from the seam
 *	(STORE-RECORD-5). out_size counts at least pt_len rounded up
 *	to the next CIPHER_BLOCK_LEN plus CIPHER_IV_LEN bytes, and
 *	out_len takes the field length.
 */
int	cipher_record_seal(const uint8_t *, const uint8_t *, size_t,
	    uint8_t *, size_t, size_t *);

#endif /* CIPHER_H */
