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
 * The record store. A record is one flat file of PINDB_RECORD_LEN
 * bytes in PINS_DIR (D-05, STORE-RECORD).
 *
 * Each call takes the static server key d and the recovered client
 * public key. It derives the record path and the two record keys from
 * them (STORE-KEYS-1), and it stores neither key (STORE-KEYS-2).
 *
 * The caller holds the lock of pindb_lock() across the load, the
 * decision and the store of one request (STORE-ATOMIC-1).
 */

#ifndef PINDB_H
#define PINDB_H

#include <stdint.h>

#include "cipher.h"

/*
 * The record directory, a compile-time constant (D-06). The path
 * sits inside the /var/www chroot (PROG-CGI-4). The regress build
 * names a directory of its own on the command line, and the path
 * stays a compile-time constant there.
 */
#ifndef PINS_DIR
#define PINS_DIR	"/fuguoracle/pins"
#endif

#define PINDB_VERSION		0x01	/* the one record version (D-09) */
#define PINDB_RECORD_LEN	129	/* the bytes of a record file */
#define PINDB_PLAIN_LEN		69	/* the bytes of a record plaintext */
#define PINDB_STRIKES		3	/* the count of a wiped record */

/* The fields of the record plaintext (STORE-RECORD). */
struct pindb_record {
	uint8_t		hash_pin_secret[CIPHER_HASH_LEN];
	uint8_t		aes_key[CIPHER_KEY_LEN];
	uint8_t		count;
	uint32_t	replay_counter;
};

/*
 * The answer of one record call. The store names the outcome, and
 * the caller decides what each outcome means (OPS-GET-2, OPS-SET-2).
 * PINDB_CORRUPT covers the four corrupt records of OPS-GET-2: a
 * wrong file length, a wrong authenticator, a wrong version, and a
 * wrong plaintext length.
 *
 * PINDB_IO and PINDB_ERROR carry the two failure classes of D-10. A
 * load answers PINDB_IO for an I/O failure, and PINDB_ERROR for
 * every other failure, such as a failure of the shim. A get_pin
 * caller answers 500 for PINDB_IO (OPS-GET-7), and it takes the
 * junk path for PINDB_ERROR (OPS-JUNK). A store and a wipe answer
 * PINDB_ERROR for each failure, and every one of them is a persist
 * failure of OPS-GET-7.
 */
enum pindb_result {
	PINDB_OK,
	PINDB_MISSING,
	PINDB_CORRUPT,
	PINDB_IO,
	PINDB_ERROR
};

/*
 * pindb_lock():
 *	The global advisory lock of the record directory
 *	(STORE-ATOMIC-1, STORE-ATOMIC-2). The call blocks until it
 *	holds the lock. It answers a file descriptor, or -1 on a
 *	failure.
 */
int	pindb_lock(void);

/*
 * pindb_unlock(fd):
 *	Release the lock that pindb_lock() answered.
 */
void	pindb_unlock(int);

/*
 * pindb_load(priv, pin_pubkey, out):
 *	The record of one client. priv holds the static key d of
 *	CIPHER_KEY_LEN bytes, and pin_pubkey holds the recovered
 *	client public key of CIPHER_PUBKEY_LEN bytes.
 *
 *	The read path checks the exact file length, then the
 *	authenticator in constant time, then the version, then the
 *	decryption, then the exact plaintext length (STORE-RECORD-1
 *	to STORE-RECORD-4). A wrong length, a wrong authenticator, a
 *	wrong version and a wrong plaintext length each answer
 *	PINDB_CORRUPT, because OPS-GET-2 names no other corrupt
 *	record. An absent file answers PINDB_MISSING. An I/O failure
 *	answers PINDB_IO, and every other failure answers
 *	PINDB_ERROR, such as a failure of the shim. D-10 sends each
 *	failure but PINDB_IO to the junk path. Each answer but
 *	PINDB_OK clears out.
 */
enum pindb_result	pindb_load(const uint8_t *, const uint8_t *,
			    struct pindb_record *);

/*
 * pindb_store(priv, pin_pubkey, rec):
 *	Write the record of one client, atomically. The steps are
 *	mkstemp(3) in PINS_DIR, the write, fsync(2), rename(2) over
 *	the target, then fsync(2) of the directory (STORE-ATOMIC-3).
 *	Each write draws a fresh IV (STORE-RECORD-5). A failure
 *	answers PINDB_ERROR. A failure before the rename(2) leaves
 *	the target and the directory as they were. A failure of the
 *	directory fsync(2) leaves the new record in the target, and
 *	the answer stays PINDB_ERROR, because a crash can still lose
 *	that record (STORE-ATOMIC-3, OPS-GET-7).
 */
enum pindb_result	pindb_store(const uint8_t *, const uint8_t *,
			    const struct pindb_record *);

/*
 * pindb_wipe(priv, pin_pubkey, rec):
 *	Destroy the key share of one client. The call writes the
 *	hash_pin_secret of rec, a zero key, the count PINDB_STRIKES
 *	and the replay counter 0xFFFFFFFF, in the record layout
 *	(OPS-WIPE-1). It overwrites the file in place, it calls
 *	fsync(2), then it calls unlink(2) (OPS-WIPE-2). An absent
 *	file answers PINDB_MISSING, and a failure answers
 *	PINDB_ERROR. A successful unlink(2) answers PINDB_OK, because
 *	the fsync(2) already carried the write.
 */
enum pindb_result	pindb_wipe(const uint8_t *, const uint8_t *,
			    const struct pindb_record *);

#ifdef REGRESS
/*
 * The two stages that a test reaches through the hook below. The
 * service build holds no hook and no stage (ARCH-LAYOUT-5).
 */
enum pindb_stage {
	PINDB_STAGE_RENAME,	/* a store, before the rename(2) */
	PINDB_STAGE_UNLINK	/* a wipe, after the fsync(2) */
};

/*
 * The hook of one stage. The store gives the stage and the path of
 * the file of that stage: the temporary file of a store, and the
 * record file of a wipe. The hook answers 0 to continue, and -1 to
 * stop the call with PINDB_ERROR.
 */
typedef int	(*pindb_hook_fn)(enum pindb_stage, const char *);

/*
 * pindb_test_hook(fn):
 *	Install the hook of the two stages, or remove it with NULL.
 *	ARCH-LAYOUT-5 states what a test can do at a stage
 *	(TEST-UNIT).
 */
void	pindb_test_hook(pindb_hook_fn);
#endif

#endif /* PINDB_H */
