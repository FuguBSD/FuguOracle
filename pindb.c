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
 * The record store. This file holds every read and every write of a
 * PIN record: the storage keys, the record format, the one global
 * lock, the atomic write, and the wipe.
 *
 * The file calls the shim of cipher.h for each cryptographic step,
 * and it includes no library header (ARCH-LAYOUT-1, ARCH-LAYOUT-2).
 *
 * Each key and each plaintext lives in a stack buffer, and each exit
 * path clears it under one goto out (SEC-MEMORY-1, SEC-MEMORY-2).
 * The authenticator comparison runs in constant time (SEC-MEMORY-3).
 */

#include <sys/types.h>

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cipher.h"
#include "pindb.h"

/* The message of the record key derivation (STORE-KEYS-1). */
#define PIN_DATA_LABEL	"pin_data"

/* The record layout: version, authenticator, enc (STORE-RECORD). */
#define ENC_OFF		(1 + CIPHER_TAG_LEN)
#define ENC_LEN		(PINDB_RECORD_LEN - ENC_OFF)

/* The plaintext room that cipher_record_open() needs. */
#define PLAIN_MAX	(ENC_LEN - CIPHER_IV_LEN)

/* The template of the temporary file of a store (STORE-ATOMIC-3). */
#define TMP_TEMPLATE	PINS_DIR "/.tmp.XXXXXXXXXX"

/*
 * The keys of one record. The hash is the file name, and the two
 * keys stay in this structure only (STORE-KEYS-2).
 */
struct keys {
	uint8_t	 hash[CIPHER_HASH_LEN];		/* pin_pubkey_hash */
	uint8_t	 storage[CIPHER_KEY_LEN];	/* storage_aes_key */
	uint8_t	 auth[CIPHER_KEY_LEN];		/* pin_auth_key */
};

static int		 derive(const uint8_t *, const uint8_t *,
			    struct keys *);
static int		 record_path(const uint8_t *, char *, size_t);
static void		 pack(const struct pindb_record *, uint8_t *);
static void		 unpack(const uint8_t *, struct pindb_record *);
static int		 seal(const struct keys *,
			    const struct pindb_record *, uint8_t *);
static enum pindb_result unseal(const struct keys *, const uint8_t *,
			    struct pindb_record *);
static int		 write_all(int, const uint8_t *, size_t);
static int		 sync_dir(void);

#ifdef REGRESS
static pindb_hook_fn	 test_hook;

void
pindb_test_hook(pindb_hook_fn fn)
{
	test_hook = fn;
}

/* The answer of the installed hook, or 0 when no hook is present. */
static int
stage(enum pindb_stage which, const char *path)
{
	if (test_hook == NULL)
		return 0;
	return test_hook(which, path);
}
#else
#define stage(which, path)	0
#endif

/*
 * The three storage keys of one client (STORE-KEYS-1). priv holds
 * the static key d, and pubkey holds the recovered client public
 * key. A failure clears the answer.
 */
static int
derive(const uint8_t *priv, const uint8_t *pubkey, struct keys *k)
{
	uint8_t	 data_key[CIPHER_KEY_LEN];
	int	 rc = -1;

	if (cipher_hmac_sha256(priv, CIPHER_KEY_LEN,
	    (const uint8_t *)PIN_DATA_LABEL, sizeof(PIN_DATA_LABEL) - 1,
	    data_key) != 0)
		goto out;
	if (cipher_sha256(pubkey, CIPHER_PUBKEY_LEN, k->hash) != 0)
		goto out;
	if (cipher_hmac_sha256(data_key, sizeof(data_key), pubkey,
	    CIPHER_PUBKEY_LEN, k->storage) != 0)
		goto out;
	if (cipher_hmac_sha256(data_key, sizeof(data_key), k->hash,
	    sizeof(k->hash), k->auth) != 0)
		goto out;
	rc = 0;
out:
	explicit_bzero(data_key, sizeof(data_key));
	if (rc != 0)
		explicit_bzero(k, sizeof(*k));
	return rc;
}

/*
 * The path of one record: the lowercase hex of the key hash, with
 * the suffix .pin, inside PINS_DIR (STORE-KEYS-3).
 */
static int
record_path(const uint8_t *hash, char *out, size_t out_size)
{
	char	 hex[2 * CIPHER_HASH_LEN + 1];
	size_t	 i;
	int	 n;

	for (i = 0; i < CIPHER_HASH_LEN; i++)
		if (snprintf(hex + 2 * i, 3, "%02x", hash[i]) != 2)
			return -1;
	n = snprintf(out, out_size, "%s/%s.pin", PINS_DIR, hex);
	if (n < 0 || (size_t)n >= out_size)
		return -1;
	return 0;
}

/* The plaintext bytes of one record. The counter is little-endian. */
static void
pack(const struct pindb_record *rec, uint8_t *plain)
{
	uint32_t	 le;

	memcpy(plain, rec->hash_pin_secret, CIPHER_HASH_LEN);
	memcpy(plain + CIPHER_HASH_LEN, rec->aes_key, CIPHER_KEY_LEN);
	plain[CIPHER_HASH_LEN + CIPHER_KEY_LEN] = rec->count;
	le = htole32(rec->replay_counter);
	memcpy(plain + CIPHER_HASH_LEN + CIPHER_KEY_LEN + 1, &le, sizeof(le));
}

/* The fields of one record plaintext. */
static void
unpack(const uint8_t *plain, struct pindb_record *rec)
{
	uint32_t	 le;

	memcpy(rec->hash_pin_secret, plain, CIPHER_HASH_LEN);
	memcpy(rec->aes_key, plain + CIPHER_HASH_LEN, CIPHER_KEY_LEN);
	rec->count = plain[CIPHER_HASH_LEN + CIPHER_KEY_LEN];
	memcpy(&le, plain + CIPHER_HASH_LEN + CIPHER_KEY_LEN + 1, sizeof(le));
	rec->replay_counter = letoh32(le);
}

/*
 * The PINDB_RECORD_LEN bytes of one record file. The authenticator
 * covers the version byte and the enc field (STORE-RECORD). A
 * failure clears the whole answer.
 */
static int
seal(const struct keys *k, const struct pindb_record *rec, uint8_t *out)
{
	uint8_t	 plain[PINDB_PLAIN_LEN];
	uint8_t	 msg[1 + ENC_LEN];
	size_t	 len;
	int	 rc = -1;

	pack(rec, plain);
	if (cipher_record_seal(k->storage, plain, sizeof(plain),
	    out + ENC_OFF, ENC_LEN, &len) != 0)
		goto out;
	if (len != ENC_LEN)
		goto out;
	out[0] = PINDB_VERSION;
	msg[0] = PINDB_VERSION;
	memcpy(msg + 1, out + ENC_OFF, ENC_LEN);
	if (cipher_hmac_sha256(k->auth, CIPHER_KEY_LEN, msg, sizeof(msg),
	    out + 1) != 0)
		goto out;
	rc = 0;
out:
	explicit_bzero(plain, sizeof(plain));
	explicit_bzero(msg, sizeof(msg));
	if (rc != 0)
		explicit_bzero(out, PINDB_RECORD_LEN);
	return rc;
}

/*
 * The record of PINDB_RECORD_LEN bytes that raw holds. The
 * authenticator answers before the decryption (STORE-RECORD-2), and
 * the plaintext length answers after it (STORE-RECORD-3). A bad
 * record answers PINDB_CORRUPT (OPS-GET-2). A failure of the shim
 * answers PINDB_ERROR, because OPS-GET-2 names no other corrupt
 * record. Each answer but PINDB_OK clears rec.
 */
static enum pindb_result
unseal(const struct keys *k, const uint8_t *raw, struct pindb_record *rec)
{
	uint8_t			 msg[1 + ENC_LEN];
	uint8_t			 tag[CIPHER_TAG_LEN];
	uint8_t			 plain[PLAIN_MAX];
	size_t			 len;
	enum pindb_result	 res = PINDB_ERROR;

	msg[0] = raw[0];
	memcpy(msg + 1, raw + ENC_OFF, ENC_LEN);
	if (cipher_hmac_sha256(k->auth, CIPHER_KEY_LEN, msg, sizeof(msg),
	    tag) != 0)
		goto out;
	if (timingsafe_bcmp(tag, raw + 1, CIPHER_TAG_LEN) != 0) {
		res = PINDB_CORRUPT;
		goto out;
	}
	if (raw[0] != PINDB_VERSION) {	/* STORE-RECORD-4 */
		res = PINDB_CORRUPT;
		goto out;
	}
	/*
	 * A failed decryption answers PINDB_ERROR, and the wrong
	 * plaintext length below answers PINDB_CORRUPT, because
	 * OPS-GET-2 names the length one a corrupt record and not
	 * the other. The authenticator covers the enc field, so only
	 * a holder of pin_auth_key can write bytes that pass it and
	 * fail to unpad.
	 */
	if (cipher_record_open(k->storage, raw + ENC_OFF, ENC_LEN, plain,
	    sizeof(plain), &len) != 0)
		goto out;
	if (len != PINDB_PLAIN_LEN) {
		res = PINDB_CORRUPT;
		goto out;
	}
	unpack(plain, rec);
	res = PINDB_OK;
out:
	explicit_bzero(msg, sizeof(msg));
	explicit_bzero(tag, sizeof(tag));
	explicit_bzero(plain, sizeof(plain));
	if (res != PINDB_OK)
		explicit_bzero(rec, sizeof(*rec));
	return res;
}

/* Every byte of the buffer to the file, or -1 on a failure. */
static int
write_all(int fd, const uint8_t *buf, size_t len)
{
	ssize_t	 n;

	while (len > 0) {
		n = write(fd, buf, len);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

/* The directory entry of the record on the disk (STORE-ATOMIC-3). */
static int
sync_dir(void)
{
	int	 fd, rc = -1;

	if ((fd = open(PINS_DIR, O_RDONLY)) == -1)
		return -1;
	if (fsync(fd) != -1)
		rc = 0;
	if (close(fd) == -1)
		rc = -1;
	return rc;
}

int
pindb_lock(void)
{
	return open(PINS_DIR "/.lock", O_RDWR | O_CREAT | O_EXLOCK, 0600);
}

void
pindb_unlock(int fd)
{
	if (fd != -1)
		close(fd);
}

enum pindb_result
pindb_load(const uint8_t *priv, const uint8_t *pubkey,
    struct pindb_record *out)
{
	struct keys		 k;
	char			 path[PATH_MAX];
	uint8_t			 raw[PINDB_RECORD_LEN + 1];
	ssize_t			 n;
	size_t			 len = 0;
	int			 fd = -1;
	enum pindb_result	 res = PINDB_ERROR;

	memset(out, 0, sizeof(*out));
	memset(&k, 0, sizeof(k));
	if (derive(priv, pubkey, &k) != 0)
		goto out;
	if (record_path(k.hash, path, sizeof(path)) != 0)
		goto out;
	if ((fd = open(path, O_RDONLY)) == -1) {
		if (errno == ENOENT)
			res = PINDB_MISSING;
		goto out;
	}

	/*
	 * The buffer takes one byte more than a record, so a longer
	 * file answers PINDB_CORRUPT with the same test
	 * (STORE-RECORD-1).
	 */
	while (len < sizeof(raw)) {
		n = read(fd, raw + len, sizeof(raw) - len);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	if (len != PINDB_RECORD_LEN) {
		res = PINDB_CORRUPT;
		goto out;
	}
	res = unseal(&k, raw, out);
out:
	if (fd != -1 && close(fd) == -1 && res == PINDB_OK)
		res = PINDB_ERROR;
	explicit_bzero(&k, sizeof(k));
	explicit_bzero(raw, sizeof(raw));
	if (res != PINDB_OK)
		explicit_bzero(out, sizeof(*out));
	return res;
}

enum pindb_result
pindb_store(const uint8_t *priv, const uint8_t *pubkey,
    const struct pindb_record *rec)
{
	struct keys		 k;
	char			 path[PATH_MAX];
	char			 tmp[sizeof(TMP_TEMPLATE)];
	uint8_t			 raw[PINDB_RECORD_LEN];
	int			 fd = -1;
	enum pindb_result	 res = PINDB_ERROR;

	memset(&k, 0, sizeof(k));
	tmp[0] = '\0';
	if (derive(priv, pubkey, &k) != 0)
		goto out;
	if (record_path(k.hash, path, sizeof(path)) != 0)
		goto out;
	if (seal(&k, rec, raw) != 0)
		goto out;

	/*
	 * The new record lands on a temporary file of the same
	 * directory, and one rename(2) then replaces the target
	 * (STORE-ATOMIC-3). mkstemp(3) draws the name of that file
	 * outside the random seam (SEC-RANDOM-2).
	 */
	memcpy(tmp, TMP_TEMPLATE, sizeof(tmp));
	if ((fd = mkstemp(tmp)) == -1) {
		tmp[0] = '\0';
		goto out;
	}
	if (write_all(fd, raw, sizeof(raw)) != 0)
		goto out;
	if (fsync(fd) == -1)
		goto out;
	if (close(fd) == -1) {
		fd = -1;
		goto out;
	}
	fd = -1;
	if (stage(PINDB_STAGE_RENAME, tmp) != 0)
		goto out;
	if (rename(tmp, path) == -1)
		goto out;
	tmp[0] = '\0';
	if (sync_dir() != 0)
		goto out;
	res = PINDB_OK;
out:
	if (fd != -1)
		close(fd);
	if (tmp[0] != '\0')
		unlink(tmp);
	explicit_bzero(&k, sizeof(k));
	explicit_bzero(raw, sizeof(raw));
	return res;
}

enum pindb_result
pindb_wipe(const uint8_t *priv, const uint8_t *pubkey,
    const struct pindb_record *rec)
{
	struct keys		 k;
	struct pindb_record	 dead;
	char			 path[PATH_MAX];
	uint8_t			 raw[PINDB_RECORD_LEN];
	int			 fd = -1;
	enum pindb_result	 res = PINDB_ERROR;

	/* The dead record keeps the hash, and it holds no key share. */
	memset(&dead, 0, sizeof(dead));
	memcpy(dead.hash_pin_secret, rec->hash_pin_secret,
	    sizeof(dead.hash_pin_secret));
	dead.count = PINDB_STRIKES;
	dead.replay_counter = UINT32_MAX;

	memset(&k, 0, sizeof(k));
	if (derive(priv, pubkey, &k) != 0)
		goto out;
	if (record_path(k.hash, path, sizeof(path)) != 0)
		goto out;
	if (seal(&k, &dead, raw) != 0)
		goto out;

	/*
	 * The wipe targets the blocks of the record, so it opens the
	 * file itself and it bypasses the atomic write path
	 * (OPS-WIPE-2). The two records hold the same length, so the
	 * write needs no truncation.
	 */
	if ((fd = open(path, O_WRONLY)) == -1) {
		if (errno == ENOENT)
			res = PINDB_MISSING;
		goto out;
	}
	if (write_all(fd, raw, sizeof(raw)) != 0)
		goto out;
	if (fsync(fd) == -1)
		goto out;
	if (stage(PINDB_STAGE_UNLINK, path) != 0)
		goto out;
	if (unlink(path) == -1)
		goto out;
	res = PINDB_OK;
out:
	/*
	 * A close(2) failure does not change the answer. On the path
	 * to PINDB_OK, the fsync(2) carried the write and the
	 * unlink(2) removed the file.
	 */
	if (fd != -1)
		close(fd);
	explicit_bzero(&k, sizeof(k));
	explicit_bzero(&dead, sizeof(dead));
	explicit_bzero(raw, sizeof(raw));
	return res;
}
