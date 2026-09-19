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
 * The unit tests of the record store (TEST-UNIT). The tests read and
 * write real files under the PINS_DIR of the regress build, and each
 * case empties that directory first.
 *
 * The tests derive the storage keys, the record path and the record
 * layout from the text of the specification, and not from pindb.c. A
 * wrong derivation or a wrong layout in the store therefore fails
 * here.
 *
 * The program writes the fixed random source first, and it names it
 * in FUGUORACLE_RANDOM (SEC-RANDOM-2). The unit tests pin no draw, so
 * the source holds the hash chain of one committed seed. Two runs
 * therefore read the same bytes through the seam. The lock test still
 * depends on the scheduler and on its timeouts, and mkstemp(3) draws
 * outside the seam.
 *
 * The program prints nothing when every test passes.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dirent.h>
#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cipher.h"
#include "pindb.h"
#include "vectors.h"

/*
 * The offsets of the record file (STORE-RECORD). The test names them
 * again, because the store must hold to this layout.
 */
#define R_HMAC		1
#define R_ENC		33
#define R_ENC_LEN	96

/*
 * The offsets of the record plaintext (STORE-RECORD).
 */
#define P_HASH		0
#define P_KEY		32
#define P_COUNT		64
#define P_REPLAY	65

/* The bytes of the fixed random source of the run. */
#define SOURCE_LEN	4096

/* The chain writes whole hash blocks, so the source holds no tail. */
_Static_assert(SOURCE_LEN % CIPHER_HASH_LEN == 0,
    "the source length must be a multiple of the hash");

/* The seed of that source. The chain of it fills SOURCE_LEN bytes. */
#define SOURCE_SEED	"fuguoracle unit tests"

/* The seconds that the first request of the lock test holds the lock. */
#define LOCK_WAIT	1

/* The count that the first request of the lock test stores. */
#define LOCK_COUNT	2

/* The milliseconds that the lock test waits for a marker or an exit. */
#define LOCK_TIMEOUT	10000

/* The milliseconds between two tests of the exit of a child. */
#define LOCK_POLL	10

/* The descriptors that the close hook of the wipe inspects. */
#define HOOK_FD_MAX	64

static uint8_t	 priv[CIPHER_KEY_LEN];		/* the static key d */
static uint8_t	 pub[CIPHER_PUBKEY_LEN];	/* the client public key */
static int	 failures;

/* The state that a hook of the store captures. */
static int	 hook_calls;
static char	 hook_path[PATH_MAX];
static uint8_t	 hook_file[PINDB_RECORD_LEN + 1];
static size_t	 hook_len;
static ino_t	 hook_ino;
static int	 hook_fd = -1;

static void	 ok(const char *, int);
static void	 ok2(const char *, const char *, int);
static void	 zeroed(const char *, const void *, size_t);
static size_t	 hexbytes(const char *, uint8_t *, size_t);
static void	 storage_keys(uint8_t *, uint8_t *, uint8_t *);
static void	 record_file(char *, size_t);
static void	 fixture(struct pindb_record *, uint8_t, uint32_t);
static void	 same_record(const char *, const struct pindb_record *,
		     const struct pindb_record *);
static void	 check_file(const char *, const uint8_t *, size_t,
		     const struct pindb_record *);
static void	 reset(void);
static int	 entries(void);
static size_t	 slurp(const char *, uint8_t *, size_t);
static void	 put(const char *, const uint8_t *, size_t);
static void	 retag(uint8_t *);
static int	 read_hook(enum pindb_stage, const char *);
static int	 stop_hook(enum pindb_stage, const char *);
static int	 close_hook(enum pindb_stage, const char *);
static int	 marker(int);
static int	 reap(pid_t, int *);
static void	 child_first(int);
static void	 child_second(int);
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

/* A buffer holds no byte of a secret (SEC-MEMORY-2). */
static void
zeroed(const char *name, const void *buf, size_t len)
{
	const uint8_t	*bytes = buf;
	size_t		 i;

	for (i = 0; i < len; i++)
		if (bytes[i] != 0) {
			warnx("%s: the buffer holds byte %zu", name, i);
			failures++;
			return;
		}
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
 * The storage keys of the test client, derived from the text of
 * STORE-KEYS-1. hash takes the key hash, or NULL when the caller
 * needs the two keys only.
 */
static void
storage_keys(uint8_t *storage, uint8_t *auth, uint8_t *hash)
{
	uint8_t	 data_key[CIPHER_KEY_LEN];
	uint8_t	 local[CIPHER_HASH_LEN];

	if (hash == NULL)
		hash = local;
	ok("the record key", cipher_hmac_sha256(priv, sizeof(priv),
	    (const uint8_t *)"pin_data", 8, data_key) == 0);
	ok("the key hash", cipher_sha256(pub, sizeof(pub), hash) == 0);
	ok("the storage key", cipher_hmac_sha256(data_key, sizeof(data_key),
	    pub, sizeof(pub), storage) == 0);
	ok("the authentication key", cipher_hmac_sha256(data_key,
	    sizeof(data_key), hash, CIPHER_HASH_LEN, auth) == 0);
	explicit_bzero(data_key, sizeof(data_key));
	explicit_bzero(local, sizeof(local));
}

/* The record path of the test client (STORE-KEYS-3). */
static void
record_file(char *out, size_t size)
{
	uint8_t	 storage[CIPHER_KEY_LEN], auth[CIPHER_KEY_LEN];
	uint8_t	 hash[CIPHER_HASH_LEN];
	char	 hex[2 * CIPHER_HASH_LEN + 1];
	size_t	 i;
	int	 n;

	storage_keys(storage, auth, hash);
	for (i = 0; i < sizeof(hash); i++)
		snprintf(hex + 2 * i, 3, "%02x", hash[i]);
	n = snprintf(out, size, "%s/%s.pin", PINS_DIR, hex);
	if (n < 0 || (size_t)n >= size)
		errx(1, "the record path is too long");
	explicit_bzero(storage, sizeof(storage));
	explicit_bzero(auth, sizeof(auth));
}

/* The record that a case stores. */
static void
fixture(struct pindb_record *rec, uint8_t count, uint32_t counter)
{
	uint8_t	 secret[CIPHER_KEY_LEN];
	uint8_t	 key[CIPHER_KEY_LEN];
	size_t	 len;

	len = hexbytes(V_PIN_SECRET, secret, sizeof(secret));
	hexbytes(V_RECORD_KEY, key, sizeof(key));
	memset(rec, 0, sizeof(*rec));
	ok("the hash of the pin_secret",
	    cipher_sha256(secret, len, rec->hash_pin_secret) == 0);
	memcpy(rec->aes_key, key, sizeof(rec->aes_key));
	rec->count = count;
	rec->replay_counter = counter;
	explicit_bzero(secret, sizeof(secret));
	explicit_bzero(key, sizeof(key));
}

/* Two records hold the same four fields. */
static void
same_record(const char *name, const struct pindb_record *got,
    const struct pindb_record *want)
{
	ok2(name, "the hash of the pin_secret",
	    memcmp(got->hash_pin_secret, want->hash_pin_secret,
	    sizeof(got->hash_pin_secret)) == 0);
	ok2(name, "the key share",
	    memcmp(got->aes_key, want->aes_key, sizeof(got->aes_key)) == 0);
	ok2(name, "the count", got->count == want->count);
	ok2(name, "the replay counter",
	    got->replay_counter == want->replay_counter);
}

/*
 * The bytes of a record file hold the four fields, under the keys of
 * STORE-KEYS-1 and the layout of STORE-RECORD.
 */
static void
check_file(const char *name, const uint8_t *raw, size_t len,
    const struct pindb_record *want)
{
	uint8_t		 storage[CIPHER_KEY_LEN], auth[CIPHER_KEY_LEN];
	uint8_t		 msg[1 + R_ENC_LEN], tag[CIPHER_TAG_LEN];
	uint8_t		 plain[R_ENC_LEN - CIPHER_IV_LEN];
	uint32_t	 le;
	size_t		 plain_len;

	ok2(name, "the file holds 129 bytes", len == PINDB_RECORD_LEN);
	if (len != PINDB_RECORD_LEN)
		return;
	ok2(name, "the version is 0x01", raw[0] == PINDB_VERSION);

	storage_keys(storage, auth, NULL);
	msg[0] = raw[0];
	memcpy(msg + 1, raw + R_ENC, R_ENC_LEN);
	ok2(name, "the authenticator answers",
	    cipher_hmac_sha256(auth, sizeof(auth), msg, sizeof(msg),
	    tag) == 0);
	ok2(name, "the authenticator covers the version and the enc field",
	    memcmp(tag, raw + R_HMAC, sizeof(tag)) == 0);
	ok2(name, "the enc field opens",
	    cipher_record_open(storage, raw + R_ENC, R_ENC_LEN, plain,
	    sizeof(plain), &plain_len) == 0);
	ok2(name, "the plaintext holds 69 bytes",
	    plain_len == PINDB_PLAIN_LEN);
	if (plain_len != PINDB_PLAIN_LEN)
		goto out;
	ok2(name, "the hash of the pin_secret",
	    memcmp(plain + P_HASH, want->hash_pin_secret,
	    sizeof(want->hash_pin_secret)) == 0);
	ok2(name, "the key share",
	    memcmp(plain + P_KEY, want->aes_key, sizeof(want->aes_key)) == 0);
	ok2(name, "the count", plain[P_COUNT] == want->count);
	memcpy(&le, plain + P_REPLAY, sizeof(le));
	ok2(name, "the replay counter", letoh32(le) == want->replay_counter);
out:
	explicit_bzero(storage, sizeof(storage));
	explicit_bzero(auth, sizeof(auth));
	explicit_bzero(plain, sizeof(plain));
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

/* The count of the files of the record directory. */
static int
entries(void)
{
	DIR		*dir;
	struct dirent	*ent;
	int		 count = 0;

	if ((dir = opendir(PINS_DIR)) == NULL)
		err(1, "%s", PINS_DIR);
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;
		count++;
	}
	closedir(dir);
	return count;
}

/* The bytes of a file, and its length. */
static size_t
slurp(const char *path, uint8_t *out, size_t size)
{
	ssize_t	 n;
	size_t	 len = 0;
	int	 fd;

	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);
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
put(const char *path, const uint8_t *raw, size_t len)
{
	int	 fd;

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

	storage_keys(storage, auth, NULL);
	msg[0] = raw[0];
	memcpy(msg + 1, raw + R_ENC, R_ENC_LEN);
	ok("the new authenticator", cipher_hmac_sha256(auth, sizeof(auth),
	    msg, sizeof(msg), raw + R_HMAC) == 0);
	explicit_bzero(storage, sizeof(storage));
	explicit_bzero(auth, sizeof(auth));
}

/* The hook of the wipe: it reads the record before the unlink. */
static int
read_hook(enum pindb_stage which, const char *path)
{
	struct stat	 st;

	hook_calls++;
	ok("the wipe reaches the unlink stage", which == PINDB_STAGE_UNLINK);
	if (strlcpy(hook_path, path, sizeof(hook_path)) >= sizeof(hook_path))
		errx(1, "the hook path is too long");
	hook_len = slurp(path, hook_file, sizeof(hook_file));
	if (stat(path, &st) == -1)
		err(1, "%s", path);
	hook_ino = st.st_ino;
	return 0;
}

/* The hook of the store: it stops the write before the rename. */
static int
stop_hook(enum pindb_stage which, const char *path)
{
	hook_calls++;
	ok("the store reaches the rename stage", which == PINDB_STAGE_RENAME);
	if (strlcpy(hook_path, path, sizeof(hook_path)) >= sizeof(hook_path))
		errx(1, "the hook path is too long");
	return -1;
}

/*
 * The hook of the wipe of t_wipe_close: it closes the descriptor that
 * the call holds. The wipe opens the record for a write, and this
 * program opens no second one, so the access mode and the inode name
 * that descriptor.
 */
static int
close_hook(enum pindb_stage which, const char *path)
{
	struct stat	 st, open_st;
	int		 fd, flags;

	hook_calls++;
	ok("the wipe reaches the unlink stage", which == PINDB_STAGE_UNLINK);
	if (stat(path, &st) == -1)
		err(1, "%s", path);
	for (fd = 0; fd < HOOK_FD_MAX; fd++) {
		if ((flags = fcntl(fd, F_GETFL)) == -1)
			continue;
		if ((flags & O_ACCMODE) != O_WRONLY)
			continue;
		if (fstat(fd, &open_st) == -1)
			continue;
		if (open_st.st_ino != st.st_ino ||
		    open_st.st_dev != st.st_dev)
			continue;
		if (close(fd) == -1)
			err(1, "close");
		hook_fd = fd;
		break;
	}
	return 0;
}

/* One marker of the order pipe, or -1 after the timeout. */
static int
marker(int fd)
{
	struct pollfd	 pfd;
	char		 c;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, LOCK_TIMEOUT) != 1)
		return -1;
	if (read(fd, &c, 1) != 1)
		return -1;
	return (unsigned char)c;
}

/*
 * The status of one child, or -1 after LOCK_TIMEOUT. A lock that no
 * request releases must not hold the regress run for ever, so the
 * wait ends with SIGKILL.
 */
static int
reap(pid_t pid, int *status)
{
	int	 ms;
	pid_t	 got;

	for (ms = 0; ms < LOCK_TIMEOUT; ms += LOCK_POLL) {
		if ((got = waitpid(pid, status, WNOHANG)) == -1)
			err(1, "waitpid");
		if (got == pid)
			return 0;
		usleep(LOCK_POLL * 1000);
	}
	if (kill(pid, SIGKILL) == -1)
		err(1, "kill");
	if (waitpid(pid, status, 0) == -1)
		err(1, "waitpid");
	return -1;
}

/*
 * The first request of the lock test. It takes the lock, it loads,
 * it waits, then it stores. The two markers bracket the wait.
 */
static void
child_first(int fd)
{
	struct pindb_record	 rec;
	int			 lock;

	if ((lock = pindb_lock()) == -1)
		_exit(1);
	if (pindb_load(priv, pub, &rec) != PINDB_OK)
		_exit(1);
	if (write(fd, "A", 1) != 1)
		_exit(1);
	sleep(LOCK_WAIT);
	rec.count = LOCK_COUNT;
	if (pindb_store(priv, pub, &rec) != PINDB_OK)
		_exit(1);
	if (write(fd, "S", 1) != 1)
		_exit(1);
	pindb_unlock(lock);
	_exit(0);
}

/*
 * The second request of the lock test. It starts while the first
 * request holds the lock, so its load must answer the record of that
 * store (TEST-UNIT-3).
 */
static void
child_second(int fd)
{
	struct pindb_record	 rec;
	int			 lock;

	if ((lock = pindb_lock()) == -1)
		_exit(1);
	if (pindb_load(priv, pub, &rec) != PINDB_OK)
		_exit(1);
	if (write(fd, "B", 1) != 1)
		_exit(1);
	if (rec.count != LOCK_COUNT)
		_exit(2);
	pindb_unlock(lock);
	_exit(0);
}

/* A store, then a load, then the bytes of the file (STORE-RECORD-4). */
static void
t_roundtrip(void)
{
	struct pindb_record	 rec, got;
	char			 path[PATH_MAX];
	uint8_t			 raw[PINDB_RECORD_LEN + 1];
	uint8_t			 other[CIPHER_PUBKEY_LEN];
	size_t			 len;

	reset();
	fixture(&rec, 1, 7);
	record_file(path, sizeof(path));
	ok("a store answers ok", pindb_store(priv, pub, &rec) == PINDB_OK);
	ok("the store writes one file", entries() == 1);

	len = slurp(path, raw, sizeof(raw));
	check_file("the stored record", raw, len, &rec);

	ok("a load answers ok", pindb_load(priv, pub, &got) == PINDB_OK);
	same_record("the loaded record", &got, &rec);

	/* The file carries no key in the clear (STORE-KEYS-2). */
	ok("the file holds no client public key",
	    memmem(raw, len, pub, sizeof(pub)) == NULL);
	ok("the file holds no key share",
	    memmem(raw, len, rec.aes_key, sizeof(rec.aes_key)) == NULL);
	ok("the file holds no hash of the pin_secret",
	    memmem(raw, len, rec.hash_pin_secret,
	    sizeof(rec.hash_pin_secret)) == NULL);

	/* Another client reaches no record of this client. */
	memcpy(other, pub, sizeof(other));
	other[sizeof(other) - 1] ^= 0x01;
	ok("a load of another client answers missing",
	    pindb_load(priv, other, &got) == PINDB_MISSING);
}

/* Two stores of one record draw two IVs (STORE-RECORD-5). */
static void
t_iv(void)
{
	struct pindb_record	 rec;
	char			 path[PATH_MAX];
	uint8_t			 first[PINDB_RECORD_LEN + 1];
	uint8_t			 second[PINDB_RECORD_LEN + 1];

	reset();
	fixture(&rec, 0, 1);
	record_file(path, sizeof(path));
	ok("the first store", pindb_store(priv, pub, &rec) == PINDB_OK);
	ok("the first store writes 129 bytes",
	    slurp(path, first, sizeof(first)) == PINDB_RECORD_LEN);
	ok("the second store", pindb_store(priv, pub, &rec) == PINDB_OK);
	ok("the second store writes 129 bytes",
	    slurp(path, second, sizeof(second)) == PINDB_RECORD_LEN);

	ok("the two stores draw two IVs",
	    memcmp(first + R_ENC, second + R_ENC, CIPHER_IV_LEN) != 0);
	ok("the two stores write two ciphertexts",
	    memcmp(first + R_ENC + CIPHER_IV_LEN,
	    second + R_ENC + CIPHER_IV_LEN,
	    R_ENC_LEN - CIPHER_IV_LEN) != 0);
	ok("the second store replaces the record", entries() == 1);
}

/*
 * A wrong length, a wrong authenticator, a wrong version and a wrong
 * plaintext length each answer corrupt (STORE-RECORD-1 to
 * STORE-RECORD-4).
 */
static void
t_corrupt(void)
{
	struct pindb_record	 rec, got;
	char			 path[PATH_MAX];
	uint8_t			 good[PINDB_RECORD_LEN + 1];
	uint8_t			 raw[PINDB_RECORD_LEN + 1];
	uint8_t			 storage[CIPHER_KEY_LEN], auth[CIPHER_KEY_LEN];
	uint8_t			 plain[PINDB_PLAIN_LEN + 1];
	size_t			 enc_len;

	reset();
	fixture(&rec, 2, 5);
	record_file(path, sizeof(path));
	ok("the base store", pindb_store(priv, pub, &rec) == PINDB_OK);
	ok("the base record holds 129 bytes",
	    slurp(path, good, sizeof(good)) == PINDB_RECORD_LEN);

	/* A short file and a long file (STORE-RECORD-1). */
	put(path, good, PINDB_RECORD_LEN - 1);
	memset(&got, 0xff, sizeof(got));
	ok("a short file answers corrupt",
	    pindb_load(priv, pub, &got) == PINDB_CORRUPT);
	zeroed("a corrupt record clears the answer", &got, sizeof(got));

	memcpy(raw, good, PINDB_RECORD_LEN);
	raw[PINDB_RECORD_LEN] = 0x00;
	put(path, raw, PINDB_RECORD_LEN + 1);
	ok("a long file answers corrupt",
	    pindb_load(priv, pub, &got) == PINDB_CORRUPT);

	/* A changed authenticator and a changed enc field
	 * (STORE-RECORD-2). */
	memcpy(raw, good, PINDB_RECORD_LEN);
	raw[R_HMAC] ^= 0x01;
	put(path, raw, PINDB_RECORD_LEN);
	ok("a changed authenticator answers corrupt",
	    pindb_load(priv, pub, &got) == PINDB_CORRUPT);

	memcpy(raw, good, PINDB_RECORD_LEN);
	raw[R_ENC] ^= 0x01;
	put(path, raw, PINDB_RECORD_LEN);
	ok("a changed enc field answers corrupt",
	    pindb_load(priv, pub, &got) == PINDB_CORRUPT);

	/* Another version, with an authenticator of its own
	 * (STORE-RECORD-4). */
	memcpy(raw, good, PINDB_RECORD_LEN);
	raw[0] = 0x02;
	retag(raw);
	put(path, raw, PINDB_RECORD_LEN);
	ok("another version answers corrupt",
	    pindb_load(priv, pub, &got) == PINDB_CORRUPT);

	/*
	 * A plaintext of 70 bytes pads to the same 80 bytes, so the
	 * file keeps its length and its authenticator answers. The
	 * plaintext length is the one step that rejects it
	 * (STORE-RECORD-3).
	 */
	storage_keys(storage, auth, NULL);
	memset(plain, 0x5a, sizeof(plain));
	memcpy(raw, good, PINDB_RECORD_LEN);
	ok("the seal of a longer plaintext",
	    cipher_record_seal(storage, plain, sizeof(plain), raw + R_ENC,
	    R_ENC_LEN, &enc_len) == 0);
	ok("the longer plaintext keeps the enc length",
	    enc_len == R_ENC_LEN);
	retag(raw);
	put(path, raw, PINDB_RECORD_LEN);
	ok("another plaintext length answers corrupt",
	    pindb_load(priv, pub, &got) == PINDB_CORRUPT);

	/* The record of the base store answers again. */
	put(path, good, PINDB_RECORD_LEN);
	ok("the base record answers ok",
	    pindb_load(priv, pub, &got) == PINDB_OK);
	same_record("the base record", &got, &rec);
	explicit_bzero(storage, sizeof(storage));
	explicit_bzero(auth, sizeof(auth));
}

/*
 * The third-strike wipe writes the dead record in place, then it
 * removes the file (TEST-UNIT-1, OPS-WIPE-1, OPS-WIPE-2).
 */
static void
t_wipe(void)
{
	struct pindb_record	 rec, dead, got;
	struct stat		 st;
	char			 path[PATH_MAX];
	uint8_t			 view[PINDB_RECORD_LEN + 1];
	ssize_t			 n;
	ino_t			 before;
	int			 fd;

	reset();
	fixture(&rec, 2, 9);
	record_file(path, sizeof(path));
	ok("the store before the wipe",
	    pindb_store(priv, pub, &rec) == PINDB_OK);
	if (stat(path, &st) == -1)
		err(1, "%s", path);
	before = st.st_ino;

	/*
	 * The descriptor holds the inode of the record across the
	 * wipe. An in-place write therefore shows the dead record
	 * through it, and a new file does not (OPS-WIPE-2).
	 */
	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);

	hook_calls = 0;
	hook_len = 0;
	pindb_test_hook(read_hook);
	ok("a wipe answers ok", pindb_wipe(priv, pub, &rec) == PINDB_OK);
	pindb_test_hook(NULL);
	ok("the hook runs once", hook_calls == 1);
	ok("the hook reads the record file", strcmp(hook_path, path) == 0);

	/* The content before the unlink (OPS-WIPE-1). */
	dead = rec;
	memset(dead.aes_key, 0, sizeof(dead.aes_key));
	dead.count = PINDB_STRIKES;
	dead.replay_counter = 0xFFFFFFFF;
	check_file("the wiped record", hook_file, hook_len, &dead);

	/* The write lands on the blocks of the record (OPS-WIPE-2). */
	ok("the wipe keeps the file", hook_ino == before);
	if ((n = pread(fd, view, sizeof(view), 0)) == -1)
		err(1, "%s", path);
	check_file("the record of the open descriptor", view, (size_t)n,
	    &dead);
	if (close(fd) == -1)
		err(1, "%s", path);

	ok("the wipe removes the file",
	    access(path, F_OK) == -1 && errno == ENOENT);
	ok("the directory holds no record", entries() == 0);
	ok("a load after the wipe answers missing",
	    pindb_load(priv, pub, &got) == PINDB_MISSING);
	ok("a wipe of an absent record answers missing",
	    pindb_wipe(priv, pub, &rec) == PINDB_MISSING);
}

/*
 * A close(2) failure after the unlink(2) keeps the answer of a
 * completed wipe (OPS-WIPE-2). The fsync(2) carries the write, so
 * the close(2) reports nothing about it.
 */
static void
t_wipe_close(void)
{
	struct pindb_record	 rec;
	char			 path[PATH_MAX];

	reset();
	fixture(&rec, 2, 13);
	record_file(path, sizeof(path));
	ok("the store before the second wipe",
	    pindb_store(priv, pub, &rec) == PINDB_OK);

	hook_calls = 0;
	hook_fd = -1;
	pindb_test_hook(close_hook);
	ok("a wipe with a closed descriptor answers ok",
	    pindb_wipe(priv, pub, &rec) == PINDB_OK);
	pindb_test_hook(NULL);
	ok("the hook runs once", hook_calls == 1);
	ok("the hook closes the descriptor of the wipe", hook_fd != -1);
	ok("the wipe removes the file",
	    access(path, F_OK) == -1 && errno == ENOENT);
}

/*
 * A failed decryption answers an error, and not corrupt, because
 * OPS-GET-2 names no such corrupt record. The case writes a fixed
 * pattern in the enc field, then it writes the authenticator of that
 * pattern with the keys of the client. The bytes therefore pass the
 * authenticator, and the unpad of them fails. In the service, only a
 * holder of pin_auth_key can write such a record, because the
 * authenticator covers the enc field.
 */
static void
t_internal(void)
{
	struct pindb_record	 rec, got;
	char			 path[PATH_MAX];
	uint8_t			 raw[PINDB_RECORD_LEN + 1];

	reset();
	fixture(&rec, 1, 4);
	record_file(path, sizeof(path));
	ok("the store before the forged record",
	    pindb_store(priv, pub, &rec) == PINDB_OK);
	ok("that record holds 129 bytes",
	    slurp(path, raw, sizeof(raw)) == PINDB_RECORD_LEN);

	memset(raw + R_ENC, 0x5a, R_ENC_LEN);
	retag(raw);
	put(path, raw, PINDB_RECORD_LEN);
	memset(&got, 0xff, sizeof(got));
	ok("a failed decryption answers an error",
	    pindb_load(priv, pub, &got) == PINDB_ERROR);
	zeroed("an error clears the answer", &got, sizeof(got));
}

/*
 * A store that stops before the rename leaves the target record and
 * leaves no second file (TEST-UNIT-2, STORE-ATOMIC-3).
 */
static void
t_atomic(void)
{
	struct pindb_record	 first, second, got;
	struct stat		 st;
	char			 path[PATH_MAX];
	uint8_t			 before[PINDB_RECORD_LEN + 1];
	uint8_t			 after[PINDB_RECORD_LEN + 1];
	size_t			 len_before, len_after;
	ino_t			 ino;

	reset();
	fixture(&first, 0, 3);
	record_file(path, sizeof(path));
	ok("the first store", pindb_store(priv, pub, &first) == PINDB_OK);
	len_before = slurp(path, before, sizeof(before));
	if (stat(path, &st) == -1)
		err(1, "%s", path);
	ino = st.st_ino;

	fixture(&second, 3, 99);
	hook_calls = 0;
	pindb_test_hook(stop_hook);
	ok("a stopped store answers an error",
	    pindb_store(priv, pub, &second) == PINDB_ERROR);
	pindb_test_hook(NULL);
	ok("the hook runs once", hook_calls == 1);
	ok("the store writes a file of its own",
	    strcmp(hook_path, path) != 0 &&
	    strncmp(hook_path, PINS_DIR "/", sizeof(PINS_DIR)) == 0);

	len_after = slurp(path, after, sizeof(after));
	ok("the target record keeps its length", len_after == len_before);
	ok("the target record keeps its bytes",
	    len_after == len_before &&
	    memcmp(before, after, len_before) == 0);
	if (stat(path, &st) == -1)
		err(1, "%s", path);
	ok("the target record keeps its inode", st.st_ino == ino);
	ok("a load answers the first record",
	    pindb_load(priv, pub, &got) == PINDB_OK);
	same_record("the record after a stopped store", &got, &first);
	ok("the stopped store leaves one file", entries() == 1);
}

/*
 * Two requests take the lock in turn: the load of the second follows
 * the store of the first (TEST-UNIT-3, STORE-ATOMIC-1).
 */
static void
t_lock(void)
{
	struct pindb_record	 rec;
	char			 order[4];
	int			 fds[2];
	int			 status, value;
	pid_t			 a, b;
	size_t			 i;

	reset();
	fixture(&rec, 0, 11);
	ok("the store before the lock test",
	    pindb_store(priv, pub, &rec) == PINDB_OK);
	if (pipe(fds) == -1)
		err(1, "pipe");

	if ((a = fork()) == -1)
		err(1, "fork");
	if (a == 0) {
		close(fds[0]);
		child_first(fds[1]);
	}

	/* The first request holds the lock when it reports its load. */
	value = marker(fds[0]);
	order[0] = value == -1 ? '?' : (char)value;

	if ((b = fork()) == -1)
		err(1, "fork");
	if (b == 0) {
		close(fds[0]);
		child_second(fds[1]);
	}
	if (close(fds[1]) == -1)
		err(1, "pipe");
	for (i = 1; i < 3; i++) {
		value = marker(fds[0]);
		order[i] = value == -1 ? '?' : (char)value;
	}
	order[3] = '\0';
	if (close(fds[0]) == -1)
		err(1, "pipe");

	ok("the first request ends well",
	    reap(a, &status) == 0 && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
	ok("the second request ends well",
	    reap(b, &status) == 0 && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);

	ok("the lock serializes the two requests",
	    strcmp(order, "ASB") == 0);
	if (strcmp(order, "ASB") != 0)
		warnx("the order is \"%s\", and not \"ASB\"", order);
}

/*
 * The fixed random source of the run. The seam of the regress build
 * reads it in draw order, and the unit tests pin no draw. The source
 * holds the hash chain of SOURCE_SEED, so two runs read the same
 * bytes through the seam (SEC-RANDOM-2). A draw outside the seam,
 * such as the one of mkstemp(3), stays random.
 */
static void
random_source(char *path, size_t size)
{
	uint8_t	 buf[SOURCE_LEN];
	uint8_t	 block[CIPHER_HASH_LEN];
	size_t	 i;
	int	 n, fd;

	n = snprintf(path, size, "unit.random.XXXXXXXXXX");
	if (n < 0 || (size_t)n >= size)
		errx(1, "the source path is too long");
	if (cipher_sha256((const uint8_t *)SOURCE_SEED,
	    sizeof(SOURCE_SEED) - 1, block) != 0)
		errx(1, "the seed of the source");
	for (i = 0; i + sizeof(block) <= sizeof(buf); i += sizeof(block)) {
		memcpy(buf + i, block, sizeof(block));
		if (cipher_sha256(block, sizeof(block), block) != 0)
			errx(1, "the chain of the source");
	}
	if ((fd = mkstemp(path)) == -1)
		err(1, "mkstemp");
	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf))
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
	hexbytes(V_CLIENT_PUB, pub, sizeof(pub));

	t_roundtrip();
	t_iv();
	t_corrupt();
	t_internal();
	t_wipe();
	t_wipe_close();
	t_atomic();
	t_lock();

	if (unlink(path) == -1)
		err(1, "%s", path);
	if (failures != 0)
		errx(1, "%d unit test(s) failed", failures);
	return 0;
}
