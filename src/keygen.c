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
 * The key generator of the service (PROG-KEYGEN). The operator runs
 * it once, as root, and outside the chroot. It draws the static key
 * d, it writes the key file of the service, and it prints the static
 * public key P of each client provision.
 *
 * The sandbox comes first. main() drops the core limit, it pledges,
 * it resolves the owner of the key file, and it then unveils the
 * target directory alone (SEC-MEMORY-5, PROG-KEYGEN-5). The passwd
 * lookup comes before the unveil calls, because it reads a database
 * outside that directory.
 *
 * The key lives in one stack buffer, and each exit path clears it
 * under one goto out (SEC-MEMORY-1, SEC-MEMORY-2). A failure after
 * the creation of the file removes the file, so the next run starts
 * clean.
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cipher.h"

/*
 * The target directory and the key file, compile-time constants
 * (D-06). This program runs outside the chroot, so the two paths
 * hold the /var/www prefix that the chroot hides (PROG-KEYGEN-2).
 */
#define KEY_DIR		"/var/www/fuguoracle"
#define KEY_PATH	KEY_DIR "/private.key"

/* The owner of the key file (PROG-KEYGEN-2). */
#define KEY_OWNER	"_fuguoracle"

/* The mode of the key file (PROG-KEYGEN-2). */
#define KEY_MODE	0400

/*
 * The draw count of one run. A draw gives a scalar out of the range
 * of the curve with a probability near 2^-128, so one draw answers
 * (PROG-KEYGEN-1). The bound stops a run that a library failure
 * holds.
 */
#define KEY_TRIES	8

int
main(void)
{
	struct rlimit	 rl = { 0, 0 };
	struct passwd	*pw;
	uint8_t		 key[CIPHER_KEY_LEN];
	uint8_t		 pub[CIPHER_PUBKEY_LEN];
	size_t		 i;
	int		 fd = -1, tries, rc = 1;

	if (setrlimit(RLIMIT_CORE, &rl) == -1)
		err(1, "setrlimit");
	if (pledge("stdio rpath wpath cpath fattr chown getpw unveil",
	    NULL) == -1)
		err(1, "pledge");
	if ((pw = getpwnam(KEY_OWNER)) == NULL)
		errx(1, "%s: the passwd entry is absent", KEY_OWNER);
	if (unveil(KEY_DIR, "rwc") == -1)
		err(1, "unveil");
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");
	if (pledge("stdio rpath wpath cpath fattr chown", NULL) == -1)
		err(1, "pledge");

	/*
	 * The draw repeats while the scalar sits outside the range of
	 * the curve (PROG-KEYGEN-1). The shim verifies the key, and
	 * it answers the public key of a valid one.
	 */
	for (tries = 0; tries < KEY_TRIES; tries++) {
		cipher_random(key, sizeof(key));
		if (cipher_pubkey(key, pub) == 0)
			break;
	}
	if (tries == KEY_TRIES) {
		warnx("the draw of the key failed");
		goto out;
	}

	/*
	 * O_EXCL refuses an existing key file (PROG-KEYGEN-3), and
	 * the two calls on the descriptor set the owner and the mode
	 * of the new file (PROG-KEYGEN-2).
	 */
	if ((fd = open(KEY_PATH, O_WRONLY | O_CREAT | O_EXCL,
	    KEY_MODE)) == -1) {
		warn("%s", KEY_PATH);
		goto out;
	}
	if (write(fd, key, sizeof(key)) != (ssize_t)sizeof(key)) {
		warn("%s", KEY_PATH);
		goto out;
	}
	if (fchown(fd, pw->pw_uid, pw->pw_gid) == -1) {
		warn("%s", KEY_PATH);
		goto out;
	}
	if (fchmod(fd, KEY_MODE) == -1) {
		warn("%s", KEY_PATH);
		goto out;
	}
	if (fsync(fd) == -1) {
		warn("%s", KEY_PATH);
		goto out;
	}

	/* The compressed public key, as 66 hex digits (PROG-KEYGEN-4). */
	for (i = 0; i < sizeof(pub); i++)
		printf("%02x", pub[i]);
	printf("\n");
	if (fflush(stdout) == EOF) {
		warn("stdout");
		goto out;
	}
	rc = 0;
out:
	explicit_bzero(key, sizeof(key));
	if (fd != -1) {
		close(fd);
		if (rc != 0)
			unlink(KEY_PATH);
	}
	return rc;
}
