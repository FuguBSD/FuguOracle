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
 * The CGI entry of the service. This file holds the sandbox, the
 * dispatch of the three endpoints, the read of the static key, and
 * the log line of one request (PROG-CGI, SEC-SANDBOX, SEC-LOGGING).
 *
 * The sandbox comes first. main() drops the core limit, it pledges,
 * it unveils the key file and the record directory, and it pledges
 * again with the reduced set. The program reads no request byte
 * before the second pledge (SEC-MEMORY-5, SEC-SANDBOX-1 to
 * SEC-SANDBOX-3).
 *
 * The dispatch reads REQUEST_METHOD and DOCUMENT_URI, and it accepts
 * three pairs (PROG-CGI-1). The failure table of PROTO-HTTP holds
 * the status of each answer:
 *
 *	GET /			200, with an empty body
 *	an unknown path		404
 *	a wrong method		405
 *	a malformed body	400
 *	a body above the cap	413
 *	ORACLE_RESPOND		200, with the response envelope
 *	ORACLE_REJECT		400
 *	ORACLE_FAILURE		500
 *	an I/O failure		500
 *
 * The static key lives in one stack buffer, and each exit path
 * clears it under one goto out (SEC-MEMORY-1, SEC-MEMORY-2). One log
 * line carries the outcome class and the status of the answer. No
 * line holds key material, a payload, cke or a record name
 * (SEC-LOGGING-3).
 */

#include <sys/types.h>
#include <sys/resource.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "cipher.h"
#include "http.h"
#include "oracle.h"
#include "pindb.h"

/*
 * The static key file, a compile-time constant (D-06). The path sits
 * inside the /var/www chroot, and it holds 32 raw bytes
 * (PROG-CGI-4). The regress build names a file of its own on the
 * command line, and the path stays a compile-time constant there.
 */
#ifndef KEY_PATH
#define KEY_PATH	"/fuguoracle/private.key"
#endif

/* The three paths of the HTTP surface (PROTO-HTTP). */
#define PATH_LIVE	"/"
#define PATH_SET	"/set_pin"
#define PATH_GET	"/get_pin"

static const char	*class_name(enum oracle_outcome);
static int		 read_key(uint8_t *);
static enum http_status	 handle_post(enum oracle_op, struct oracle_response *,
			    enum oracle_outcome *);

/*
 * The name of one outcome class (SEC-LOGGING-2). The liveness answer
 * of GET / is a successful GET, so it carries ORACLE_OUT_OK_GET.
 */
static const char *
class_name(enum oracle_outcome outcome)
{
	switch (outcome) {
	case ORACLE_OUT_OK_SET:
		return "ok_set";
	case ORACLE_OUT_OK_GET:
		return "ok_get";
	case ORACLE_OUT_JUNK:
		return "junk";
	case ORACLE_OUT_REJECT:
		return "reject";
	case ORACLE_OUT_ERROR:
		break;
	}
	return "error";
}

/*
 * The static key d of KEY_PATH. key takes CIPHER_KEY_LEN bytes. The
 * reader takes one byte above that length, so a longer file answers
 * -1 (PROG-CGI-4). A failed open, a short file and a read failure
 * answer -1 as well, and the answer then clears key.
 */
static int
read_key(uint8_t *key)
{
	uint8_t	 buf[CIPHER_KEY_LEN + 1];
	size_t	 off = 0;
	ssize_t	 r;
	int	 fd, rc = -1;

	if ((fd = open(KEY_PATH, O_RDONLY)) == -1)
		return -1;
	while (off < sizeof(buf)) {
		r = read(fd, buf + off, sizeof(buf) - off);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (r == 0)
			break;
		off += (size_t)r;
	}
	if (off != CIPHER_KEY_LEN)
		goto out;
	memcpy(key, buf, CIPHER_KEY_LEN);
	rc = 0;
out:
	explicit_bzero(buf, sizeof(buf));
	close(fd);
	if (rc != 0)
		explicit_bzero(key, CIPHER_KEY_LEN);
	return rc;
}

/*
 * The answer of one POST request. op names the endpoint, and res
 * takes the response envelope of a 200 answer. outcome takes the
 * class of the log line, on every path. Each I/O failure writes a
 * line of its own (SEC-LOGGING-2).
 */
static enum http_status
handle_post(enum oracle_op op, struct oracle_response *res,
    enum oracle_outcome *outcome)
{
	uint8_t			 env[HTTP_DATA_MAX];
	uint8_t			 key[CIPHER_KEY_LEN];
	size_t			 env_len = 0;
	enum http_status	 status = HTTP_STATUS_INTERNAL;

	memset(key, 0, sizeof(key));
	*outcome = ORACLE_OUT_ERROR;
	switch (http_request(env, sizeof(env), &env_len)) {
	case HTTP_OK:
		break;
	case HTTP_MALFORMED:
		*outcome = ORACLE_OUT_REJECT;
		status = HTTP_STATUS_BAD_REQUEST;
		goto out;
	case HTTP_TOO_LARGE:
		*outcome = ORACLE_OUT_REJECT;
		status = HTTP_STATUS_TOO_LARGE;
		goto out;
	case HTTP_IO:
		syslog(LOG_ERR, "the read of the request body failed");
		goto out;
	}
	if (read_key(key) != 0) {
		syslog(LOG_ERR, "the read of the static key failed");
		goto out;
	}
	switch (oracle_handle(key, op, env, env_len, res, outcome)) {
	case ORACLE_RESPOND:
		status = HTTP_STATUS_OK;
		break;
	case ORACLE_REJECT:
		status = HTTP_STATUS_BAD_REQUEST;
		break;
	case ORACLE_FAILURE:
		status = HTTP_STATUS_INTERNAL;
		break;
	}
out:
	explicit_bzero(key, sizeof(key));
	return status;
}

int
main(void)
{
	struct rlimit		 rl = { 0, 0 };
	struct oracle_response	 res;
	const char		*method, *uri;
	enum oracle_outcome	 outcome = ORACLE_OUT_REJECT;
	enum http_status	 status;
	int			 rc;

	if (setrlimit(RLIMIT_CORE, &rl) == -1)
		err(1, "setrlimit");
	if (pledge("stdio rpath wpath cpath flock unveil", NULL) == -1)
		err(1, "pledge");
	if (unveil(KEY_PATH, "r") == -1)
		err(1, "unveil");
	if (unveil(PINS_DIR, "rwc") == -1)
		err(1, "unveil");
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");
	if (pledge("stdio rpath wpath cpath flock", NULL) == -1)
		err(1, "pledge");

	openlog("fuguoracle", LOG_PID, LOG_DAEMON);
	memset(&res, 0, sizeof(res));
	if ((method = getenv("REQUEST_METHOD")) == NULL)
		method = "";
	if ((uri = getenv("DOCUMENT_URI")) == NULL)
		uri = "";

	/*
	 * An unknown path answers 404, and a known path with another
	 * method answers 405 (PROTO-HTTP-5). An absent variable
	 * names no path and no method, so it answers 404.
	 */
	if (strcmp(uri, PATH_LIVE) == 0) {
		if (strcmp(method, "GET") != 0)
			status = HTTP_STATUS_BAD_METHOD;
		else {
			status = HTTP_STATUS_OK;
			outcome = ORACLE_OUT_OK_GET;
		}
	} else if (strcmp(uri, PATH_SET) == 0 || strcmp(uri, PATH_GET) == 0) {
		if (strcmp(method, "POST") != 0)
			status = HTTP_STATUS_BAD_METHOD;
		else
			status = handle_post(strcmp(uri, PATH_SET) == 0 ?
			    ORACLE_OP_SET : ORACLE_OP_GET, &res, &outcome);
	} else
		status = HTTP_STATUS_NOT_FOUND;

	/*
	 * The 200 answer of a POST request carries the response
	 * envelope, and every other answer carries an empty body
	 * (PROTO-HTTP-6).
	 */
	if (status == HTTP_STATUS_OK && res.len > 0)
		rc = http_respond_data(res.env, res.len);
	else
		rc = http_respond(status);
	if (rc != 0)
		syslog(LOG_ERR, "the write of the answer failed");
	syslog(LOG_INFO, "%s %d", class_name(outcome), status);
	return rc == 0 ? 0 : 1;
}
