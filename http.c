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
 * The CGI surface. This file holds the body read, the JSON scanner,
 * the base64 pair of libc, and the response writer. It calls no JSON
 * library, and it holds no state of the oracle (PROTO-HTTP-7).
 *
 * Every byte of this file travels on the wire: a request envelope, a
 * response envelope, and the base64 of each one. No secret passes
 * through, so no buffer here needs explicit_bzero(3). The envelope
 * carries each secret of a request, and cipher.c opens it
 * (SEC-MEMORY-1).
 */

#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"

/* The one member that the scanner reads (PROTO-HTTP-7). */
#define DATA_NAME	"data"

/* The base64 of HTTP_DATA_MAX bytes, with the NUL byte. */
#define B64_MAX		((HTTP_DATA_MAX + 2) / 3 * 4 + 1)

/* The bytes of a number, of true, of false, and of null. */
#define TOKEN_BYTES	"+-.0123456789Eaeflnrstu"

/* The cursor of the scanner: the next byte, and the end of the body. */
struct scan {
	const char	*p;
	const char	*end;
};

static enum http_result	 read_body(char *, size_t, size_t *);
static void		 skip_ws(struct scan *);
static int		 take(struct scan *, char);
static int		 scan_string(struct scan *, const char **, size_t *,
			    int *);
static int		 scan_token(struct scan *);
static int		 scan_value(struct scan *);
static int		 scan_data(const char *, size_t, const char **,
			    size_t *);
static int		 header(enum http_status, const char *);
static int		 flush(void);

/*
 * The body of one POST request (PROG-CGI-2). CONTENT_LENGTH carries
 * the length, and the reader takes exactly that many bytes from
 * standard input. buf_size counts HTTP_BODY_MAX bytes, the cap of
 * PROTO-HTTP-2, so one test answers a body above the cap and a body
 * above the buffer.
 */
static enum http_result
read_body(char *buf, size_t buf_size, size_t *len)
{
	const char	*cl;
	size_t		 n = 0, off = 0;
	ssize_t		 r;

	*len = 0;
	if ((cl = getenv("CONTENT_LENGTH")) == NULL || *cl == '\0')
		return HTTP_MALFORMED;
	for (; *cl != '\0'; cl++) {
		if (*cl < '0' || *cl > '9')
			return HTTP_MALFORMED;
		n = n * 10 + (size_t)(*cl - '0');
		if (n > buf_size)
			return HTTP_TOO_LARGE;
	}
	while (off < n) {
		r = read(STDIN_FILENO, buf + off, n - off);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			return HTTP_IO;
		}
		if (r == 0)
			return HTTP_MALFORMED;	/* a short body */
		off += (size_t)r;
	}
	*len = n;
	return HTTP_OK;
}

/* Step over the insignificant whitespace of JSON (PROTO-HTTP-7). */
static void
skip_ws(struct scan *s)
{
	while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' ||
	    *s->p == '\n' || *s->p == '\r'))
		s->p++;
}

/* Take one byte c. Every other byte answers -1, and it stays. */
static int
take(struct scan *s, char c)
{
	if (s->p == s->end || *s->p != c)
		return -1;
	s->p++;
	return 0;
}

/*
 * The span of one JSON string. The cursor stands on the opening
 * quote, and a 0 answer leaves it after the closing quote. val and
 * len take the bytes between the quotes, and esc answers 1 for a
 * string with an escape sequence. A control byte and an unterminated
 * string each answer -1. The control byte test rejects the NUL byte,
 * so the decoder below reads the whole value of a data member.
 */
static int
scan_string(struct scan *s, const char **val, size_t *len, int *esc)
{
	const char	*start;

	*esc = 0;
	if (take(s, '"') != 0)
		return -1;
	start = s->p;
	while (s->p < s->end && *s->p != '"') {
		if ((unsigned char)*s->p < 0x20)
			return -1;
		if (*s->p == '\\') {
			*esc = 1;
			if (++s->p == s->end)
				return -1;
		}
		s->p++;
	}
	if (take(s, '"') != 0)
		return -1;
	*val = start;
	*len = (size_t)(s->p - 1 - start);
	return 0;
}

/* Step over one number, one true, one false, or one null. */
static int
scan_token(struct scan *s)
{
	const char	*start = s->p;

	while (s->p < s->end && *s->p != '\0' &&
	    strchr(TOKEN_BYTES, *s->p) != NULL)
		s->p++;
	return s->p == start ? -1 : 0;
}

/*
 * Step over the value of an unknown member (PROTO-HTTP-7). A string
 * carries its own escape sequences, and an object or an array runs
 * to the byte that closes it. The scanner reads the extent of such a
 * value, and it reads no grammar inside it. Every other value is one
 * token. The cursor stops on the byte after the value.
 */
static int
scan_value(struct scan *s)
{
	const char	*val;
	size_t		 len, depth = 0;
	int		 esc;

	do {
		if (s->p == s->end)
			return -1;
		switch (*s->p) {
		case '"':
			if (scan_string(s, &val, &len, &esc) != 0)
				return -1;
			break;
		case '{':
		case '[':
			depth++;
			s->p++;
			break;
		case '}':
		case ']':
			if (depth == 0)
				return -1;
			depth--;
			s->p++;
			break;
		case ',':
		case ':':
			if (depth == 0)
				return -1;
			s->p++;
			break;
		default:
			if (scan_token(s) != 0)
				return -1;
			break;
		}
		skip_ws(s);
	} while (depth > 0);
	return 0;
}

/*
 * The base64 value of the data member of one request body
 * (PROTO-HTTP-7). val and len take the bytes of the value. The
 * scanner accepts one object with one data member of a string, and
 * it steps over each other member. A second data member, a data
 * member with an escape sequence, a data member of another type, a
 * byte after the object, and every other shape answer -1. An object
 * with no data member answers -1 as well, because the service reads
 * one shape only.
 */
static int
scan_data(const char *body, size_t body_len, const char **val, size_t *len)
{
	struct scan	 s;
	const char	*name;
	size_t		 name_len;
	int		 esc, found = 0;

	s.p = body;
	s.end = body + body_len;
	skip_ws(&s);
	if (take(&s, '{') != 0)
		return -1;
	skip_ws(&s);
	for (;;) {
		if (scan_string(&s, &name, &name_len, &esc) != 0)
			return -1;
		skip_ws(&s);
		if (take(&s, ':') != 0)
			return -1;
		skip_ws(&s);
		if (esc == 0 && name_len == sizeof(DATA_NAME) - 1 &&
		    memcmp(name, DATA_NAME, name_len) == 0) {
			if (found)
				return -1;
			if (scan_string(&s, val, len, &esc) != 0 || esc != 0)
				return -1;
			found = 1;
		} else if (scan_value(&s) != 0)
			return -1;
		skip_ws(&s);
		if (take(&s, ',') != 0)
			break;
		skip_ws(&s);
	}
	if (take(&s, '}') != 0)
		return -1;
	skip_ws(&s);
	return found && s.p == s.end ? 0 : -1;
}

enum http_result
http_request(uint8_t *out, size_t out_size, size_t *out_len)
{
	char			 body[HTTP_BODY_MAX];
	char			 b64[HTTP_BODY_MAX + 1];
	const char		*val;
	size_t			 body_len, len;
	int			 n;
	enum http_result	 res;

	*out_len = 0;
	if ((res = read_body(body, sizeof(body), &body_len)) != HTTP_OK)
		return res;
	if (scan_data(body, body_len, &val, &len) != 0)
		return HTTP_MALFORMED;

	/*
	 * b64_pton(3) reads a string, and the value of the member
	 * holds no NUL byte, so the copy below terminates it. The
	 * value is a part of the body, and the buffer takes the
	 * longest body with that byte.
	 */
	memcpy(b64, val, len);
	b64[len] = '\0';
	if ((n = b64_pton(b64, out, out_size)) < 0)
		return HTTP_MALFORMED;
	*out_len = (size_t)n;
	return HTTP_OK;
}

/*
 * The header block of one answer. Each line ends with CRLF, and the
 * empty line closes the block (PROG-CGI-3). A NULL type writes no
 * Content-Type header, and the answer then carries an empty body
 * (PROTO-HTTP-6).
 */
static int
header(enum http_status status, const char *type)
{
	if (printf("Status: %d\r\n", status) < 0)
		return -1;
	if (type != NULL && printf("Content-Type: %s\r\n", type) < 0)
		return -1;
	if (printf("\r\n") < 0)
		return -1;
	return 0;
}

/* The bytes of the answer, on standard output. */
static int
flush(void)
{
	if (fflush(stdout) != 0 || ferror(stdout))
		return -1;
	return 0;
}

int
http_respond(enum http_status status)
{
	if (header(status, NULL) != 0)
		return -1;
	return flush();
}

int
http_respond_data(const uint8_t *env, size_t env_len)
{
	char	 b64[B64_MAX];

	if (env_len > HTTP_DATA_MAX)
		return -1;
	if (b64_ntop(env, env_len, b64, sizeof(b64)) < 0)
		return -1;
	if (header(HTTP_STATUS_OK, "application/json") != 0)
		return -1;

	/*
	 * The framing is the framing of the upstream server: no space
	 * after the colon, and one newline after the closing brace, so
	 * the acceptance compares the two bodies byte for byte
	 * (PROTO-RESPONSE-3, D-12).
	 */
	if (printf("{\"data\":\"%s\"}\n", b64) < 0)
		return -1;
	return flush();
}
