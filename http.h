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
 * The CGI surface of the service: one call reads the request, and
 * two calls write the answer (PROTO-HTTP, PROG-CGI).
 *
 * The calls hold no state of the oracle, and they read no key and no
 * record. The caller dispatches on REQUEST_METHOD and DOCUMENT_URI
 * (PROG-CGI-1), and it maps each failure below to a status.
 */

#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdint.h>

/* The bytes of the longest request body (PROTO-HTTP-2). */
#define HTTP_BODY_MAX	4096

/*
 * The bytes of the longest data value, in each direction. A body of
 * HTTP_BODY_MAX base64 characters decodes to this length.
 */
#define HTTP_DATA_MAX	(HTTP_BODY_MAX / 4 * 3)

/* The statuses of the failure table (PROTO-HTTP). */
enum http_status {
	HTTP_STATUS_OK		= 200,
	HTTP_STATUS_BAD_REQUEST	= 400,
	HTTP_STATUS_NOT_FOUND	= 404,
	HTTP_STATUS_BAD_METHOD	= 405,
	HTTP_STATUS_TOO_LARGE	= 413,
	HTTP_STATUS_INTERNAL	= 500
};

/*
 * The answer of http_request(). The caller maps each failure to one
 * status of the table above: HTTP_STATUS_BAD_REQUEST for
 * HTTP_MALFORMED, HTTP_STATUS_TOO_LARGE for HTTP_TOO_LARGE, and
 * HTTP_STATUS_INTERNAL for HTTP_IO (PROTO-HTTP-2 to PROTO-HTTP-4).
 * HTTP_IO reports an I/O error, so the caller logs it
 * (SEC-LOGGING-2).
 */
enum http_result {
	HTTP_OK,
	HTTP_MALFORMED,
	HTTP_TOO_LARGE,
	HTTP_IO
};

/*
 * http_request(out, out_size, out_len):
 *	The request envelope of one POST request. CONTENT_LENGTH
 *	carries the body length, and the call reads exactly that
 *	many bytes from standard input (PROG-CGI-2). It extracts the
 *	one data member of the body, and it decodes the base64 of
 *	that member into out (PROTO-HTTP-7, PROTO-ENVELOPE). out_len
 *	takes the envelope length, and out_size counts HTTP_DATA_MAX
 *	bytes for the longest answer.
 *
 *	An absent CONTENT_LENGTH, a value that is not a decimal
 *	number, a body shorter than that value, a body of another
 *	shape, and a decode that out cannot hold each answer
 *	HTTP_MALFORMED. A value above HTTP_BODY_MAX answers
 *	HTTP_TOO_LARGE, and a read failure answers HTTP_IO. Each
 *	answer but HTTP_OK writes 0 to out_len, and a failed decode
 *	can leave a part of its answer in out.
 */
enum http_result	http_request(uint8_t *, size_t, size_t *);

/*
 * http_respond(status):
 *	One answer with an empty body (PROTO-HTTP-6). The liveness
 *	answer of GET / carries HTTP_STATUS_OK, and each error
 *	answer carries its status of the failure table. The call
 *	answers 0, or -1 on a write failure.
 */
int	http_respond(enum http_status);

/*
 * http_respond_data(env, env_len):
 *	The 200 answer of a POST request. The header block holds
 *	Content-Type: application/json, and the body holds the
 *	base64 of env in the data member (PROTO-HTTP-6,
 *	PROTO-RESPONSE-3). env_len counts at most HTTP_DATA_MAX
 *	bytes. The call answers 0, or -1 on a failure.
 */
int	http_respond_data(const uint8_t *, size_t);

#endif /* HTTP_H */
