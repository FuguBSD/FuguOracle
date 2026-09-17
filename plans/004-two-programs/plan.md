# 004 — The two programs

## Status

Proposed. It waits on plan 003 for the operations. Plan 005 waits on it.

Implements: PROTO-HTTP, PROG-CGI, PROG-KEYGEN, SEC-SANDBOX, SEC-LOGGING.
Implements: ARCH-LAYOUT, SEC-MEMORY, OPS-WIPE. Defers: DEPLOY-HTTPD,
DEPLOY-SERVICE.

Of the three shared units, this plan lands ARCH-LAYOUT-4, SEC-MEMORY-5, and
OPS-WIPE-3, and each unit reaches `done`. The deployment files are the work of
plan 005. This plan runs the program under a hand-made `httpd(8)` and
`slowcgi(8)` in the guest.

## Purpose

`fuguoracle` is the CGI program, and `fuguoracle-keygen` makes its static key.
This plan lands `main.c`, `http.c`, and `keygen.c`, the two manual pages, the
sandbox, and the log line. After it, the service answers a request.

## Constraints that shape the design

**The sandbox comes before the first byte.** `main()` sets `RLIMIT_CORE` to
zero, then pledges. It unveils the key path and the record directory, and
pledges again with the reduced set (SEC-SANDBOX-1 to SEC-SANDBOX-3). The program
reads no request byte before that.

**The dispatch reads two variables.** `REQUEST_METHOD` and `DOCUMENT_URI` name
the endpoint (PROG-CGI-1). `CONTENT_LENGTH` must be a decimal number of at most
4096, and the program reads exactly that many bytes (PROG-CGI-2).

**The JSON reader is a scanner.** `http.c` extracts the one `data` member of one
object, accepts insignificant whitespace, and ignores unknown members. It
rejects a duplicate `data` member and every other shape (PROTO-HTTP-7). The
base64 decode is `b64_pton(3)`. The program uses no JSON library.

**Every failure has one status.** The failure table of PROTO-HTTP is the
contract: `404`, `405`, `413`, `400`, or `500`, with an empty body. A `200`
answer carries `Content-Type: application/json` (PROTO-HTTP-6).

**One log line per request.** `openlog("fuguoracle", LOG_PID, LOG_DAEMON)`, then
one `syslog(3)` line with the outcome class (SEC-LOGGING-1, SEC-LOGGING-2). A
wipe logs at `LOG_WARNING`, and every I/O error logs (OPS-WIPE-3). No line holds
key material, a payload, `cke`, or a record name at the default level
(SEC-LOGGING-3).

**The keygen refuses to overwrite.** It resolves `_fuguoracle` with
`getpwnam(3)` before it unveils, and draws until `secp256k1_ec_seckey_verify`
passes. It writes the key with mode `0400` and prints the compressed public key
as hex (PROG-KEYGEN-1 to PROG-KEYGEN-5).

## Files

| File                  | Change                                                 |
| --------------------- | ------------------------------------------------------ |
| `main.c`              | The sandbox, the dispatch, the body read, the log line |
| `http.c`, `http.h`    | The JSON scanner, base64, the response writer          |
| `keygen.c`            | `fuguoracle-keygen`                                    |
| `fuguoracle.8`        | The manual page of the service                         |
| `fuguoracle-keygen.8` | The manual page of the key generator                   |
| `Makefile`            | The second program and the two pages                   |
| `regress/Makefile`    | The `cgi` target                                       |
| `regress/cgi.sh`      | The tests below                                        |
| `spec/STATUS.md`      | The cited units                                        |

The manual page of the service states the weak deletion guarantee of the wipe
and the compile-time paths (D-06).

## Tests

`regress/cgi.sh` runs the program directly, with the CGI variables in the
environment and the body on standard input, and holds:

- `GET /` answers `200` with an empty body.
- An unknown path answers `404`, and a wrong method answers `405`.
- A `CONTENT_LENGTH` above 4096 answers `413`.
- Malformed JSON, bad base64, a duplicate `data` member, and a short envelope
  answer `400`.
- A `set_pin` and a `get_pin` round trip answer `200` with the header of
  PROTO-HTTP-6, through the fixed random file.
- The log line holds the outcome class and no hex of the request.
- The line count of the C sources stays near the target of ARCH-LAYOUT-4.

The keygen test runs in the guest as root. It writes the key with mode `0400`
and the owner `_fuguoracle`, refuses a second run, and prints 66 hex digits.

## Acceptance

- `make check` passes on the host, and `regress/guest` passes in the guest.
- In the guest, `slowcgi(8)` and `httpd(8)` serve one `set_pin` and one
  `get_pin` from the upstream `client.py`.
- Every cited unit reads `done`.
- The change deletes this plan.

## What this plan does not do

It ships no `httpd.conf`, no rc.d script, and no pkg-readme. It runs no upstream
test suite.
