# 004 — The two programs

## Status

Proposed. It can land now, because the tree holds the operations and the
transcript pair. Plan 005 waits on it.

Implements: OVW-PURPOSE, PROTO-HTTP, PROTO-ENVELOPE, PROTO-PAYLOAD,
PROTO-RESPONSE, PROG-CGI, PROG-KEYGEN, SEC-LOGGING. Implements: SEC-SANDBOX
without SEC-SANDBOX-4. Implements: ARCH-DEPS, ARCH-LAYOUT, SEC-MEMORY, OPS-SET,
OPS-GET, OPS-JUNK, OPS-WIPE. Defers: DEPLOY-HTTPD, DEPLOY-SERVICE.

This plan lands the absent part of each `partial` unit that it cites. PROTO-HTTP
lands the error status of PROTO-ENVELOPE-2, PROTO-PAYLOAD-5, OPS-SET-7 and
OPS-GET-7, and the status and the headers of OPS-JUNK. It also lands the base64
value and the JSON object of PROTO-RESPONSE-3. PROG-CGI serves a client, and it
lands OVW-PURPOSE-3 and OVW-PURPOSE-4. This plan also lands ARCH-DEPS-4,
ARCH-LAYOUT-4, SEC-MEMORY-5 and OPS-WIPE-3. The deployment files are the work of
plan 005, and its rc.d script lands SEC-SANDBOX-4. This plan runs the program
directly, with the CGI variables in the environment.

## Purpose

`fuguoracle` is the CGI program, and `fuguoracle-keygen` makes its static key.
This plan lands `main.c`, `http.c`, and `keygen.c`, the two manual pages, the
sandbox, and the log line. After it, the service answers a request.

## Constraints that shape the design

**The sandbox comes before the first byte.** `main()` sets `RLIMIT_CORE` to
zero, then pledges. It unveils the key path and the record directory, and
pledges again with the reduced set (SEC-SANDBOX-1 to SEC-SANDBOX-3). The program
reads no request byte before that.

**The two paths are constants.** `KEY_PATH` and `PINS_DIR` are compile-time
constants (D-06, PROG-CGI-4). The regress build compiles the program with its
own key path constant and its own `PINS_DIR` constant, both directories of the
regress tree. Each path stays a compile-time constant. `regress/cgi.sh` writes
the static private key of the vectors to that key path before the run.

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
- A payload of another length, a replayed `set_pin`, and a `get_pin` over a
  record with no read permission each answer `500`. A payload length violation
  and a signature recovery failure are internal failures (PROTO-PAYLOAD-5).
  OPS-SET-7 gives every `set_pin` failure after envelope decryption an HTTP
  error status. An I/O failure on load, and every persist failure, are internal
  failures (OPS-GET-7). The test encrypts the payload of another length with the
  request keys of the tweak vector in `regress/vectors.h`.
- A `set_pin` and a `get_pin` round trip answer `200` with the header of
  PROTO-HTTP-6. The test reads the transcript pair of one client key from
  `regress/vectors.h`, and sends each request envelope as base64. The
  `replay_counter` of the `get_pin` envelope is above the counter of the
  `set_pin` envelope.
- A wrong PIN, a missing record, and a replayed `get_pin` each answer `200` with
  a valid response envelope (OPS-JUNK-1). The three junk paths answer one
  identical status and one identical header set. OPS-JUNK-2 makes the status,
  the headers, and the envelope size identical on every junk path. The body of
  each answer holds the 96-byte envelope of PROTO-RESPONSE-2, as base64 in the
  `data` member.
- The log line holds the outcome class and no hex of the request.
- The line count of the C sources stays near the target of ARCH-LAYOUT-4.

The keygen test runs in the guest as root. It writes the key with mode `0400`
and the owner `_fuguoracle`, refuses a second run, and prints 66 hex digits.

## Acceptance

- `make check` passes on the host, and `regress/guest` passes in the guest.
- Every cited unit reads `done`, except SEC-SANDBOX, which reads `partial` with
  SEC-SANDBOX-4 as the absent part.
- The change deletes this plan.

The round trip through `httpd(8)` and `slowcgi(8)` belongs to plan 005, which
lands the deployment files and the interop harness.

## What this plan does not do

It ships no `httpd.conf`, no rc.d script, and no pkg-readme. It runs no upstream
test suite.
