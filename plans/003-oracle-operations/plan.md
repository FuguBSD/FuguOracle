# 003 — The oracle operations

## Status

Proposed. It waits on plan 002 for the store. Plan 004 waits on it.

Implements: PROTO-ENVELOPE, PROTO-PAYLOAD, OPS-SET, OPS-GET, OPS-JUNK,
OVW-PURPOSE. Implements: PROTO-RESPONSE without PROTO-RESPONSE-3. Defers:
PROTO-HTTP, SEC-LOGGING, TEST-ACCEPT.

The operations return a decision and an outcome class. Plan 004 maps the
decision to an HTTP status (PROTO-HTTP) and writes the outcome class to the log
(SEC-LOGGING). PROTO-RESPONSE-3 encodes the envelope as base64 and returns the
JSON object, and plan 004 lands it. The draw order of TEST-ACCEPT-2 binds this
plan, and plan 005 proves it against the upstream server.

## Purpose

`oracle.c` is the state machine of the service: bytes in, bytes out. It takes
the operation and the decoded envelope, and it returns the response envelope or
a decision to reject. It never touches HTTP, JSON, or base64. This plan lands
that file, with the envelope layout, the two payload forms, the `set_pin` and
`get_pin` rules, and the junk path. With it, the purpose of the oracle holds in
code: the service learns no PIN and no secret (OVW-PURPOSE-1, OVW-PURPOSE-2).

## Constraints that shape the design

**One entry point.** `oracle_handle(op, envelope, len, &response, &outcome)`
returns one of three decisions: a `200` response, a client error, or an internal
failure. The outcome class is `ok_set`, `ok_get`, `junk`, `reject`, or `error`.
The caller of plan 004 turns the decision into a status and logs the class.

**The order of checks is the order of the protocol.** First the envelope length
and the block alignment (PROTO-ENVELOPE-1, PROTO-ENVELOPE-2). Then the tweak and
the open through the shim. Then the payload length and the recovery
(PROTO-PAYLOAD-1 to PROTO-PAYLOAD-5). Every failure up to here is a reject or an
internal failure, never junk (PROTO-HTTP-8). After the payload extracts, a
`get_pin` failure other than I/O takes the junk path, and a `set_pin` failure is
an internal failure (D-10).

**The draws follow the upstream order.** The byte-identity harness needs both
servers to draw the same bytes for the same step (TEST-ACCEPT-2). On a wrong
PIN, the store write and its IV come before the junk key. On a success, the
storage IV comes before the response IV. The code draws through the seam in
exactly the order of the draw table.

**A change persists before an answer.** The store call precedes the response on
every path that changes a record (OPS-GET-7). An I/O failure on that store is an
internal failure, never junk.

## Files

| File                   | Change                                                  |
| ---------------------- | ------------------------------------------------------- |
| `oracle.c`, `oracle.h` | The envelope, the payload, the decisions, the junk path |
| `regress/Makefile`     | The `ops` target                                        |
| `regress/ops.c`        | The tests below, with a regress-side client             |
| `spec/STATUS.md`       | The cited units                                         |

The regress-side client builds request envelopes with the shim: an ephemeral
key, the tweaked static public key, the signed payload hash, and the seal. It
signs with `secp256k1_ecdsa_sign_recoverable`, which the service never calls.

## Tests

`regress/ops` holds:

- A `set_pin` then a `get_pin` return the same key, and the record holds
  `count = 0` and the client counter (OPS-SET-4, OPS-GET-4).
- A `set_pin` without `entropy` and a `set_pin` with a stale counter are
  internal failures (OPS-SET-1, OPS-SET-2, OPS-SET-7).
- A wrong PIN twice then the correct PIN: two junk answers, then the real key,
  then `count = 0` (OPS-GET-5).
- A wrong PIN three times: junk, junk, then the wipe, then junk for every later
  request (OPS-GET-6).
- A stale and an equal counter take the junk path and move no count (OPS-GET-2).
- A missing record and a corrupt record take the junk path (OPS-GET-2).
- Every junk answer has the same envelope size, and two junk answers differ
  (OPS-JUNK-1, OPS-JUNK-2).
- Both payload forms pass on `get_pin`, and the 97-byte form fails on `set_pin`
  (OPS-GET-1, OPS-SET-1).
- An envelope of 100 bytes and a ciphertext of 17 bytes are rejects
  (PROTO-ENVELOPE-1, PROTO-ENVELOPE-2).
- The response envelope has 96 bytes (PROTO-RESPONSE-2).
- With the fixed random file, the draws of each path match the draw table.

## Acceptance

- `make check` passes on the host, and `regress/guest` passes in the guest.
- Every cited unit reads `done`, except PROTO-RESPONSE, which reads `partial`
  with PROTO-RESPONSE-3 as the absent part.
- The change deletes this plan.

## What this plan does not do

It reads no CGI variable and writes no status line. It logs nothing.
