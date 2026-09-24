# 005 — The deployment files and the interop harness

## Status

Proposed. It can land now, because the tree holds the two programs. Plan 006 and
plan 007 wait on it. It needs the OpenBSD guest that the `fuguvm` tool supplies.

Implements: ARCH-STACK without ARCH-STACK-3. Implements: TEST-INTEROP,
TEST-ACCEPT. Defers: DEPLOY-BACKUP, PKG-ORACLE, TEST-FUZZ.

The root `Makefile` links the two programs static, so ARCH-STACK-3 is done. The
rc.d script lands SEC-SANDBOX-4, the one open rule of that unit. The rc.d script
and the `httpd.conf` fragment land in the port directory, so plan 007 packages
them without a move. The pkg-readme, the backup text, and the port build are the
work of plan 007. The fuzzer is plan 006.

## Purpose

The service runs behind `httpd(8)` and `slowcgi(8)`, one process per request
(D-04). This plan lands the two deployment files. It lands the harness that
points the upstream `client.py` and test suite at the full stack in the guest.
It also lands the byte-identity comparison of D-12: the same requests, the same
fixed random bytes, the same `200` bodies from both servers.

## Constraints that shape the design

**The deployment files are port files.**
`ports/security/fuguoracle/pkg/fuguoracle.rc` wraps the base `slowcgi(8)` with
the flags of DEPLOY-SERVICE-1. `ports/security/fuguoracle/files/httpd.conf` is
the fragment of DEPLOY-HTTPD, and the port installs it as an example. The manual
page `fuguoracle.8` gains the free-space statement of DEPLOY-SERVICE-3.

**The harness is a Perl program on Fugu, on the host.** `regress/interop` runs
`fuguvm` as a command only, with `Fugu::Process` and an argument list
(TEST-INTEROP-4). It reads each exit code: 11 installs the guest again, 5 stops
the guest before a snapshot, and 7 is a timeout (TEST-INTEROP-5). It copies the
source tree, the upstream checkout, the two deployment files, and the fixed
random file in with `fuguvm put`. It copies the report out with `fuguvm get`
(TEST-INTEROP-7). `make interop` in `mk/local.mk` runs it on the host.

**The checks run in the guest.** The guest builds both servers, installs the CGI
program into the chroot, runs `fuguoracle-keygen`, and starts the two daemons.
Python 3 and `wallycore` come from `pkg_add` and `pip`, and
`fuguvm snapshot save` records the provisioned guest. The upstream test suite
runs against the local URL. A second script, `regress/interop-checks.py`, holds
the checks that the upstream suite lacks: the junk uniformity and the failure
table (TEST-INTEROP-2, TEST-INTEROP-3).

**Both servers read one random file.** The regress build of the CGI program
reads `regress/random.bin` through the `cipher_random` seam. A wrapper,
`regress/upstream-fixed.py`, patches `os.urandom` of the upstream server to read
the same file, then runs the server. The harness sends identical requests to
both and compares each `200` body byte for byte (TEST-ACCEPT-1, TEST-ACCEPT-3).

**The guest stays private.** The harness runs on a private host, because the
guest permits a root login with a generated password (TEST-INTEROP-6).

## Files

| File                                          | Change                                         |
| --------------------------------------------- | ---------------------------------------------- |
| `ports/security/fuguoracle/pkg/fuguoracle.rc` | The rc.d script (DEPLOY-SERVICE-1)             |
| `ports/security/fuguoracle/files/httpd.conf`  | The fragment (DEPLOY-HTTPD)                    |
| `fuguoracle.8`                                | The free-space statement (DEPLOY-SERVICE-3)    |
| `regress/interop`                             | The harness                                    |
| `regress/interop-checks.py`                   | The junk uniformity and failure table checks   |
| `regress/upstream-fixed.py`                   | The upstream server with the fixed random file |
| `regress/random.bin`                          | The fixed random source                        |
| `mk/local.mk`                                 | The `interop` target                           |
| `deps/Darwin.txt`, `deps/Linux.txt`           | `Fugu`, for the harness                        |
| `spec/STATUS.md`                              | The cited units                                |

## Tests

The harness holds, against the stack in the guest:

- The upstream test suite passes.
- A set and get round trip, and a wrong PIN twice then the correct PIN
  (TEST-INTEROP-1). Three wrong PINs, then the wipe, then junk. A stale and an
  equal counter, and both payload forms.
- The four junk paths answer with one status, one header set, and one body
  length (TEST-INTEROP-2).
- Each failure class of the failure table that a client can construct answers
  its status (TEST-INTEROP-3).
- With the fixed random file, every `200` body of the two servers is identical
  for every row of the draw table (TEST-ACCEPT-1 to TEST-ACCEPT-3).

## Acceptance

- `make check` passes on the host, and `make interop` passes against a fresh
  guest and against the saved snapshot.
- Every cited unit reads `done`.
- The change deletes this plan.

## Open questions

`wallycore` has no OpenBSD package, so `pip` builds it from source in the guest.
The first run of the harness proves the build. When the build fails, the
fallback is the upstream client on the host through an SSH port forward. That
fallback needs a `fuguvm` change.

## What this plan does not do

It builds no port and writes no pkg-readme. It fuzzes nothing.
