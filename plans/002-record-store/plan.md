# 002 — The record store

## Status

Proposed. It waits on plan 001 for the record cipher and the random seam. Plan
003 waits on it.

Implements: STORE-KEYS, STORE-RECORD, STORE-ATOMIC, TEST-UNIT. Implements:
OPS-WIPE without OPS-WIPE-3. Defers: OPS-GET, OPS-SET.

The wipe is a file operation, so its write lands here. The third-strike decision
that calls it is OPS-GET-6, in plan 003. The wipe log line is OPS-WIPE-3, in
plan 004.

## Purpose

PIN records live as flat files in one directory (D-05). `pindb.c` holds every
record read and write: the storage keys, the 129-byte format, the one global
lock, the atomic write, and the in-place wipe. This plan lands that file and the
unit tests that prove the wipe content, the atomicity, and the lock.

## Constraints that shape the design

**The store never sees the client key.** The caller passes the recovered client
public key. The store derives the record path, the storage key, and the
authentication key from it through the shim (STORE-KEYS-1). It stores none of
them (STORE-KEYS-2).

**The read path checks before it decrypts.** The exact length of 129 bytes, then
the HMAC with `timingsafe_bcmp(3)`, then the decrypt, then the exact plaintext
length (STORE-RECORD-1 to STORE-RECORD-3). A failure of any step is one result,
"corrupt". A missing file is a second result, and an I/O error is a third. The
caller decides what each result means.

**One lock, one write path, one exception.** The lock is
`open(PINS_DIR "/.lock", O_RDWR|O_CREAT|O_EXLOCK)`, and the caller holds it
across load, decide, and store (STORE-ATOMIC-1). A store is `mkstemp(3)` in
`PINS_DIR`, write, `fsync(2)`, `rename(2)`, then `fsync(2)` of the directory
(STORE-ATOMIC-3). The wipe overwrites in place with the layout of OPS-WIPE-1,
calls `fsync(2)`, then `unlink(2)` (OPS-WIPE-2).

**The record directory is a constant.** `PINS_DIR` is a compile-time constant
(D-06). The regress build reads the directory from the environment variable
`FUGUORACLE_PINS`, so each test runs in its own temporary directory. This is the
second and last regress seam, beside the random seam.

**A test hook stops a write.** The regress build calls `pindb_test_hook` at two
stages: before the `rename(2)` of a store, and between the `fsync(2)` and the
`unlink(2)` of a wipe. The test installs the hook to stop a write or to read the
file. The service build holds no hook.

## Files

| File                 | Change                                   |
| -------------------- | ---------------------------------------- |
| `pindb.c`, `pindb.h` | The store: keys, load, store, wipe, lock |
| `regress/Makefile`   | The `unit` target                        |
| `regress/unit.c`     | The unit tests below                     |
| `spec/STATUS.md`     | The cited units                          |

## Tests

`regress/unit` holds:

- A store then a load return the same record, and the file has 129 bytes with
  version `0x01` (STORE-RECORD-4).
- Two stores of one record write two different IVs (STORE-RECORD-5).
- A load of a file with a wrong length, a wrong HMAC, or a wrong plaintext
  length returns "corrupt".
- A wipe writes the stored hash, a zero key, `count = 3`, and
  `replay_counter = 0xFFFFFFFF` in the 129-byte layout. The hook reads that
  content before the unlink (TEST-UNIT-1).
- A store that the hook stops before the `rename(2)` leaves the target record
  intact and leaves no second record file (TEST-UNIT-2).
- Two child processes take the lock in turn: the second load starts after the
  first store ends (TEST-UNIT-3).

## Acceptance

- `make check` passes on the host, and `regress/guest` passes in the guest.
- Every cited unit reads `done`, except OPS-WIPE, which reads `partial` with
  OPS-WIPE-3 as the absent part.
- The change deletes this plan.

## What this plan does not do

It parses no envelope and makes no decision. It logs nothing.
