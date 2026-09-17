# 001 — The cipher shim and its known-answer vectors

## Status

Proposed. It can land now, and it depends on no other plan. Every other plan of
this repository waits on it.

Implements: ARCH-DEPS, PROTO-TWEAK, PROTO-ENCRYPT, SEC-RANDOM, TEST-KAT.
Implements: ARCH-LAYOUT without ARCH-LAYOUT-4. Implements: SEC-MEMORY without
SEC-MEMORY-5. Defers: ARCH-STACK, PROTO-PAYLOAD, STORE-RECORD.

ARCH-LAYOUT-4 is a size target of the whole program, and plan 004 measures it.
SEC-MEMORY-5 binds the two `main()` functions, and plan 004 lands it. The public
key recovery and the record cipher land here as shim functions. Plan 003 and
plan 002 use them.

## Purpose

The wire protocol assumes the exact semantics of `libwally`: the TapTweak
derivation, the ECDH hash, the HMAC-SHA512 key split, and the CBC envelope. One
file, `cipher.c`, holds every call into `libsecp256k1` and `libcrypto`
(ARCH-LAYOUT-1). This plan lands that file, its small API, and the known-answer
vectors that pin each function. The TapTweak vector comes first, before any
other code (TEST-KAT-3).

## Constraints that shape the design

**The vectors come from `libwally`.** A Python 3 script,
`regress/vectors/generate.py`, imports `wallycore` and writes
`regress/vectors.h` with every vector as a hex string. The developer runs it
once, in a virtual environment under `scratch/`, and commits the header.
`make regress` needs no Python and no network (TEST-KAT-2). Each transcript
holds both sides: the static private key, the ephemeral private key, the
counter, and every derived value. A client implementation can therefore reuse
the same file, and the FuguPass envelope tests do.

**The shim API is small.** `cipher.h` declares the tweak of the static key, the
ECDH key split under a label, and the envelope open and seal. It declares the
public key recovery, the record encrypt and decrypt, SHA-256, HMAC-SHA256, and
one random function. `oracle.c` and `pindb.c` call these functions and include
no library header (ARCH-LAYOUT-2).

**One random seam.** `cipher_random` wraps `arc4random_buf(3)`. A regress build,
with `-DREGRESS`, reads the bytes from the file that the environment variable
`FUGUORACLE_RANDOM` names, in draw order (SEC-RANDOM-2). The service build holds
no such path. The byte-identity harness `regress/interop` rests on this seam.

**The memory rules apply from the first line.** Secrets live in stack buffers or
in `freezero(3)` allocations. Every exit path clears them with
`explicit_bzero(3)` under one `goto out`. Every MAC comparison uses
`timingsafe_bcmp(3)` (SEC-MEMORY-1 to SEC-MEMORY-3).

**The build is BSD make.** The root `Makefile` follows `bsd.prog.mk`, with
`-Wall -Wextra -Werror` and the two static archives (ARCH-DEPS-4,
ARCH-LAYOUT-3). GNU make reads the synced `GNUmakefile` for the document gates,
and OpenBSD make reads the `Makefile`, so the two coexist. `regress/Makefile`
follows `bsd.regress.mk`.

**The guest builds and tests.** No `libsecp256k1` port exists yet, so the
developer builds the library in the guest from the upstream release tarball.
`regress/guest` runs the steps with `fuguvm put` and `fuguvm ssh`, and it takes
the tarball path as an argument. The developer fetches the tarball from the
address that the packaging document names. Plan 007 replaces this step with the
port.

## Files

| File                          | Change                                                  |
| ----------------------------- | ------------------------------------------------------- |
| `Makefile`                    | The program build, static, with the warning flags       |
| `cipher.c`, `cipher.h`        | The shim                                                |
| `regress/Makefile`            | The regress build and the `kat` target                  |
| `regress/kat.c`               | The known-answer test program                           |
| `regress/vectors.h`           | The committed vectors, as hex                           |
| `regress/vectors/generate.py` | The one-time generator                                  |
| `regress/guest`               | The guest steps: put, build the library, build, regress |
| `spec/STATUS.md`              | The cited units, and `regress/` in the code roots       |

## Tests

`regress/kat` decodes each vector and holds:

- The TapTweak derivation of `d'` from `d`, `cke`, and the counter
  (PROTO-TWEAK-1, PROTO-TWEAK-2).
- The ECDH shared secret and the split into `enc_key` and `mac_key`, for both
  labels (PROTO-ENCRYPT-1, PROTO-ENCRYPT-2).
- The envelope open of a 97-byte and of a 129-byte payload, and the rejection of
  a wrong tag before any decryption (PROTO-ENCRYPT-3).
- The envelope seal with a fixed IV from the seam equals the `libwally` output
  (PROTO-ENCRYPT-4).
- The envelope open of a transcript pair of one client key: a `set_pin`
  envelope, then a `get_pin` envelope with a higher `replay_counter`.
  `regress/cgi.sh` replays that pair as a round trip.
- The public key recovery from the signed payload hash.
- The record encrypt and decrypt of the 69-byte record plaintext. PKCS#7 pads
  the plaintext to 80 bytes, and the 96-byte `enc` field holds the IV and the
  ciphertext.
- The seam returns the file bytes in order under `-DREGRESS`.

## Acceptance

- `make check` passes on the host, and `regress/guest` passes in the guest.
- Every cited unit reads `done`, except ARCH-LAYOUT and SEC-MEMORY, which read
  `partial` with the absent rule named.
- The change deletes this plan.

## What this plan does not do

It reads no record and answers no request. It holds no HTTP code.
