# Implementation register

This register is the one record of implementation state. One row exists for each
unit of the specification. A unit is one design element of one specification
document. The [conventions](index.md#conventions) define the unit IDs. Each row
describes the current state only. A row must not carry a plan name or a
reference to an earlier state. A note can carry the date of a recorded fact.

## States

| State   | Meaning                                                              |
| ------- | -------------------------------------------------------------------- |
| open    | No code implements the unit.                                         |
| partial | Code implements a part of the unit. The note names each absent part. |
| done    | Code implements the full unit. The note links the code or the tests. |
| n-a     | No code can implement the unit. It exists for citation only.         |

The "Done by" column names a phase of the [roadmap](ROADMAP.md), or "—" when no
phase applies.

## Units

| Unit                                            | State   | Done by | Note                                                                                                                                                                                                                                                                          |
| ----------------------------------------------- | ------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [OVW-PURPOSE](overview.md#ovw-purpose)          | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [OVW-SCOPE](overview.md#ovw-scope)              | n-a     | —       | Citation only.                                                                                                                                                                                                                                                                |
| [OVW-VOCABULARY](overview.md#ovw-vocabulary)    | done    | —       | [vocabulary.t](../t/fuguoracle/vocabulary.t) reads the five words and scans the tree outside `ports/`.                                                                                                                                                                        |
| [OVW-RISKS](overview.md#ovw-risks)              | n-a     | —       | Citation only.                                                                                                                                                                                                                                                                |
| [ARCH-STACK](architecture.md#arch-stack)        | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [ARCH-DEPS](architecture.md#arch-deps)          | done    | P1      | [regress/Makefile](../regress/Makefile) links the two static archives, and [guest](../regress/guest) builds the library and the tests in the guest.                                                                                                                           |
| [ARCH-LAYOUT](architecture.md#arch-layout)      | partial | P3      | [cipher.c](../cipher.c) holds every library call, and `#ifdef REGRESS` guards each test entry point. ARCH-LAYOUT-4 is absent, because the size target counts the program of PROG-CGI.                                                                                         |
| [PROTO-HTTP](protocol.md#proto-http)            | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [PROTO-ENVELOPE](protocol.md#proto-envelope)    | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [PROTO-TWEAK](protocol.md#proto-tweak)          | done    | P1      | [cipher.c](../cipher.c) derives the request key and the request public key, and [kat.c](../regress/kat.c) pins `m` and both keys. The public tweak of PROTO-TWEAK-4 answers a client, so the service build leaves it out.                                                     |
| [PROTO-ENCRYPT](protocol.md#proto-encrypt)      | done    | P1      | [cipher.c](../cipher.c) opens and seals an envelope, and [kat.c](../regress/kat.c) pins each value.                                                                                                                                                                           |
| [PROTO-PAYLOAD](protocol.md#proto-payload)      | partial | P2      | [cipher.c](../cipher.c) recovers the client public key of PROTO-PAYLOAD-2 and PROTO-PAYLOAD-4, and [kat.c](../regress/kat.c) pins it. PROTO-PAYLOAD-1, PROTO-PAYLOAD-3 and PROTO-PAYLOAD-5 are absent, because they need the payload reader of OPS-GET and OPS-SET.           |
| [PROTO-RESPONSE](protocol.md#proto-response)    | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [STORE-KEYS](storage.md#store-keys)             | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [STORE-RECORD](storage.md#store-record)         | partial | P2      | [cipher.c](../cipher.c) seals and opens the `enc` field with a fresh IV, and [kat.c](../regress/kat.c) pins STORE-RECORD-5. STORE-RECORD-1, STORE-RECORD-2, STORE-RECORD-3 and STORE-RECORD-4 are absent, because they need the record reader of STORE-KEYS and STORE-ATOMIC. |
| [STORE-ATOMIC](storage.md#store-atomic)         | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [OPS-SET](operations.md#ops-set)                | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [OPS-GET](operations.md#ops-get)                | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [OPS-WIPE](operations.md#ops-wipe)              | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [OPS-JUNK](operations.md#ops-junk)              | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [DEPLOY-HTTPD](deployment.md#deploy-httpd)      | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [DEPLOY-SERVICE](deployment.md#deploy-service)  | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [DEPLOY-BACKUP](deployment.md#deploy-backup)    | open    | P4      | —                                                                                                                                                                                                                                                                             |
| [CLIENT-MODEL](clients.md#client-model)         | n-a     | —       | Citation only.                                                                                                                                                                                                                                                                |
| [CLIENT-PROVISION](clients.md#client-provision) | open    | P4      | —                                                                                                                                                                                                                                                                             |
| [CLIENT-JADE](clients.md#client-jade)           | open    | P4      | —                                                                                                                                                                                                                                                                             |
| [PKG-SECP](packaging.md#pkg-secp)               | open    | P4      | —                                                                                                                                                                                                                                                                             |
| [PKG-ORACLE](packaging.md#pkg-oracle)           | open    | P4      | —                                                                                                                                                                                                                                                                             |
| [PROG-CGI](programs.md#prog-cgi)                | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [PROG-KEYGEN](programs.md#prog-keygen)          | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [SEC-THREAT](security.md#sec-threat)            | n-a     | —       | Citation only.                                                                                                                                                                                                                                                                |
| [SEC-SANDBOX](security.md#sec-sandbox)          | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [SEC-MEMORY](security.md#sec-memory)            | partial | P3      | [cipher.c](../cipher.c) clears each secret and compares each tag in constant time. SEC-MEMORY-5 is absent, because it binds the two programs of PROG-CGI and PROG-KEYGEN.                                                                                                     |
| [SEC-RANDOM](security.md#sec-random)            | done    | P1      | [cipher.c](../cipher.c) holds the one seam, and it randomizes the library context beside the seam. [kat.c](../regress/kat.c) reads the fixed source through the seam.                                                                                                         |
| [SEC-LOGGING](security.md#sec-logging)          | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [TEST-KAT](testing.md#test-kat)                 | done    | P1      | [kat.c](../regress/kat.c) runs each vector of [vectors.h](../regress/vectors.h).                                                                                                                                                                                              |
| [TEST-UNIT](testing.md#test-unit)               | open    | P2      | —                                                                                                                                                                                                                                                                             |
| [TEST-INTEROP](testing.md#test-interop)         | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [TEST-FUZZ](testing.md#test-fuzz)               | open    | P3      | —                                                                                                                                                                                                                                                                             |
| [TEST-LIVE](testing.md#test-live)               | open    | P4      | —                                                                                                                                                                                                                                                                             |
| [TEST-ACCEPT](testing.md#test-accept)           | open    | P3      | —                                                                                                                                                                                                                                                                             |

## Update protocol

1. The change that implements a unit, or a part of one, sets the unit state in
   this register in the same change.
2. A `partial` note names each absent rule or part. For each absent part, the
   note names the unit that the part needs.
3. A `done` note holds at least one relative link to code or to tests.
4. A change to the text of a `partial` or `done` unit updates the row of that
   unit in the same change. The CI drift check enforces this rule.
5. The human merge review compares the register diff with the code diff.

## Code roots

The drift gate maps each document to the code that implements it.

| Document        | Roots                                               |
| --------------- | --------------------------------------------------- |
| overview.md     | `oracle.c`, `regress/`, `t/fuguoracle/vocabulary.t` |
| architecture.md | `Makefile`, `cipher.c`, `regress/`                  |
| protocol.md     | `http.c`, `cipher.c`, `regress/`                    |
| storage.md      | `pindb.c`, `cipher.c`, `regress/`                   |
| operations.md   | `oracle.c`                                          |
| deployment.md   | `ports/`                                            |
| clients.md      | `ports/`                                            |
| packaging.md    | `ports/`                                            |
| programs.md     | `main.c`, `keygen.c`                                |
| security.md     | `main.c`, `cipher.c`, `regress/`                    |
| testing.md      | `regress/`                                          |
