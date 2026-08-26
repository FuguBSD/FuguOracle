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

The "Done by" column names a phase of the [roadmap](ROADMAP.md). At the exit of
that phase, the unit must have the state `done`. A unit can reach `done` before
that phase. An `n-a` unit has no "Done by" value.

## Units

| Unit                                            | State | Done by | Note           |
| ----------------------------------------------- | ----- | ------- | -------------- |
| [OVR-PURPOSE](overview.md#ovr-purpose)          | open  | P3      | —              |
| [OVR-SCOPE](overview.md#ovr-scope)              | n-a   | —       | Citation only. |
| [OVR-RISKS](overview.md#ovr-risks)              | n-a   | —       | Citation only. |
| [ARCH-STACK](architecture.md#arch-stack)        | open  | P3      | —              |
| [ARCH-DEPS](architecture.md#arch-deps)          | open  | P1      | —              |
| [ARCH-LAYOUT](architecture.md#arch-layout)      | open  | P3      | —              |
| [PROTO-HTTP](protocol.md#proto-http)            | open  | P3      | —              |
| [PROTO-ENVELOPE](protocol.md#proto-envelope)    | open  | P2      | —              |
| [PROTO-TWEAK](protocol.md#proto-tweak)          | open  | P1      | —              |
| [PROTO-CRYPTO](protocol.md#proto-crypto)        | open  | P1      | —              |
| [PROTO-PAYLOAD](protocol.md#proto-payload)      | open  | P2      | —              |
| [PROTO-RESPONSE](protocol.md#proto-response)    | open  | P2      | —              |
| [STORE-KEYS](storage.md#store-keys)             | open  | P2      | —              |
| [STORE-RECORD](storage.md#store-record)         | open  | P2      | —              |
| [STORE-ATOMIC](storage.md#store-atomic)         | open  | P2      | —              |
| [OPS-SET](operations.md#ops-set)                | open  | P2      | —              |
| [OPS-GET](operations.md#ops-get)                | open  | P2      | —              |
| [OPS-WIPE](operations.md#ops-wipe)              | open  | P2      | —              |
| [OPS-JUNK](operations.md#ops-junk)              | open  | P2      | —              |
| [SEC-THREAT](security.md#sec-threat)            | n-a   | —       | Citation only. |
| [SEC-SANDBOX](security.md#sec-sandbox)          | open  | P3      | —              |
| [SEC-MEMORY](security.md#sec-memory)            | open  | P3      | —              |
| [SEC-RANDOM](security.md#sec-random)            | open  | P3      | —              |
| [SEC-LOGGING](security.md#sec-logging)          | open  | P3      | —              |
| [PROG-CGI](programs.md#prog-cgi)                | open  | P3      | —              |
| [PROG-KEYGEN](programs.md#prog-keygen)          | open  | P3      | —              |
| [DEPLOY-HTTPD](deployment.md#deploy-httpd)      | open  | P3      | —              |
| [DEPLOY-SERVICE](deployment.md#deploy-service)  | open  | P3      | —              |
| [DEPLOY-BACKUP](deployment.md#deploy-backup)    | open  | P4      | —              |
| [CLIENT-MODEL](clients.md#client-model)         | n-a   | —       | Citation only. |
| [CLIENT-PROVISION](clients.md#client-provision) | open  | P4      | —              |
| [CLIENT-JADE](clients.md#client-jade)           | open  | P4      | —              |
| [PKG-SECP](packaging.md#pkg-secp)               | open  | P4      | —              |
| [PKG-ORACLE](packaging.md#pkg-oracle)           | open  | P4      | —              |
| [TEST-KAT](testing.md#test-kat)                 | open  | P1      | —              |
| [TEST-UNIT](testing.md#test-unit)               | open  | P2      | —              |
| [TEST-INTEROP](testing.md#test-interop)         | open  | P3      | —              |
| [TEST-FUZZ](testing.md#test-fuzz)               | open  | P3      | —              |
| [TEST-LIVE](testing.md#test-live)               | open  | P4      | —              |
| [TEST-ACCEPT](testing.md#test-accept)           | open  | P3      | —              |

## Update protocol

1. The change that implements a unit, or a part of a unit, sets the state of the
   unit in this register, in the same change.
2. A `partial` note names each absent rule or part. For each absent part, the
   note names the unit that the part needs.
3. A `done` note holds at least one relative link to code or to tests.
4. A change to the text of a `partial` or `done` unit updates the row of that
   unit in the same change. The CI drift check enforces this rule.
5. The human merge review compares the register diff with the code diff.

## Code roots

The roots are the code paths that implement a document, relative to the
repository root.

| Document        | Roots                  |
| --------------- | ---------------------- |
| overview.md     | `oracle.c`, `regress/` |
| architecture.md | `Makefile`             |
| protocol.md     | `http.c`, `crypto.c`   |
| storage.md      | `pindb.c`              |
| operations.md   | `oracle.c`             |
| security.md     | `main.c`, `crypto.c`   |
| programs.md     | `main.c`, `keygen.c`   |
| deployment.md   | `ports/`               |
| clients.md      | `ports/`               |
| packaging.md    | `ports/`               |
| testing.md      | `regress/`             |

## Retired IDs

| ID  | Unit |
| --- | ---- |
