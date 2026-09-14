# FuguOracle specification

FuguOracle is a blind PIN oracle. It is a virtual secure element for client
devices and client programs. A client holds a secret in encrypted form, under a
key that the client alone cannot rebuild. The oracle holds a key share for each
client, and it releases the share only for a request that proves the correct
PIN. The oracle does not learn the PIN, and it does not learn the protected
secret. After three bad PIN attempts, the oracle destroys the key share. The
wire protocol is version 2 of the Blockstream `blind_pin_server` protocol.
[Blockstream Jade](clients.md#client-jade) is the reference client.

This document is the entry point of the specification. It holds the plan
contract, the ID conventions, and the document tables.

## Plan contract

- Read [DECISIONS.md](DECISIONS.md) before you make a plan.
- A plan must not go against a decision. To go against a decision, propose a
  change to [DECISIONS.md](DECISIONS.md) and get human approval first.
- A plan must cite each unit that it implements and that is not `done`, for
  example `Implements: OPS-GET`.
- A plan can exclude a rule from a unit under `Implements:` with `without`, for
  example `Implements: OPS-GET without OPS-GET-6`.
- A plan must cite each unit that it touches but neither implements nor extends,
  for example `Defers: STORE-ATOMIC`.
- A plan must cite each `done` unit that it extends, for example
  `Extends: OVW-VOCABULARY`.
- The change that implements a unit, or a part of one, must set the unit state
  in [STATUS.md](STATUS.md) in the same change.

<a id="conventions"></a>

## Conventions

The ID overlay lives in [spec/CLAUDE.md](CLAUDE.md): the unit anchors, the rule
shape, the append-only numbers, the retire procedure, and the citation forms.

## Specification documents

Each document specifies one area of work. The code of a document prefixes the
IDs of its units.

| Code   | Document                           | Area                                  |
| ------ | ---------------------------------- | ------------------------------------- |
| OVW    | [overview.md](overview.md)         | Purpose, scope, vocabulary, and risks |
| ARCH   | [architecture.md](architecture.md) | Service architecture and dependencies |
| PROTO  | [protocol.md](protocol.md)         | Wire protocol, version 2              |
| STORE  | [storage.md](storage.md)           | PIN record storage                    |
| OPS    | [operations.md](operations.md)     | Oracle operations                     |
| DEPLOY | [deployment.md](deployment.md)     | Deployment on OpenBSD                 |
| CLIENT | [clients.md](clients.md)           | Client integration                    |
| PKG    | [packaging.md](packaging.md)       | Ports packaging                       |
| PROG   | [programs.md](programs.md)         | Programs and file layout              |
| SEC    | [security.md](security.md)         | Security design                       |
| TEST   | [testing.md](testing.md)           | Test strategy                         |

## Governance documents

These documents carry no units.

| Document                     | Role                                                  |
| ---------------------------- | ----------------------------------------------------- |
| [DECISIONS.md](DECISIONS.md) | The decisions. A plan must not go against a decision. |
| [ROADMAP.md](ROADMAP.md)     | The schedule of the work.                             |
| [STATUS.md](STATUS.md)       | The implementation register.                          |
