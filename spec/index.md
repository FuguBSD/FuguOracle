# FuguOracle specification

FuguOracle is a blind PIN oracle.
It acts as a virtual secure element for client devices and client programs.
A client holds a secret in encrypted form, under a key that the client alone cannot rebuild.
The oracle holds a key share for each client, and it releases the share only for a request that proves the correct PIN.
The oracle does not learn the PIN, and it does not learn the protected secret.
After three bad PIN attempts, the oracle destroys the key share.
The wire protocol is version 2 of the Blockstream `blind_pin_server` protocol.
[Blockstream Jade](clients.md#client-jade) is the reference client.

This document is the entry point of the specification.
It holds the plan contract, the ID conventions, and the document tables.

## Plan contract

- Read [decisions.md](decisions.md) before you make a plan.
- A plan must not go against a decision.
  To go against a decision, propose a change to [decisions.md](decisions.md) and get
  human approval first.
- A plan must cite each unit that it implements, for example
  `Implements: OPS-GET, OPS-JUNK`.
- A plan can exclude a rule from a cited unit with `without`, for example
  `Implements: OPS-GET without OPS-GET-6`.
- A plan must cite each unit that it touches but defers, for example
  `Defers: STORE-ATOMIC`.
- The change that implements a unit, or a part of a unit, must set the state of the
  unit in [STATUS.md](STATUS.md) in the same change.

<a id="conventions"></a>

## Conventions

A unit is one implementable design element.
An invisible HTML anchor marks each unit, and the unit ID is the anchor in upper case:

```markdown
<a id="ops-get"></a>

## PIN retrieval
```

- The anchor of a unit must start with the code of its document, in lower case,
  followed by a hyphen.
- A unit extends from its anchor to the next unit anchor or heading, whichever comes
  first.
- A rule ID names one requirement inside a unit.
  A rule is a bold-lead list item, for example: `- **OPS-GET-3** — The oracle must …`.
- Rule numbers only append: never renumber a rule, and never reuse a number.
- An ID must not change.
  To retire a unit: delete its anchor and its register row, and add the ID to the
  "Retired IDs" table of [STATUS.md](STATUS.md).
- Each document describes the target design in the current state only.
  Only [roadmap.md](roadmap.md) and [STATUS.md](STATUS.md) say when work occurs.

## Specification documents

Each document specifies one area of work.
The code of a document prefixes the IDs of its units.

| Code | Document | Area |
| --- | --- | --- |
| OVR | [overview.md](overview.md) | Purpose, scope, and risks |
| ARCH | [architecture.md](architecture.md) | Service architecture and dependencies |
| PROTO | [protocol.md](protocol.md) | Wire protocol, version 2 |
| STORE | [storage.md](storage.md) | PIN record storage |
| OPS | [operations.md](operations.md) | Oracle operations |
| SEC | [security.md](security.md) | Security design |
| PROG | [programs.md](programs.md) | Programs and file layout |
| DEPLOY | [deployment.md](deployment.md) | Deployment on OpenBSD |
| CLIENT | [clients.md](clients.md) | Client integration |
| PKG | [packaging.md](packaging.md) | Ports packaging |
| TEST | [testing.md](testing.md) | Test strategy |

## Governance documents

These documents carry no units.

| Document | Role |
| --- | --- |
| [decisions.md](decisions.md) | The decisions. A plan must not go against a decision. |
| [roadmap.md](roadmap.md) | The phases of the work. |
| [STATUS.md](STATUS.md) | The implementation register. |
