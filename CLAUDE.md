# CLAUDE.md

FuguOracle is a blind oracle service designed after OpenBSD principles.
The service acts as a virtual secure element.
It implements the Blockstream Jade v2 protocol.
The oracle must not learn the secrets that it protects.

## The specification is a living document

The specification in [`spec/`](spec/index.md) governs all work.
Read the [decisions](spec/decisions.md) before you make a plan.
A plan must not go against a decision.

The specification is not frozen.
It must agree with the project at all times.
Apply these rules:

- When your change alters a design, an interface, or a procedure, update the
  specification in the same change.
- When the specification is wrong or not complete, correct the specification.
  Do not work around it, and do not let code and specification drift apart.
- When your change goes against a decision, stop.
  Propose a change to [decisions](spec/decisions.md) and get human approval first.
- When you update the specification, write the text so that it describes the current
  state only. Do not write the update as an amendment or a revision, and do not refer to
  an earlier state.
- When your change implements a unit of the specification, or a part of a unit, set the
  state of the unit in [spec/STATUS.md](spec/STATUS.md) in the same change.

## Critical: writing standard

All output and all artifacts must comply with ASD-STE100 Simplified Technical English.
This rule applies to documentation, specifications, runbooks, commit messages, and pull
requests.
Write short sentences, in the active voice, with one instruction per sentence.
Use “must” for a requirement, “must not” for a prohibition, and “can” for a capability.
