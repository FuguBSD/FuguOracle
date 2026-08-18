# CLAUDE.md

This directory holds the FuguOracle specification.
[index.md](index.md) is the entry point.
It holds the plan contract, the ID conventions, and the document tables.
[decisions.md](decisions.md) holds the decisions. A plan must not go against a
decision.

## Format

- One document specifies one area of work.
- All text complies with ASD-STE100 Simplified Technical English: short sentences, the
  active voice, one instruction per sentence, “must” for a requirement, “must not” for a
  prohibition, “can” for a capability.
- A rule item can join tightly coupled requirements on one object with “and must”.
  Each sentence stays short and active.
- Each document describes the target design in the current state only.
  Do not write an amendment, and do not refer to an earlier state.
- Only [roadmap.md](roadmap.md) and [STATUS.md](STATUS.md) say when work occurs.

## The ID overlay

A unit is one implementable design element.
An invisible HTML anchor marks each unit, and the unit ID is the anchor in upper case:

```markdown
<a id="pin-verify"></a>

## PIN verification
```

- A unit extends from its anchor to the next unit anchor or heading, whichever comes
  first.
- A rule ID names one requirement inside a unit, as a bold-lead list item, for example
  PIN-VERIFY-6. Rule numbers only append: never renumber, and never reuse a number.
- A plan cites units and rules: `Implements: PIN-VERIFY without PIN-VERIFY-6` and
  `Defers: PIN-STORE`.
- An ID must not change.
  To retire a unit: delete its anchor and its register row, and add the ID to the
  “Retired IDs” table of the register.
- The document codes are in [index.md](index.md).

## STATUS.md, the implementation register

[STATUS.md](STATUS.md) is the only home of implementation state: one row per unit, with
a state (`open`, `partial`, `done`, `n-a`), a “Done by” phase, and a note.
When your change implements a unit, or a part of a unit, set the state of the unit in
the register in the same change.
A `partial` note names each absent part.
A `done` note links the code or the tests.

## Checks

`just spec-check` runs `scripts/spec_check.py`. It validates the links, the anchors, the
register, the rule definitions, the citations, and the phase lint.
On a pull request, CI adds a drift gate: a change to a document with a `partial` or
`done` unit must also change STATUS.md or a mapped code root.
