# 006 — The differential fuzzer

## Status

Proposed. It waits on plan 005 for the provisioned guest, the fixed random file,
and the upstream server wrapper.

Implements: TEST-FUZZ.

## Purpose

Two servers that agree on every well-formed request can still disagree on a
mutated one. The fuzzer mutates the envelope bytes inside a well-formed JSON
body and runs each mutation against both servers. It requires the same decision
from both: reject, junk, or a real key (TEST-FUZZ-1). It is a development tool,
and it never enters the port (TEST-FUZZ-2).

## Constraints that shape the design

**The fuzzer runs in the guest.** The CGI program runs on OpenBSD only, and the
fuzzer calls it directly (TEST-FUZZ-4). The guest therefore gains Perl with the
Fugu distribution, through `cpanm`, and the guest snapshot of `regress/interop`
records the addition.

**Every process is a Fugu process.** The fuzzer starts the upstream server with
`Fugu::Process->spawn_command` and stops it with `Fugu::Process->terminate`.
Each CGI run is `Fugu::Process->run` with a `timeout`. The CGI variables sit in
the environment of the child, and the body on standard input (TEST-FUZZ-3,
TEST-FUZZ-4). It never runs a shell.

**Each mutation is random, and each stop is clean.**
`Fugu::Random->random_bytes` draws the mutation positions and values. One
`Fugu::Signal` manager, with `setup_interrupt_flag`, stops the loop between two
mutations. Each failing case goes to a file with `Fugu::File->write_atomic`,
under a directory that the caller names (TEST-FUZZ-3).

**The decision is one of three.** Both servers read `regress/random.bin`, so a
real key is byte-identical on both sides. An HTTP error status is a reject. A
`200` body that decrypts to the enrolled key is a real key, and any other `200`
body is junk. The fuzzer enrolls one record on each server first, then mutates
`get_pin` requests against it.

## Files

| File              | Change                                          |
| ----------------- | ----------------------------------------------- |
| `regress/fuzz`    | The fuzzer                                      |
| `regress/interop` | The `cpanm Fugu` step of the guest provisioning |
| `spec/STATUS.md`  | TEST-FUZZ `done`                                |

## Tests

The fuzzer is a test tool, and its own proof is one run:

- A run of 10000 mutations reports no disagreement, or writes each disagreement
  as a file that holds the body and both answers.
- A mutation of the tag alone is a reject on both sides. A mutation of the `cke`
  field alone is a reject or junk on both sides.
- A `SIGINT` between two mutations ends the run, and the upstream server is gone
  afterwards.

## Acceptance

- `make check` passes on the host, and one run of the fuzzer in the guest
  passes.
- TEST-FUZZ reads `done`.
- The change deletes this plan.

## What this plan does not do

It changes no server. A disagreement that it finds is a defect report for plan
003 or for the upstream project, never a fix in this plan.
