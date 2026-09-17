# 007 — The two ports

## Status

Proposed. It waits on plan 004 for the programs and on plan 005 for the
deployment files. It also waits on a decision, stated under Open questions
below: the vocabulary rule forbids a word that the `libsecp256k1` port must
name.

Implements: PKG-SECP, PKG-ORACLE, DEPLOY-BACKUP, CLIENT-PROVISION, CLIENT-JADE,
TEST-LIVE. Defers: OVW-VOCABULARY.

## Purpose

The project delivers two OpenBSD ports in one submission:
`security/libsecp256k1` and `security/fuguoracle` (`spec/packaging.md`). The
second port carries the pkg-readme. The pkg-readme carries the operator text:
the bring-up, the backup warning, and the key rotation procedure. It also
carries the client provisioning and the live test before real use.

## Constraints that shape the design

**The library port is minimal.** It enables `ecdh`, `recovery`, and `extrakeys`,
and no other module (PKG-SECP-1). It ships the static archive, the headers, and
the pkg-config file, and its `do-test` runs the upstream suite (PKG-SECP-2,
PKG-SECP-3).

**The service port links static.** It declares the library as a build dependency
only, and no `WANTLIB` beyond base (PKG-ORACLE-5). Its PLIST creates the user
and the group, and it `@sample`-creates the two directories with the modes of
PKG-ORACLE-3. `make regress` runs the known-answer suite with no network
(PKG-ORACLE-4).

**The distfile is a tag.** The port fetches a release tag of this repository
through the GitHub mechanism of the ports tree, and `distinfo` pins it. The
operator tags the release before the port build.

**The pkg-readme and the manual page both hold the operator text.** The backup
warning and the key rotation procedure live in the pkg-readme and in
`fuguoracle.8`. DEPLOY-BACKUP-3 and DEPLOY-BACKUP-5 name the two artifacts. The
pkg-readme also holds the bring-up commands, the path of the `httpd.conf`
example, the Jade procedure, and the live test. It points to the manual page for
the provisioning statements.

**Both architectures build.** The developer builds both ports on an amd64 guest
and on an arm64 guest, with `fuguvm` as a command only (PKG-ORACLE-6,
PKG-ORACLE-7). A port never depends on `fuguvm`.

## Files

| File                                    | Change                                                |
| --------------------------------------- | ----------------------------------------------------- |
| `ports/security/libsecp256k1/Makefile`  | The library port                                      |
| `ports/security/libsecp256k1/distinfo`  | The pinned distfile                                   |
| `ports/security/libsecp256k1/pkg/DESCR` | The description                                       |
| `ports/security/libsecp256k1/pkg/PLIST` | The archive, the headers, the pkg-config file         |
| `ports/security/fuguoracle/Makefile`    | The service port                                      |
| `ports/security/fuguoracle/distinfo`    | The pinned tag                                        |
| `ports/security/fuguoracle/pkg/DESCR`   | The description                                       |
| `ports/security/fuguoracle/pkg/PLIST`   | The files, the user, the sample directories           |
| `ports/security/fuguoracle/pkg/README`  | The bring-up, the backup, the rotation, the live test |
| `fuguoracle.8`                          | The backup and the provisioning statements            |
| `regress/guest`                         | The port build in place of the tarball build          |
| `spec/STATUS.md`                        | The cited units                                       |

## Tests

- `make port-lib-check` and `make lint` of the ports tree pass on both ports, in
  the guest.
- `make regress` of the service port passes with the network off.
- A `pkg_add` of the built package, then the bring-up of DEPLOY-SERVICE, serves
  one round trip from the upstream `client.py`.
- The operator provisions a spare reference client and passes the full cycle:
  set the PIN, unlock, and the three-strike wipe (TEST-LIVE-1). The register
  note records the date.

## Acceptance

- `make check` passes on the host, and the port builds pass on amd64 and on
  arm64.
- Every cited unit reads `done`. TEST-LIVE reads `done` after the operator
  records the pass.
- The change deletes this plan.

## Open questions

The library port must name the upstream GitHub account in `GH_ACCOUNT`, and the
first half of that name is a banned word (D-13, OVW-VOCABULARY-2). The
vocabulary test exempts a code span, a code block, `docs/research/`, and a
synced file, and a port Makefile is none of these. Two ways out exist, and each
needs human approval first. The first amends D-13 and OVW-VOCABULARY-3 of this
repository to exempt `ports/`. The same decision reaches each sibling repository
through its own plan. The second fetches the distfile from an address of the
organization, and that breaks the convention of the ports tree for a submission.

## What this plan does not do

It submits nothing to the ports tree: the submission is the operator's act,
after the two builds pass.
