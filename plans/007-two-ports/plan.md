# 007 — The two ports

## Status

In progress. The two ports, the pkg-readme and the manual statements landed, and
the arm64 builds pass. The amd64 builds and the live client test remain.

Implements: PKG-ORACLE, CLIENT-JADE, TEST-LIVE.

## Purpose

The project delivers two OpenBSD ports in one submission:
`security/libsecp256k1` and `security/fuguoracle` (`spec/packaging.md`). The
second port carries the pkg-readme. The pkg-readme carries the operator text:
the bring-up, the backup warning, and the key rotation procedure. It also
carries the live test before real use, and it points to the manual page for the
client provisioning.

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

| File             | Change          |
| ---------------- | --------------- |
| `spec/STATUS.md` | The cited units |

## Tests

- The two ports build, and their test targets pass, on the amd64 guest.
- The operator provisions a spare reference client and passes the full cycle:
  set the PIN, unlock, and the three-strike wipe (TEST-LIVE-1). The register
  note records the date.

## Acceptance

- `make check` passes on the host, and the port builds pass on amd64 and on
  arm64.
- Every cited unit reads `done`. TEST-LIVE reads `done` after the operator
  records the pass.
- The change deletes this plan.

## What this plan does not do

It submits nothing to the ports tree: the submission is the operator's act,
after the two builds pass.
