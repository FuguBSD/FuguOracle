# Overview

<a id="ovr-purpose"></a>

## Purpose

FuguOracle is a blind PIN oracle, written in C for OpenBSD. The oracle acts as a
virtual secure element: it supplies the anti-brute-force property that a
hardware secure element gives, as a network service.

A client holds a secret in encrypted form, under a key that the client alone
cannot rebuild. To unlock, the client proves knowledge of a PIN to the oracle
and receives a key share in return. The oracle enforces three PIN attempts.
After the third bad attempt, the oracle destroys its key share, and the
encrypted secret on the client becomes undecryptable.

The security of the scheme rests on two properties: the secrecy of the oracle's
static secp256k1 key, and the integrity of the attempt counter.

- **OVR-PURPOSE-1** — The oracle must not learn the PIN.
- **OVR-PURPOSE-2** — The oracle must not learn the protected secret.
- **OVR-PURPOSE-3** — The oracle must serve every client that speaks the wire
  protocol. The design must not depend on properties of one client product.
- **OVR-PURPOSE-4** — One oracle instance can serve many clients at the same
  time.

<a id="ovr-scope"></a>

## Scope

The wire protocol is version 2 of the Blockstream `blind_pin_server` protocol.
The upstream reference is `github.com/Blockstream/blind_pin_server` (Python).
[Blockstream Jade](clients.md#client-jade) is the reference client.

Goals:

- Serve the smallest viable feature set: protocol v2 only.
- Use the OpenBSD base system for everything except secp256k1 arithmetic.
- Do not reimplement cryptography. All primitives come from LibreSSL `libcrypto`
  (base) and `libsecp256k1` (port).
- Follow idiomatic OpenBSD design: `httpd(8)`, `slowcgi(8)`, a statically linked
  CGI program, `pledge(2)`, `unveil(2)`, `arc4random(3)`, `syslog(3)`, `mdoc(7)`
  man pages, an rc.d script, and a clean ports-tree package.

Non-goals, as deviations from the upstream server:

| Upstream feature                                                 | FuguOracle                                                        | Rationale                                                                                                                         |
| ---------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Protocol v1 (`/start_handshake`, sessions, explicit hmac fields) | Absent                                                            | Legacy clients only. v2 is stateless: no session table, no lifetime configuration.                                                |
| Redis storage backend                                            | Absent                                                            | Flat files in one directory serve the workload.                                                                                   |
| `python-dotenv` configuration                                    | Absent                                                            | Compile-time paths, documented in the man page.                                                                                   |
| Flask, Werkzeug, gunicorn, nginx                                 | Absent                                                            | `httpd(8)` and `slowcgi(8)` come from base.                                                                                       |
| Non-atomic record writes                                         | Corrected                                                         | Writes use `mkstemp(3)`, `fsync(2)`, and `rename(2)`.                                                                             |
| v0 to v1 database migration                                      | Absent                                                            | Fresh deployments write and read record version `0x01` only.                                                                      |
| HTTP 500 for every request-parse failure                         | `400` before envelope decryption, empty error bodies              | A malformed request is a client error, and the status says so. Failures from the MAC check onward keep status `500`, as upstream. |
| No request body size limit                                       | `413` for a body larger than 4096 bytes                           | The cap bounds the input surface. Honest v2 bodies stay under 400 bytes.                                                          |
| Lenient base64 and JSON reading                                  | Strict `b64_pton` and a strict scanner; a violation answers `400` | Lenient parsing grows the input surface. Honest clients send canonical encodings.                                                 |
| Junk key on a `get_pin` record I/O failure, read or persist      | Status `500`, fail closed                                         | An attempt that the service cannot count must not receive an answer (see OPS-GET-7).                                              |
| Lenient CBC unpad that never fails                               | Strict PKCS#7 unpad; forged padding answers `500`                 | Only a holder of the derived keys can build such an input, because the MAC check runs first.                                      |

<a id="ovr-risks"></a>

## Risks

| Risk                                                                                                              | Mitigation                                                                                                                                                                       |
| ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Upstream semantics drift in future client firmware                                                                | Protocol v2 is stable, and the record carries a version byte. Known-answer tests pin the current behavior. Watch the upstream repository.                                        |
| TapTweak and merkle-root confusion in the key derivation, the classic interop trap                                | Generate the known-answer vector from libwally first, before any other code.                                                                                                     |
| PKCS#7 edge cases between the EVP layer and libwally's lenient unpad                                              | The envelope known-answer tests cover block-aligned plaintexts. The 97-byte and 129-byte payload forms both exercise padding.                                                    |
| The third-strike overwrite gives a weak deletion guarantee on SSD and FFS                                         | The man page documents the limit. The wiped record is also cryptographically dead: zero key, then unlink.                                                                        |
| A single global lock serializes requests                                                                          | Intentional. The workload is a few requests per day.                                                                                                                             |
| No standalone `libsecp256k1` port exists in the ports tree                                                        | The companion port is a deliverable of this project.                                                                                                                             |
| Response time differs between junk paths that write and paths that do not                                         | Accepted. The response bytes stay identical (OPS-JUNK-2). The workload is a few requests per day, and network jitter dominates.                                                  |
| A filesystem restore of an old record resets the attempt counter and the replay counter                           | Accepted, inherited from the upstream design: the record authenticator has no freshness anchor. The operator restores `pins/` only after an incident review (see DEPLOY-BACKUP). |
| Any caller can create records without limit                                                                       | Accepted: the protocol has no client authentication. The operator monitors free space (DEPLOY-SERVICE-3).                                                                        |
| `set_pin` resets the replay counter to 0, so envelopes captured before a PIN change replay against the new record | Accepted, inherited from the upstream server. Anti-replay protects between PIN changes. Exploitation needs transport compromise.                                                 |
