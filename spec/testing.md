# Test strategy

<a id="test-kat"></a>

## Known-answer tests

- **TEST-KAT-1** — The `regress/` suite must hold a known-answer vector, generated
  once from upstream libwally, for every crypto shim function: the TapTweak
  derivation, the ECDH shared secret, the HMAC-SHA512 KDF split, envelope encrypt and
  decrypt, public key recovery, and record encrypt and decrypt.
- **TEST-KAT-2** — The vectors are committed as hex. `make regress` must need no
  Python and no network.
- **TEST-KAT-3** — The TapTweak vector must exist before any other code
  (see the [risks](overview.md#ovr-risks)).

<a id="test-unit"></a>

## Unit tests

- **TEST-UNIT-1** — A unit test must run the third-strike wipe against a real record
  file and must inspect the file content before the unlink: the stored
  `hash_pin_secret`, `aes_key = 0³²`, `count = 3`, and `replay_counter = 0xFFFFFFFF`,
  in the 129-byte layout ([OPS-WIPE-1](operations.md#ops-wipe)).
- **TEST-UNIT-2** — A unit test must prove write atomicity: a write that stops before
  the `rename(2)` must leave the target record intact
  ([STORE-ATOMIC-3](storage.md#store-atomic)).
- **TEST-UNIT-3** — A unit test must prove the lock serialization: two concurrent
  requests must serialize their load, decide, and store steps
  ([STORE-ATOMIC-1](storage.md#store-atomic)).

<a id="test-interop"></a>

## Interop harness

A development-only harness, not packaged, points the upstream repository's `client.py`
and test suite at a local `httpd(8)` + `slowcgi(8)` + FuguOracle stack.

- **TEST-INTEROP-1** — The harness must pass: a set/get roundtrip; a wrong PIN twice,
  then the correct PIN; a wrong PIN three times, then the wipe, then junk-key
  responses; replay-counter rejection for a stale and for an equal counter; and both
  the 97-byte and the 129-byte payload forms.
- **TEST-INTEROP-2** — The harness must assert junk-response uniformity: for a missing
  record, a corrupt record, a replay violation, and a wrong PIN, the status, the
  headers, and the body length must be identical
  ([OPS-JUNK-2](operations.md#ops-junk)).
- **TEST-INTEROP-3** — The harness must assert the status of every failure class in
  the failure table of [PROTO-HTTP](protocol.md#proto-http) that the harness can
  construct.

<a id="test-fuzz"></a>

## Differential fuzzing

- **TEST-FUZZ-1** — A development-only fuzzer must mutate the envelope bytes inside a
  well-formed JSON body and must run every mutation against FuguOracle and against the
  upstream server. It must assert the same decision from both: reject (an HTTP error
  status), a junk key, or a real key.

<a id="test-live"></a>

## Live client test

- **TEST-LIVE-1** — Before any real use, the operator must provision a spare reference
  client against the oracle and must pass a full cycle: set the PIN, unlock, and the
  three-strike wipe.

<a id="test-accept"></a>

## Acceptance

- **TEST-ACCEPT-1** — Acceptance is behavioral equality with the upstream server for
  well-formed requests: the same reject, junk, or real decision, and byte-identical
  `200` response bodies for identical input and identical stored state. Test builds
  route every draw through the random seam
  ([SEC-RANDOM-2](security.md#sec-random)), and the harness patches the same fixed
  source into the upstream `os.urandom` (see D-12).
- **TEST-ACCEPT-2** — The service must draw random bytes in the upstream order of the
  draw table below, so that fixed-source outputs align.

| Operation and path | Draws, in order |
| --- | --- |
| `set_pin`, success | `server_random32` (32), storage IV (16), response IV (16) |
| `get_pin`, correct PIN | storage IV (16), response IV (16) |
| `get_pin`, wrong PIN, and the third strike | storage IV (16), junk key (32), response IV (16) |
| `get_pin`, missing record, corrupt record, or replay violation | junk key (32), response IV (16) |

`mkstemp(3)` draws file names outside the seam: record bytes on disk are out of the
byte-identity scope.
