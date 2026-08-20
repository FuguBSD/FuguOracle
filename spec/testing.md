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
The harness runs `client.py` in the OpenBSD guest, because the `fuguvm` tool forwards
the guest SSH port only.

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
- **TEST-INTEROP-4** — The harness must run the stack in an OpenBSD guest, and must
  build the guest with the `fuguvm` tool. The harness must call `fuguvm up`, then
  `fuguvm wait`, then one `fuguvm ssh` call for each step. The harness must use
  `fuguvm` as a command only, and must not load an `App::FuguVM` module.
- **TEST-INTEROP-5** — The harness must read the exit code of each `fuguvm` call.
  Exit code 11 reports an absent snapshot, and the harness must then install the guest
  again. Exit code 5 reports a running guest. The harness must stop the guest before it
  saves or restores a snapshot. Exit code 7 reports a timeout.
- **TEST-INTEROP-6** — The developer must run the harness on a private host. Each
  forwarded guest port must otherwise bind to the loopback address. The guest permits a
  root login with a generated password.
- **TEST-INTEROP-7** — The harness must copy the source tree and the upstream
  checkout into the guest with `fuguvm put`. It must copy the `httpd.conf` fragment and
  the rc.d script in the same way. The harness must copy the test report out of the
  guest with `fuguvm get`.

<a id="test-fuzz"></a>

## Differential fuzzing

- **TEST-FUZZ-1** — A development-only fuzzer must mutate the envelope bytes inside a
  well-formed JSON body and must run every mutation against FuguOracle and against the
  upstream server. It must assert the same decision from both: reject (an HTTP error
  status), a junk key, or a real key.
- **TEST-FUZZ-2** — The fuzzer is a development-only Perl program on the Fugu
  library. The fuzzer must not enter the port.
- **TEST-FUZZ-3** — The fuzzer must start each server with
  `Fugu::Process->spawn_command`, and must stop each server with
  `Fugu::Process->terminate`. It must run each mutation with `Fugu::Process->run` and a
  `timeout`. It must draw each mutation with `Fugu::Random->random_bytes`. It must write
  each failing case with `Fugu::File->write_atomic`. It must stop early on a signal: it
  must build one `Fugu::Signal` manager, must call `setup_interrupt_flag` on that
  manager, and must read the flag between two mutations.
- **TEST-FUZZ-4** — The fuzzer must call the CGI program directly for the FuguOracle
  side. It must set the request variables of [PROG-CGI-1](programs.md#prog-cgi) and
  [PROG-CGI-2](programs.md#prog-cgi) in the environment of each child. It must pass the
  mutated body on standard input.

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
- **TEST-ACCEPT-3** — The harness must keep the fixed random source as one committed
  file. It must give the same file to both servers. It must set the environment of each
  child with `Fugu::Process`. It must compare the two `200` bodies byte for byte.

| Operation and path | Draws, in order |
| --- | --- |
| `set_pin`, success | `server_random32` (32), storage IV (16), response IV (16) |
| `get_pin`, correct PIN | storage IV (16), response IV (16) |
| `get_pin`, wrong PIN, and the third strike | storage IV (16), junk key (32), response IV (16) |
| `get_pin`, missing record, corrupt record, or replay violation | junk key (32), response IV (16) |

`mkstemp(3)` draws file names outside the seam: record bytes on disk are out of the
byte-identity scope.
