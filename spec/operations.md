# Oracle operations

This document specifies the request handling logic, after envelope decryption
and payload extraction per [PROTO-PAYLOAD](protocol.md#proto-payload). `H(x)` is
SHA-256. `HMAC(k, m)` is HMAC-SHA256.

<a id="ops-set"></a>

## set_pin

- **OPS-SET-1** — The service must require the 129-byte payload form: `entropy`
  is mandatory.
- **OPS-SET-2** — If a record exists for `pin_pubkey_hash`, the service must
  load it and must enforce anti-replay: the client counter must be strictly
  greater than the stored counter. A missing record is normal. A replay
  violation and a corrupt record are internal failures (`500`).
- **OPS-SET-3** — The service must compute
  `new_key = HMAC(key = server_random32, msg = entropy)`, with `server_random32`
  drawn from `arc4random_buf(3)`. The key material mixes server entropy and
  client entropy.
- **OPS-SET-4** — The service must persist the record with `H(pin_secret)`,
  `new_key`, `count = 0`, and `replay_counter = 0`.
- **OPS-SET-5** — The service must respond with
  `HMAC(key = new_key, msg = pin_secret)` per
  [PROTO-RESPONSE](protocol.md#proto-response).
- **OPS-SET-6** — The service must not persist `pin_secret` or any value derived
  from it other than `H(pin_secret)`.
- **OPS-SET-7** — Every `set_pin` failure after envelope decryption must return
  an HTTP error status, never a junk key (see D-10). A client cannot detect a
  junk key on the set flow, and a silent failure desynchronizes the client from
  the oracle.

`set_pin` persists `replay_counter = 0`. Envelopes captured before a PIN change
stay replayable against the new record, until the stored counter passes their
values. The [risk table](overview.md#ovr-risks) records this accepted property.

<a id="ops-get"></a>

## get_pin

- **OPS-GET-1** — The service must accept the 97-byte and the 129-byte payload
  forms and must ignore `entropy`.
- **OPS-GET-2** — The service must load the record and must enforce anti-replay:
  the client counter must be strictly greater than the stored counter. A missing
  record, a corrupt record (a wrong file length, a bad `hmac`, or a wrong
  plaintext length), and a replay violation all take the junk path
  ([OPS-JUNK](operations.md#ops-junk)).
- **OPS-GET-3** — The service must compare `H(pin_secret)` to the stored hash
  with `timingsafe_bcmp(3)`.
- **OPS-GET-4** — On a correct PIN, the service must persist the record with
  `count = 0` and the client's `replay_counter`, and must respond with
  `HMAC(key = saved aes_key, msg = pin_secret)`.
- **OPS-GET-5** — On a wrong PIN with `count < 2`, the service must persist
  `count + 1` and the client's `replay_counter`, and must take the junk path.
- **OPS-GET-6** — On a wrong PIN with `count >= 2`, the third strike, the
  service must destroy the key share ([OPS-WIPE](operations.md#ops-wipe)) and
  must take the junk path.
- **OPS-GET-7** — The service must persist a record change before it sends the
  response. An I/O failure on load, other than a missing record, and every
  persist failure are internal failures (`500`): an attempt that the service
  cannot count must not receive an answer.

<a id="ops-wipe"></a>

## Third-strike wipe

- **OPS-WIPE-1** — The service must overwrite the record file in place, in the
  same 129-byte record layout, with the stored `hash_pin_secret`,
  `aes_key = 0³²`, `count = 3`, and `replay_counter = 0xFFFFFFFF`.
- **OPS-WIPE-2** — The service must `fsync(2)` the overwritten record, then
  `unlink(2)` it. The wipe write bypasses the atomic write path
  ([STORE-ATOMIC-3](storage.md#store-atomic)): a `rename(2)` writes a new inode
  and leaves the old blocks untouched.
- **OPS-WIPE-3** — The service must log a wipe event prominently (see
  [SEC-LOGGING](security.md#sec-logging)).

The in-place overwrite before unlink is a best effort against media recovery,
inherited from the upstream server. FFS and SSD hardware give no overwrite
guarantee. The man page must state this limit. The wiped record is also
cryptographically dead: the key share is zero, and the file is gone.

<a id="ops-junk"></a>

## Junk path

The junk path answers `get_pin` failures after payload extraction: no record, a
corrupt record, a replay violation, and a wrong PIN. An I/O failure returns
status `500` instead ([OPS-GET-7](operations.md#ops-get)). `set_pin` failures
return HTTP error statuses (see [OPS-SET-7](operations.md#ops-set) and D-10).

- **OPS-JUNK-1** — The service must respond with status `200` and a valid
  response envelope whose payload is `HMAC(key = random32, msg = pin_secret)`,
  with `random32` drawn fresh from `arc4random_buf(3)`.
- **OPS-JUNK-2** — A caller must not be able to distinguish a wrong PIN from a
  missing record, or from a replayed request, by the response bytes: the status,
  the headers, and the envelope size must be identical on every junk path. The
  only failure signal is the client's own decrypt failure. Response time can
  differ between paths that write and paths that do not; the
  [risk table](overview.md#ovr-risks) records this accepted risk. The design
  depends on this property: preserve it exactly (see D-10).
- **OPS-JUNK-3** — HTTP error statuses answer every failure class outside the
  junk path (see the failure table in [PROTO-HTTP](protocol.md#proto-http)).
