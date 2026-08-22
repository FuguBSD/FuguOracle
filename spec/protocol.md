# Wire protocol, version 2

This document is normative. All byte lengths are exact. All multi-byte counters
use little-endian byte order. `H(x)` is SHA-256. `HMAC(k, m)` is HMAC-SHA256,
unless the text says otherwise. `‖` marks concatenation.

<a id="proto-http"></a>

## HTTP surface

| Method | Path       | Body                   | Success response              |
| ------ | ---------- | ---------------------- | ----------------------------- |
| `GET`  | `/`        | —                      | `200`, empty body (liveness)  |
| `POST` | `/get_pin` | `{"data": "<base64>"}` | `200`, `{"data": "<base64>"}` |
| `POST` | `/set_pin` | `{"data": "<base64>"}` | `200`, `{"data": "<base64>"}` |

A client builds the two POST paths when it appends `/get_pin` and `/set_pin` to
the provisioned URL (see [CLIENT-PROVISION](clients.md#client-provision)).

- **PROTO-HTTP-1** — The service must not inspect the request `Content-Type`.
  This matches the upstream server.
- **PROTO-HTTP-2** — The service must reject a body larger than 4096 bytes with
  status `413`.
- **PROTO-HTTP-3** — The service must reject malformed JSON, bad base64, and a
  length violation with status `400`.
- **PROTO-HTTP-4** — The service must answer these failures with status `500`:
  an envelope failure (a bad MAC, a decrypt error, or bad padding), a payload
  extraction failure (see [PROTO-PAYLOAD-5](protocol.md#proto-payload)), a
  `set_pin` failure after payload extraction, and an I/O failure.
- **PROTO-HTTP-5** — The service must answer an unknown path with `404` and a
  wrong method with `405`.
- **PROTO-HTTP-6** — The service must set the response header
  `Content-Type: application/json` on every `200` response to a `POST` request.
  Error responses and the liveness response must carry an empty body.
- **PROTO-HTTP-7** — The JSON reader must accept only one request shape: an
  object with a `data` member whose value is a base64 string without escape
  sequences. A small linear scanner extracts the member. The scanner must ignore
  unknown members, must accept insignificant JSON whitespace, and must treat a
  duplicate `data` member or any other shape as malformed JSON. The service must
  not use a JSON library.
- **PROTO-HTTP-8** — HTTP error statuses answer every failure up to and through
  payload extraction, every `set_pin` failure, and every I/O failure. After
  payload extraction succeeds, [OPS-JUNK](operations.md#ops-junk) governs every
  `get_pin` failure except an I/O failure ([OPS-GET-7](operations.md#ops-get)).

The failure table assigns every failure class one response:

| Failure                                           | `get_pin`                     | `set_pin`                              |
| ------------------------------------------------- | ----------------------------- | -------------------------------------- |
| Unknown path or wrong method                      | `404` / `405`                 | `404` / `405`                          |
| Body larger than 4096 bytes                       | `413`                         | `413`                                  |
| Malformed JSON, bad base64, or a length violation | `400`                         | `400`                                  |
| Envelope MAC, decrypt, or padding failure         | `500`                         | `500`                                  |
| Payload length or signature recovery failure      | `500`                         | `500`                                  |
| Payload without `entropy` (the 97-byte form)      | Normal: `entropy` is optional | `500`                                  |
| Missing record                                    | `200`, junk key               | Normal: the service creates the record |
| Corrupt record                                    | `200`, junk key               | `500`                                  |
| Replay violation                                  | `200`, junk key               | `500`                                  |
| Wrong PIN                                         | `200`, junk key               | —                                      |
| I/O or persist failure                            | `500`                         | `500`                                  |

<a id="proto-envelope"></a>

## Request envelope

The `data` value decodes from base64 to this layout:

| Offset | Length | Field            | Content                                                                             |
| ------ | ------ | ---------------- | ----------------------------------------------------------------------------------- |
| 0      | 33     | `cke`            | Client ephemeral public key, SEC1 compressed                                        |
| 33     | 4      | `replay_counter` | uint32 LE, strictly monotonic per PIN record (see [OPS-GET](operations.md#ops-get)) |
| 37     | N      | `encrypted`      | `IV(16) ‖ AES-256-CBC ciphertext ‖ HMAC-SHA256 tag(32)`                             |

- **PROTO-ENVELOPE-1** — The service must reject an envelope shorter than 101
  bytes (33 + 4 + 16 + 16 + 32).
- **PROTO-ENVELOPE-2** — The ciphertext between the IV and the tag must be a
  positive multiple of 16 bytes. A violation is a length violation (`400`).

A well-formed request envelope has 197 bytes for the 97-byte payload form and
229 bytes for the 129-byte payload form (see
[PROTO-PAYLOAD](protocol.md#proto-payload)).

<a id="proto-tweak"></a>

## Per-request server key derivation

The server holds a static keypair `(d, P)`. For each request, the server derives
a request-specific private key `d'`:

```
m   = H( HMAC(key = cke, msg = replay_counter) )        ; 32 bytes
d'  = BIP341-private-tweak(d, merkle_root = m)
```

The BIP341 private tweak is exactly the `libsecp256k1` x-only keypair tweak:

```
keypair  = secp256k1_keypair_create(d)
xonly_P  = secp256k1_keypair_xonly_pub(keypair)
t        = secp256k1_tagged_sha256("TapTweak", xonly_P ‖ m)
           secp256k1_keypair_xonly_tweak_add(keypair, t)
d'       = secp256k1_keypair_sec(keypair)
```

- **PROTO-TWEAK-1** — The service must compute `m` as
  `H(HMAC(key = cke, msg = replay_counter))`.
- **PROTO-TWEAK-2** — The service must derive `d'` with
  `secp256k1_keypair_xonly_tweak_add`. The scalar added is the tagged hash
  `t = H_TapTweak(xonly_P ‖ m)`, with even-Y negation of `d`. The scalar added
  is not `m` itself.
- **PROTO-TWEAK-3** — A known-answer vector generated from libwally must pin
  this derivation (see [TEST-KAT](testing.md#test-kat)).

Interop note, verified against the libwally source: the upstream server calls
`wally_ec_private_key_bip341_tweak(d, tweak, 0)` and passes the pin-server
"tweak" value `m` as the merkle-root argument. A service that adds `m` directly
produces envelopes that no client can read. `secp256k1_keypair_xonly_tweak_add`
matches libwally by construction, because libwally itself calls it.

<a id="proto-crypto"></a>

## Envelope encryption

The semantics match libwally `aes_cbc_with_ecdh_key`, verified against libwally
`src/aes.c`:

```
shared  = secp256k1_ecdh(cke, d')      ; default hash function:
                                       ;   SHA256(compressed shared point)
keys64  = HMAC-SHA512(key = shared, msg = label)
enc_key = keys64[0:32]                 ; AES-256-CBC key
mac_key = keys64[32:64]                ; HMAC-SHA256 key
```

The labels are ASCII, with no NUL terminator:

| Direction                   | Label                   |
| --------------------------- | ----------------------- |
| Request (client to server)  | `blind_oracle_request`  |
| Response (server to client) | `blind_oracle_response` |

- **PROTO-CRYPTO-1** — The ECDH step must use the `libsecp256k1` default hash
  function: SHA-256 of the compressed shared point.
- **PROTO-CRYPTO-2** — The key derivation must split
  `HMAC-SHA512(shared, label)` into `enc_key` (bytes 0 to 31) and `mac_key`
  (bytes 32 to 63).
- **PROTO-CRYPTO-3** — To decrypt a request: split `IV(16) ‖ ct ‖ tag(32)`,
  require `timingsafe_bcmp(tag, HMAC(mac_key, IV ‖ ct)) == 0` before decryption
  (encrypt-then-MAC), then decrypt with AES-256-CBC and PKCS#7 padding.
- **PROTO-CRYPTO-4** — To encrypt a response: draw a fresh random IV from
  `arc4random_buf(3)`, then output
  `IV ‖ CBC-encrypt(payload) ‖ HMAC(mac_key, IV ‖ ct)`.
- **PROTO-CRYPTO-5** — Both directions must use the same `shared` secret (same
  `d'`, same `cke`). Only the label differs.

The EVP layer of `libcrypto` with default PKCS#7 padding interoperates with
libwally. Libwally pads PKCS#7 with 1 to 16 bytes on encrypt, and it adds a full
pad block only for a block-aligned plaintext. The libwally unpad is lenient: it
reads the last byte modulo 16, it never fails, and it accepts strict PKCS#7
output. The strict EVP unpad rejects forged padding that the lenient unpad
accepts. Only a holder of the derived keys can build such an input, because the
MAC check runs first. The service answers it with status `500` per
[PROTO-HTTP-4](protocol.md#proto-http). Byte-identity testing excludes such
vectors (see D-12).

<a id="proto-payload"></a>

## Request payload

After envelope decryption, the plaintext has one of these forms:

```
get_pin:  pin_secret(32) ‖ sig(65)                    = 97 bytes
     or:  pin_secret(32) ‖ entropy(32) ‖ sig(65)      = 129 bytes (entropy ignored)
set_pin:  pin_secret(32) ‖ entropy(32) ‖ sig(65)      = 129 bytes (entropy required)
```

- **PROTO-PAYLOAD-1** — The service must reject every other payload length.
- **PROTO-PAYLOAD-2** — `sig` is a recoverable ECDSA signature of 65 bytes, in
  the libwally format: `sig[0]` is a header byte with
  `recid = (sig[0] - 27) & 3`, and `sig[1..64]` is the compact `r ‖ s`.
- **PROTO-PAYLOAD-3** — The signed message is
  `H( cke ‖ replay_counter ‖ pin_secret ‖ entropy )`. For the 97-byte form,
  `entropy` is empty.
- **PROTO-PAYLOAD-4** — The service must recover the client public key from the
  signature: parse with
  `secp256k1_ecdsa_recoverable_signature_parse_compact(&rsig, sig+1, recid)`,
  recover with `secp256k1_ecdsa_recover(&pin_pubkey, &rsig, msghash)`, then
  serialize `pin_pubkey` as SEC1 compressed (33 bytes).
- **PROTO-PAYLOAD-5** — A payload length violation and a signature recovery
  failure are internal failures (`500`), on both endpoints. The junk path needs
  `pin_secret` and the recovered key, so it cannot answer these failures.

The recovered key never travels on the wire. The client holds the matching
private key independent of the PIN, and possession of that key is the client's
identity. The client mixes the PIN into `pin_secret` only (see
[CLIENT-MODEL](clients.md#client-model)). A wrong PIN yields the same recovered
public key and a different `pin_secret`: the request addresses the same record,
and the wrong guess burns one attempt. The hash of the recovered key addresses
the PIN record (see [STORE-KEYS](storage.md#store-keys)).

<a id="proto-response"></a>

## Response payload

- **PROTO-RESPONSE-1** — The response plaintext is one 32-byte AES key.
- **PROTO-RESPONSE-2** — The service must envelope the response per
  [PROTO-CRYPTO](protocol.md#proto-crypto) with the response label. The
  enveloped size is exactly `16 + 48 + 32 = 96` bytes.
- **PROTO-RESPONSE-3** — The service must encode the envelope as base64 and must
  return it as `{"data": "<base64>"}`.
