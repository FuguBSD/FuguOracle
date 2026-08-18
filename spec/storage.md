# PIN record storage

This document is normative.
`H(x)` is SHA-256.
`HMAC(k, m)` is HMAC-SHA256.
`d` is the static server private key.
`PINS_DIR` is the record directory, a compile-time constant
(see [PROG-CGI-4](programs.md#prog-cgi)).

<a id="store-keys"></a>

## Storage keys

```
aes_pin_data_key = HMAC(key = d, msg = "pin_data")        ; derived once
pin_pubkey       = recovered client public key, compressed ; 33 bytes
pin_pubkey_hash  = H(pin_pubkey)                           ; 32 bytes
record path      = PINS_DIR "/<lowercase-hex(pin_pubkey_hash)>.pin"
storage_aes_key  = HMAC(aes_pin_data_key, pin_pubkey)
pin_auth_key     = HMAC(aes_pin_data_key, pin_pubkey_hash)
```

- **STORE-KEYS-1** — The service must derive the storage keys exactly as above.
- **STORE-KEYS-2** — The service must not store `pin_pubkey`. The record encryption
  key derives from it, so an attacker with the disk, and even with the static key `d`,
  cannot read a record without a client request that supplies the key.
- **STORE-KEYS-3** — The record file name must be the lowercase hex of
  `pin_pubkey_hash`, with the suffix `.pin`, inside `PINS_DIR`.

<a id="store-record"></a>

## Record format

A record has exactly 129 bytes, in version `0x01` only:

| Offset | Length | Field | Content |
| --- | --- | --- | --- |
| 0 | 1 | `version` | `0x01` |
| 1 | 32 | `hmac` | `HMAC(pin_auth_key, version ‖ enc)` |
| 33 | 96 | `enc` | `IV(16) ‖ AES-256-CBC(storage_aes_key, plaintext)` |

The record plaintext has 69 bytes, padded with PKCS#7 to 80 bytes:

| Offset | Length | Field | Content |
| --- | --- | --- | --- |
| 0 | 32 | `hash_pin_secret` | `H(pin_secret)` |
| 32 | 32 | `aes_key` | The persisted key share |
| 64 | 1 | `count` | Bad-attempt counter, 0 to 3 |
| 65 | 4 | `replay_counter` | uint32 LE, the highest value seen |

- **STORE-RECORD-1** — The read path must check the exact record length of 129 bytes
  first.
- **STORE-RECORD-2** — The read path must verify `hmac` with `timingsafe_bcmp(3)`
  before decryption.
- **STORE-RECORD-3** — The read path must check the exact plaintext length after
  decryption.
- **STORE-RECORD-4** — The service must write and read record version `0x01` only.
- **STORE-RECORD-5** — Every record write must draw a fresh random IV from
  `arc4random_buf(3)` (see [SEC-RANDOM-1](security.md#sec-random)). The storage key is
  fixed per record, so a reused IV reveals to a disk observer whether the first
  plaintext block changed.

<a id="store-atomic"></a>

## Locking and atomic writes

- **STORE-ATOMIC-1** — The service must hold one global advisory lock across the
  load, decide, and store steps of a request:
  `open(PINS_DIR "/.lock", O_RDWR|O_CREAT|O_EXLOCK)`.
- **STORE-ATOMIC-2** — The service must not use per-record locks.
- **STORE-ATOMIC-3** — A write that creates or updates a record must be atomic:
  `mkstemp(3)` in `PINS_DIR`, write the 129 bytes, `fsync(2)`, `rename(2)` over the
  target, then `fsync` the directory file descriptor. A crashed request must not leave
  a torn record. The third-strike wipe is the one exception: it overwrites the record
  in place ([OPS-WIPE-1](operations.md#ops-wipe)), because the wipe targets the
  existing blocks.
