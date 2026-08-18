# FuguOracle — Specification

**A native OpenBSD blind PIN oracle for Blockstream Jade, written in C.**

| | |
|---|---|
| Status | Draft 1 |
| Target OS | OpenBSD -stable (current release at time of import) |
| Language | C (KNF, `style(9)`) |
| License | ISC (new code); wire-compatible with Blockstream `blind_pin_server` (MIT) |
| Upstream reference | `github.com/Blockstream/blind_pin_server` (Python, 712 LOC) |
| Scope | PIN-server **protocol v2 only** — the protocol spoken by current Jade firmware |

---

## 1. Purpose and scope

FuguOracle is a from-scratch C implementation of the Blockstream blind PIN
oracle, byte-for-byte wire-compatible with `blind_pin_server` protocol v2, so
that a self-hosted OpenBSD machine can serve as the PIN server for one or more
Jade hardware wallets.

The oracle's job: a Jade holds a wallet secret encrypted under a key it does
not store. To unlock with a 6-digit PIN, the Jade proves knowledge of the PIN
to the oracle (blindly — the oracle never learns the PIN or the wallet secret)
and receives a key share in return. The oracle enforces **three PIN attempts**,
after which it destroys its share, making the Jade's flash contents
undecryptable. Security of the scheme rests on the secrecy of the oracle's
static secp256k1 key and the integrity of its attempt counter.

### 1.1 Goals

- Smallest viable feature set: serve the **latest Jade firmware only**.
- OpenBSD base for everything except secp256k1 arithmetic.
- No reimplemented cryptography. All primitives come from LibreSSL
  `libcrypto` (base) and `libsecp256k1` (port).
- Idiomatic OpenBSD design: `httpd(8)` + `slowcgi(8)` + a statically linked
  CGI binary, `pledge(2)`, `unveil(2)`, `arc4random(3)`, `syslog(3)`,
  `mdoc(7)` man pages, an rc.d script, and a clean ports-tree package.

### 1.2 Non-goals (explicit deviations from upstream)

| Upstream feature | FuguOracle | Rationale |
|---|---|---|
| Protocol v1 (`/start_handshake`, sessions, explicit hmac fields) | **Dropped** | Legacy clients only; v2 is stateless — no session table, no lifetime config |
| Redis storage backend | **Dropped** | Flat files in one directory; workload is a handful of requests per day |
| `python-dotenv` config | **Dropped** | Compile-time paths documented in the man page; OpenBSD has no dotenv culture |
| Flask/Werkzeug/gunicorn/nginx | **Dropped** | `httpd(8)` + `slowcgi(8)` from base |
| Non-atomic record writes | **Fixed** | `mkstemp(3)` + `fsync(2)` + `rename(2)` |
| v0→v1 database migration | **Dropped** | Fresh deployments write and read record version `0x01` only |

---

## 2. Architecture

```
                    Internet (Green app / gdk performs the HTTPS call,
                              relaying for the Jade over USB/BLE/QR)
                        │
                 ┌──────▼──────┐  TLS (acme-client(1) / native httpd TLS)
                 │  httpd(8)   │  chroot /var/www
                 └──────┬──────┘
                        │ FastCGI, unix socket /var/www/run/fuguoracle.sock
                 ┌──────▼──────┐
                 │ slowcgi(8)  │  -u _fuguoracle  (dedicated user)
                 └──────┬──────┘
                        │ fork+exec per request (CGI)
                 ┌──────▼──────────────────────┐
                 │ /cgi-bin/fuguoracle (static)│  pledge + unveil
                 │  ├─ libcrypto (base, .a)    │
                 │  └─ libsecp256k1 (port, .a) │
                 └──────┬──────────────────────┘
                        │
        /var/www/fuguoracle/private.key   (0400 _fuguoracle)
        /var/www/fuguoracle/pins/*.pin    (records, 129 bytes each)
```

Design notes:

- **Process per request** is a feature, not a limitation. Each request gets a
  fresh address space; secrets live for milliseconds; there is no long-lived
  daemon to exploit. Request volume for a personal oracle is measured in
  requests per day. `slowcgi(8)` exists in base for exactly this shape of
  program (cf. `bgplg(8)`, `man.cgi(8)`).
- **Statically linked**, because the CGI executes inside the `/var/www`
  chroot where no shared libraries are present. This matches base-system
  chrooted CGI practice.
- **v2 is stateless**, so the CGI holds no state between requests other than
  the PIN record files. No session table, no cleanup timer, nothing to tune.

---

## 3. Dependencies

### 3.1 From OpenBSD base

| Facility | Used for |
|---|---|
| `libcrypto` (LibreSSL, `/usr/lib/libcrypto.a`) | SHA-256, HMAC-SHA256, HMAC-SHA512, AES-256-CBC (EVP, PKCS#7) |
| `libc` | `arc4random_buf(3)` (CSPRNG), `b64_ntop`/`b64_pton` (base64), `explicit_bzero(3)`, `freezero(3)`, `timingsafe_bcmp(3)` |
| `httpd(8)`, `slowcgi(8)` | TLS termination, FastCGI→CGI |
| `pledge(2)`, `unveil(2)` | Sandboxing |
| `syslog(3)` via `/var/www/dev/log` | Logging (socket created by default `syslogd(8)`) |
| `acme-client(1)` | Certificate for the public endpoint |

### 3.2 From ports: `security/libsecp256k1` (new port, prerequisite)

OpenBSD's ports tree currently has **no standalone libsecp256k1** (`net/bitcoin`
formerly installed the library but removed it from its PLIST after vendoring).
FuguOracle therefore requires a small companion port of upstream
`bitcoin-core/secp256k1`:

- Modules enabled: `ecdh`, `recovery`, `extrakeys`
  (`schnorrsig`, `ellswift`, `musig` off — not needed).
- MIT licensed; builds cleanly with base clang; ships `libsecp256k1.a`,
  headers, and pkg-config file.
- FuguOracle consumes it as a **BUILD_DEPENDS** and links the static archive
  (no `WANTLIB`, since the final binary is static for the chroot).

This is the "don't reimplement crypto" decision made concrete: libsecp256k1 is
the reference implementation the upstream server uses (via wallycore), with
constant-time scalar arithmetic, exhaustive test suite, and the exact ECDH,
recovery, and x-only-tweak semantics the wire protocol assumes. Reproducing
those semantics on top of LibreSSL's generic EC would mean hand-writing public
key recovery and matching libsecp256k1 conventions by hand — precisely the
reimplementation this project forbids.

**Division of labor:** libsecp256k1 does everything involving the curve;
libcrypto does everything symmetric (hashes, HMAC, AES). Nothing is written
twice, nothing is written from scratch.

---

## 4. Wire protocol (v2) — normative

All byte lengths are exact. All multi-byte counters are **little-endian**.
`H(x)` = SHA-256. `HMAC(k, m)` = HMAC-SHA256 unless noted.

### 4.1 HTTP surface

| Method | Path | Body | Success response |
|---|---|---|---|
| `GET` | `/` | — | `200`, empty body (liveness) |
| `POST` | `/get_pin` | `{"data": "<base64>"}` | `200`, `{"data": "<base64>"}` |
| `POST` | `/set_pin` | `{"data": "<base64>"}` | `200`, `{"data": "<base64>"}` |

- Request `Content-Type` is not inspected (matches upstream).
- Body limit: 4096 bytes. Anything larger: `413`.
- Malformed JSON, bad base64, or length violations: `400`.
- Internal failures (record corruption, I/O): `500`.
- Unknown path: `404`; wrong method: `405`.
- Response `Content-Type: application/json`.

JSON handling is deliberately trivial: the only accepted request shape is a
single-key object with a base64 string value. A ~120-line recursive-descent
scanner that extracts the `data` member is sufficient and auditable; no JSON
library is needed or wanted.

### 4.2 Request envelope (decoded from base64)

```
offset  len   field
0       33    cke              client ephemeral pubkey, SEC1 compressed
33      4     replay_counter   uint32 LE, strictly monotonic per client key
37      N     encrypted        IV(16) ‖ AES-256-CBC ciphertext ‖ HMAC-SHA256(32)
```

Minimum total length: 101 bytes (33 + 4 + 16 + 16 + 32).

### 4.3 Per-request server key derivation (BIP341 tweak)

The server holds a static keypair `(d, P)`. For each request it derives a
request-specific private key — this replaces v1's signed-handshake:

```
m   = H( HMAC(key = cke, msg = replay_counter) )          ; 32 bytes
d'  = BIP341-private-tweak(d, merkle_root = m)
```

where BIP341-private-tweak is exactly libsecp256k1's x-only keypair tweak:

```
keypair  = secp256k1_keypair_create(d)
xonly_P  = secp256k1_keypair_xonly_pub(keypair)
t        = secp256k1_tagged_sha256("TapTweak", xonly_P ‖ m)
           secp256k1_keypair_xonly_tweak_add(keypair, t)
d'       = secp256k1_keypair_sec(keypair)
```

**Interop note (verified against libwally source):** upstream calls
`wally_ec_private_key_bip341_tweak(d, tweak, 0)` where the pin-server's
"tweak" value `m` is passed as the *merkle root* argument. The scalar actually
added is the full TapTweak tagged hash `t = H_TapTweak(xonly_P ‖ m)`, with
even-Y negation of `d` — not `m` itself. Getting this wrong produces a server
the Jade silently cannot talk to. Using `keypair_xonly_tweak_add` matches
wally by construction because wally itself calls it.

### 4.4 Envelope encryption (`aes_cbc_with_ecdh_key` semantics)

Verified against libwally `src/aes.c`:

```
shared = secp256k1_ecdh(cke, d')       ; default hashfp:
                                       ;   SHA256(compressed shared point)
keys64 = HMAC-SHA512(key = shared, msg = label)
enc_key = keys64[0:32]                 ; AES-256-CBC key
mac_key = keys64[32:64]                ; HMAC-SHA256 key
```

Labels (ASCII, no NUL):

- request (client→server): `blind_oracle_request`
- response (server→client): `blind_oracle_response`

Decrypt (request): split `IV(16) ‖ ct ‖ tag(32)`; require
`timingsafe_bcmp(tag, HMAC(mac_key, IV ‖ ct)) == 0` **before** decrypting
(encrypt-then-MAC); then AES-256-CBC decrypt with PKCS#7 padding.

Encrypt (response): fresh random IV from `arc4random_buf`; output
`IV ‖ CBC-encrypt(payload) ‖ HMAC(mac_key, IV ‖ ct)`.

Both directions use the same `shared` (same `d'`, same `cke`), differing only
in label. libcrypto's EVP layer with default PKCS#7 interoperates: wally pads
PKCS#7 on encrypt (always at least one pad block), and its lenient unpad
accepts strict PKCS#7 output.

### 4.5 Request payload (plaintext, after envelope decrypt)

```
get_pin:  pin_secret(32) ‖ sig(65)                    = 97 bytes
     or:  pin_secret(32) ‖ entropy(32) ‖ sig(65)      = 129 bytes (entropy ignored)
set_pin:  pin_secret(32) ‖ entropy(32) ‖ sig(65)      = 129 bytes (entropy required)
```

Any other length: reject.

`sig` is a **recoverable ECDSA signature**, 65 bytes, wally format
(verified against libwally `src/sign.c`):

```
sig[0]      header byte; recid = (sig[0] - 27) & 3
sig[1..64]  compact r ‖ s
```

Signed message: `H( cke ‖ replay_counter ‖ pin_secret ‖ entropy )`
(entropy empty for the 97-byte form). The client public key is **recovered**:

```
secp256k1_ecdsa_recoverable_signature_parse_compact(&rsig, sig+1, recid)
secp256k1_ecdsa_recover(&pin_pubkey, &rsig, msghash)
pin_pubkey → SEC1 compressed (33 bytes)
```

The server never sees this key on the wire; possession of the corresponding
private key (derived on the Jade from the PIN + device secrets) *is* the
client's identity. Its hash addresses the PIN record.

### 4.6 Response payload

A single 32-byte AES key, enveloped per §4.4 with the response label.
Enveloped size is exactly `16 + 48 + 32 = 96` bytes → base64 → `{"data": …}`.

---

## 5. PIN database — normative

### 5.1 Storage keys

```
aes_pin_data_key = HMAC(key = d, msg = "pin_data")       ; derived once
pin_pubkey       = recovered client pubkey, compressed    ; 33 bytes
pin_pubkey_hash  = H(pin_pubkey)                          ; 32 bytes
record path      = pins/<lowercase-hex(pin_pubkey_hash)>.pin
storage_aes_key  = HMAC(aes_pin_data_key, pin_pubkey)
pin_auth_key     = HMAC(aes_pin_data_key, pin_pubkey_hash)
```

Records are encrypted under a key derived from `pin_pubkey`, which is **not
stored** — an attacker with the disk and even the static key `d` cannot read
record contents without a client request supplying the pubkey.

### 5.2 Record format (129 bytes, version 0x01 only)

```
offset  len  field
0       1    version = 0x01
1       32   hmac    = HMAC(pin_auth_key, version ‖ enc)
33      96   enc     = IV(16) ‖ AES-256-CBC(storage_aes_key, plaintext)

plaintext (69 bytes → PKCS#7 → 80):
0       32   hash_pin_secret = H(pin_secret)
32      32   aes_key         (the persisted server key share)
64      1    count           (bad-attempt counter, 0..3)
65      4    replay_counter  uint32 LE (highest seen)
```

Read path: exact 129-byte length check → HMAC verify with
`timingsafe_bcmp` → decrypt → exact plaintext length check.

### 5.3 `set_pin` algorithm

1. Extract fields (§4.5); require entropy.
2. If a record exists for `pin_pubkey_hash`: load it and enforce anti-replay
   (`client_counter > stored_counter`, strict). Missing record is fine;
   a corrupt record is `500`.
3. `new_key = HMAC(key = server_random32, msg = entropy)` with
   `server_random32` from `arc4random_buf` — key material mixes server and
   client entropy.
4. Persist record: `H(pin_secret)`, `new_key`, `count = 0`,
   `replay_counter = 0`.
5. Respond with `HMAC(key = new_key, msg = pin_secret)` (§4.6). The
   pin_secret component is never persisted.

### 5.4 `get_pin` algorithm

1. Extract fields (§4.5); entropy ignored.
2. Load record; enforce anti-replay (strict greater).
3. Compare `H(pin_secret)` to stored hash with `timingsafe_bcmp(3)`.
4. **Correct PIN:** persist record with `count = 0` and the client's
   `replay_counter`; respond `HMAC(saved_key, pin_secret)`.
5. **Wrong PIN, count < 2:** persist `count + 1` and client's counter;
   take the junk path (step 7).
6. **Wrong PIN, count ≥ 2 (third strike):** overwrite the record in place —
   same 129-byte envelope, `aes_key = 0³²`, `count = 3`,
   `replay_counter = 0xFFFFFFFF` — `fsync`, then `unlink(2)`. The key share
   is destroyed. (In-place overwrite before unlink is best-effort against
   media recovery, inherited from upstream; no guarantee on FFS/SSD, noted
   in the man page.)
7. **Junk path (any failure: no record, bad HMAC, replay violation, wrong
   PIN):** respond `200` with `HMAC(key = random32, msg = pin_secret)`,
   `random32` fresh from `arc4random_buf`. A caller cannot distinguish
   "wrong PIN" from "no such record" from "replayed request" — the only
   observable failure oracle is the Jade's own decrypt failing. This
   property is load-bearing; preserve it exactly. HTTP-level errors (`4xx`/
   `5xx`) are reserved for requests that fail *before* envelope decryption.

### 5.5 Concurrency and atomicity

- One global advisory lock: `open("pins/.lock", O_RDWR|O_CREAT|O_EXLOCK)`
  held across the load→decide→store critical section. Coarse, correct, and
  appropriate for the workload; no per-record lock choreography.
- Writes: `mkstemp(3)` in `pins/`, write 129 bytes, `fsync(2)`, `rename(2)`
  over the target, `fsync` the directory fd. A crashed request never leaves
  a torn record.

---

## 6. Security design

### 6.1 Threat model in one paragraph

The oracle's static key `d` and the per-record `aes_key` shares are the
assets. Compromise of `d` alone lets an attacker who has *also* stolen a
Jade's flash contents brute-force the 6-digit PIN offline (the whole point of
the oracle is that this requires the server's cooperation, rate-limited to 3
tries). Therefore: constant-time curve arithmetic (libsecp256k1), minimal
attack surface (CGI, no parser zoo), key file unreadable by the web stack
(`_fuguoracle` user, 0400), and sandbox confinement.

### 6.2 pledge/unveil

```c
if (pledge("stdio rpath wpath cpath flock unveil", NULL) == -1) err(1, "pledge");
if (unveil(KEY_PATH,  "r")   == -1) err(1, "unveil");
if (unveil(PINS_DIR,  "rwc") == -1) err(1, "unveil");
if (unveil(NULL, NULL) == -1) err(1, "unveil");
if (pledge("stdio rpath wpath cpath flock", NULL) == -1) err(1, "pledge");
```

Applied first thing in `main()`, before reading a single request byte. No
`inet` promise: the CGI touches only stdio and two filesystem paths. The
process is additionally confined by the `/var/www` chroot and runs as
`_fuguoracle` (via `slowcgi -u`), not `www` — `httpd`'s own workers cannot
read the key file.

### 6.3 Memory hygiene

- `d`, `d'`, shared secrets, derived keys, plaintexts: stack buffers or
  `freezero(3)`-released allocations; `explicit_bzero(3)` on every exit path
  (use `__attribute__((cleanup))` or a single `goto out` discipline per
  `style(9)`).
- All secret comparisons: `timingsafe_bcmp(3)`. Never `memcmp` on MACs or
  PIN hashes.
- Base clang hardening (RETGUARD, stack protector, W^X) applies by default;
  build with `-Wall -Wextra -Werror`.

### 6.4 Randomness

`arc4random_buf(3)` everywhere (IVs, junk keys, server entropy, keygen).
No seeding, no `/dev/urandom` plumbing, works in the chroot — this is the
OpenBSD answer and the reason the upstream `os.urandom` calls map cleanly.

### 6.5 Logging

`openlog("fuguoracle", LOG_PID, LOG_DAEMON)` over `/var/www/dev/log`
(present in the chroot by default `syslogd(8)` configuration). Log: request
outcome class, wipe events (prominently), and I/O errors. **Never** log key
material, payloads, `cke`, or record names at default level; record names at
`LOG_DEBUG` only.

---

## 7. Programs and file layout

### 7.1 `fuguoracle` (the CGI, `man 8 fuguoracle`)

Dispatch on `REQUEST_METHOD` + `SCRIPT_NAME`/`PATH_INFO`; read at most
`CONTENT_LENGTH ≤ 4096` bytes from stdin; emit CGI response on stdout.
Compile-time paths (chroot-relative):

```
/fuguoracle/private.key      static key, 32 raw bytes
/fuguoracle/pins/            record directory
```

### 7.2 `fuguoracle-keygen` (`man 8 fuguoracle-keygen`)

Run once, as root, **outside** the chroot:

- Generates 32 random bytes until `secp256k1_ec_seckey_verify` passes
  (first draw succeeds with overwhelming probability).
- Writes `/var/www/fuguoracle/private.key`, owner `_fuguoracle:_fuguoracle`,
  mode `0400`; refuses to overwrite an existing key.
- Prints the compressed public key as hex — this is what gets provisioned
  into the Jade (§9).
- `pledge("stdio rpath wpath cpath", NULL)`; `unveil` the target directory.

### 7.3 Source layout (~1,500 LOC target)

```
fuguoracle/
├── Makefile            BSD make, bsd.prog.mk style
├── main.c              CGI entry, dispatch, pledge/unveil, limits
├── http.c/.h           CGI env, body read, JSON in/out, base64 (b64_*)
├── crypto.c/.h         §4.3–4.4: tweak, ECDH-envelope, hashes, AES (EVP)
├── oracle.c/.h         §4.5–4.6 + §5.3–5.4: protocol logic
├── pindb.c/.h          §5.1–5.2, §5.5: records, locking, atomic writes
├── keygen.c            fuguoracle-keygen
├── fuguoracle.8        mdoc
├── fuguoracle-keygen.8 mdoc
└── regress/            KATs + unit tests (make regress)
```

`crypto.c` is the only file that includes `<secp256k1*.h>` and
`<openssl/*.h>`; `oracle.c` and `pindb.c` see an 8-function shim API. This
keeps the wally-semantics surface in one reviewable place.

---

## 8. Deployment configuration (shipped in pkg-readme)

### 8.1 `/etc/httpd.conf`

```
server "oracle.example.org" {
        listen on egress tls port 443
        tls {
                certificate "/etc/ssl/oracle.example.org.fullchain.pem"
                key "/etc/ssl/private/oracle.example.org.key"
        }
        location "/get_pin" {
                fastcgi {
                        socket "/run/fuguoracle.sock"
                        param SCRIPT_FILENAME "/cgi-bin/fuguoracle"
                }
        }
        location "/set_pin" {
                fastcgi {
                        socket "/run/fuguoracle.sock"
                        param SCRIPT_FILENAME "/cgi-bin/fuguoracle"
                }
        }
        location "/" {
                fastcgi {
                        socket "/run/fuguoracle.sock"
                        param SCRIPT_FILENAME "/cgi-bin/fuguoracle"
                }
        }
        location match ".*" { block }
}
```

### 8.2 Dedicated slowcgi instance

The port installs `/etc/rc.d/fuguoracle`, a standard `rc.subr(8)` script
wrapping base `slowcgi(8)`:

```
daemon="/usr/sbin/slowcgi"
daemon_flags="-p /var/www -s /var/www/run/fuguoracle.sock -u _fuguoracle"
```

Bring-up:

```
# pkg_add fuguoracle
# fuguoracle-keygen                     # note the printed pubkey hex
# rcctl enable httpd fuguoracle
# rcctl start fuguoracle httpd
```

No cron jobs, no cleanup tasks, no state beyond `pins/`.

---

## 9. Jade provisioning

The Jade must be told to trust this oracle instead of Blockstream's:

- Via the companion app / gdk `update_pinserver` call, set the oracle **URL**
  (`https://oracle.example.org`) and the **static public key** (hex from
  `fuguoracle-keygen`).
- The Jade authenticates the oracle cryptographically: it computes the
  expected tweaked server key from the provisioned static pubkey
  (§4.3 public-key side) and the envelope MAC fails against an impostor. TLS
  protects metadata and availability, not the core secret — but is still
  required because the wallet app performs the HTTPS call.
- After provisioning, `set_pin` occurs on next wallet initialization/PIN set;
  `get_pin` on every unlock.

**Backup warning (man page + pkg-readme):** the static key *is* the service.
Loss of `private.key` or the `pins/` directory renders every enrolled Jade's
PIN unlock permanently inoperable (recovery phrase still works). Back up the
key offline at enrollment time; treat `pins/` as precious.

---

## 10. Ports packaging

Two ports, submitted together:

### 10.1 `security/libsecp256k1` (new)

```
COMMENT =       optimized C library for EC operations on curve secp256k1
GH_ACCOUNT =    bitcoin-core
GH_PROJECT =    secp256k1
CONFIGURE_ARGS = --enable-module-ecdh \
                 --enable-module-recovery \
                 --enable-module-extrakeys \
                 --disable-benchmark
```

Runs upstream's test suite in `do-test`. Useful beyond FuguOracle (any
future Bitcoin-adjacent port).

### 10.2 `security/fuguoracle`

```
COMMENT =       blind PIN oracle for Blockstream Jade (pinserver v2)
BUILD_DEPENDS = security/libsecp256k1
# static link: no LIB_DEPENDS/WANTLIB beyond base
```

- Installs: `/var/www/cgi-bin/fuguoracle` (static, `@mode 0555`),
  `/usr/local/sbin/fuguoracle-keygen`, man pages, rc.d script, pkg-readme.
- `pkg/PLIST` uses `@newuser _fuguoracle` / `@newgroup` (uid from the ports
  user registry for official submission), `@sample`-creates
  `/var/www/fuguoracle/pins/` (`0700 _fuguoracle`).
- `make regress` runs the KAT suite (no network).

---

## 11. Testing

1. **Known-answer tests (regress/):** vectors generated once from upstream
   wallycore for every shim function — TapTweak derivation, ECDH shared
   secret, HMAC-SHA512 KDF split, envelope encrypt/decrypt, pubkey recovery,
   record encrypt/decrypt. Committed as hex; `make regress` needs no Python
   and no network.
2. **Interop harness (dev-only, not packaged):** upstream repo's
   `client.py` and test suite pointed at a local
   `httpd`+`slowcgi`+FuguOracle stack. Must pass: set→get roundtrip, wrong
   PIN ×2 then correct, wrong PIN ×3 → wipe → junk-key responses, replay
   counter rejection (stale and equal), 97- vs 129-byte payload forms.
3. **Differential fuzzing (dev-only):** afl or simple mutation of the
   base64 body against both servers; assert identical status-class behavior
   and identical junk-vs-real key decisions.
4. **Live Jade test:** provision a spare Jade against the oracle; full
   set-PIN / unlock / 3-strike-wipe cycle before any real use.

Acceptance: byte-identical responses to upstream for identical inputs and
identical stored state (given fixed RNG in test builds — RNG calls routed
through one seam, overridable in regress builds only).

---

## 12. Risks and open questions

| Risk | Mitigation |
|---|---|
| Wally semantics drift in future Jade firmware | Protocol v2 is stable and versioned in the DB record; KATs pin current behavior; watch upstream repo |
| TapTweak/merkle-root confusion (§4.3) — the classic interop trap | KAT vector generated from wally on day one, before any other code |
| PKCS#7 edge cases between EVP and wally's lenient unpad | Covered by envelope KATs including block-aligned plaintexts (97 and 129 bytes both exercise padding) |
| Third-strike overwrite gives weak deletion guarantees on SSD/FFS | Documented; the wiped record is also cryptographically dead (zero key + unlink); consider `softdep`-independent `fsync` ordering, already specified |
| Single global lock serializes requests | Intentional; workload is trivially small |
| No standalone libsecp256k1 port exists yet | Companion port is part of this project's deliverables |

---

## 13. Milestones

1. **M1 — crypto shim + KATs.** `crypto.c` complete; all wally-derived
   vectors pass. (The hard 20% lives here.)
2. **M2 — pindb + oracle logic.** Record format, locking, get/set state
   machine; unit tests.
3. **M3 — CGI + deployment.** `main.c`/`http.c`, pledge/unveil, httpd +
   slowcgi config; upstream `client.py` interop green.
4. **M4 — ports + docs.** Both port skeletons, man pages, pkg-readme;
   live Jade validation.
