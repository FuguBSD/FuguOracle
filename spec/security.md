# Security design

<a id="sec-threat"></a>

## Threat model

The assets are the static server key `d` and the per-record `aes_key` shares.
An attacker who compromises `d`, and who has also stolen a client's flash contents, can
brute-force the low-entropy PIN offline.
The purpose of the oracle is to make that brute force require the server's cooperation,
rate-limited to three attempts.
The defenses follow from this: constant-time curve arithmetic (`libsecp256k1`), a
minimal attack surface (a CGI program, no parser zoo), a key file that the web stack
cannot read (owner `_fuguoracle`, mode `0400`), and sandbox confinement.

<a id="sec-sandbox"></a>

## Sandbox

```c
struct rlimit rl = { 0, 0 };
if (setrlimit(RLIMIT_CORE, &rl) == -1) err(1, "setrlimit");
if (pledge("stdio rpath wpath cpath flock unveil", NULL) == -1) err(1, "pledge");
if (unveil(KEY_PATH,  "r")   == -1) err(1, "unveil");
if (unveil(PINS_DIR,  "rwc") == -1) err(1, "unveil");
if (unveil(NULL, NULL) == -1) err(1, "unveil");
if (pledge("stdio rpath wpath cpath flock", NULL) == -1) err(1, "pledge");
```

- **SEC-SANDBOX-1** — The CGI program must apply `pledge(2)` and `unveil(2)`
  immediately after the `RLIMIT_CORE` call ([SEC-MEMORY-5](security.md#sec-memory)),
  before it reads a single request byte. `setrlimit(2)` needs the `proc` promise,
  which the program must not hold, so that call precedes `pledge(2)`.
- **SEC-SANDBOX-2** — The pledge promises are exactly
  `stdio rpath wpath cpath flock unveil`, reduced to
  `stdio rpath wpath cpath flock` after the unveil calls. The program must not hold
  the `inet` promise: it touches only stdio and two filesystem paths.
- **SEC-SANDBOX-3** — The program must unveil only the key path, read-only, and the
  records directory, read-write-create.
- **SEC-SANDBOX-4** — The program must run inside the `/var/www` chroot, as the user
  `_fuguoracle` (via `slowcgi -u`), so that the `httpd(8)` workers cannot read the key
  file.

<a id="sec-memory"></a>

## Memory hygiene

- **SEC-MEMORY-1** — `d`, `d'`, shared secrets, derived keys, and plaintexts must live
  in stack buffers or in allocations released with `freezero(3)`.
- **SEC-MEMORY-2** — Every exit path must clear secrets with `explicit_bzero(3)`. Use
  one `goto out` discipline per `style(9)`.
- **SEC-MEMORY-3** — Every secret comparison must use `timingsafe_bcmp(3)`. The
  program must not use `memcmp` on a MAC or on a PIN hash.
- **SEC-MEMORY-4** — The base clang hardening applies by default: RETGUARD, the stack
  protector, and W^X.
- **SEC-MEMORY-5** — The CGI program and `fuguoracle-keygen` must set `RLIMIT_CORE`
  to zero with `setrlimit(2)`, first in `main()` and before the first `pledge(2)`
  call. A crash must not write secrets to a core file.

<a id="sec-random"></a>

## Randomness

- **SEC-RANDOM-1** — All random bytes must come from `arc4random_buf(3)`: IVs, junk
  keys, server entropy, and key generation. It needs no seeding, and it works inside
  the chroot.
- **SEC-RANDOM-2** — All random calls must route through one seam. Only regress builds
  can override the seam, to give tests a fixed random source (see D-12).

<a id="sec-logging"></a>

## Logging

- **SEC-LOGGING-1** — The program must log with
  `openlog("fuguoracle", LOG_PID, LOG_DAEMON)` and `syslog(3)`. OpenBSD `syslog(3)`
  delivers messages with the `sendsyslog(2)` system call: it needs no log socket, it
  works inside the chroot, and the `stdio` pledge promise covers it.
- **SEC-LOGGING-2** — The program must log one line per request with the outcome
  class: `ok_set`, `ok_get`, `junk`, `reject`, or `error`. The program must log wipe
  events prominently, and every I/O error.
- **SEC-LOGGING-3** — The program must not log key material, payloads, `cke`, or
  record names at the default level. Record names can appear at `LOG_DEBUG` only.
