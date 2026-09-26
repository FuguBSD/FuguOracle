# Architecture

This document specifies the service stack, the dependencies, and the source
layout.

<a id="arch-stack"></a>

## Service stack

```
        Internet (a client app performs the HTTPS call,
                  relaying for the client device)
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

- **ARCH-STACK-1** — `httpd(8)` must terminate TLS and must forward requests
  over FastCGI to `slowcgi(8)`.
- **ARCH-STACK-2** — `slowcgi(8)` must run the CGI program as the dedicated user
  `_fuguoracle`, not as `www`.
- **ARCH-STACK-3** — The CGI program must be statically linked, because it
  executes inside the `/var/www` chroot, where no shared libraries are present.
- **ARCH-STACK-4** — The service must run one process per request, and it must
  hold no state between requests other than the PIN record files.
- **ARCH-STACK-5** — A developer must verify the stack on OpenBSD. The `fuguvm`
  tool supplies the OpenBSD guest. `fuguvm up` starts the guest, and
  `fuguvm ssh` runs each check in the guest. The tool forwards the guest SSH
  port only, so each check must run in the guest. `fuguvm snapshot save` records
  a provisioned guest, and `fuguvm snapshot restore` returns to it. The guest
  holds a test key only, because it permits a root login.

One process per request is a feature: each request gets a fresh address space,
and secrets live for milliseconds. There is no long-lived daemon to exploit, no
session table, no cleanup timer, and nothing to tune.

<a id="arch-deps"></a>

## Dependencies

From the OpenBSD base system:

| Facility                                       | Used for                                                                                             |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `libcrypto` (LibreSSL, `/usr/lib/libcrypto.a`) | SHA-256, HMAC-SHA256, HMAC-SHA512, AES-256-CBC (EVP, PKCS#7)                                         |
| `libc`                                         | `arc4random_buf(3)`, `b64_ntop`/`b64_pton`, `explicit_bzero(3)`, `freezero(3)`, `timingsafe_bcmp(3)` |
| `httpd(8)`, `slowcgi(8)`                       | TLS termination, FastCGI to CGI                                                                      |
| `pledge(2)`, `unveil(2)`                       | Sandbox confinement                                                                                  |
| `syslog(3)`, delivered with `sendsyslog(2)`    | Logging                                                                                              |
| `acme-client(1)`                               | Certificate for the public endpoint                                                                  |

From ports: `security/libsecp256k1`, a new companion port that this project
delivers (see [PKG-SECP](packaging.md#pkg-secp)).

- **ARCH-DEPS-1** — All curve operations must come from `libsecp256k1`: ECDH,
  public key recovery, and the x-only keypair tweak.
- **ARCH-DEPS-2** — All symmetric operations must come from `libcrypto`: hashes,
  HMAC, and AES.
- **ARCH-DEPS-3** — The project must not implement a cryptographic primitive in
  its own code.
- **ARCH-DEPS-4** — The build must consume `libsecp256k1` as a build dependency
  and must link the static archive.
- **ARCH-DEPS-5** — The build and the regression tests run in the OpenBSD guest
  of [ARCH-STACK](architecture.md#arch-stack). `fuguvm put` copies the source
  tree and the port files into the guest. The guest keeps the `comp` set, so it
  compiles the static program. The service needs no virtual machine of its own.

`libsecp256k1` is the reference implementation that the upstream server uses,
through `libwally`. It gives constant-time scalar arithmetic and the exact ECDH,
recovery, and x-only tweak semantics that the wire protocol assumes.

<a id="arch-layout"></a>

## Source layout

```
fuguoracle/
├── src/
│   ├── Makefile            The entry point of the C build, bsd.subdir.mk
│   ├── main.c              CGI entry, dispatch, pledge/unveil, limits
│   ├── http.c/.h           CGI environment, body read, JSON in/out, base64
│   ├── cipher.c/.h         Key tweak, ECDH envelope, hashes, AES (EVP)
│   ├── oracle.c/.h         Payload parsing and the get/set state machine
│   ├── pindb.c/.h          Records, locking, atomic writes
│   ├── keygen.c            fuguoracle-keygen
│   ├── lib/                libfuguoracle.a of the flat sources, bsd.lib.mk
│   ├── fuguoracle/         The CGI program and its mdoc man page
│   ├── fuguoracle-keygen/  The key generator and its mdoc man page
│   └── regress/            Known-answer tests and unit tests (make regress)
└── tests/
    ├── guest               The guest driver: the library, the build, the tests
    ├── interop             The interop harness and the acceptance
    ├── fuzz                The differential fuzzer
    ├── pypi-fetch          The pinned Python distributions of the guest
    ├── interop-checks.py   The checks of TEST-INTEROP and TEST-ACCEPT
    ├── interop-upstream.py The upstream test suite against the stack
    ├── upstream-fixed.py   The upstream server on the fixed random file
    ├── random.bin          The fixed random source of the acceptance
    └── vectors/            generate.py writes vectors.h from libwally
```

- **ARCH-LAYOUT-1** — Only `cipher.c` can include the `libsecp256k1` and
  `libcrypto` headers.
- **ARCH-LAYOUT-2** — `cipher.c` must expose a small shim API to `oracle.c` and
  `pindb.c`. This keeps the surface that matches the `libwally` semantics in one
  reviewable place.
- **ARCH-LAYOUT-3** — The build must use `-Wall -Wextra -Werror`.
- **ARCH-LAYOUT-4** — The target size of the implementation is about 1,500 lines
  of C. The count reads the lines of the `.c` files outside the comments and the
  blank lines.
- **ARCH-LAYOUT-5** — The shim and the record store can each hold an entry point
  that the tests alone reach. `#ifdef REGRESS` must guard each such entry point.
  A shim entry point can compute a client answer, because a known-answer vector
  must pin both sides of a request (see
  [PROTO-TWEAK-4](protocol.md#proto-tweak)). A record store entry point can give
  a test control at one step of a store or of a wipe (see
  [TEST-UNIT](testing.md#test-unit)). The test acts there on the state of that
  step, and it then continues the call or stops it. The entry point must hold no
  test logic of its own. The service program must not carry test code, and it
  must not carry code that only a client needs.

<a id="arch-build"></a>

## The build

- **ARCH-BUILD-1** — The archive sources must sit flat in `src/`. `src/lib` must
  build the archive `libfuguoracle.a` from them with `.PATH`. Each program
  directory must link that archive, so each archive source compiles once in the
  production build.
- **ARCH-BUILD-2** — `src/Makefile` is the entry point of the C build, and the
  OpenBSD `make` reads it. Each program must have a directory of its own under
  `src/`. That directory must hold the Makefile and the manual page of the
  program, and it must read `bsd.prog.mk`. `SUBDIR` of `src/Makefile` must name
  each directory that builds. `src/regress` holds the tests, and it must read
  `bsd.regress.mk`.
- **ARCH-BUILD-3** — `src/regress` must compile each source that it tests
  through `.PATH`, with `-DREGRESS`. The compile must set the record directory
  and the key path of the test build (D-06,
  [ARCH-LAYOUT-5](architecture.md#arch-layout)). It must not link the archive,
  because the archive holds no test hook.
- **ARCH-BUILD-4** — The C build and the gates of the repository root must stay
  apart. The OpenBSD `make` reads `src/Makefile`, and GNU `make` reads
  `GNUmakefile`. The org pack of FuguBSD/Tooling owns `GNUmakefile`, so this
  repository must not edit it.
- **ARCH-BUILD-5** — The host harness must sit in `tests/`: the guest driver,
  the interop harness, the fuzzer, the vector generator and its header.
  `src/regress` must read that header through an include path of `tests/`. The
  harness runs on the host or in the guest, and never through `src/Makefile`.

The layout follows `usr.bin/ssh` of the OpenBSD tree: the sources sit flat, and
one directory builds each program beside its manual page. The regress build
compiles the sources a second time. The test hooks of ARCH-LAYOUT-5 must stay
out of the archive that the service links. The C build needs an OpenBSD machine,
and the gates of the repository root need none.
