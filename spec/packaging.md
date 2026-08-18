# Ports packaging

The project delivers two OpenBSD ports, submitted together.

<a id="pkg-secp"></a>

## security/libsecp256k1

The ports tree has no standalone `libsecp256k1`.
This new companion port packages upstream `bitcoin-core/secp256k1`.

```
COMMENT =       optimized C library for EC operations on curve secp256k1
GH_ACCOUNT =    bitcoin-core
GH_PROJECT =    secp256k1
CONFIGURE_ARGS = --enable-module-ecdh \
                 --enable-module-recovery \
                 --enable-module-extrakeys \
                 --disable-benchmark
```

- **PKG-SECP-1** — The port must enable the modules `ecdh`, `recovery`, and
  `extrakeys`, and must not enable `schnorrsig`, `ellswift`, or `musig`.
- **PKG-SECP-2** — The port must ship `libsecp256k1.a`, the headers, and the
  pkg-config file.
- **PKG-SECP-3** — The `do-test` target must run the upstream test suite.

The library is MIT licensed and builds cleanly with base clang.
It is useful beyond FuguOracle, for any future Bitcoin-adjacent port.

<a id="pkg-oracle"></a>

## security/fuguoracle

```
COMMENT =       blind PIN oracle and virtual secure element (pinserver v2)
BUILD_DEPENDS = security/libsecp256k1
# static link: no LIB_DEPENDS/WANTLIB beyond base
```

- **PKG-ORACLE-1** — The port must install `/var/www/cgi-bin/fuguoracle` (static,
  `@mode 0555`), `/usr/local/sbin/fuguoracle-keygen`, the man pages, the rc.d script,
  and the pkg-readme.
- **PKG-ORACLE-2** — The `pkg/PLIST` must create the user and the group with
  `@newuser _fuguoracle` and `@newgroup`, with a uid from the ports user registry for
  the official submission.
- **PKG-ORACLE-3** — The `pkg/PLIST` must `@sample`-create `/var/www/fuguoracle/` with
  mode `0710` and owner `root:_fuguoracle`, and `/var/www/fuguoracle/pins/` with mode
  `0700` and owner `_fuguoracle:_fuguoracle`. The parent directory holds the key file
  that `fuguoracle-keygen` writes (see [PROG-KEYGEN-2](programs.md#prog-keygen)).
- **PKG-ORACLE-4** — `make regress` must run the known-answer test suite without
  network access.
- **PKG-ORACLE-5** — The port must declare `security/libsecp256k1` as a build
  dependency only. The static link leaves no `WANTLIB` beyond base.
