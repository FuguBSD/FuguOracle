# Programs

<a id="prog-cgi"></a>

## fuguoracle, the CGI program

`fuguoracle` is the service binary. Its man page is `fuguoracle(8)`, in
`mdoc(7)`.

- **PROG-CGI-1** — The program must dispatch on `REQUEST_METHOD` and
  `DOCUMENT_URI`. `httpd(8)` sets `DOCUMENT_URI` to the decoded request path,
  independent of the filesystem; it splits `SCRIPT_NAME` and `PATH_INFO` against
  the document root on disk, so those variables do not carry the endpoint path.
  The accepted pairs are `GET /`, `POST /get_pin`, and `POST /set_pin`. Every
  other pair answers `404` or `405` per [PROTO-HTTP-5](protocol.md#proto-http).
- **PROG-CGI-2** — The program must reject a `POST` request when
  `CONTENT_LENGTH` is absent, is not a decimal number, or exceeds 4096, with the
  statuses of [PROTO-HTTP-2](protocol.md#proto-http) and
  [PROTO-HTTP-3](protocol.md#proto-http). The program must read exactly
  `CONTENT_LENGTH` bytes from stdin.
- **PROG-CGI-3** — The program must emit the CGI response on stdout.
- **PROG-CGI-4** — The paths are compile-time constants, relative to the chroot:
  `/fuguoracle/private.key` (the static key, 32 raw bytes) and
  `/fuguoracle/pins/` (the record directory). See D-06.

<a id="prog-keygen"></a>

## fuguoracle-keygen

`fuguoracle-keygen` creates the static server key. Its man page is
`fuguoracle-keygen(8)`, in `mdoc(7)`. The operator runs it once, as root,
outside the chroot.

- **PROG-KEYGEN-1** — The program must draw 32 random bytes and repeat until
  `secp256k1_ec_seckey_verify` passes. The first draw succeeds with overwhelming
  probability.
- **PROG-KEYGEN-2** — The program must write `/var/www/fuguoracle/private.key`
  with owner `_fuguoracle:_fuguoracle` and mode `0400`.
- **PROG-KEYGEN-3** — The program must refuse to overwrite an existing key file.
- **PROG-KEYGEN-4** — The program must print the compressed public key as hex.
  The operator provisions this value into each client (see
  [CLIENT-PROVISION](clients.md#client-provision)).
- **PROG-KEYGEN-5** — The program must resolve the `_fuguoracle` passwd entry
  with `getpwnam(3)` before it applies `unveil(2)`. The pledge promises are
  `stdio rpath wpath cpath fattr chown getpw unveil`, reduced to
  `stdio rpath wpath cpath fattr chown` after the unveil calls. The `fattr` and
  `chown` promises cover the `fchmod(2)` and `fchown(2)` calls that
  PROG-KEYGEN-2 needs. The program must unveil only the target directory, with
  the permissions `rwc`.
