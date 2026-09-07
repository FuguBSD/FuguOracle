# FuguOracle

A blind PIN oracle service, designed after OpenBSD principles.

FuguOracle is a virtual secure element for client devices and client programs. A
client holds a secret in encrypted form, under a key that the client alone
cannot rebuild.

The oracle holds a key share for each client, and it releases the share only for
a request that proves the correct PIN. The oracle does not learn the PIN, and it
does not learn the protected secret. After three bad PIN attempts, the oracle
destroys the key share.

The service implements the Blockstream Jade v2 protocol.
[FuguPass](https://github.com/FuguBSD/FuguPass) is a reference client.

## Documentation

The project is specification-first: the specification in [spec/](spec/index.md)
is the authoritative reference. Research notes live in `docs/research/`.

## Commands

```sh
make check       # spec-check + ste-lint + gitleaks + test
make spec-check  # validate the specification and the plans
```

`make check` runs the Markdown format gate, and prettier runs through bunx. The
operator installs bun, for example from Homebrew. The manifest does not provide
it, because the format gate needs `bunx` before a target can run.

    make deps        # install the external tools of the repository

`make deps` installs gitleaks, the tool of the secret gate, from the manifest of
the platform in `deps/`. It installs the `tool` environment before every other
environment, so the gate tool is present for each chain. `deps/SHA256.txt`
records the sha256 digest of each versioned download, and `make deps` compares
the downloaded bytes against it. The CI gate installs gitleaks the same way, so
one pin serves the operator gate and the CI gate.

## Commit scopes

`spec`, `docs`, `ci`.

## License

ISC. See [LICENSE](LICENSE).
