# FuguOracle

A blind PIN oracle service, designed after OpenBSD principles. FuguOracle is a
virtual secure element for client devices and client programs. A client holds a
secret in encrypted form, under a key that the client alone cannot rebuild.

The oracle holds a key share for each client, and it releases the share only to
a request that proves the correct PIN. It does not learn the PIN or the secret,
and it destroys the share after three bad attempts. The service implements the
Blockstream Jade v2 protocol, and
[FuguPass](https://github.com/FuguBSD/FuguPass) is a reference client.

## Commands

```sh
make deps        # install gitleaks
make check       # run every gate; run it before each commit
make test        # run the test suite
make format-fix  # fix the Markdown, JSON and YAML formatting
```

## Commit scopes

`spec`, `docs`, `ci`.
