# FuguOracle

A blind PIN oracle service that holds a key share for each client, and releases
it to the correct PIN alone. FuguOracle does not learn the PIN or the secret,
and it destroys the share after three bad attempts. A client holds its secret in
encrypted form, under a key that the client alone cannot rebuild.

The service implements version 2 of the Blockstream `blind_pin_server` protocol,
and Blockstream Jade is the reference client.
[FuguPass](https://github.com/FuguBSD/FuguPass) is a second client. The design
follows OpenBSD principles.

## Commands

```sh
make deps        # install signify, gitleaks and the Fugu library
make check       # run every gate; run it before each commit
make test        # run the test suite
make interop     # run the interop harness against the OpenBSD guest
make format-fix  # fix the Markdown, JSON and YAML formatting
```
