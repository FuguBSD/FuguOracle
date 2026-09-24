# FuguOracle

A blind PIN oracle service, designed after OpenBSD principles. FuguOracle is a
virtual secure element for client devices and client programs. A client holds a
secret in encrypted form, under a key that the client alone cannot rebuild.

The oracle holds a key share for each client, and it releases the share only to
a request that proves the correct PIN. It does not learn the PIN or the secret,
and it destroys the share after three bad attempts. The service implements
version 2 of the Blockstream `blind_pin_server` protocol, and Blockstream Jade
is the reference client. [FuguPass](https://github.com/FuguBSD/FuguPass) is a
second client.

## Commands

```sh
make deps        # install signify, gitleaks and the Fugu library
make check       # run every gate; run it before each commit
make test        # run the test suite
make format-fix  # fix the Markdown, JSON and YAML formatting
```
