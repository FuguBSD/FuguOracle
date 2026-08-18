# FuguOracle

A blind PIN oracle service, designed after OpenBSD principles.

FuguOracle acts as a virtual secure element for client devices and client
programs. A client holds a secret in encrypted form, under a key that the
client alone cannot rebuild. The oracle holds a key share for each client, and
it releases the share only for a request that proves the correct PIN. The
oracle does not learn the PIN, and it does not learn the protected secret.
After three bad PIN attempts, the oracle destroys the key share.

The service implements the Blockstream Jade v2 protocol.
[FuguPass](https://github.com/FuguBSD/FuguPass) is a reference client.

## Quick start

```sh
just spec-check
```

The project is specification-first: the code follows the specification.

## Documentation

The specification in [spec/](spec/index.md) is the authoritative reference.
Read [spec/decisions.md](spec/decisions.md) before you make a plan.

## Development

See [CLAUDE.md](CLAUDE.md) for the development guide: the specification
process and the writing standard.

## License

ISC. See [LICENSE](LICENSE).
