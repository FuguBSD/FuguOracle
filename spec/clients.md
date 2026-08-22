# Client integration

<a id="client-model"></a>

## Client model

FuguOracle serves any client that speaks the wire protocol (see D-01). A
conforming client:

- Holds a secret in encrypted form, under key material that includes the
  oracle's key share.
- Holds a client keypair that does not depend on the PIN. The client derives the
  keypair from its own device secrets, or generates it once and stores it.
  Possession of the private key is the client's identity (see
  [PROTO-PAYLOAD](protocol.md#proto-payload)).
- Mixes the PIN into `pin_secret` only. A wrong PIN produces the same recovered
  public key and a different `pin_secret`, so the guess addresses the same
  record and burns one attempt. A keypair that changes with the PIN would
  address a missing record on every wrong guess, and the attempt counter would
  never move.
- Enrolls with `set_pin` and unlocks with `get_pin`.
- Authenticates the oracle cryptographically: the client computes the expected
  tweaked server key from the provisioned static public key, so the envelope MAC
  fails against an impostor.

One oracle instance serves many clients: each record is addressed by the hash of
the client's recovered public key.

<a id="client-provision"></a>

## Provisioning

- **CLIENT-PROVISION-1** — The operator must give each client two values: the
  oracle URL, for example `https://oracle.example.org`, and the static public
  key, as the hex string that `fuguoracle-keygen` prints. The URL must not end
  with a slash: the client appends `/get_pin` and `/set_pin` to it (see
  [PROTO-HTTP](protocol.md#proto-http)).
- **CLIENT-PROVISION-2** — The deployment terminates TLS
  ([DEPLOY-HTTPD](deployment.md#deploy-httpd)). The client does not require TLS:
  the envelope authenticates the oracle, and TLS protects metadata and
  availability.
- **CLIENT-PROVISION-3** — A deployment with a private CA must also provision
  its TLS root certificate. The client stores the certificate and hands it to
  the companion app, which verifies the endpoint with it.
- **CLIENT-PROVISION-4** — A client can hold a second oracle URL, for example an
  onion address. The companion app selects between the URLs. Both URLs must
  point at the same oracle instance, because the records and the static key live
  on one host.

After provisioning, the client calls `set_pin` on its next initialization or PIN
change, and `get_pin` on every unlock.

<a id="client-jade"></a>

## Blockstream Jade, the reference client

The Blockstream Jade hardware wallet is the reference client. The Jade holds a
wallet secret encrypted under a key that it does not store, and it relays oracle
calls through the companion app (Green app or gdk) over USB, BLE, or QR.

- **CLIENT-JADE-1** — The service must serve the current Jade firmware, which
  speaks protocol v2.
- **CLIENT-JADE-2** — The operator provisions a Jade with the companion app or
  the gdk `update_pinserver` call, and sets the oracle URL and the static public
  key.
- **CLIENT-JADE-3** — An initialized Jade refuses a change of the oracle public
  key, with the message `Cannot update initialized unit`. The operator must
  provision the oracle before the first wallet setup, or must factory-reset the
  unit first. URL and certificate updates stay possible on an initialized unit.
