# Deployment on OpenBSD

The pkg-readme ships this configuration.

<a id="deploy-httpd"></a>

## httpd configuration

```
server "oracle.example.org" {
        listen on egress tls port 443
        tls {
                certificate "/etc/ssl/oracle.example.org.fullchain.pem"
                key "/etc/ssl/private/oracle.example.org.key"
        }
        connection max request body 4096
        location "/get_pin" {
                fastcgi {
                        socket "/run/fuguoracle.sock"
                        param SCRIPT_FILENAME "/cgi-bin/fuguoracle"
                }
        }
        location "/set_pin" {
                fastcgi {
                        socket "/run/fuguoracle.sock"
                        param SCRIPT_FILENAME "/cgi-bin/fuguoracle"
                }
        }
        location "/" {
                fastcgi {
                        socket "/run/fuguoracle.sock"
                        param SCRIPT_FILENAME "/cgi-bin/fuguoracle"
                }
        }
        location match ".*" { block }
}
```

- **DEPLOY-HTTPD-1** — `httpd(8)` must expose only `/`, `/get_pin`, and
  `/set_pin`, and must block every other path.
- **DEPLOY-HTTPD-2** — `acme-client(1)` supplies the TLS certificate for the
  public endpoint.
- **DEPLOY-HTTPD-3** — `httpd(8)` must cap the request body at 4096 bytes with
  `connection max request body`, so that an oversized body stops at the front
  door. The CGI check per [PROG-CGI-2](programs.md#prog-cgi) stays in place
  behind it.

The base defaults bound each request in time: `slowcgi(8)` ends a request after
120 seconds and closes the program's standard input, output, and error, and
`httpd(8)` applies its own FastCGI timeouts. The defaults need no tuning.

<a id="deploy-service"></a>

## The slowcgi service

The package installs `/etc/rc.d/fuguoracle`, a standard `rc.subr(8)` script that
wraps the base `slowcgi(8)`:

```
daemon="/usr/sbin/slowcgi"
daemon_flags="-p /var/www -s /var/www/run/fuguoracle.sock -u _fuguoracle"
```

Bring-up:

```
# pkg_add fuguoracle
# fuguoracle-keygen                     # note the printed pubkey hex
# rcctl enable httpd fuguoracle
# rcctl start fuguoracle httpd
```

- **DEPLOY-SERVICE-1** — The rc.d script must run a dedicated `slowcgi(8)`
  instance with the flags above: chroot `/var/www`, a dedicated socket, and the
  user `_fuguoracle`.
- **DEPLOY-SERVICE-2** — The deployment must need no cron job, no cleanup task,
  and no state beyond the `pins/` directory.
- **DEPLOY-SERVICE-3** — The operator must monitor the free space of the
  filesystem that holds `pins/`: any caller can create records without limit
  (see the [risks](overview.md#ovr-risks)). The operator can mount a dedicated
  filesystem on `/var/www/fuguoracle`, so that a fill cannot starve the rest of
  `/var/www`.

<a id="deploy-backup"></a>

## Backup

The static key is the service. Loss of `private.key`, or of the `pins/`
directory, makes the PIN unlock of every enrolled client permanently inoperable.
A client with its own recovery path, such as a wallet recovery phrase, can still
recover by that path.

- **DEPLOY-BACKUP-1** — The operator must back up the static key offline at
  enrollment time.
- **DEPLOY-BACKUP-2** — The operator must treat the `pins/` directory as
  precious.
- **DEPLOY-BACKUP-3** — The man page and the pkg-readme must carry this backup
  warning.
- **DEPLOY-BACKUP-4** — The operator must restore `pins/` only after an incident
  review: a restore rewinds attempt counters and replay counters to the backup
  time (see the [risks](overview.md#ovr-risks)).
- **DEPLOY-BACKUP-5** — Key rotation in place is not supported: every storage
  key derives from the static key, so a new key orphans every record. On a
  suspected key compromise, the operator must generate a new key, must clear
  `pins/`, must provision the new public key into every client, and must have
  every client run `set_pin` again. The man page and the pkg-readme must carry
  this procedure.
