# mTLS and certificate inspection

## Client authentication in probes

```
setura explain https://orders.example.test/ --cert client.pem --key client.key \
  [--ca ca.pem] [--tls-server-name NAME] [--min-tls 1.2|1.3] [--warn-expiry-days 30]
```

`--cert` and `--key` must be given together. There is deliberately no
`--insecure-skip-verify`. `--tls-server-name` sets both SNI and the name the
server certificate is verified against.

The `tls` step records: `version`, `cipher_suite`, `client_cert`,
`server_subject`, `server_issuer`, `not_after`, `days_to_expiry` and, when
under the `--warn-expiry-days` threshold, `expiry_warning` (the state stays
`ok`).

`client_cert` values:

| value | meaning |
| --- | --- |
| `presented` | the server requested a certificate and one was sent |
| `not_requested` | the server did not ask for a client certificate |
| `withheld` | the server asked, none was configured, and the handshake still succeeded |
| `rejected` | the handshake or first read failed with a TLS alert; the reason says whether a certificate was missing or refused |

## check files

New optional case keys: `cert`, `key`, `server_name`, `min_tls`,
`warn_expiry_days` and `min_cert_days`. `min_cert_days` is an assertion: the tls
step fails when the server certificate has fewer days left.

## `setura certs HOST:PORT`

```
setura certs host:443 [--ca FILE] [--sni NAME] [--cert F --key F] [--warn-expiry-days N] [--timeout S] [--json]
```

Prints each presented certificate (subject, issuer, SANs, validity, key type,
signature algorithm), then verifies the chain against the system roots or
`--ca` for the SNI name. The handshake itself does not verify, so an invalid
chain can still be shown; verification is performed explicitly afterwards.
Exit 1 when the chain does not verify or any certificate expires within
`--warn-expiry-days`; exit 2 for usage errors; connection failures are reported
as errors.
