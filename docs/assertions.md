# Assertions, retries and certificate lists

Round 2 of the probe commands. The ideas come from comparable tools: Hurl's `jsonpath`,
`matches` and `retry`, Gatus's `[BODY].path` conditions and `[CERTIFICATE_EXPIRATION]`,
and the usual "is this hostile origin refused?" CORS test.

## JSON, regular expression and header assertions

`explain` flags and `check` or `watch` file keys:

| Flag | File key | Meaning |
| --- | --- | --- |
| `--json-path "$.a.b[0]=VALUE"` (repeatable) | `"json": {"$.a.b[0]": "VALUE"}` | A value in a JSON response body |
| `--body-matches REGEX` | `"body_matches": "REGEX"` | The first 1 MiB of the body matches a Go (RE2) regular expression |
| `--header "Name: ~REGEX"` | `"headers": {"Name": "~REGEX"}` | The response header (multiple values joined with `, `) matches |
| `--header "Name: !"` | `"headers": {"Name": "!"}` | The response header must be absent |

The path is `$.key.key[index]` (the `$` is optional). `VALUE` is one of:

| Form | Passes when |
| --- | --- |
| `*` (or no `=VALUE`) | the path exists, whatever its value |
| `text`, `7`, `true`, `null` | the scalar at the path equals it (numbers compare as written in the document) |
| `!=text` | the value differs (a missing path still fails) |
| `>n`, `>=n`, `<n`, `<=n` | the value is a number in range |
| `~REGEX` | the scalar matches |
| `==text` | a literal that starts with an operator character, such as `==>5` |

In a check file the expected value may be a JSON string, number, boolean or null. A body that
is not JSON, an unreachable path, an array or object compared with a scalar, and bad paths or
regular expressions all fail (the last two before any request is sent, as a usage error).

```json
[
  {
    "url": "https://api.shop.test/health",
    "json": {"$.status": "ok", "$.checks.db.latency_ms": "<50", "$.version": "~^v2\\."},
    "headers": {"Cache-Control": "~max-age=\\d+", "Set-Cookie": "!"}
  }
]
```

## Retries: `check --retries`

A rollout is eventually consistent, so a check run right after it can fail once and pass a
second later. A failed case is probed again up to N more times:

```sh
setura check checks.json --retries 5 --retry-interval 2s
```

A case can override both: `"retries": 3, "retry_interval_ms": 500`. At most 20 retries and a
minute between them. A case that was retried reports `"attempts": N` in JSON; the report shown
(and the exit code) is the last attempt. Cases that pass the first time are not repeated, and
a usage error is never retried.

## Certificate lists: `certs` with several targets

```sh
setura certs api.shop.test:443 db.shop.test:5432 --warn-expiry-days 21
setura certs --file targets.txt --warn-expiry-days 30 --json
```

Give two or more `HOST:PORT` arguments, or `--file FILE` (one target per line, `#` comments,
`-` for stdin), and `certs` inspects them (eight at a time, duplicates collapsed, at most 500)
and prints one row each, soonest expiry first, with unreachable targets on top:

```text
TARGET            STATUS      DAYS  DETAIL
db.shop.test:5432 ERROR          -  dial tcp ...: connection refused
api.shop.test:443 EXPIRING      12  a certificate in the chain expires in under 21 days
www.shop.test:443 OK            71  CN=www.shop.test
1 of 3 need attention
```

`DAYS` is the minimum over the presented chain. A row is `ok`, `expiring` (under
`--warn-expiry-days`), `unverified` (chain or name does not verify against `--ca` or the system
roots) or `error` (no connection or handshake). Exit 1 unless every row is `ok`. `--ca`, `--sni`
(applied to every target), `--cert`, `--key` and `--timeout` work as in single mode, which is
unchanged for one target. JSON output is `{"ok": bool, "targets": [...]}`.

## A hostile origin must be refused: `cors --expect-refused`

```sh
setura cors https://api.shop.test/v1/items --origin https://evil.example --expect-refused
```

Passes (exit 0) when a browser following the Fetch rules would refuse the preflight, and fails
when it would accept it: the check that catches a server reflecting every `Origin`. An
unreachable server still fails, so an outage is not mistaken for a refusal. JSON adds
`"expect_refused": true` and `"allowed"`.

## Variables in check and watch files

One file, several environments, and no credential written into it:

```json
[{"url": "{{base}}/health", "request_headers": {"Authorization": "Bearer {{token}}"}}]
```

```sh
SETURA_VAR_token="$TOKEN" setura check checks.json --var base=https://staging.shop.test
setura check checks.json --vars-file prod.vars
setura watch --file checks.json --vars-file prod.vars
```

- `{{name}}` (letters, digits, `_`, `-`; no spaces) is replaced in every string value.
  Object keys (header names, JSON paths) and numbers are left as written, so `status`
  cannot be templated.
- Precedence: `--var name=value`, then `--vars-file` (`name=value` lines, `#` comments,
  values trimmed, a name only once), then the environment variable `SETURA_VAR_name`.
  A name containing `-` can only come from the first two in most shells.
- An undefined name is a usage error (exit `2`) before any request is sent. `gateway
  rollout --checks` resolves variables from the environment only and refuses before
  changing the live config.
- `\\{{name}}` in JSON (`\{{name}}` after decoding) keeps the braces as literal text.
- Substitution happens after the JSON is parsed, so a value cannot add keys or cases.
- This is not secret redaction. Request header values are never echoed, but a URL
  appears in reports, history files and alerts, and a failed response assertion prints
  the expected value. Prefer headers for credentials.

## Bench thresholds

`setura bench --threshold EXPR` (repeatable, at most 32) fails the run unless every
expression holds:

```sh
setura bench http://orders.test:8080/ --address 127.0.0.1 --requests 500 \
  --threshold 'p95<200' --threshold 'p(99.9)<=800ms' \
  --threshold 'error_rate<0.01' --threshold 'rps>=50'
```

| Metric | Meaning |
| --- | --- |
| `min`, `avg` (`mean`), `med`, `p95`, `p(99.9)`, `max` | latency in milliseconds (`ms` suffix optional), nearest-rank percentiles over all requests including failed ones |
| `error_rate` | failed share, 0 to 1 |
| `errors`, `requests` | counts |
| `rps` | requests divided by the run time |

Operators are `<`, `<=`, `>`, `>=`, `==` and `!=`. A latency or rate threshold with no
samples fails. `--json` adds `thresholds: [{expr, observed, ok}]`. The older
`--max-p99-ms` and `--max-error-rate` still work and can be combined with it. Numbers are
what one client measured from where it runs; they are not a capacity statement.

## Domain registration expiry: `certs --domain-expiry`

A certificate that renews itself does not help when the domain lapses.

```sh
setura certs --file targets.txt --warn-expiry-days 21 --domain-expiry --warn-domain-days 45
```

```text
TARGET                STATUS  DAYS  DOMAIN         DOMSTATE   DAYS  DETAIL
www.shop.example:443  OK        71  shop.example   EXPIRING     12  domain: the registration expires in under 45 days
```

- The date comes from RDAP (RFC 9083, the `expiration` event). The registry's server is
  found in the IANA bootstrap file (RFC 9224); `--rdap-bootstrap URL` reads another copy
  and `--rdap-url BASE` queries one server directly.
- The longest name is asked first (`a.shop.co.uk`, then `shop.co.uk`) until a registry
  has a record, at most five labels; the `DOMAIN` column shows which name answered.
  Lookups are sequential and cached for the run.
- `unknown` fails the run like `expiring`: a date that could not be read is not a pass.
  This includes registries without RDAP in the bootstrap file, registries that publish no
  expiration date, rate limiting (HTTP 429) and non-ASCII names (give the `xn--` form).
  IP addresses and single-label names are `skipped`; for an IP target, `--sni` names the
  domain.
- Privacy: this is the one probe that talks to a third party. The domain name is sent to
  its registry, and the bootstrap file is fetched from `data.iana.org`. Without the flag
  nothing changes.
- A single target with `--domain-expiry` prints the table.
