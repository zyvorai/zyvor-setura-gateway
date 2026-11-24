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
