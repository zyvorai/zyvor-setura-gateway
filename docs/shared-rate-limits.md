# Shared rate limits (Redis)

A rate limit in the built-in gateway is a token bucket in each replica's memory. With four
replicas a `100/s` rule admits about 400/s, and `--rate-limit-share` only approximates the
fix by dividing the rate (see [observability](observability.md)). A **shared** limit keeps
the count in Redis, so every replica draws from the same budget and the limit holds for the
fleet.

It is selected per rule, next to the local limiter, by adding `shared` to the existing
`setura.zyvor.dev/rate-limit` block:

```json
{"setura.zyvor.dev/rate-limit": {
  "rate": "100/s",
  "key": "client-ip",
  "shared": {"redis": "main", "keyPrefix": "prod:api", "failOpen": true}
}}
```

and by starting the gateway with the Redis server it names:

```
setura gateway run --config gw.json --redis main=redis.internal:6379 --redis-password-file /etc/redis/pass
```

The gateway-wide `--rate-limit` stays local. Only rule limits can be shared.

## The block

| Field | Meaning |
|---|---|
| `rate` | As for a local limit: `N/s`, `N/m`, `N/h`. It means N requests per window of that length. |
| `key` | `client-ip` (default), `route` or `header:NAME`, as for a local limit. |
| `burst` | Not allowed with `shared` (a window counter has no burst; remove it). |
| `shared.redis` | Name of a `--redis NAME=ADDR` server. Default `default`, the name of an unnamed `--redis ADDR`. |
| `shared.keyPrefix` | Namespace of the keys in Redis. Default `setura:rl`. Give each environment its own when they share a Redis. At most 128 bytes, no spaces. |
| `shared.failOpen` | What to do when Redis cannot be used. `true` (default) keeps serving, `false` answers 503. |
| `shared.fallback` | With `failOpen` true: `local` (default) enforces the same rate with a per-replica token bucket, `none` lets everything through. |
| `shared.fallbackReplicas` | Divides the local fallback rate by this many replicas, so the fleet stays near the shared rate during an outage. |

A route that names a `shared.redis` the gateway was not started with is **refused at load**
(`shared.redis "x" is not configured`); the previous configuration keeps serving.

## How it counts

A sliding window counter, with no Lua: per client there is one counter per window, kept for
two windows. A request is counted with one pipelined round trip

```
MULTI
INCR   PREFIX:ns/route#rule:HASH(client):WINDOW
PEXPIRE same-key  2*window+1s
GET    PREFIX:ns/route#rule:HASH(client):WINDOW-1
EXEC
```

and admitted when `previous * (share of the previous window still inside the sliding window) + current`
is at most the limit. A refused request gives its slot back with a `DECR`, so a client that
keeps hammering is not penalised beyond the budget it already used. The client part of the
key is a SHA-256 prefix, so a long or hostile header value cannot grow keys. Keys expire by
themselves.

The sliding window is smooth at window turnover (no burst of `2 x limit` across the edge as a
fixed window has) but it is an estimate: it assumes requests in the previous window were
evenly spread. The count is exact for what Redis saw; Redis itself is one instance (or a
primary): the limiter does not use Redis Cluster slots or Sentinel, point `--redis` at a
primary or a proxy that follows failover.

## Answers

Every response of a rule with a shared limit carries

* `X-RateLimit-Limit`: requests allowed per window.
* `X-RateLimit-Remaining`: what is left in the sliding window (never negative).
* `X-RateLimit-Reset`: seconds until the current window ends (at least 1).

A refused request is `429` with `Retry-After` and is logged as `rate limited (route, shared)`. When
Redis answered, `Retry-After` equals `Reset` (the seconds until the window turns over).

When the local fallback answered (the log says `fallback`) the two differ: `X-RateLimit-Limit`
is still N and `Remaining` is the bucket's remaining tokens, `X-RateLimit-Reset` is the whole
window length (the bucket has no window), but `Retry-After` is the time until the bucket has
one token again, which is usually shorter. Trust `Retry-After` for when to retry.

Header names are case-insensitive. The gateway sends `WWW-Authenticate` and `X-RateLimit-*` with
exactly these spellings on HTTP/1; HTTP/2 lowercases every name on the wire.

## When Redis is down

Each failed round trip (connect, deadline, protocol error, `-ERR`, failed AUTH) marks Redis
down for one second, measured on the gateway's clock, so a dead Redis costs one slow request
per second, not one per request. During that time:

| `failOpen` | `fallback` | Requests are |
|---|---|---|
| `true` | `local` (default) | limited by a per-replica token bucket of the same rate (divide with `fallbackReplicas`), with a burst of the replica's share of N, at most 100 (an `N/m` limit lets a client inside its limit send N requests at once; a bucket of one token would refuse it) |
| `true` | `none` | not limited at all |
| `false` | | answered `503` with `Retry-After`, `rate limit service unavailable` |

After the cooldown the next request tries Redis again and shared counting resumes. Lint
warns about the two risky settings (`SET071`) and about header keys on open rules (`SET072`).

## Connecting

| Flag | Meaning |
|---|---|
| `--redis [NAME=]ADDR` | `HOST:PORT`, or `redis://[user:password@]HOST:PORT[/DB]`, or `rediss://...` for TLS. Repeatable; names must be unique. |
| `--redis-password-file FILE` | Password for servers whose address has none (also `SETURA_REDIS_PASSWORD`). Prefer this to a password in the URL, which shows in the process list. |
| `--redis-tls`, `--redis-ca FILE` | TLS for every server, and the CA bundle that signed them (default: system roots). TLS 1.2 or newer, the host of the address is verified. |
| `--redis-timeout DUR` | Deadline of one round trip (default 250ms). Keep it small: it is added to every request while Redis is slow. |
| `--redis-dial-timeout DUR` | Deadline to connect (default 1s). |
| `--redis-pool N` | Most open connections per server (default 16). Requests wait for a free one until their own context ends. |

AUTH (with or without a username, Redis 6 ACL) and `SELECT` run when a connection opens. The
client speaks RESP2 only and never sends `HELLO`.

## Metrics

All have bounded labels (route and rule from the configuration, fixed result values, the
`--redis` names):

* `setura_gateway_shared_ratelimit_requests_total{route,rule,result}` with `result` one of
  `allowed`, `limited`, `fallback_allowed`, `fallback_limited`, `open` (Redis down, no
  fallback), `unavailable` (Redis down, fail closed).
* `setura_gateway_redis_errors_total{redis}`.
* `setura_gateway_redis_up{redis}`: 1 when the last round trip worked, 0 when it failed.

Shared decisions also count in `setura_gateway_ratelimit_allowed_total` and
`setura_gateway_ratelimit_limited_total` and in the per-rule counters.

## Explaining a limit

`setura why` (and the admin `/why`) names the source of the rule limit: `local` or `shared`,
the prefix and Redis name, what happens when Redis is down, and, against a running gateway
(`--admin`), the client's live window (`1.0 of 100 requests used in the sliding window`) read
without counting a request.

## Limits of this design

* One Redis, no cluster slot handling, no Sentinel.
* The window is an estimate, and `X-RateLimit-Remaining` is floored.
* Clients behind a NAT share one IP; use `header:NAME` behind a trusted layer, or an
  authenticated identity, for a fairer key (see [security](security.md) and
  `--trusted-proxies`).
* Redis time is not used: windows come from each gateway's clock, so replicas whose clocks
  differ by more than a fraction of the window disagree about where windows start. Run NTP.
* gRPC rate limiting is the gateway-wide local limiter only.
