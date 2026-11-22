# Shadow diffing

A `RequestMirror` normally sends a copy of the request to a second backend and
throws the answer away. With shadow diffing the built-in gateway compares that
answer with the one the client got, so you can ask "does the new version behave
like the old one?" on real traffic before you shift a single user.

The Gateway API semantics do not change: the mirrored response never reaches
the client and never delays or alters it. The comparison runs after the primary
response has been written, on a bounded pool.

## Turning it on

Per mirror, in a snapshot, with an extension block on the `RequestMirror`
filter:

```json
{
  "type": "RequestMirror",
  "requestMirror": {
    "backendRef": {"name": "orders-v2", "port": 80},
    "setura.zyvor.dev/shadow-diff": {
      "compare": true,
      "sample": 100,
      "headers": ["X-Api-Version"],
      "ignoreHeaders": ["Cache-Control"],
      "ignoreJSONPaths": ["$.timestamp", "$..requestId", "$.items[0].etag"],
      "maxBody": 1048576,
      "latencyThresholdMs": 0
    }
  }
}
```

Or for every mirror at once with a gateway flag:

```sh
setura gateway run --config routes.json --shadow-diff 10   # compare 10% of mirrored requests
```

| Field | Default | Meaning |
|-------|---------|---------|
| `compare` | `true` with `--shadow-diff`, else off | `false` disables comparison for this mirror even with the flag. |
| `sample` | the flag value, else 100 | Percent of requests compared. Overrides `--shadow-diff`. |
| `headers` | none | Response headers to compare in addition to the defaults. |
| `ignoreHeaders` | none | Headers to leave out. |
| `ignoreJSONPaths` | none | Paths removed from both bodies before the JSON comparison. |
| `maxBody` | 1 MiB | Bytes of each body that are captured and compared. |
| `latencyThresholdMs` | 0 | Flag a `latency` mismatch when the shadow is slower by more than this. 0 records the delta but never flags it. |

An invalid block (a bad path, a sample over 100) makes the route invalid rather
than silently comparing nothing. The existing `percent` on the mirror still
decides which requests are mirrored at all; sampling applies to those.

Requests are mirrored as before for non-compared requests too: a request that
is not sampled, or whose comparison is dropped because the pool is busy, still
sends its fire-and-forget copy.

## What is compared

* Status code.
* Headers: `Content-Type`, `Cache-Control`, `Location`, plus `headers`.
  Never compared: `Date`, `Server`, `Set-Cookie`, `X-Request-Id`, `Via`, trace
  headers (`traceparent`, `tracestate`, `b3`, `x-b3-*`, `x-cloud-trace-context`,
  `x-amzn-trace-id`) and `x-setura-*`.
* Body. If both bodies are JSON they are compared structurally (key order,
  whitespace and `1` versus `1.0` do not matter) after `ignoreJSONPaths` are
  removed. Otherwise the bytes are compared. A body over `maxBody` is compared
  on its first `maxBody` bytes only.
* Latency: shadow time minus primary time is recorded for every comparison
  (p50 and p95 per route). It becomes a mismatch only above
  `latencyThresholdMs`.

The mirrored request does not follow redirects, so a `Location` difference is
visible.

### JSON path subset

`$.a.b`, `$.a[0]`, `$['a']['b']` and `$..key` (that key at any depth). A path
that selects nothing is ignored. Anything else is rejected at load time.

## What a mismatch records

Each differing category of a request becomes one entry in a ring of the last 200:

```json
{"time":"2026-11-22T10:00:00Z","route":"shop/orders","category":"body","method":"GET","path":"/orders/42",
 "detail":{"where":"$.items[1].price","primary":"19.99","shadow":"21.99"},
 "primary":{"backend":"shop/orders-v1:80","status":200,"ms":4.1},
 "shadow":{"backend":"shop/orders-v2:80","status":200,"ms":9.3},"deltaMs":5.2}
```

Categories are `status`, `header`, `body` and `latency`. The path never
includes the query string. The excerpt is the first differing JSON path, or the
first differing byte offset with about 80 characters of context, truncated, with
obvious secrets (values of keys such as `password`, `token`, `secret`,
`api_key`, `authorization`, bearer tokens, JWTs, long hex strings, cloud access
keys) replaced by `[redacted]`. Values under a secret-looking JSON key are never
shown. Redaction is pattern based; it is a safety net, not a guarantee, so do
not point shadow diffing at a backend whose responses you could not log.

## Never back-pressures traffic

* The shadow request starts at the same moment as the primary, concurrently.
* The comparison waits for the primary response to complete and runs in a
  separate goroutine. At most 64 comparisons are in flight; beyond that the
  comparison is skipped and counted as `dropped`.
* A shadow that is slow, down or erroring only increases `error` or the
  latency delta. A primary that never finishes is abandoned after 30 seconds.

## Reading the results

Admin endpoint `GET /shadow` (default `127.0.0.1:19000`):

```json
{"schema":"setura.shadow/v1","sampled":12400,"compared":12400,"matched":12301,"mismatched":99,
 "errors":0,"dropped":0,"matchRate":99.2,
 "byCategory":{"status":1,"header":4,"body":94,"latency":0},"p50DeltaMs":1.8,"p95DeltaMs":7.4,
 "routes":{"shop/orders":{"compared":12400,"matchRate":99.2,"p50DeltaMs":1.8,"p95DeltaMs":7.4}},
 "recent":[ ... newest first ... ]}
```

`matchRate` is `matched / compared` in percent and is absent until something
was compared. Shadow request failures count as `errors`, not mismatches, and
are not part of the rate.

Prometheus on `/metrics`:

```
setura_gateway_shadow_total{route="shop/orders",result="matched"}
setura_gateway_shadow_total{route="shop/orders",result="mismatched"}
setura_gateway_shadow_total{route="shop/orders",result="status|header|body|latency"}
setura_gateway_shadow_total{route="shop/orders",result="error"}
setura_gateway_shadow_total{route="shop/orders",result="dropped"}
```

`mismatched` counts requests; the category results count categories, so one
request can add to several.

Dashboard (`--ui`): once shadow comparison has run, a Shadow card shows
"Shadow: 99.2% match over 12,400 requests" and the latest mismatches. Without
shadow diffing the section is absent.

## CLI and rollout gate

```sh
setura shadow                       # summary and recent mismatches
setura shadow --format json         # the raw /shadow document
setura shadow --follow              # keep printing new mismatches
setura shadow --admin 10.0.0.5:19000 --fail-under 99.5
```

With `--fail-under PCT` the command exits 1 when the match rate is under PCT, or
when nothing has been compared yet, so a pipeline can gate a rollout:

```sh
setura gateway run --config routes.json --shadow-diff 100 &
# ... replay or wait for traffic ...
setura shadow --fail-under 99.5 || { echo "shadow regressed"; exit 1; }
```

Exit 2 means usage error or an unreachable admin endpoint.

## Limits

* Results live in memory and reset on restart; they survive config reloads.
* Only the built-in gateway implements this. The block is a snapshot extension;
  a real `HTTPRoute` object in Kubernetes would drop the unknown field, so
  controller mode does not carry it.
* gRPC and TLS passthrough routes are not compared.
* Bodies above the 1 MiB mirror buffer are not mirrored (existing behaviour)
  and therefore not compared.
