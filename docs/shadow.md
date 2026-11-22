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
      "maxBody": 16777216,
      "latencyThresholdMs": 0
    }
  }
}
```

In Kubernetes controller mode the same block travels in an annotation, see
"Controller mode: annotations" below. A `GRPCRoute` rule takes the same block on
its `RequestMirror` filter, see "gRPC". Or for every mirror at once with a
gateway flag:

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
| `maxBody` | 16 MiB | Ceiling in bytes up to which a body is compared (see "Large bodies"). Above it the body is not compared and the request counts as `skipped`. |
| `ignoreFrames` | none | gRPC only: 0-based indexes of response message frames left out of the comparison. |
| `frameFormat` | `bytes` | gRPC only: `bytes` compares frame payloads byte for byte; `json` compares them structurally (and applies `ignoreJSONPaths`) when both parse as JSON. |
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
  removed. Otherwise the bytes are compared. Bodies above 1 MiB are compared
  by length and SHA-256, up to `maxBody`; see "Large bodies".
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

Categories are `status`, `header`, `body` and `latency`, plus `grpc-status` and
`grpc-message` on gRPC routes. The path never
includes the query string. The excerpt is the first differing JSON path, or the
first differing byte offset with about 80 characters of context, truncated, with
obvious secrets (values of keys such as `password`, `token`, `secret`,
`api_key`, `authorization`, bearer tokens, JWTs, long hex strings, cloud access
keys) replaced by `[redacted]`. Values under a secret-looking JSON key are never
shown. Redaction is pattern based; it is a safety net, not a guarantee, so do
not point shadow diffing at a backend whose responses you could not log.

## Large bodies

Each side of a comparison is streamed through a SHA-256 and a length counter as
it passes, and only its first 1 MiB is kept in memory for detail.

* Up to 1 MiB the comparison is as described above: structural for JSON, bytes
  otherwise, with the first differing path or offset in the mismatch entry.
* From 1 MiB up to `maxBody` (default 16 MiB, per mirror) a body is compared by
  length and SHA-256 without ever being held whole in memory. A difference is a
  `body` mismatch with `where` like `length 3145728 vs 3145729, sha256 3f2a...`;
  when the first 1 MiB already differs the excerpt shows that offset, otherwise
  it says the difference is beyond the first MiB. JSON is not compared
  structurally at this size (`ignoreJSONPaths` cannot apply to bytes that are
  not parsed), so a large response that differs only in an ignorable field is
  reported as a mismatch.
* **Request bodies** above the 1 MiB mirror buffer used to be sent to no
  mirror at all. For a mirror that compares they now stream into a spool as the
  primary backend reads them: memory up to 1 MiB, then a temporary file in the
  system temp directory, deleted when the request ends. The mirror copy is sent
  when the body has been read to its end, so it starts later than for small
  bodies, and a primary that answers without reading the whole upload never
  triggers it. Mirrors that do not compare keep the old behaviour.
* Above `maxBody`, for a request or a response, the body is not compared. The
  request is counted as `skipped` (`skipped` in `/shadow`, `result="skipped"` in
  Prometheus) and the old path applies: nothing is mirrored for a request body
  above the 1 MiB buffer, as before. For a response above the ceiling the other
  categories (status, headers, latency) are still compared.

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
 "errors":0,"dropped":0,"skipped":0,"matchRate":99.2,
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
setura_gateway_shadow_total{route="shop/orders",result="skipped"}
```

gRPC adds the categories `grpc-status` and `grpc-message` (`byCategory` and the
`result` label show them once they occur).

`mismatched` counts requests; the category results count categories, so one
request can add to several.

Dashboard (`--ui`): once shadow comparison has run, a Shadow card shows
"Shadow: 99.2% match over 12,400 requests" and the latest mismatches. Without
shadow diffing the section is absent.

## gRPC

A `GRPCRoute` rule accepts a `RequestMirror` filter (rule level only), carrying
the same `setura.zyvor.dev/shadow-diff` block:

```json
"rules": [{"backendRefs": [{"name": "orders-v1", "port": 9090}],
  "filters": [{"type": "RequestMirror", "requestMirror": {
    "backendRef": {"name": "orders-v2", "port": 9090},
    "setura.zyvor.dev/shadow-diff": {"compare": true, "frameFormat": "json",
      "ignoreJSONPaths": ["$.generatedAt"], "ignoreFrames": [0]}}}]}]
```

The client's request is teed while the primary proxy reads it (up to the
`maxBody` ceiling, memory then temporary file, as for large HTTP bodies); when the
client has finished sending, the same frames go to the mirror backend over HTTP/2
while the primary call is still running. A mirror without `compare` is sent
fire-and-forget. What is compared:

* the HTTP status and `Content-Type`, as for HTTP;
* `grpc-status` (category `grpc-status`) and `grpc-message` (category
  `grpc-message`), from the trailers, or from the headers for a Trailers-Only
  response;
* the response message frames (5-byte header: compressed flag and big-endian
  length): the compressed flag, the number of frames and each payload, by bytes
  or, with `frameFormat: "json"`, structurally. `ignoreFrames` skips frames by
  index (server-assigned ids, timestamps). Payloads are compared as opaque
  bytes: no protobuf schema is needed or used, so two encodings of the same
  message that differ in field order or default values are reported as a
  mismatch. Above 1 MiB of response frames the stream is compared by length and
  SHA-256 only and `ignoreFrames` and `frameFormat` do not apply;
* latency, as for HTTP.

Because the mirror copy is sent only when the client has finished its request,
client-streaming and bidirectional calls are mirrored after the client closes
its side; a call that never half-closes is not mirrored. The mirrored response
is never returned to the client and a slow or failing mirror only counts as
`error`.

**TLS passthrough** (`TLSRoute`) cannot be compared, and this is inherent: the
gateway forwards the encrypted bytes without terminating TLS, so there is no
request or response to see on either side. It is not a missing feature.

## Controller mode: annotations

A real `HTTPRoute` (or `GRPCRoute`) object in Kubernetes has no place for the
extension field, so the block is carried in annotations on the route object and
read by the controller's Kubernetes source:

| Annotation | Applies to |
|------------|------------|
| `setura.zyvor.dev/shadow-diff` | every `RequestMirror` filter in the route's rules |
| `setura.zyvor.dev/shadow-diff.rule-N` | the `RequestMirror` filter(s) of rule N, counting from 1 in `spec.rules` order; wins over the route wide annotation |

The value is the JSON block from the table above, as a string:

```yaml
metadata:
  annotations:
    setura.zyvor.dev/shadow-diff: '{"compare": true, "sample": 25}'
    setura.zyvor.dev/shadow-diff.rule-2: '{"compare": true, "ignoreJSONPaths": ["$..requestId"], "latencyThresholdMs": 200}'
spec:
  rules:
    - backendRefs: [{name: orders-v1, port: 80}]
      filters: [{type: RequestMirror, requestMirror: {backendRef: {name: orders-v2, port: 80}}}]   # rule 1: sample 25
    - backendRefs: [{name: reports-v1, port: 80}]
      filters: [{type: RequestMirror, requestMirror: {backendRef: {name: reports-v2, port: 80}}}]  # rule 2: its own block
```

Rules:

* The annotation only configures the comparison of a `RequestMirror` filter
  that exists; the mirror itself (backend, `percent`) is ordinary Gateway API.
  Annotations are re-read on every poll like the rest of the object.
* An annotation does not override a block written inline in the filter (only
  possible in snapshots); the more specific one wins.
* The block is decoded strictly in annotations: unknown fields, trailing data
  or invalid values make the route invalid rather than comparing nothing. A
  `rule-N` annotation with N out of range or not a number is ignored by the
  gateway with a warning in its log (and flagged by SET015).
* `setura snapshot` copies these annotations into the route spec under
  `setura.zyvor.dev/annotations` (a snapshot keeps specs only), and the
  built-in gateway reads them from there in file mode exactly as in controller
  mode. They are therefore visible to `setura lint`.
* Lint rule **SET015** validates the inline block and every shadow-diff
  annotation (valid JSON, known fields, sample 0 to 100, non-negative
  `maxBody`, `latencyThresholdMs` and frame indexes, parseable
  `ignoreJSONPaths`, `frameFormat` `bytes` or `json`) and reports an annotation
  that has no `RequestMirror` filter to apply to, or a `rule-N` that names no
  rule. It is an error because the gateway rejects the route.

## Persistence

```sh
setura gateway run --config routes.json --shadow-diff 100 --shadow-state /var/lib/setura/shadow.json
```

With `--shadow-state FILE` the gateway snapshots the counters, the per-route
latency delta windows and the recent-mismatch ring to FILE every 10 seconds and
once more at shutdown, and reloads them at start. The write is atomic (temporary
file in the same directory, fsync, rename; mode 0600), so a crash leaves either
the previous snapshot or the new one. A missing file means a fresh start; an
unreadable or foreign file is reported on stderr and ignored (it is overwritten
at the next snapshot). Results from before a SIGKILL are lost back to the last
snapshot. The file is for one gateway process; two gateways must not share it.

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

* Results live in memory; without `--shadow-state` they reset on restart. They
  always survive config reloads. Between two snapshots a crash loses the
  results since the last one.
* Only the built-in gateway implements this. In controller mode the block comes
  from annotations on the route, so it needs the route object to be writable by
  you; there is no CRD field.
* TLS passthrough routes cannot be compared: the traffic is encrypted end to end
  and the gateway never sees it in the clear. This is inherent.
* gRPC payloads are compared as bytes (or JSON), never decoded with a protobuf
  schema, and gRPC mirroring starts only once the client half-closes.
* A request body is mirrored for comparison only when the primary backend reads
  it to the end, and bodies above `maxBody` (16 MiB by default) are skipped.
* Responses above 1 MiB are compared by length and SHA-256: a mismatch there
  says that the bodies differ and where the first MiB differs, not the exact
  path or offset beyond it.
