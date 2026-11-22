# Performance

Honest numbers for the built-in gateway, how they were measured, and how to repeat or extend
the measurement. Nothing here is a claim about Envoy or any other proxy.

## Machine and conditions

| | |
|---|---|
| Date | 2026-11-22 |
| Hardware | Apple M4, 10 cores, 16 GiB, macOS (Darwin 27.3.0), arm64 |
| Go | go1.27.4 darwin/arm64, `CGO_ENABLED=0` release build (`make build`) |
| Load | **a shared developer machine, load average 12 to 27 during the runs** (other builds and test suites ran concurrently), with client, gateway and both backends on the same 10 cores |

Because of that load, wall-clock numbers (ns/op, requests/s, latency) are lower and noisier than
a quiet machine would give, and two runs of the same configuration differed by tens of percent.
Allocation counts and bytes per operation are deterministic, so the before and after
comparison below relies on those. Repeat the commands on your own hardware before drawing
conclusions from any rate.

## Tools

* `go test ./internal/gateway -run '^$' -bench . -benchtime 2s`: benchmarks over real loopback
  sockets with parallel keep-alive clients: HTTP/1.1 (bare, default, access log JSON and text,
  OTLP tracing, rate limit, shadow mirror, shadow diff at 100 percent, everything on), TLS with
  HTTP/1.1 and HTTP/2, TLS handshakes, gRPC unary over h2c, WebSocket echo through the tunnel,
  and a direct-to-upstream floor. Client, gateway and upstream share one process, so allocs/op
  and B/op include the client and the upstream (the `Direct` row shows that floor).
* `setura load URL`: a keep-alive load generator (`--concurrency`, `--duration`, `--warmup`,
  `--rate`, `--http2`, `--body-bytes`, `--json-out`). It reports requests/s, p50/p90/p99/p99.9/max
  from a log-linear histogram (about 9 percent resolution, constant memory so a soak needs no
  per-request storage), errors, and, with `--sample-url`, gateway goroutines and heap over time.
* `setura gateway run --pprof 127.0.0.1:PORT`: serves `net/http/pprof` and `/debug/runtime`
  (goroutines, heap, GC count, RSS on Linux). Loopback only; any other address is refused.
* `scripts/loadtest.sh`: starts `setura echo` backends and `setura gateway run`, drives them with
  `setura load`, samples process RSS with `ps` each second, and optionally (`--profile`) writes
  `cpu.pprof` and `heap.pprof`. Inspect with `go tool pprof bin/setura cpu.pprof`.
* Fuzz targets: see [Fuzzing](#fuzzing).

## Findings and fixes

Profiling the benchmark and the real binary under load (`scripts/loadtest.sh --profile`) showed:

* About 84 percent of gateway CPU at roughly 20k requests/s is system calls (the socket reads and
  writes of client, upstream and flush), so the Go code of the gateway is a small slice and the
  absolute ceiling here is the loopback kernel path and the shared cores.
* **`httputil.ReverseProxy` allocated a fresh 32 KiB copy buffer for every response** (about 64 percent
  of all bytes allocated per request). Fixed with a `sync.Pool` (`BufferPool`) in both the HTTP and
  gRPC proxies.
* A defensive deep copy of the outbound request was made for every request although only a
  cross-backend retry ever uses it. It is now made only for rules with `retry` and more than one
  backendRef.
* The retry-aware transport deep-cloned the request again for each attempt. When the rule has no
  `retry`, the single attempt now shares the header map and copies only the URL.
* A `log.Logger` was allocated per request for the proxy's discarded error log; it is now shared.
* The per-request counters (`Stats.record`) formatted the status class with `fmt.Sprintf` under a
  global mutex. They are now atomics found under a read lock (new file `stats.go`), with
  identical `/stats` and `/metrics` output.
* The request path read the clock three times when logging; it reads it once.

Not changed, with the reason: the dashboard history, latency histograms and connection table each
take one short mutex per request. The mutex profile in a 10-core benchmark attributed delay to
them, but at the 20 to 30k requests/s measured here the per-request cost is a few hundred
nanoseconds against about 30 microseconds of request work, so it was not worth the added
complexity and risk. Access log writes are one `write` per line; batching them is an option if a
profile on a faster machine shows it.

### Before and after

Same benchmark file against the starting commit (`80ae800`) and this branch, `-benchtime 2s
-count 3`, median. B/op and allocs/op are the reliable columns; the ns/op delta is dominated
by machine load (the `Direct` row, which no change touches, moved by +199 percent between the
two runs) and is **not** evidence either way.

| Benchmark | B/op before | B/op after | change | allocs before | allocs after |
|---|---:|---:|---:|---:|---:|
| HTTP1/bare | 51038 | 16446 | -67.8% | 216 | 203 |
| HTTP1/default (conn history on) | 51464 | 16964 | -67.0% | 220 | 208 |
| HTTP1/accesslog | 52293 | 17792 | -66.0% | 222 | 209 |
| HTTP1/tracing-otlp | 59204 | 24977 | -57.8% | 302 | 290 |
| HTTP1/shadow-diff100 | 96828 | 63824 | -34.1% | 355 | 343 |
| HTTP1/everything | 104939 | 72230 | -31.2% | 440 | 428 |
| TLS/http1 | 52237 | 17867 | -65.8% | 231 | 219 |
| TLS/http2 | 55665 | 20401 | -63.4% | 244 | 230 |
| GRPCUnary/default | 68376 | 34885 | -49.0% | 341 | 334 |
| Direct (no gateway, unchanged) | 6063 | 6141 | +1.3% | 67 | 67 |

The last allocation changes (shared request on a single attempt, atomic stats) came after
that table was taken; the final numbers for the two micro-benchmarks are:

| Benchmark (10 goroutines) | before | after |
|---|---|---|
| `StatsRecord` | 458 to 503 ns/op, 2 allocs | 211 to 228 ns/op, 0 allocs |

The shape of the equivalence is checked by `TestUpstreamRequestMatchesProxy` and the rest of
`go test -race ./internal/gateway`, which pass unchanged.

## Load runs

`scripts/loadtest.sh --duration 15s --warmup 3s --concurrency 64`, two echo backends, one route,
`GET /x/y?a=1`, plain HTTP/1.1 keep-alive, access log off unless stated, loaded machine as above.
Order and spread between rows are within the noise of the shared machine and should not be read
as the cost of each feature.

| Gateway flags | requests/s | p50 ms | p90 | p99 | p99.9 | errors | RSS at end |
|---|---:|---:|---:|---:|---:|---:|---:|
| (defaults, connection history on) | 30779 | 1.79 | 3.84 | 7.68 | 13.3 | 0 | 35.0 MiB |
| `--conn-history 0` | 27893 | 1.92 | 4.61 | 9.22 | 18.4 | 0 | 36.6 MiB |
| `--rate-limit 1000000/s` | 25125 | 2.30 | 5.12 | 10.2 | 20.5 | 0 | 36.3 MiB |
| `--access-log FILE` | 23711 | 2.30 | 5.12 | 11.3 | 20.5 | 0 | 38.1 MiB |

## Soak

```
scripts/loadtest.sh --duration 10m --warmup 10s --concurrency 64 \
  --gateway-flags "--access-log FILE --access-log-max-size 50MB --access-log-keep 2"
```

11,811,205 requests in 600 s (19,685 requests/s average on the loaded machine), 0 errors, all
200. Latency ms: mean 3.25, p50 2.56, p90 6.14, p99 16.4, p99.9 45.1, max 370.

| Time into run | goroutines | heap in use | heap alloc | gateway RSS (`ps`) |
|---|---:|---:|---:|---:|
| 0 s (idle) | 78 | 3.1 MiB | 1.3 MiB | 13.5 MiB |
| 5 s | 313 | 11.2 MiB | 8.6 MiB | 41.2 MiB (at 60 s) |
| 150 s | 377 | 11.1 MiB | 8.5 MiB | 40.2 MiB (at 180 s) |
| 300 s | 385 | 11.7 MiB | 9.3 MiB | 41.0 MiB |
| 450 s | 378 | 9.2 MiB | 5.3 MiB | 41.0 MiB (at 421 s) |
| 610 s (end) | 318 | 9.4 MiB | 5.3 MiB | 42.2 MiB (peak 42.7) |

Goroutines settle at roughly five per client connection (client side, server side, upstream
transport) and fall back after the load stops; heap and RSS rise during the first minute and
then stay flat (RSS 41.2 MiB at one minute, 42.2 MiB at ten, within allocator noise). No leak
was observed over the 10 minutes; this does not rule out slower growth over days.

## Fuzzing

Native Go fuzz targets, with seed corpora committed under `testdata/fuzz/<Target>`
(and the same seeds inline). `go test` runs every seed, so CI catches regressions with no
fuzzing time.

| Package | Targets |
|---|---|
| `internal/gateway` | `FuzzParseConfig` (snapshot parser then table build), `FuzzHostMatching`, `FuzzPathMatching` (path, header, query and method matchers incl. regular expressions), `FuzzJSONPath`, `FuzzTraceparent`, `FuzzClientHello` (TLS ClientHello and ALPN parsing used by TLS passthrough) |
| `internal/setura` | `FuzzDecodeManifests` (migrate YAML and JSON reader), `FuzzReplayLogLine` (JSON, logfmt and Common Log Format) |

```
go test ./internal/gateway -run '^$' -fuzz '^FuzzParseConfig$' -fuzztime 30s
SETURA_WRITE_SEEDS=1 go test ./internal/gateway ./internal/setura -run TestWriteFuzzSeeds   # regenerate seeds
```

Each target was run for 30 seconds on 2026-11-22 (about 0.3 to 1.9 million executions each)
and found no crash or invariant failure. There is no PROXY protocol parser in the gateway, so
none is fuzzed.

## Comparing with Envoy Gateway

another machine, another configuration or by a different generator would not be comparable.
To produce one yourself, change only the proxy and keep everything else equal:

1. Pick one machine for client, proxy and backends (or put the proxy and backends on a second
   machine and keep the client on the first, and write down which). Record CPU model, core
   count, OS, kernel and the versions of Setura (`setura version`) and Envoy Gateway.
2. Start the same backends for both runs, for example `setura echo --name app1 --listen
   127.0.0.1:18101` and `app2` on 18102, and the same generator for both:
   `setura load http://load.test:PORT/x/y?a=1 --address 127.0.0.1 --host load.test --concurrency
   64 --duration 60s --warmup 10s --sample-url ...` (leave `--sample-url` out for Envoy; it only
   reads the Setura `--pprof` endpoint).
3. Setura: `scripts/loadtest.sh --duration 60s --warmup 10s --concurrency 64`, which starts the
   backends and the gateway for you with the route `/` on host `load.test`.
4. Envoy Gateway: on a disposable cluster (K3s is enough), install Envoy Gateway, create a
   `Gateway` with an HTTP listener and an `HTTPRoute` for host `load.test` and path prefix `/` with
   two `backendRefs` to Deployments running `setura echo` (or any equivalent fixed-response
   server), disable access logging and tracing on the Envoy side to match
   `--access-log off`, and port-forward or use the node address of the Envoy Service so the
   generator reaches it. Run the same `setura load` command against it. Cluster networking adds
   hops Setura on loopback does not have; for a fair read run both under the same cluster.
5. For each run keep the full `setura load --json-out` file. Compare requests/s, p50 to p99.9
   and errors at the same concurrency, and, because latency at saturation mostly measures queueing,
   also at a fixed offered load with `--rate N` below the slower proxy's saturation point.
6. Record process RSS from `ps` or `kubectl top` for the proxy under test, from before the run
   to after it.

Publish the commands, the versions, the hardware and the raw JSON along with any comparison.
