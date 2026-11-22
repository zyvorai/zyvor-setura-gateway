# Protocols: HTTP/2, gRPC health and bench

All three features are stdlib-only and run from the client, like `explain`.

## HTTP/2 (`--http2`)

```
setura explain https://orders.example.test/checkout --address 10.0.0.5 --ca ca.pem --http2
```

The probe still dials the pinned `--address`, verifies TLS against the URL
host and sends the URL's `Host`. It offers ALPN `h2` and `http/1.1`:

- `tls` step gains `alpn` (the negotiated protocol). If the server does not
  select `h2` the `tls` stage fails with `server did not negotiate h2` and
  later stages stay `untested`.
- `http` step gains `proto` (`HTTP/2.0`).
- `--http2` needs an `https://` URL (exit 2 otherwise).

In a `check` file use `"http2": true` (must be a JSON boolean).

Implementation note: the TLS connection established by the staged pipeline is
handed once to `net/http`'s built-in HTTP/2 transport through a custom
`DialTLSContext`, so per-stage evidence is preserved.

## gRPC health

```
setura grpc-health HOST:PORT [--service NAME] [--ca ca.pem] [--timeout 4] [--json]
```

Calls `grpc.health.v1.Health/Check` with hand-framed protobuf
(`HealthCheckRequest{service=1}`, `HealthCheckResponse{status=1}`) over
HTTP/2 + TLS. Output fields: `status` (`SERVING`, `NOT_SERVING`,
`SERVICE_UNKNOWN`, `UNKNOWN`), `grpc_status`, `grpc_message`, `alpn`,
`http_status`, `error`, `elapsed_ms`.

Exit 0 only for `SERVING`; 1 for any other status or network, TLS or gRPC
error; 2 for bad input. TLS is required: plaintext h2c needs Go 1.24
`http.Protocols`, which the module (go 1.22) does not assume, so
`--tls=false` is rejected with exit 2.

## bench

```
setura bench URL [--requests N] [--concurrency C] [--duration D]
                 [--max-p99-ms MS] [--max-error-rate R] [--address IP] [--ca FILE]
                 [--status CODE] [--timeout S] [--http2] [--json]
```

Each request is a full staged `Probe` (DNS, TCP, TLS, HTTP), so every sample
includes connection setup. Defaults: 100 requests unless `--duration` is given,
concurrency 4 (max 256), requests max 1,000,000. With both `--requests` and
`--duration`, whichever is hit first ends the run.

Output: `requests`, `errors`, `error_rate`, `rps`, `latency_ms`
(`min mean p50 p90 p99 max`, nearest-rank), `status` histogram (`error` for
requests that never produced a status), `violations`, `first_error`. A request
counts as an error when its probe fails (wrong status, TLS failure, ...).

Exit 1 when `--max-p99-ms` or `--max-error-rate` (0..1) is exceeded.
