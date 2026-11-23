# Setura gateway in Netra

Netra's application collector can scrape the built-in gateway's Prometheus
endpoint with its generic `prometheus` kind. Nothing needs to change in Netra:
copy [netra/apps.yaml](netra/apps.yaml) into `/etc/netra/apps.yaml`
(`NETRA_APPS_CONFIG`) or the Helm value `metricsPlatform.apps.config`.

```yaml
apps:
  - kind: prometheus
    name: setura
    url: http://127.0.0.1:19000/metrics
    bearer_env: SETURA_ADMIN_TOKEN
    include: ["setura_gateway_*"]
    exclude:
      - "setura_gateway_accesslog_rotation*"
      - "setura_gateway_ratelimit_buckets"
      - "setura_gateway_circuit_active_requests"
      - "setura_gateway_circuit_pending_requests"
    max_series: 4000
    timeout: 3s
    labels: {service: setura-gateway}
```

## Reaching the admin endpoint

The gateway serves `/metrics` on its admin address (`--admin`, default
`127.0.0.1:19000`). On loopback it needs no credentials. Bound to a pod or
node address it requires the admin token, which Netra sends as a bearer token:
set `bearer_env: SETURA_ADMIN_TOKEN` and give the agent that variable from a
Secret (`metricsPlatform.apps.existingSecret`). Netra never reads Secrets through
the Kubernetes API, so the variable must be provided by you. The install
manifests (`setura gateway install`) put the token in the Secret
`setura-gateway-admin`, key `token`.

Netra sends `Accept: text/plain;version=0.0.4`, so the gateway answers with the
plain Prometheus format (no exemplars). Exemplars are only produced for
scrapers that ask for `application/openmetrics-text`.

## What Netra does with the series

Netra turns each series into a chart named `prometheus_setura.<metric>` (context
`prometheus.<metric>`, labelled `app_name=setura` plus `service=setura-gateway`),
one dimension per label set, for example `code=5xx,route=shop/web`.

* Counters (`*_total`) become per-second rates.
* Gauges stay absolute.
* Histograms contribute `_sum` and `_count` rates and a lifetime mean
  (`<name>_mean`). **Buckets are skipped**, so Netra shows mean request duration per
  route and backend but not percentiles. Use the Grafana dashboard
  ([grafana/setura-gateway.json](../grafana/setura-gateway.json)) for p50/p95/p99
  and the `SeturaGatewayLatencyP95` alert.
* At most `max_series` series per instance are kept (default 2,000). Per-route and
  per-backend series multiply with status classes; 4,000 is comfortable for a few
  hundred routes. When the cap is hit the later series are dropped silently, so
  raise it or narrow `include` rather than guessing.

## What to chart and alert on

| Question | Series |
|---|---|
| Is traffic flowing? | rate of `setura_gateway_requests_total` |
| Which routes fail? | rate of `setura_gateway_route_requests_total{code="5xx"}` per `route` |
| Which backends fail? | rate of `setura_gateway_backend_requests_total{code="5xx"}` per `backend` |
| Are requests slow? | `setura_gateway_request_duration_seconds_mean` per `route`, `setura_gateway_backend_request_duration_seconds_mean` per `backend` |
| Are retries or ejections happening? | rates of `setura_gateway_retries_total`, `setura_gateway_ejections_total`; gauge `setura_gateway_endpoint_ejected` |
| Is a backend shedding load? | gauge `setura_gateway_circuit_state` (0 closed, 1 open, 2 half-open) |
| Is the rate limiter biting? | rate of `setura_gateway_ratelimit_limited_total` |
| Is auth rejecting clients? | rate of `setura_gateway_auth_requests_total{decision="denied"}` by `reason` |
| Is the pipeline healthy? | rates of `setura_gateway_accesslog_dropped_total`, `setura_gateway_otlp_spans_dropped_total`, `setura_gateway_logsink_dropped_total` |
| Do certificates expire soon? | gauge `setura_gateway_cert_expiry_seconds` per `listener` |
| Is a shadow backend diverging? | rate of `setura_gateway_shadow_total{result="mismatched"}` against `matched` |

## The metric contract

These names, types and label sets are stable. A golden test
(`internal/gateway/metrics_ext_test.go`, `testdata/metrics_catalog.golden`) fails
when one is renamed, retyped or relabelled, so Netra configuration written against
them keeps working. A family appears only when its subsystem is on (for example
`setura_gateway_ratelimit_*` needs `--rate-limit`); HELP and TYPE are present for
the families that are always on even before the first sample.

| Metric | Type | Labels |
|---|---|---|
| `setura_gateway_requests_total` | counter |  |
| `setura_gateway_unmatched_requests_total` | counter |  |
| `setura_gateway_route_requests_total` | counter | `route`, `code` |
| `setura_gateway_backend_requests_total` | counter | `backend`, `code` |
| `setura_gateway_request_duration_seconds` | histogram | `route` |
| `setura_gateway_backend_request_duration_seconds` | histogram | `backend` |
| `setura_gateway_requests_in_flight` | gauge |  |
| `setura_gateway_connections_open` | gauge |  |
| `setura_gateway_retries_total` | counter | `backend` |
| `setura_gateway_retries_denied_total` | counter | `backend` |
| `setura_gateway_retries_cross_backend_total` | counter | `backend` |
| `setura_gateway_retry_per_try_timeouts_total` | counter | `backend` |
| `setura_gateway_ejections_total` | counter | `backend` |
| `setura_gateway_endpoint_healthy` | gauge | `backend`, `endpoint` |
| `setura_gateway_endpoint_ejected` | gauge | `backend`, `endpoint` |
| `setura_gateway_circuit_state` | gauge | `backend` |
| `setura_gateway_circuit_active_requests` | gauge | `backend` |
| `setura_gateway_circuit_pending_requests` | gauge | `backend` |
| `setura_gateway_circuit_opened_total` | counter | `backend` |
| `setura_gateway_circuit_rejected_total` | counter | `backend`, `reason` |
| `setura_gateway_ratelimit_allowed_total` | counter |  |
| `setura_gateway_ratelimit_limited_total` | counter | `route` |
| `setura_gateway_ratelimit_buckets` | gauge |  |
| `setura_gateway_shadow_total` | counter | `route`, `result` |
| `setura_gateway_auth_requests_total` | counter | `route`, `decision`, `reason` |
| `setura_gateway_cors_preflights_total` | counter | `route` |
| `setura_gateway_backend_tls_handshake_failures_total` | counter | `backend` |
| `setura_gateway_session_persistence_hits_total` | counter | `route` |
| `setura_gateway_cert_expiry_seconds` | gauge | `listener` |
| `setura_gateway_l4_connections_total` | counter | `protocol`, `route`, `backend` |
| `setura_gateway_l4_failures_total` | counter | `protocol`, `route`, `backend` |
| `setura_gateway_l4_bytes_in_total` | counter | `protocol`, `route`, `backend` |
| `setura_gateway_l4_bytes_out_total` | counter | `protocol`, `route`, `backend` |
| `setura_gateway_udp_sessions_open` | gauge |  |
| `setura_gateway_accesslog_written_total` | counter |  |
| `setura_gateway_accesslog_dropped_total` | counter |  |
| `setura_gateway_accesslog_rotations_total` | counter |  |
| `setura_gateway_accesslog_rotation_errors_total` | counter |  |
| `setura_gateway_otlp_spans_exported_total` | counter |  |
| `setura_gateway_otlp_spans_dropped_total` | counter |  |
| `setura_gateway_otlp_export_failures_total` | counter |  |
| `setura_gateway_otlp_retries_total` | counter |  |
| `setura_gateway_otlp_queue_length` | gauge |  |
| `setura_gateway_logsink_sent_total` | counter | `sink` |
| `setura_gateway_logsink_dropped_total` | counter | `sink` |
| `setura_gateway_logsink_failures_total` | counter | `sink` |
| `setura_gateway_logsink_retries_total` | counter | `sink` |
| `setura_gateway_logsink_queue_length` | gauge | `sink` |
| `setura_ai_requests_total` | counter | `route`, `provider`, `model`, `outcome` |
| `setura_ai_tokens_total` | counter | `route`, `provider`, `model`, `direction` |
| `setura_ai_cost_estimate_total` | counter | `route`, `provider`, `model` |
| `setura_ai_key_tokens_total` | counter | `route`, `key`, `direction` |
| `setura_ai_key_cost_estimate_total` | counter | `route`, `key` |
| `setura_ai_cache_requests_total` | counter | `route`, `result` |
| `setura_ai_cache_evictions_total` | counter | `route` |
| `setura_ai_budget_rejections_total` | counter | `route`, `limit` |
| `setura_ai_provider_attempts_total` | counter | `route`, `provider`, `result` |
| `setura_ai_failovers_total` | counter | `route`, `from`, `to` |
| `setura_ai_pii_findings_total` | counter | `route`, `rule`, `action` |
| `setura_ai_provider_up` | gauge | `route`, `provider` |

Histograms are exposed as the usual `_bucket`, `_sum` and `_count` series. Label
values: `route` is `namespace/name` of the HTTPRoute, `backend` is
`namespace/service:port`, `code` is the status class (`1xx` to `5xx`),
`decision` is `allowed` or `denied`, `reason` for denials is `unauthenticated`,
`forbidden`, `client_cert` or `external`, `sink` is `syslog`, `loki` or `otlp_logs`.

## Optional: a `setura` preset in Netra

A dedicated kind would let operators write `kind: setura` and get discovery of
the admin port without listing the include globs. Netra's own code makes that a
small change: one entry in `appKinds` (using the `withDefaults` pattern of
`envoy`, `coredns` and `etcd`), a one-glob include list, one discovery probe
(process `setura`, port 19000, path `/metrics`), a test and a docs row.
[netra/setura-preset.patch](netra/setura-preset.patch) is that change as a patch against
the Netra repository. It is a proposal: it has been checked to apply cleanly
(`patch -p1 --dry-run`) and to be gofmt-clean, but its test was not run, because the
Netra project is read-only reference here. Apply it in the Netra repository
yourself, run `go test ./internal/collectors/`, and review it like any other change.

```sh
cd path/to/netra && git apply path/to/zyvor-setura-gateway/docs/netra/setura-preset.patch
```

Until then the `prometheus` kind above does the same job.
