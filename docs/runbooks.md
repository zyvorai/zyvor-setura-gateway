# Runbooks

Every alert shipped with the gateway (the Helm chart's `prometheusRule`, and
`setura gateway install --with-monitoring`) carries a `runbook_url` that points at
its section here. Thresholds are Helm values (`prometheusRule.*`).

## SeturaGatewayDown

*critical.* No gateway admin endpoint is being scraped.

Check the gateway pods (`kubectl -n setura-system get pods`) and that the ServiceMonitor selects the Service with the `admin` port. Check the admin token: off loopback the scrape needs it (`SETURA_ADMIN_TOKEN`). While this fires every other alert is blind; traffic may still be fine.

## SeturaGateway5xxRatio

*warning.* More than the threshold share of responses are 5xx over 10 minutes.

Find the route: the dashboard panel "Backend errors", or `setura connections --filter status=5xx`. If one backend dominates, look at `SeturaGatewayCircuitOpen` and `SeturaGatewayAllBackendsEjected`. If the status is gateway generated (502/503/504), the access log `error` field says why (`setura connections --format json | jq ".history[0].error"`).

## SeturaGatewayLatencyP95

*warning.* p95 request duration of a route is above the threshold.

The alert names the route. Compare `setura_gateway_backend_request_duration_seconds` per backend to see whether one backend is slow, check retries (`setura_gateway_retries_total`) and the per-try timeout, then the traces linked from the exemplars on the Latency panel (OpenMetrics scrape).

## SeturaGatewayAllBackendsEjected

*critical.* Every endpoint of a backend is ejected by outlier detection.

Requests to the backend fail or go to ejected endpoints. Check the pods behind the Service, then lower the blast radius: ejected endpoints return after their ejection time (doubling each time, `--outlier-base-ejection`). `setura why GET URL --admin ADDR` shows the endpoint states.

## SeturaGatewayCertExpiring

*warning.* A listener certificate expires within the threshold (14 days by default).

The label `listener` names it. Renew the Secret the Gateway listener references (cert-manager `Certificate`, or the TLS Secret you manage); the gateway picks up the new Secret without a restart. `setura certs HOST:PORT` shows what is served now.

## SeturaGatewayCircuitOpen

*warning.* A backend circuit breaker has been open for two minutes.

The backend is being shed with 503 (`X-Setura-Circuit: open`). Check why it fails (`SeturaGateway5xxRatio`, backend logs); the breaker probes again after `--cb-open-for` and closes when the probes succeed.

## SeturaGatewayShadowMismatchRate

*warning.* A shadow backend answers differently from the primary.

`setura shadow` lists the mismatches by category (status, header, body, latency). Decide whether the candidate has a bug or the comparison needs `ignore` rules before promoting the candidate.

## SeturaGatewayUnmatchedRoutes

*warning.* Requests match no route.

Clients hit a host or path no HTTPRoute serves: a typo in a route, a missing hostname, or scanners. `setura connections --filter status=404` shows what they ask for.

## SeturaGatewayEndpointEjected

*warning.* An endpoint has been ejected for five minutes.

One pod keeps failing. Look at it directly; the gateway keeps serving from the others.

## SeturaGatewayAccessLogDropping

*info.* Access log lines are dropped.

The log writer is slower than the request rate. Check the disk or collector behind `--access-log`, raise the buffer, or send logs to a sink (`--loki-url`, `--syslog`, `--otlp-logs-endpoint`); also see `setura_gateway_logsink_dropped_total`. Requests are never slowed by this.
