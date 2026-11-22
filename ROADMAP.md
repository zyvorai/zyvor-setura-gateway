# Roadmap

Plans, not promises. Dates are intentionally absent.

## Released

- **0.6.0.** GRPCRoute and TLSRoute, resilience, observability, `ui`, `why`, `replay`,
  guarded rollout, shadow diff, `migrate check`, connections, multi-cluster, alerting,
  Kubernetes watches and leader election.

## 0.7.0 (merged, release pending)

Gateway API 1.5 features, traffic security, ACME and certificate reload, PROXY protocol,
operator UX (`top`, `init`, `doctor gateway`, dashboard Changes page and command
palette), `migrate convert`, observability integrations (Grafana, alerts, OTLP gRPC,
log sinks, SLOs, Netra), performance work and fuzzing, signed releases, packages and
a Helm chart. See `CHANGELOG.md`.

## Next

Things we know are missing, in the order we would take them:

1. **Prove it.** Run the upstream Gateway API conformance suite on K3s and publish the
   report; automate a real controller-mode smoke test (the existing `cluster-smoke.sh`
   covers the Envoy Gateway path, not Setura's controller); run ACME against Let's Encrypt
   staging end to end.
2. **GRPCRoute auth and filters.** gRPC routes currently get identity-header stripping and
   client-certificate headers only; add the JWT, API key and CORS-equivalent policies.
3. **Client-certificate revocation** (CRL and client-side OCSP checks).
4. **HTTP/3.** Deferred until the standard library gains a QUIC server; an HTTP/3-capable
   edge in front works today with `--alt-svc` (see `docs/http3.md`).
5. **A shared store for rate limits** across replicas, and for session-persistence keys.
6. **Netra:** percentile latency from histograms (needs a change in Netra's collector; a
   proposed patch is in `docs/netra/`).
