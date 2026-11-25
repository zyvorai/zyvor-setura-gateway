# Roadmap

Plans, not promises. Dates are intentionally absent.

## Released

- **0.9.0.** Direct responses and per-route limits, client-certificate authorisation, install options and cluster status, an AI gateway, API metering and plans, shadow-API discovery with contract enforcement, game-day chaos and pull-request traffic checks, load balancing algorithms and external backends, OIDC login and authorization rules, Redis-backed shared rate limits, compression, connection limits, gRPC-web, and Envoy Gateway policy compatibility.
- **0.7.0.** Gateway API 1.5 features, traffic security, ACME and certificate reload, PROXY
  protocol, operator UX (`top`, `init`, `doctor gateway`, dashboard Changes page and command
  palette), `migrate convert`, observability integrations, performance work and fuzzing,
  signed releases (cosign, SLSA provenance, SBOMs), packages and a Helm chart.
- **0.6.0.** GRPCRoute and TLSRoute, resilience, observability, `ui`, `why`, `replay`,
  guarded rollout, shadow diff, `migrate check`, connections, multi-cluster, alerting,
  Kubernetes watches and leader election.

## Next

Things we know are missing, in the order we would take them:

1. **Prove it.** Get the upstream Gateway API conformance suite to run: the scheduled run
   stops during setup because the suite creates several Gateways on port 80, which one
   shared data plane reports as `HostnameConflict`. That needs an address or data plane per
   Gateway. Then publish the report; watch the new controller-mode smoke (`scripts/controller-smoke.sh`, in the cluster-smoke job)
   go green for the first time; run ACME against Let's Encrypt
   staging end to end.
2. **GRPCRoute filters and limits.** Auth and rate limits now apply; per-route size limits, direct responses and fault injection are still HTTP only.
3. **Client-certificate revocation** (CRL and client-side OCSP checks).
4. **HTTP/3.** Deferred until the standard library gains a QUIC server; an HTTP/3-capable
   edge in front works today with `--alt-svc` (see `docs/http3.md`).
5. **A shared store for rate limits** across replicas, and for session-persistence keys.
6. **Netra:** percentile latency from histograms (needs a change in Netra's collector; a
   proposed patch is in `docs/netra/`).
