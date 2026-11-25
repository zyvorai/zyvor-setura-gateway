# Gateway research and engineering decisions

## Findings

| Area | Upstream behavior | Setura decision |
| --- | --- | --- |
| Gateway API | HTTPRoute declares parent attachment, hostnames, match rules and backend references. Route status is per parent. | Preserve the user's route. Display every reported parent and mark generation mismatches. [HTTPRoute](https://gateway-api.sigs.k8s.io/reference/api-types/httproute/) |
| Kubernetes forwarding | kubectl can forward a Service port to a selected pod. The session ends when the selected pod terminates. | Use this as a foreground development transport. Identify the proxy Service, preserve the HTTP Host and TLS server name, and expose transport failures. [kubectl port-forward](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_port-forward/) |
| Envoy Gateway | The quickstart discovers generated Services using owning Gateway labels. EnvoyProxy customizes the managed Service type. | Discover by Gateway name and namespace, validate listener protocol and port, and reject an ambiguous result. Use ClusterIP for the demo. [Quickstart](https://gateway.envoyproxy.io/v1.8/tasks/quickstart/) · [EnvoyProxy](https://gateway.envoyproxy.io/latest/tasks/operations/customize-envoyproxy/) |
| K3s | The packaged Traefik and ServiceLB installation typically occupies ports 80 and 443 on nodes. | Run a dedicated Envoy class with a ClusterIP Service. The local demo uses 8080 and can coexist with a separate ingress controller. [K3s networking](https://docs.k3s.io/networking/networking-services) |
| Endpoint discovery | EndpointSlices may span multiple objects, carry readiness conditions, and list an endpoint more than once. | Aggregate records across slices and preserve unknown readiness. A count is Service inventory, not a count of unique healthy backends for the requested port. [EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/) |
| Apple Virtualization | A VZVirtioSocketDevice belongs to the running VM and provides port-based host/guest connections. NAT handles guest external connectivity. | For a native transport, add a host adapter in the VM-owning process and a guest listener. Prototype recovery across VM stop/start before promising stable publication. [Virtio sockets](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdevice) · [NAT](https://developer.apple.com/documentation/virtualization/vznatnetworkdeviceattachment) |
| Lima | Lima already forwards guest ports automatically and documents SSH and gRPC transports. | Measure what Setura adds using hostname fidelity, backend assertions and actionable failures. [Port forwarding](https://lima-vm.io/docs/config/port/) |
| Telepresence | HTTP-filtered intercepts already support selective interception. For encrypted traffic the interception point needs access to decrypted headers. | Future personal previews should authenticate at the gateway after TLS termination. Separate the preview identity from client-set routing headers. [Protocols](https://telepresence.io/docs/reference/attachments/protocols) · [TLS intercepts](https://telepresence.io/docs/howtos/mtls) |
| Cilium | Cilium can redirect ingress traffic to Envoy with eBPF and transparently proxy it on Linux. | Add an independent origin probe for the advertised Linux address before claiming ingress health. The Kubernetes API forwarding path bypasses the external entry point. [Cilium Gateway API](https://docs.cilium.io/en/latest/network/servicemesh/gateway-api/gateway-api/) |
| Envoy observability | Envoy Gateway annotates xDS resources with metadata identifying the originating Kubernetes resource. | A future trace can join a request ID, access log and source HTTPRoute. Until that join exists, report observed HTTP responses and control-plane status separately. [Gateway API metadata](https://gateway.envoyproxy.io/v1.9/tasks/observability/gateway-api-metadata/) |
| Cross-namespace references | ReferenceGrant expresses permission in the namespace that owns the referenced resource. | Reading a Service for inspection cannot establish that a Route may target it. Surface the controller's ResolvedRefs condition and preserve namespace boundaries in future reconcilers. [ReferenceGrant](https://gateway-api.sigs.k8s.io/reference/api-types/referencegrant/) |
| Migration traffic | HTTPRoute supports weighted backendRefs and incremental traffic shifting. | A Transiva adapter can stage a VM Service and a pod Service using ordinary weights. Store the previous resource version and weights, require a successful identity probe, and detect concurrent edits before rollback. [Traffic splitting](https://gateway-api.sigs.k8s.io/guides/user-guides/traffic-splitting/) |

## Proposed milestones after 0.1

1. **Mactra native publication.** Implement a narrow VZ socket transport in the VM owner, a guest agent restricted to registered listeners, per-VM lifecycle ownership and a local publication registry. Verify repeated sleep/wake, guest restart, two VMs claiming the same hostname, and a VPN DNS change on Apple Silicon hardware. Measure reconnect duration and leaked listeners.
2. **RouteCheck and GatewayPublication controllers.** Promote the current checks into namespaced Kubernetes objects. Record the probe origin, timestamp, observed generation and conditions. Keep host enrollment and listener ownership explicit. Test duplicate publications and deletion during reconciliation.
3. **Private Xcode previews.** Register one local process under a renewable lease. Bind the preview to an authenticated developer and the intended namespace. Prove isolation with two developers, verify expiry during a disconnect, and test long-lived streams while the backend is withdrawn.
4. **Transiva cutovers.** Pin preflight checks to each backend, then compare failure rate and latency by backend identity before promoting weights. Exercise rollback with live requests and concurrent edits. Stateful writes and session affinity require an application-specific migration plan.
5. **Netra and external-origin evidence.** Add optional Linux policy verdicts and an explicit LAN probe. Label which observations came from the Mac, Envoy or Linux node. Missing telemetry must remain visible as unknown.

A useful benchmark uses the same Mac, guest, route, backend payload and concurrency for kubectl, native VZ and external ingress. Collect successful requests, failures, p50/p95 latency, sustained throughput, host/guest CPU, and time to first verified response after wake. No benchmark or conformance result is claimed for this release.

## Research pass 2026-11: verifying what a Gateway API listener actually answers

Added 2026-11-23 to the earlier findings above. Every claim carries a source URL read during this pass. A claim
marked **[U]** was not read from a fetched page (it comes from memory or from a search
snippet) and should be re-checked before anyone relies on it. Nothing here is a
conformance or performance result for Setura.

### What the field does

| Tool or spec | What it does | Source |
| --- | --- | --- |
| Gateway API conformance suite | Implementations run the upstream suite and publish reports. CORS is an Extended feature tested as `HTTPRoute CORS` (supported feature `HTTPRouteCORS`). The suite runs inside the cluster against a controller; it verifies an implementation, not a particular deployment of your routes. Profiles (Gateway, Mesh) and the report format: **[U]**, the conformance concepts page returned 404. | <https://gateway-api.sigs.k8s.io/geps/gep-1767> (CORS status); search result for v1.5 implementations page <https://gateway-api.sigs.k8s.io/implementations/v1.5/> **[U]** |
| Gateway API v1.5 (2026-02-27) | Moved ListenerSet, TLSRoute, HTTPRoute CORS filter, client certificate validation, certificate selection for Gateway TLS origination and ReferenceGrant to the Standard channel. | <https://kubernetes.io/blog/2026/04/21/gateway-api-v1-5/> (feature list only; the rest of the article was not read) |
| NGINX Gateway Fabric 2.5.0 | Claims Gateway API 1.5 conformance and CORS support through the HTTPRoute CORS filter. Envoy Gateway, Istio, Cilium and Contour support was not found in the search results: **[U]**. | <https://blog.nginx.org/?p=74969> (search snippet) |
| HTTPRoute filter rules | URLRewrite and RequestRedirect "may not be combined"; repeating a core filter has unspecified behaviour; a controller may report `IncompatibleFilters`; a rule with no backends and no responding filter returns 500. | <https://gateway-api.sigs.k8s.io/reference/api-types/httproute/> |
| Traffic splitting | `weight` is a proportion, not a percentage, default 1; weight 0 means no traffic; the denominator is the sum of the rule's weights. The guide says nothing about how closely observed traffic follows the weights. | <https://gateway-api.sigs.k8s.io/guides/traffic-splitting/> |
| CORS filter (GEP-1767) | `allowOrigins`, `allowCredentials`, `allowMethods`, `allowHeaders`, `exposeHeaders`, `maxAge` (default 5). Credentialed requests must never get `*`; the gateway answers preflights itself with 200 or 204; a non-matching preflight gets 200/204 without CORS headers (403 also mentioned). | <https://gateway-api.sigs.k8s.io/geps/gep-1767> |
| CORS on the wire | Preflight is `OPTIONS` with `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers`; wildcards are not honoured for credentialed requests; `Vary: Origin` should accompany a specific origin; `Max-Age` default 5 and browser ceilings. | <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS> |
| Blackbox exporter | HTTP probe with `method`, `headers`, `body`, `valid_status_codes`, `fail_if_header_matches` and `fail_if_header_not_matches`, `fail_if_ssl`, `follow_redirects`. It does not mention traffic splits or CORS. Certificate expiry metrics: not on the configuration page, **[U]**. | <https://github.com/prometheus/blackbox_exporter/blob/master/CONFIGURATION.md> |
| k6 | Thresholds decide the exit code; checks alone do not fail a run. Setura follows the same split: assertions in `check` fail the run, informational output does not. | <https://grafana.com/docs/k6/latest/using-k6/thresholds/> |
| Checkly, Istio, Cilium, Contour, Envoy Gateway verification features | Not researched beyond search results. **[U]** | |
| `ReferenceGrant`, `BackendTLSPolicy`, `ClientTrafficPolicy` | ReferenceGrant is Standard in v1.5 (above); Setura already lints it (SET004, SET012). BackendTLSPolicy is already linted (SET019) and ClientTrafficPolicy is covered by the Envoy Gateway compatibility rules (SET080 to SET083). | <https://kubernetes.io/blog/2026/04/21/gateway-api-v1-5/>, repository docs |

### What Setura lacked at 0.9.0

1. **Probes could only `GET`.** `explain`, `check`, `watch`, `bench` sent one fixed request. A
   route that matches on method or header, a header-based canary, a rewrite visible only
   through a response header, or a CORS preflight could not be verified from the client
   at all, which is the point of the product. Blackbox exporter has had `method` and
   `headers` for years.
2. **No way to check a traffic split.** `bench` reports latency; nothing counted who
   answered. The Gateway API guide defines weights as proportions, and the observed
   share is a sampling outcome, so a naive "is it exactly 90/10" test either flakes or
   hides real errors.
3. **No CORS verification.** CORS became a Standard filter in v1.5. A user can lint the
   filter's shape (SET019), but not ask "does this origin get through, from the client".
4. **Lint did not know the filter-combination rules** the HTTPRoute page states in words
   (URLRewrite with RequestRedirect).
5. Not built, see ranked list: certificate and DNS expiry as a `check` assertion (partly
   there: `warn_expiry_days`, `min_cert_days`, `certs`), redirect-chain following,
   GRPCRoute and TLSRoute probes beyond `grpc-health`, running the upstream conformance
   suite for a report.

### Ranked ideas

| # | Idea | Why it ranks here | Decision |
| --- | --- | --- | --- |
| 1 | Method and request headers in probes | Unblocks every other check. A client-side verifier that cannot send a header cannot verify a header match. Small, stdlib only. | **Built**: `--method`, `--request-header`, check and watch keys. Refuses Host and framing headers, CR/LF, more than 32 headers, non-allow-listed methods; mutating methods need an explicit flag and never carry a body. |
| 2 | Canary traffic-split verification | The commonest rollout question ("did 10% really reach v2?"). The rollout and `shadow` commands judge error rate and diffs; nothing checked the split. | **Built**: `setura split`. Binomial tolerance (3.29 sigma), minimum sample for small shares, unexpected identities fail, error budget, caps. States that it is statistical and client-side. |
| 3 | CORS preflight verifier | Standard filter in v1.5; wrong CORS is invisible to curl-style probes and obvious to users. The rules are deterministic, so the check is exact for one response. | **Built**: `setura cors`. Limited to one response; says it is not a browser. |
| 4 | Lint for filter combinations (SET090) | Cheap, offline, catches `Accepted: False` before apply. | **Built**, errors only for combinations the HTTPRoute page names or the CRD validation implies; items not read from a page are marked **[U]** below. |
| 5 | Run the upstream conformance suite and publish a report | The largest credibility gap (ROADMAP "Prove it"). | Not built: needs a real K3s cluster, Docker and root. Already scripted (`scripts/run-conformance.sh`); cannot run here. |
| 6 | Redirect-chain and `Location` assertions | Already possible: probes do not follow redirects, so `status: 301` plus `headers: {"Location": ...}` works. A convenience wrapper adds little. | Rejected. |
| 7 | Derive expected split from the snapshot (`split --route`) | Convenient, but the identity header value need not equal a Service name, so mapping would be a guess and violate the honesty rule. | Rejected; the user states the identity names. |
| 8 | Synthetic-monitoring SaaS integration (Checkly-style scheduling) | Outside the one-binary identity; `watch` plus Prometheus covers it. | Rejected. |
| 9 | Certificate and DNS expiry gates across a hostname list | Mostly covered by `certs --warn-expiry-days` and `explain --warn-expiry-days`; a list mode would be a loop. | Deferred. |
| 10 | HTTPRoute `CORS` filter lint against live preflight | Joins SET019 with `cors`; needs a running listener. | Deferred. |

### Unverified items used by SET090 **[U]**

The HTTPRoute page read for this pass states the URLRewrite and RequestRedirect
exclusion and the unspecified repeat of core filters. It does not state these, which
SET090 also enforces from the published CRD validation as remembered: a core filter must
not repeat (admission rule), `ReplacePrefixMatch` is valid only with `PathPrefix`
matches, `requestRedirect.scheme` is `http` or `https`, `port` is 1 to 65535. If a
controller you use accepts any of these, `--disable SET090` or a baseline silences the
rule; the finding text says what it believes the API requires.

### Honesty boundaries kept

- Probes originate at the CLI and report one client's observation. `split` and `cors`
  repeat that statement in their output and docs.
- Statistics are named as statistics, with their false-alarm rate and a refusal when the
  sample is too small, instead of a green tick on a number that could be noise.
- No new dependency (standard library only); the CONTRIBUTING rule holds.
- Exit codes keep their meaning: `0` passed, `1` observed failure, `2` usage or setup.
- No data leaves the machine: header values are never echoed in errors.

## Research pass 2026-11-25: what comparable tools check that Setura did not

Pages fetched on 2026-11-25. Items marked **[U]** came from a search summary or a page that
was only partly read.

| Source | What was read | Setura decision |
| --- | --- | --- |
| [Gatus README](https://github.com/TwiN/gatus) | Placeholders `[DOMAIN_EXPIRATION]`, `[CERTIFICATE_EXPIRATION]`, `[DNS_RCODE]`; alert `failure-threshold` (default 3) and `success-threshold` (default 2); maintenance windows. How Gatus looks domains up (WHOIS or RDAP) was not in the part read **[U]**. | **Built**: `certs --domain-expiry` over RDAP; `watch --alert-after` and `--alert-recover-after` (default 1, so behaviour is unchanged). Maintenance windows and DNS record checks: not built. |
| [Hurl templates](https://hurl.dev/docs/templates.html), [running tests](https://hurl.dev/docs/running-tests.html), [asserts](https://hurl.dev/docs/asserting-response.html) | `{{name}}` variables from `--variable`, `--variables-file`, `HURL_VARIABLE_name`; `--secret` redaction; JUnit, TAP, HTML and JSON reports; `--repeat`. | **Built**: variables in check and watch files with the same three sources. Secrets redaction is not offered and the docs say so. Setura already has JUnit and SARIF. |
| [k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/) | `<metric> <operator> <value>`, `avg`, `p(N)`, `rate`, `count`; any failed threshold gives a non-zero exit; `abortOnFail`. | **Built**: `bench --threshold`. `abortOnFail` not built: `bench` runs are short and bounded. |
| [gwctl README](https://github.com/kubernetes-sigs/gwctl) | `get`, `describe` with effective policies, `analyze` of a manifest before apply, DOT graphs; experimental. | Not built: `lint`, `pr-check`, `impact` and `map` cover most of it. Effective-policy display remains an idea. |
| [Ingress2Gateway 1.0](https://kubernetes.io/blog/2026/03/20/ingress2gateway-1-0-release) | `print` with providers and emitters; warnings for untranslatable annotations; SSL redirect default; case-insensitive regex paths; behaviour tests against live controllers. | `migrate convert` already reports unsupported annotations and emits the default SSL redirect. Nothing built; its behavioural-equivalence testing is what `migrate check --ingress-url --gateway-url` does for one deployment. |
| [GRPCRoute](https://gateway-api.sigs.k8s.io/reference/api-types/grpcroute/), [TLSRoute](https://gateway-api.sigs.k8s.io/reference/api-types/tlsroute/), [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md) | `backendRefs` weights; TLSRoute matches on SNI; the outcome of a call is `grpc-status` in trailers (or a trailers-only response). | **Built**: `split --grpc` and `split tls://`. |
| [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083.html), [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224.html), [IANA bootstrap](https://data.iana.org/rdap/dns.json) | `events[].eventAction = "expiration"`; longest label match, HTTPS first. The bootstrap file listed `com`, `net`, `dev` and `ai`, and no entry for `io`. | **Built** as above; a TLD without a server is `unknown`, which fails. Not tried against a real registry. |
