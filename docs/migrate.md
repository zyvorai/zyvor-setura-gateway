# setura migrate check

Verify an Ingress to Gateway API migration. Compares each Ingress rule with the converted HTTPRoute, GRPCRoute or TLSRoute rule, optionally probes both data planes, and lists `nginx.ingress.kubernetes.io/*` annotations that need attention.

    setura migrate check [flags]

## Inputs

Objects come from the live cluster (through `kubectl`, like the other commands) or from files. Mix freely: `--ingress` replaces only the Ingress read, `--routes` only the HTTPRoute and Gateway read.

| Flag | Meaning |
| --- | --- |
| `--ingress PATH` | Ingress objects from a YAML/JSON file or directory (`networking.k8s.io/v1`) |
| `--routes PATH` | HTTPRoutes, GRPCRoutes, TLSRoutes and optionally Gateways, from a YAML/JSON file or directory |
| `--services PATH` | Services, to resolve named backend ports and ExternalName targets, from a YAML/JSON file or directory. Service objects found in the other inputs are used too |
| `--objects PATH` | other supporting objects from a YAML/JSON file or directory: EndpointSlices, Endpoints, ReferenceGrants, IngressClasses (and Services). The same kinds are picked up from `--ingress` and `--routes` files too; passing `--objects` declares the files complete, so a missing grant or endpoint is a finding instead of "not available" |
| `--ingress-class NAME` | only analyse Ingresses of this class (default: all classes) |
| `-n`, `--namespace NS` | namespace for cluster reads (default `default`); `-A` reads all namespaces |

When an input comes from the cluster (Ingresses, or routes, or both), the command also reads `grpcroutes` and `tlsroutes` (a missing CRD is fine unless an Ingress needs that kind), `ingressclasses` (for the default class, when Ingresses come from the cluster), `services` when none were supplied, `endpointslices.discovery.k8s.io` (falling back to `endpoints`) when an Ingress uses a named backend port, and `referencegrants.gateway.networking.k8s.io` once per namespace that a cross-namespace reference points into. With both `--ingress` and `--routes` given, nothing is read from the cluster.

The YAML reader is built in (the module has no dependencies). It handles block and flow collections (also spanning lines), explicit `? key` entries (keys that span lines, or are collections), plain scalars folded across lines, single and double quoted scalars (multi-line, with escapes), `|` and `>` block scalars with chomping and indentation indicators, anchors, aliases and `<<` merge keys, tags (`!!str`, `!!int`, `!!float`, `!!bool` and `!!null` are honoured, other tags are ignored), comments, directives and multi-document files, so helm output reads as is. An unquoted `*.example.com` is read as a wildcard host, not an alias.

#### YAML 1.1 or 1.2 scalars

Kubernetes tooling (kubectl, sigs.k8s.io/yaml on go-yaml v2) resolves unquoted scalars with YAML 1.1 rules, so the reader does the same, to see what the cluster sees:

- `y`, `yes`, `on` (spellings `y Y yes Yes YES on On ON true True TRUE`) are `true`; `n`, `no`, `off` likewise `false`. A host or name that spells one of these has to be quoted, as it does for kubectl.
- Integers may be hexadecimal (`0x1F`), binary (`0b101`), octal (`0o17` and the 1.1 form `0755`) and contain underscores (`1_000`). `.inf`, `-.inf` and `.nan` are floats.
- Quoted scalars (`"yes"`, `'0x10'`) and `!!str` values are always strings, and a mapping key keeps the text it was written with (`on:` is the key `on`).
- Sexagesimal numbers (`1:30`) and timestamps stay strings, as in go-yaml v2.

A collection used as an explicit key is stored under its compact JSON text (Kubernetes objects never have such keys). Plain implicit keys must stay on one line, as the YAML specification requires; use `? key` for longer ones.

## Matching

Each Ingress rule (host, path, pathType, backend Service and port, TLS) is matched to an HTTPRoute rule by namespace, hostname and path (a trailing slash is ignored). Among candidates the closest one wins, and the route named by the `ingress2gateway` convention is preferred on a tie. That convention is `<ingress-name>-<host with . as ->`, `wildcard` for `*`, and `all-hosts` for no host. A route with another name still matches by content; the report notes the naming difference.

| Status | Meaning |
| --- | --- |
| `equivalent` | host, path, path type, backend Service and port agree |
| `different` | a rule matches by host and path but differs (path type, backend, port, redirect instead of forwarding, TLS) |
| `unresolved` | everything that could be compared agrees, but a named backend port could not be resolved against a Service (see below); counts as a failure |
| `missing-in-gateway` | no route rule of the expected kind has this host and path |
| `extra-in-gateway` | a route rule that no Ingress rule maps to |

Notes on semantics: `Exact` maps to `Exact`; `Prefix` and `ImplementationSpecific` map to `PathPrefix` (the latter is called out); `nginx.ingress.kubernetes.io/use-regex: "true"` expects `RegularExpression`. `backend.resource` is reported as different. The `spec.defaultBackend` is treated as a `/` prefix rule for all hosts.

### Route kinds

The kind a rule converts to follows the annotations of its Ingress:

| Ingress | Expected route | Compared |
| --- | --- | --- |
| default | `HTTPRoute` | host, path and path type, backend, TLS |
| `backend-protocol: GRPC` or `GRPCS` | `GRPCRoute` | host, gRPC service/method against the Ingress path (`/pkg.Service` or `/pkg.Service/Method`), backend, TLS |
| `ssl-passthrough: "true"` | `TLSRoute` | host (SNI routing has no path; the Ingress path is not compared), backend; the parent Gateway needs a TLS listener with `tls.mode: Passthrough` covering the host |

A rule that exists in the wrong kind (for example an HTTPRoute for a gRPC Ingress) is `different`. The annotations `backend-protocol: GRPC` and `ssl-passthrough` count as handled when the matched rule is in the expected route kind.

### Named backend ports

A named port (`service.port.name`) is looked up in the Service's `spec.ports` and the resulting port number is compared with the backendRef port. Services come from `--services`/`--objects`, from Service objects in the other inputs, or, when an input comes from the cluster, from `kubectl get services`. If the Service is not available the rule is `unresolved` with the reason, never silently accepted. If the Service has no port with that name the rule is `different`.

Beyond the port number:

- **Targets.** When the HTTPRoute backend port differs from the one the name resolves to, the difference says which `targetPort` each side reaches (`Ingress port http reaches targetPort 80, HTTPRoute port 9090 reaches targetPort 8081`), or that the route port is not a port of the Service at all.
- **Endpoints.** With EndpointSlices (the `kubernetes.io/service-name` label) or Endpoints objects (from files or the cluster), the endpoints of the named port are checked. The rule is `unresolved` when the Service has no endpoints at all, none list the port by name, none are ready, or they serve a different port than a numeric `targetPort`. This is a health finding, not a migration difference: the Ingress would fail the same way. Without any endpoint source a note says endpoints were not inspected.
- **ExternalName.** A rule whose backend is an ExternalName Service says where it points (`... pointing at db.data.svc.cluster.local (the in-cluster Service data/db, ports sql=5432)`; in-cluster names are resolved against the loaded Services). ExternalName Services have no endpoints to inspect and their support as a Gateway API backend is implementation-specific. A named port on an ExternalName Service without ports is `unresolved`.

### Ingress classes

The class of an Ingress is `spec.ingressClassName`, or the `kubernetes.io/ingress.class` annotation when that is not set. An Ingress with neither belongs to the default IngressClass, the one annotated `ingressclass.kubernetes.io/is-default-class: "true"`. The default is read from the cluster (`kubectl get ingressclasses`, whenever Ingresses come from the cluster) or from IngressClass objects in the input files; with several defaults the first by name is used and a note says so. Every rule reports its class (`ingress_class` in JSON, a CLASS column in the table); `ingress_class_default` and a detail line mark a class that came from the default. With `--ingress-class NAME` only Ingresses of that class are analysed; an Ingress without a class counts when NAME is the default class (below). Routes that belong to Ingresses of other classes are left out of the `extra-in-gateway` list, and a note says how many were skipped.

### TLS

For TLS hosts, when Gateway objects are loaded, the parent Gateway (narrowed by `sectionName`) must have an HTTPS or TLS terminate listener covering the host, and the Ingress `tls.secretName` must be among that listener's `certificateRefs` (compared by name, and by namespace when the reference sets one). With no Gateways loaded the report says TLS was not verified.

### GRPCRoute matches

A GRPCRoute rule is matched by host and by the `/service/method` path its method match makes (`service` and `method`, or the service alone). Beyond that:

- a method match of type `RegularExpression` for a literal Ingress path, or a literal one for a regex Ingress, is different;
- an Ingress implies no header matches, so a GRPCRoute match with `headers` is different (requests without them would not be routed there);
- an Ingress with `canary: "true"` and `canary-by-header` (with `-value` or `-pattern`) implies that header match: it must be present with the same value or pattern (header names compare case-insensitively), and a canary header without a value is satisfied by any match on that header name.

### ReferenceGrants

A backendRef of an HTTPRoute, GRPCRoute or TLSRoute (of the analysed classes) whose `namespace` differs from the route's, and a Gateway listener `certificateRef` whose `namespace` differs from the Gateway's, need a ReferenceGrant in the target namespace whose `from` names the referring kind and namespace (`group`, `kind`, `namespace`) and whose `to` names the target kind (and the name, unless it omits it). A reference without one is listed under `reference_grants` in JSON (`status`, `namespace`, `from`, `to` and `fix`, the YAML of a ReferenceGrant that would allow it), in a ReferenceGrants section of the table, and as an error annotation with `--format github`. It counts toward exit code 1 and the summary key `grants_missing`.

Grants come from the input files (any ReferenceGrant object, or `--objects`) or, for inputs from the cluster, from one `kubectl get referencegrants` per target namespace. References into a namespace whose grants were not available are not judged; a note names the namespaces.

## Live comparison

Give both a base URL for the Ingress controller and one for the Gateway data plane:

    setura migrate check --ingress ingress.yaml --routes routes.yaml \
      --ingress-url http://10.0.0.10 --gateway-url http://10.0.0.20

For every Ingress rule Setura sends `GET` to the rule's host and path (wildcard hosts use a stand-in label) at each target, with the right Host header and TLS name, using the same probe code as `setura explain`. Differences in HTTP status, redirect target (`Location`), `X-Setura-Backend` and selected headers turn the rule into `different`. Paths that look like regular expressions are skipped. Probing has no side effects beyond one GET per rule per target.

gRPC rules are probed with one unary call per target: a POST of an empty message (a 5-byte gRPC frame with zero length) to `/service/method` over HTTP/2, `h2` with TLS for `https` URLs and prior-knowledge `h2c` for `http` URLs, framed by hand like `setura grpc health`. Only rules whose Ingress path is a full `/service/method` can be called; a service prefix is skipped with a reason. The comparison treats the answers sensibly for an empty request:

- the same `grpc-status` on both sides is equivalent; if both are `UNIMPLEMENTED` a detail says the probe cannot tell the sides apart (method not routed or not served on either);
- `UNIMPLEMENTED` on one side only means the route or method is not served there, and is a difference;
- `UNAVAILABLE` on one side is reported as no reachable backend;
- any other pair of different codes (for example `OK` against `INVALID_ARGUMENT`) means both reached a backend but answered differently, and is a difference;
- a different HTTP status, a `grpc-status` on one side only, or a different `X-Setura-Backend` is a difference, and a transport failure on either side is reported like in HTTP probes.

The call carries no payload but it does reach the backend method; leave gRPC rules out of live checks (or use a test environment) if an empty call could have side effects. Routes that exist only in the Gateway are probed only with `--probe-extra`; a difference is added to their details while the status stays `extra-in-gateway`.

| Flag | Meaning |
| --- | --- |
| `--ingress-url URL`, `--gateway-url URL` | base URLs; both are required together |
| `--probe-extra` | also probe `extra-in-gateway` rules (default: off) |
| `--address IP` | connect both targets to this IP, keeping Host and TLS identity |
| `--ingress-address IP`, `--gateway-address IP` | per-target IP override |
| `--ca FILE` | trusted CA bundle for HTTPS |
| `--timeout S` | per-operation timeout, default 4 |
| `--header NAME` | extra response header to compare, repeatable. Defaults: `Content-Type`, `Cache-Control`, `Strict-Transport-Security`, `Access-Control-Allow-Origin` |

## Annotations

Every `nginx.ingress.kubernetes.io/*` annotation is classified:

- `translatable`: Gateway API has a filter for it. It counts as handled when a matched route rule carries that filter (`rewrite-target` needs `URLRewrite`, `ssl-redirect` needs `RequestRedirect`, and so on); otherwise it is flagged.
- `implementation-specific`: only a controller policy resource covers it (`proxy-body-size`, `limit-rps`, `auth-url`, timeouts, allow lists).
- `unsupported`: nothing replaces it, such as `configuration-snippet` and `server-snippet`.
- `unknown`: not in the table.

Each finding includes a replacement hint. `ssl-redirect: "false"` is ignored. The table lives in `internal/setura/migrate_annotations.go`; it is advice, not a converter.

## Output and exit codes

`--format auto|pretty|json|github`. Auto prints the table on a terminal and JSON when piped. `github` emits workflow annotations (`::error` for different and missing rules, `::warning` for extra and unresolved rules and flagged annotations).

JSON shape: `{"ok", "summary", "rules": [{"status", "ingress", "ingress_class", "ingress_class_default", "kind", "route", "route_kind", "expected_route", "host", "path", "path_type", "backend", "tls", "details", "probe"}], "annotations", "reference_grants", "notes"}`. A `probe` holds the `ingress` and `gateway` observations (`status`, `redirect`, `backend`, `headers`, `error`, and `grpc_status`/`grpc_message` for gRPC calls) and the `differences`.

| Code | Meaning |
| --- | --- |
| 0 | everything equivalent and no annotation needs attention |
| 1 | differences, missing, extra or unresolved rules, flagged annotations, missing ReferenceGrants, or a live difference |
| 2 | usage or setup error (bad flags, unreadable files, kubectl failure, no Ingress objects) |

## Example

    setura migrate check --ingress examples/migrate/ingress.yaml --routes examples/migrate/routes.yaml

The files in `examples/migrate/` contain equivalent rules (one gRPC rule matched by a GRPCRoute), a named port resolved from `services.yaml`, one rule with a wrong port, one missing rule, extra routes (one a GRPCRoute rule restricted by a header, one sending traffic into another namespace), an Ingress of another class (hidden with `--ingress-class nginx`), and annotations of different classes. `objects.yaml` adds an IngressClass marked default, an EndpointSlice whose only endpoint is not ready (so the named port is reported `unresolved`) and a ReferenceGrant that does not cover the cross-namespace route.

    setura migrate check --ingress examples/migrate/ingress.yaml --routes examples/migrate/routes.yaml \
      --services examples/migrate/services.yaml --ingress-class nginx

    setura migrate check --ingress examples/migrate/ingress.yaml --routes examples/migrate/routes.yaml \
      --services examples/migrate/services.yaml --objects examples/migrate/objects.yaml

## Not handled

- Header matches are compared for GRPCRoute only; HTTPRoute header, query and method matches are not compared with the Ingress. TLSRoute backends are compared by name and port only.
- ReferenceGrants are matched on group, kind, namespace and name; their Gateway API status is not read.
- Endpoints are inspected for named ports only, and only for readiness and port, not addresses, topology or zone hints.
- Live gRPC probes send an empty request message, so they show routing and presence, not whether real requests succeed. Streaming, client certificates and gRPC-Web are not covered.
- The default IngressClass is attributed by annotation only; `spec.controller` (which controller owns the class) is not checked.
- YAML: sexagesimal numbers and timestamps stay strings, and implicit keys that span lines are an error (as in the YAML specification).
