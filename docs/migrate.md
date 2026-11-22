# setura migrate check

Verify an Ingress to Gateway API migration. Compares each Ingress rule with the converted HTTPRoute, GRPCRoute or TLSRoute rule, optionally probes both data planes, and lists `nginx.ingress.kubernetes.io/*` annotations that need attention.

    setura migrate check [flags]

## Inputs

Objects come from the live cluster (through `kubectl`, like the other commands) or from files. Mix freely: `--ingress` replaces only the Ingress read, `--routes` only the HTTPRoute and Gateway read.

| Flag | Meaning |
| --- | --- |
| `--ingress PATH` | Ingress objects from a YAML/JSON file or directory (`networking.k8s.io/v1`) |
| `--routes PATH` | HTTPRoutes, GRPCRoutes, TLSRoutes and optionally Gateways, from a YAML/JSON file or directory |
| `--services PATH` | Services, to resolve named backend ports, from a YAML/JSON file or directory. Service objects found in `--ingress` and `--routes` inputs are used too |
| `--ingress-class NAME` | only analyse Ingresses of this class (default: all classes) |
| `-n`, `--namespace NS` | namespace for cluster reads (default `default`); `-A` reads all namespaces |

When an input comes from the cluster, the command also reads `grpcroutes` and `tlsroutes` (a missing CRD is fine unless an Ingress needs that kind), `ingressclasses` when `--ingress-class` is given, and `services` when an Ingress uses a named backend port and no Services were supplied.

The YAML reader is built in (the module has no dependencies). It handles block and flow collections (also spanning lines), plain scalars folded across lines, single and double quoted scalars (multi-line, with escapes), `|` and `>` block scalars with chomping and indentation indicators, anchors, aliases and `<<` merge keys, tags (`!!str`, `!!int`, `!!float`, `!!bool` and `!!null` are honoured, other tags are ignored), comments, directives and multi-document files, so helm output reads as is. An unquoted `*.example.com` is read as a wildcard host, not an alias.

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

A named port (`service.port.name`) is looked up in the Service's `spec.ports` and the resulting port number (not the `targetPort`) is compared with the backendRef port. Services come from `--services`, from Service objects in the other inputs, or, when an input comes from the cluster, from `kubectl get services`. If the Service is not available the rule is reported `unresolved` with the reason, never silently accepted. If the Service has no port with that name the rule is `different`.

### Ingress classes

The class of an Ingress is `spec.ingressClassName`, or the `kubernetes.io/ingress.class` annotation when that is not set. Every rule reports it (`ingress_class` in JSON, a CLASS column in the table). With `--ingress-class NAME` only Ingresses of that class are analysed; an Ingress without a class counts when a loaded IngressClass named NAME is marked `ingressclass.kubernetes.io/is-default-class: "true"`. Routes that belong to Ingresses of other classes are left out of the `extra-in-gateway` list, and a note says how many were skipped.

### TLS

For TLS hosts, when Gateway objects are loaded, the parent Gateway (narrowed by `sectionName`) must have an HTTPS or TLS terminate listener covering the host, and the Ingress `tls.secretName` must be among that listener's `certificateRefs` (compared by name, and by namespace when the reference sets one). With no Gateways loaded the report says TLS was not verified.

## Live comparison

Give both a base URL for the Ingress controller and one for the Gateway data plane:

    setura migrate check --ingress ingress.yaml --routes routes.yaml \
      --ingress-url http://10.0.0.10 --gateway-url http://10.0.0.20

For every Ingress rule Setura sends `GET` to the rule's host and path (wildcard hosts use a stand-in label) at each target, with the right Host header and TLS name, using the same probe code as `setura explain`. Differences in HTTP status, redirect target (`Location`), `X-Setura-Backend` and selected headers turn the rule into `different`. Paths that look like regular expressions are skipped. Probing has no side effects beyond one GET per rule per target. gRPC rules are not probed (a plain GET does not exercise them). Routes that exist only in the Gateway are probed only with `--probe-extra`; a difference is added to their details while the status stays `extra-in-gateway`.

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

JSON shape: `{"ok", "summary", "rules": [{"status", "ingress", "ingress_class", "kind", "route", "route_kind", "expected_route", "host", "path", "path_type", "backend", "tls", "details", "probe"}], "annotations", "notes"}`.

| Code | Meaning |
| --- | --- |
| 0 | everything equivalent and no annotation needs attention |
| 1 | differences, missing, extra or unresolved rules, flagged annotations, or a live difference |
| 2 | usage or setup error (bad flags, unreadable files, kubectl failure, no Ingress objects) |

## Example

    setura migrate check --ingress examples/migrate/ingress.yaml --routes examples/migrate/routes.yaml

The files in `examples/migrate/` contain equivalent rules (one through a named port resolved from `services.yaml`, one gRPC rule matched by a GRPCRoute), one with a wrong port, one missing rule, one extra route, an Ingress of another class (hidden with `--ingress-class nginx`), and annotations of different classes.

    setura migrate check --ingress examples/migrate/ingress.yaml --routes examples/migrate/routes.yaml \
      --services examples/migrate/services.yaml --ingress-class nginx

## Not handled

- YAML: complex keys (`? `), keys that span lines, YAML 1.1 booleans such as `yes`/`no`, and hexadecimal or octal numbers. Use `kubectl get -o json` for such files.
- Named ports compare the Service port number only; endpoints, `targetPort` and ExternalName Services are not inspected.
- GRPCRoute header matches and TLSRoute backends beyond name and port are not compared; ReferenceGrants for cross-namespace certificate or backend references are not checked.
- Which Ingress is the default class is known only from IngressClass objects that were loaded.
- gRPC rules are not probed live.

