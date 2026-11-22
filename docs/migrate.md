# setura migrate check

Verify an Ingress to Gateway API migration. Compares each Ingress rule with the converted HTTPRoute rule, optionally probes both data planes, and lists `nginx.ingress.kubernetes.io/*` annotations that need attention.

    setura migrate check [flags]

## Inputs

Objects come from the live cluster (through `kubectl`, like the other commands) or from files. Mix freely: `--ingress` replaces only the Ingress read, `--routes` only the HTTPRoute and Gateway read.

| Flag | Meaning |
| --- | --- |
| `--ingress PATH` | Ingress objects from a YAML/JSON file or directory (`networking.k8s.io/v1`) |
| `--routes PATH` | HTTPRoutes, and optionally Gateways, from a YAML/JSON file or directory |
| `-n`, `--namespace NS` | namespace for cluster reads (default `default`); `-A` reads all namespaces |

The YAML reader is built in (the module has no dependencies). It handles normal Kubernetes manifests: block and flow collections, quoted scalars, `|` and `>` block scalars, comments and multi-document files. It does not support anchors, tags or multi-line flow collections; convert such files with `kubectl get -o json`.

## Matching

Each Ingress rule (host, path, pathType, backend Service and port, TLS) is matched to an HTTPRoute rule by namespace, hostname and path (a trailing slash is ignored). Among candidates the closest one wins, and the route named by the `ingress2gateway` convention is preferred on a tie. That convention is `<ingress-name>-<host with . as ->`, `wildcard` for `*`, and `all-hosts` for no host. A route with another name still matches by content; the report notes the naming difference.

| Status | Meaning |
| --- | --- |
| `equivalent` | host, path, path type, backend Service and port agree |
| `different` | a rule matches by host and path but differs (path type, backend, port, redirect instead of forwarding, TLS) |
| `missing-in-gateway` | no HTTPRoute rule has this host and path |
| `extra-in-gateway` | an HTTPRoute rule that no Ingress rule maps to |

Notes on semantics: `Exact` maps to `Exact`; `Prefix` and `ImplementationSpecific` map to `PathPrefix` (the latter is called out); `nginx.ingress.kubernetes.io/use-regex: "true"` expects `RegularExpression`. A named Ingress backend port is not resolved against the Service, so only the Service name is compared and the report says so. `backend.resource` is reported as different. For TLS hosts, when Gateway objects are loaded, the parent Gateway must have an HTTPS or TLS listener covering the host; with no Gateways loaded the report says TLS was not verified. The `spec.defaultBackend` is treated as a `/` prefix rule for all hosts.

## Live comparison

Give both a base URL for the Ingress controller and one for the Gateway data plane:

    setura migrate check --ingress ingress.yaml --routes routes.yaml \
      --ingress-url http://10.0.0.10 --gateway-url http://10.0.0.20

For every Ingress rule Setura sends `GET` to the rule's host and path (wildcard hosts use a stand-in label) at each target, with the right Host header and TLS name, using the same probe code as `setura explain`. Differences in HTTP status, redirect target (`Location`), `X-Setura-Backend` and selected headers turn the rule into `different`. Paths that look like regular expressions are skipped. Probing has no side effects beyond one GET per rule per target.

| Flag | Meaning |
| --- | --- |
| `--ingress-url URL`, `--gateway-url URL` | base URLs; both are required together |
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

`--format auto|pretty|json|github`. Auto prints the table on a terminal and JSON when piped. `github` emits workflow annotations (`::error` for different and missing rules, `::warning` for extra rules and flagged annotations).

JSON shape: `{"ok", "summary", "rules": [{"status", "ingress", "route", "expected_route", "host", "path", "path_type", "backend", "tls", "details", "probe"}], "annotations", "notes"}`.

| Code | Meaning |
| --- | --- |
| 0 | everything equivalent and no annotation needs attention |
| 1 | differences, missing or extra rules, flagged annotations, or a live difference |
| 2 | usage or setup error (bad flags, unreadable files, kubectl failure, no Ingress objects) |

## Example

    setura migrate check --ingress examples/migrate/ingress.yaml --routes examples/migrate/routes.yaml

The files in `examples/migrate/` contain one equivalent rule, one with a wrong port, one missing rule, one extra route, and three annotations of different classes.
