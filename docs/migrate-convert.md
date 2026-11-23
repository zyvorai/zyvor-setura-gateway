# setura migrate convert

Turn what you run today into Gateway API YAML that the built-in gateway and [`setura migrate check`](migrate.md) understand.

    setura migrate convert [--from SOURCE] [PATH...] [flags]

| `--from` | Input | Output |
| --- | --- | --- |
| `ingress-nginx` (default) | `networking.k8s.io/v1` Ingress objects and their `nginx.ingress.kubernetes.io/*` annotations | Gateway, HTTPRoute, GRPCRoute, TLSRoute, BackendTLSPolicy, ReferenceGrant |
| `envoy-gateway` | HTTPRoutes, GRPCRoutes, Gateways plus SecurityPolicy, BackendTrafficPolicy, ClientTrafficPolicy and HTTPRouteFilter | the same routes with the policies folded into rule fields, filters and Setura auth blocks |
| `traefik` | IngressRoute, IngressRouteTCP and Middleware (`traefik.io` and `traefik.containo.us`) | Gateway, HTTPRoute, TLSRoute, BackendTLSPolicy, ReferenceGrant |
| `nginx-conf` | a `nginx.conf` (or a directory of `*.conf`) in the documented subset | Gateway, HTTPRoute, BackendTLSPolicy, ReferenceGrant |

Nothing is dropped silently. A setting with no equivalent becomes a `# TODO(setura)` comment above the generated object, with the exact annotation (or field) and a plain-language reason, and an entry in the summary and in the report. The exit code stays at 1 until none are left.

## Inputs

`PATH` is a YAML or JSON file or directory (multi-document streams and `List` kinds are fine). Without a path the objects are read from the cluster through the same `kubectl` helper as the other commands (`-n NS`, `-A`); the command only reads. Services found in the inputs resolve named backend ports; ConfigMaps found in the inputs resolve `proxy-set-headers` and `custom-headers`.

| Flag | Meaning |
| --- | --- |
| `--from SOURCE` | `ingress-nginx`, `envoy-gateway`, `traefik` or `nginx-conf` |
| `-n`, `--namespace NS`, `-A` | namespace for cluster reads, and for objects that carry none (nginx.conf) |
| `--ingress-class NAME` | only convert Ingresses of this class |
| `--gateway-class NAME` | `gatewayClassName` of the generated Gateways (default `setura`; `envoy-gateway` keeps the input's unless given) |
| `--out DIR` | write one file per resource (`gateway-nginx.yaml`, `httproute-shop-shop-example-test.yaml`, in a subdirectory per namespace when there are several); the summary goes to stdout |
| `--force` | overwrite existing files of `--out` and `--report`. Without it the command refuses, naming the files, and exits 2 |
| `--report FILE` | machine-readable report (JSON) |
| `--format pretty\|json\|yaml` | `pretty` (default): YAML on stdout and the summary on stderr, or the summary on stdout with `--out`; `json`: the report including the generated `manifests`; `yaml`: manifests only |
| `--no-check` | skip the equivalence check |
| `--compat-report` | with `--from envoy-gateway`: print every Envoy Gateway policy field with Supported, Partial or Unsupported and its Setura equivalent (`--format pretty`, `json` or `markdown`); converts nothing |

## Naming

Like ingress2gateway: the Gateway is named after the Ingress class (`nginx` without one) in the Ingress namespace; a route is `<ingress>-<host with . as ->` (`wildcard` for `*`, `all-hosts` for no host); listeners are `<host>-http` and `<host>-https` (`<host>-tls` for passthrough). A name that is already taken in its namespace and kind gets `-2`, `-3`, and a note says so. The policy objects are `<service>-backend-tls`, and cross-namespace backends get a `ReferenceGrant` named `allow-<namespace>-<kind>s` in the target namespace.

## ingress-nginx

| Annotation | Becomes |
| --- | --- |
| `rewrite-target` (no `$` capture) | `URLRewrite`: `ReplacePrefixMatch` on prefix paths, `ReplaceFullPath` on `Exact`. With capture groups: TODO |
| `ssl-redirect`, `force-ssl-redirect` | a second HTTPRoute on the `-http` listener with `RequestRedirect` scheme `https`; the main route attaches to the `-https` listener. Like ingress-nginx this is on by default for hosts under `spec.tls` unless `ssl-redirect: "false"`. Gateway API allows 301 and 302 only, so nginx's 308 becomes 301 |
| `permanent-redirect`, `temporal-redirect` (+ `-code`), `app-root` | `RequestRedirect` on the rule, or an extra `Exact /` rule |
| `upstream-vhost`, `x-forwarded-prefix` | `URLRewrite` hostname, `RequestHeaderModifier` |
| `proxy-set-headers`, `custom-headers` | header modifier filters, when the named ConfigMap is in the inputs |
| `mirror-target` | `RequestMirror` (a Service URL of the cluster) |
| `proxy-read-timeout`, `proxy-send-timeout` | rule `timeouts.backendRequest`, the larger of the two |
| `enable-cors`, `cors-*` | the Gateway API 1.5 `CORS` filter ([gateway-api-1-5.md](gateway-api-1-5.md)); nginx's defaults fill what the annotations leave out. Regex origins: TODO |
| `canary`, `canary-weight(-total)` | weighted `backendRefs` on the rule of the main Ingress for the same host and path |
| `canary-by-header(-value/-pattern)` | an extra rule before it with a header match (`Exact`, or `RegularExpression` for a pattern; `always` when no value is set). `canary-by-cookie`: TODO |
| `whitelist-source-range`, `allowlist-source-range`, `denylist-source-range` | the `ipAllow` / `ipDeny` of the Setura auth block, as the route annotation `setura.zyvor.dev/auth.rule-N` ([security.md](security.md)) |
| `auth-type: basic` | a `basic` auth block without users (TODO: Setura stores pbkdf2 hashes, htpasswd has bcrypt or apr1; add users with `setura gateway hash --kind password`) |
| `auth-url`, `auth-response-headers` | an `ExternalAuth` filter to the Service in the URL. `auth-signin` and the other `auth-*` knobs: TODO |
| `affinity: cookie`, `session-cookie-name`, `-max-age` | `sessionPersistence` (type `Cookie`); cookie path, SameSite and the rest: TODO |
| `backend-protocol: HTTPS`, `GRPCS` | `BackendTLSPolicy` for the Service, with a placeholder CA reference and a TODO (BackendTLSPolicy always verifies, ingress-nginx does not by default) |
| `backend-protocol: GRPC` | a GRPCRoute; paths must be `/pkg.Service` or `/pkg.Service/Method` |
| `ssl-passthrough` | a TLSRoute on a `TLS` listener with `mode: Passthrough`; HTTP-level annotations on such an Ingress are TODO |
| `use-regex` | `RegularExpression` path (or method) matches |
| `server-alias` | extra route hostnames and listeners |

Everything else in the [annotation table](migrate.md#annotations) is a TODO with a reason: `proxy-body-size` (no per-route limit in Gateway API or the gateway), `limit-rps`/`-rpm`/`-connections` (the gateway's rate limit is global: `--rate-limit`), `proxy-connect-timeout`, snippets, ModSecurity, client certificate annotations, unknown annotations. A `backend.resource` backend and a named port that no Service resolves are TODOs too.

## envoy-gateway

The routes and Gateways are copied; each policy is applied to the rules it targets (a `targetRef` to a Gateway means every route attached to it, a `sectionName` that names a rule narrows it).

| Policy | Converted | TODO |
| --- | --- | --- |
| BackendTrafficPolicy | `timeout.http.requestTimeout` to `timeouts.request`; `retry` to the rule `retry` (attempts, status codes, backoff, per-try timeout); `rateLimit` (Local, and Global when the policy has the `setura.zyvor.dev/compat-redis` annotation) to the `setura.zyvor.dev/rate-limit` annotation; `faultInjection` to the `setura.zyvor.dev/fault` annotation (ttl 24h); `mirrors` to a `RequestMirror` filter; `loadBalancer` to the `setura.zyvor.dev/load-balancer` annotation (HTTPRoute rules); `compression` (Gzip) to `setura.zyvor.dev/compress`; `requestBuffer.limit` to `setura.zyvor.dev/limits` | other timeouts and retry triggers, brotli and zstd, `loadBalancer` on a GRPCRoute; `circuitBreaker`, `healthCheck` and `proxyProtocol` are backend settings with no manifest field (a TODO naming the Setura setting the controller applies) |
| SecurityPolicy | `cors` to the `CORS` filter; `jwt` (first provider) to the auth `jwt` block; `authorization` on `clientCIDRs` to `ipAllow` / `ipDeny`, with JWT claims, scopes, headers or methods to the auth `authorization` rules; `oidc` to the auth `oidc` block (with the `setura.zyvor.dev/compat-oidc-cookie-key` annotation); `extAuth` to `ExternalAuth` | further JWT providers, `apiKeyAuth` (the Secret is not read: a TODO), `basicAuth` (not enforced, a TODO), `oidc` without the cookie key annotation |
| ClientTrafficPolicy | `tls.minVersion`, `tls.maxVersion`, `tls.ciphers` and `tls.session` to the Gateway listener `tls.options`; `tls.clientValidation` to the Gateway `spec.tls.frontend`, its `subjectAltNames` to the Gateway annotation `setura.zyvor.dev/client-allow`; `connection.connectionLimit` is a TODO (a listener limits block of a snapshot, or `--max-connections`) | every other field, with the matching gateway flag where there is one (`--trusted-proxies` for `clientIPDetection`) |
| HTTPRouteFilter | `directResponse` on a rule that references it becomes the `setura.zyvor.dev/direct-response` annotation; `credentialInjection` becomes the rule's auth `inject` | `urlRewrite` with a regular expression: the `ExtensionRef` stays, so Setura refuses the route instead of serving it unrewritten |

The conversion and the controller (`setura gateway run --kubernetes --envoy-compat`, which reads the same policies from the cluster at run time) use one translation. `--compat-report` lists every Envoy Gateway field with Supported, Partial or Unsupported and its Setura equivalent; the table is [envoy-gateway-compat.md](envoy-gateway-compat.md), and [envoy-compat.md](envoy-compat.md) says how to switch.

## traefik

An IngressRoute rule is one route per host. Supported match terms joined with `&&`: `Host`, `PathPrefix`, `Path`, `PathRegexp`, `Headers`, `HeadersRegexp`, `Method`; `||`, `!`, `HostRegexp` and other matchers make that rule a TODO. The entry point `web` means HTTP on 80 and `websecure` HTTPS on 443 (the route attaches to that listener only); other names are a TODO. `tls.secretName` becomes the listener certificate; `certResolver` is a TODO. An IngressRouteTCP with `tls.passthrough` becomes a TLSRoute.

Middlewares: `stripPrefix` (when it strips the rule's own prefix), `replacePath`, `redirectScheme`, `headers` (custom request and response headers, the CORS fields, and the plain security headers `stsSeconds`, `frameDeny`, `contentTypeNosniff`, `browserXssFilter`, `referrerPolicy`, `contentSecurityPolicy`, `permissionsPolicy`), `ipAllowList`/`ipWhiteList`, `retry`, `forwardAuth` (a Service address), and `chain` (expanded). `rateLimit`, `basicAuth` users and all other middleware fields are TODOs; a `services[].scheme: https` adds a BackendTLSPolicy.

## nginx-conf

The documented subset:

    http { upstream NAME { server HOST:PORT [weight=N]; }
           server { listen 80 | 443 [ssl]; server_name HOST...;
                    ssl_certificate / ssl_certificate_key   (TODO: create the Secret)
                    location [= | ^~ | ~] URI {
                        proxy_pass http[s]://TARGET[/URI];
                        proxy_set_header NAME LITERAL;  add_header NAME LITERAL;
                        proxy_read_timeout / proxy_send_timeout DURATION;
                        allow ADDR; ... deny all;  (or deny ADDR; only)
                        return 301|302 URL; } } }

`TARGET` is a Service (`name`, `name:port`, `name.namespace.svc[.cluster.local]:port`) or an upstream of those, with weights. `proxy_pass` with a URI replaces the matched prefix when both end in `/`. `proxy_set_header Host $host` and the usual forwarding headers are recognised as defaults; other variables are refused. Directives that parse but have no equivalent (`client_max_body_size`, `ssl_protocols`, `gzip`, `proxy_connect_timeout`) are TODOs.

Everything else is refused: the command prints `FILE:LINE: reason` for every unsupported construct (`if`, `rewrite`, `try_files`, `root`, regex `server_name`, `limit_req`, listen ports other than 80 and 443, `~*` locations, `include`, IP or external hosts as `proxy_pass` targets, ...) and exits 2 without writing anything.

## Equivalence check

After converting, the generated YAML is read back and compared with the original the way `setura migrate check` does, offline: host, path and path type, backend and port, TLS listener and certificate, ReferenceGrants. Settings that became filters or policies count as handled; redirect routes and alias routes the converter added are not reported as extra. For Traefik and nginx.conf the comparison runs against an Ingress synthesised from the input; for Envoy Gateway it checks that every route rule survived unchanged (the policies are verified by the TODO list, not by a data plane). `--no-check` skips it. To verify the converted routes against a running Ingress controller, use `migrate check` with `--ingress-url`/`--gateway-url`.

## Output and exit codes

| Code | Meaning |
| --- | --- |
| 0 | everything converted and the check found the routes equivalent |
| 1 | `TODO(setura)` items remain, or the check found differences |
| 2 | usage or input error: bad flags, unreadable input, no objects, refusing to overwrite without `--force`, unsupported nginx.conf constructs |

The report (`--report FILE`, or `--format json`):

    {"source", "verdict": "equivalent|needs-review", "ok",
     "summary": {"converted", "todo", "ignored", "resources"},
     "resources": [{"kind", "namespace", "name", "file", "todos"}],
     "items": [{"source", "key", "value", "status": "converted|todo|ignored", "target", "reason"}],
     "check": {"ok", "skipped", "summary", "rules", "notes"}, "notes", "manifests"}

## Worked example

`examples/migrate/convert-shop.yaml` is an ingress-nginx setup with TLS, a rewrite, a longer read timeout, CORS, an IP allow list, cookie affinity, a canary Ingress taking 10 percent of `/api`, and two annotations nothing replaces.

    setura migrate convert examples/migrate/convert-shop.yaml --out gateway/

    setura migrate convert  ingress-nginx → Gateway API

      Converted
        ✓  Ingress demo/shop         rewrite-target                                   URLRewrite ReplacePrefixMatch
        ✓  Ingress demo/shop         proxy-read-timeout                               timeouts.backendRequest
        ✓  Ingress demo/shop         enable-cors                                      CORS filter
        ✓  Ingress demo/shop         cors-allow-origin                                CORS filter
        ✓  Ingress demo/shop         whitelist-source-range                           setura.zyvor.dev/auth ipAllow
        ✓  Ingress demo/shop         affinity                                         sessionPersistence type Cookie
        ✓  Ingress demo/shop         ssl-redirect (default for hosts under spec.tls)  RequestRedirect scheme https (301) ...
        ✓  Ingress demo/shop-canary  canary                                           folded into the rule of the non-canary Ingress
        ✓  Ingress demo/shop-canary  canary-weight                                    weighted backendRefs (90 to 10)

      Needs a human
        ▲  Ingress demo/shop         configuration-snippet                            arbitrary nginx configuration has no Gateway API ...
        ▲  Ingress demo/shop         proxy-body-size                                  Gateway API has no request body limit and the Se...

      Generated
        Gateway    demo/nginx                            gateway-nginx.yaml
        HTTPRoute  demo/shop-shop-example-test           httproute-shop-shop-example-test.yaml  2 TODO
        HTTPRoute  demo/shop-shop-example-test-redirect  httproute-shop-shop-example-test-redirect.yaml

      Check  ✓ 3 rules equivalent to the original

      needs review  9 converted, 2 need a human, 3 resources
      Next: resolve the TODO(setura) comments (grep -rn 'TODO(setura)' gateway/), then setura migrate check --routes gateway/

The main route carries the TODOs and the translated settings:

    # TODO(setura) nginx.ingress.kubernetes.io/configuration-snippet: more_set_headers "X-Frame-Options: DENY"; -- arbitrary nginx configuration has no Gateway API equivalent; ...
    # TODO(setura) nginx.ingress.kubernetes.io/proxy-body-size: 8m -- Gateway API has no request body limit and the Setura gateway has none per route; ...
    apiVersion: gateway.networking.k8s.io/v1
    kind: HTTPRoute
    metadata:
      name: shop-shop-example-test
      namespace: demo
      annotations:
        setura.zyvor.dev/auth.rule-1: "{\"ipAllow\":[\"10.0.0.0/8\",\"192.168.0.0/16\"]}"
        setura.zyvor.dev/auth.rule-2: "{\"ipAllow\":[\"10.0.0.0/8\",\"192.168.0.0/16\"]}"
    spec:
      hostnames:
        - shop.example.test
      parentRefs:
        - name: nginx
          sectionName: shop-example-test-https
      rules:
        - backendRefs:
            - {name: api, port: 8080, weight: 90}
            - {name: api-v2, port: 8080, weight: 10}
          filters: [URLRewrite ReplacePrefixMatch /, CORS ...]
          matches:
            - path: {type: PathPrefix, value: /api}
          sessionPersistence: {sessionName: INGRESSCOOKIE, type: Cookie}
          timeouts: {backendRequest: 120s}
        ...

(The listing is shortened; the files hold the full objects.) Decide what to do about the two TODOs, delete the comments, then:

    kubectl apply --dry-run=server -f gateway/

and, once both data planes run, compare live responses with `setura migrate check --ingress-url ... --gateway-url ...`. A plain `migrate check` of the output against the original Ingress still lists annotations that became policies (`whitelist-source-range`, `canary-weight`) and the generated redirect route, because its annotation table only recognises route filters; the check inside `convert` accounts for them and reports them as converted.

## Not handled

- The generated listeners use ports 80 and 443; other ports need their own listeners.
- Redirects use 301 (Gateway API allows 301 and 302), where nginx uses 308.
- Regex rewrites with capture groups, snippets and ModSecurity have no equivalent and stay TODOs.
- Basic auth users are never converted (the hash formats differ); BackendTLSPolicy needs a CA you provide.
- The check compares routing, not behaviour; filters and policies are covered by the report, not by probing.
