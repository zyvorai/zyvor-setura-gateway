# `setura gateway install` options

`setura gateway install` prints plain YAML for the in-cluster controller and never
applies it. Every option below changes the printed YAML only, so nothing has to be
patched with `kubectl patch` afterwards. The output is deterministic: the same flags
print the same text (the admin Secret holds a random token unless you opt out with `--no-admin-secret` or `--admin-token-secret`).

    setura gateway install \
      --service-type NodePort --node-port HTTP=30080,HTTPS=30443,7443=30743 \
      --listener-port 7443 --listener-port 18443 \
      --external-traffic-policy Local --replicas 2 \
      --arg --rate-limit=100 --arg --rate-key=ip \
      --resources requests.cpu=100m,requests.memory=64Mi,limits.memory=256Mi \
      --node-selector node-role.kubernetes.io/edge=true | kubectl apply -f -

## Service

| Flag | Effect |
| --- | --- |
| `--service-type ClusterIP\|NodePort\|LoadBalancer` | `spec.type` of the `setura-gateway` Service (default `ClusterIP`). |
| `--node-port HTTP=30080,HTTPS=30443` | Sets `nodePort` on Service ports. Keys are the port names `http` and `https` (any case), or a Service port number such as `7443=30743`. Repeatable. Needs `NodePort` or `LoadBalancer`. Two ports may not share a node port. |
| `--listener-port N` | Adds a Service port named `listener-N` for a Gateway listener port, and a matching container port. Repeatable. A port below 1024 maps to `N+8000` (the controller runs with `--port-offset=8000`), any other port maps to itself. 80, 443 and 19000 are already used. |
| `--expose-gateway-ports` | Existing option: the controller adds `gw-N` Service ports itself for every listener port it sees (needs the `services` patch RBAC, which this flag adds). It leaves `listener-N` ports alone. Use `--listener-port` when you want the ports to exist before any Gateway does, or want `--node-port` on them. |
| `--envoy-compat` | Runs the controller with `--envoy-compat` and adds read and status access to the optional Envoy Gateway CRDs (`gateway.envoyproxy.io`: backendtrafficpolicies, clienttrafficpolicies, securitypolicies, httproutefilters, backends) and to nothing else of that group. See [envoy-compat.md](envoy-compat.md). |
| `--external-traffic-policy Local\|Cluster` | `spec.externalTrafficPolicy`; `Local` keeps client addresses. Needs `NodePort` or `LoadBalancer`. |

`--node-port` is checked against the ports the Service will have: naming `7443` without
`--listener-port 7443` is an error rather than a silent no-op. The usual node port range
of a cluster is 30000-32767; Setura only checks 1-65535 because the range is configurable.

## Deployment

| Flag | Effect |
| --- | --- |
| `--replicas N` | Controller replicas (default 1). With `--leader-elect` (always set) one replica writes status and all serve traffic. |
| `--host-network` | `hostNetwork: true` with `dnsPolicy: ClusterFirstWithHostNet`, and a rolling update with `maxSurge: 0` so a new pod never competes for the node ports. The controller binds node ports 8080, 8443 and the listener ports (it runs as non-root, so it cannot bind 80 and 443; put a redirect or load balancer in front). Only one controller pod fits per node. |
| `--arg FLAG` | Appends one flag to the controller container args, for example `--arg --rate-limit=100 --arg --rate-key=ip`. Repeatable; every value must start with `-`. Flags that need a value use `=`. Values that YAML could misread are quoted. See `setura gateway -h` for the flags `gateway run` accepts. |
| `--resources` | `requests.cpu`, `requests.memory`, `limits.cpu`, `limits.memory`, any subset, comma separated, for example `requests.cpu=100m,limits.memory=256Mi`. Values must be Kubernetes quantities. Nothing is printed without this flag. |
| `--node-selector KEY=VALUE[,KEY=VALUE]` | `nodeSelector` of the pod. Repeatable. |
| `--namespace`, `--image`, `--class`, `--with-monitoring` | As before. |

## The admin token

The controller reads its admin token from the Secret `setura-gateway-admin`, key `token`.
`setura gateway install | kubectl apply -f -` prints that Secret with a new random token, so the
pod starts at once, but re-applying the output rotates the token. To keep it stable:

* `--no-admin-secret` prints no Secret. The header of the output shows the one-line command
  that creates it, and `setura` reminds you on stderr. Re-applying never touches the token.
* `--admin-token-secret NAME` makes the Deployment read an existing Secret (key `token`)
  instead; again nothing is printed for it. Use this to bring your own, or to share one.
* `--create-admin-secret` prints the Secret even together with `--admin-token-secret`.

First install, step by step:

    setura gateway install --crds | kubectl apply -f -     # see Gateway API CRDs below
    kubectl -n setura-system create secret generic setura-gateway-admin \
      --from-literal=token="$(openssl rand -hex 24)"

The pod starts as soon as the Secret exists (kubelet retries on its own). The Helm chart
keeps its existing behaviour: it looks the Secret up and only generates a token when none exists.

## Gateway API CRDs

The controller needs the Gateway API CRDs. They are large and versioned by the Gateway API
project, so Setura does not embed them. Instead:

* `--crds` adds the exact command to the header of the output:
  `kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml`
* `--gateway-api-version vX.Y.Z` picks another release (default `v1.7.0`, the release
  Setura documents and runs conformance against).
* `--gateway-api-channel experimental` points at the experimental channel, which TCPRoute
  and UDPRoute need.
* `setura gateway install --check` (and `setura doctor gateway --kube`) reads the CRDs
  installed in the cluster through `kubectl` and reports what is missing or too old.
  It exits 1 when a CRD is missing or a Setura feature is unavailable. The global
  `--context` flag selects the cluster.

Which feature needs which CRD (the live check reads the CRD schema, so it is exact for the
cluster; the release numbers explain what to upgrade to):

| Setura feature | CRD | Needs |
| --- | --- | --- |
| Gateway, GatewayClass, HTTPRoute | `gateways`, `gatewayclasses`, `httproutes` | Gateway API v1.1.0 or newer (required) |
| GRPCRoute, cross-namespace references | `grpcroutes`, `referencegrants` | v1.1.0 or newer |
| HTTPRoute `CORS` filter | `httproutes` field `cors` | v1.5.0 or newer, standard channel |
| HTTPRoute `ExternalAuth` filter | `httproutes` field `externalAuth` | v1.7.0 or newer, standard channel |
| BackendTLSPolicy | `backendtlspolicies` | v1.4.0 or newer |
| ListenerSet, TLSRoute | `listenersets`, `tlsroutes` | v1.5.0 or newer |
| TCPRoute, UDPRoute | `tcproutes`, `udproutes` | experimental channel only |

The ExternalAuth row was confirmed on a cluster: standard CRDs v1.6.3 reject the field
(`unknown field "externalAuth"`) and `install --check` reports it with the upgrade command.
The other release numbers come from the Gateway API release notes; if they differ on your
cluster, trust the schema check, and tell us.

Upgrading CRDs: `kubectl apply --server-side -f URL` replaces the CRD schemas in place and
keeps existing Gateways and routes. Read the Gateway API release notes first.
