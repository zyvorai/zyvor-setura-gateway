# Cluster troubleshooting

Three commands answer "why does my Gateway or route not work" without `kubectl describe`.

## `setura gateway status`

    setura gateway status              # every namespace
    setura gateway status -n shop      # one namespace
    setura gateway status --format json
    setura --context prod gateway status

Lists the Gateways of the Setura controller (GatewayClasses with controllerName
`zyvor.dev/setura-gateway`) and the HTTPRoutes, GRPCRoutes and TLSRoutes attached to
them, with `Accepted`, `Programmed` and `ResolvedRefs` and the controller's reason and
message for everything that is not healthy. `--all-controllers` also shows objects that
belong to other controllers. It reads with `kubectl`, changes nothing, and exits 1 when
anything needs attention.

    Gateways
      ✓ infra/edge                           class setura
      ✗ team-b/edge                          class setura
          → Gateway: Programmed=False (ListenersNotValid): one or more listeners are not programmed: ...
          → listener web (8080/HTTP): Conflicted (HostnameConflict): listener "web" of Gateway infra/edge already serves ...
    Routes
      ✗ team-b/shop (HTTPRoute)              -> team-b/edge
          → parent team-b/edge: Accepted=False (NotAllowedByListeners): listener does not allow this route: ...

`setura doctor gateway --kube` runs the same check as part of the doctor checklist, next
to the CRD check below (`--namespace NS` limits it).

## `setura gateway install --check`

Reads the Gateway API CRDs and says which Setura features the installed release cannot
provide, with the exact `kubectl apply --server-side -f ...` to fix it. See
[install-options.md](install-options.md). Typical output for the error
`unknown field "externalAuth"`:

    ▲ HTTPRoute ExternalAuth filter   the installed CRDs (bundle v1.6.3, standard channel) have no
                                      spec.rules.filters.externalAuth field, so the API server rejects such
                                      routes with "unknown field"; it needs Gateway API v1.7.0 or newer
      → kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml

## Two Gateways on the same port and hostname

Gateways in different namespaces that declare the same port, protocol and hostname cannot
both serve it. The Gateways are ordered by `namespace/name`; the first one keeps the
listener and every later one gets:

* on the listener, `Conflicted=True` with reason `HostnameConflict` and a message that
  names the winner: `listener "web" of Gateway infra/edge already serves port 8080,
  protocol HTTP and hostname "x.test" ...`;
* on the Gateway, `Programmed=False` with reason `ListenersNotValid` and the message
  `one or more listeners are not programmed: listener "web": HostnameConflict: ...`
  (earlier versions only said "one or more listeners are not programmed");
* on each route that attached to the losing listener, `Accepted=False` with reason
  `NotAllowedByListeners` and the same explanation: `listener does not allow this
  route: listener team-b/edge/web is not serving: HostnameConflict: ...`.

A port shared by different protocols is reported the same way with `ProtocolConflict`.

Fix it by giving the later Gateway another port or hostname, by adding the second
listener to the first Gateway, or by deleting the duplicate. `setura gateway status`
shows all of this in one screen; `setura why` and `setura explain` give the same text
for a single request.

## Other common causes

| Symptom | Check |
| --- | --- |
| Pod in `CreateContainerConfigError` | The admin token Secret does not exist yet: see "The admin token" in [install-options.md](install-options.md). |
| `no matches for kind "Gateway"` or `unknown field` on apply | `setura gateway install --check`. |
| A listener port answers nothing from outside | The Service has no port for it: install with `--listener-port N` or `--expose-gateway-ports`, and `--node-port` for NodePort. |
| Client addresses are all node or pod addresses | `--external-traffic-policy Local`. |
| Gateway has no status at all | The controller is not running or not leader: `kubectl -n setura-system logs deploy/setura-gateway`. |
