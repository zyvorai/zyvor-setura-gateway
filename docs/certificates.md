# Certificates and edge protocols

How the built-in gateway gets, reloads and presents certificates, and how it talks PROXY
protocol and HTTP/2 to upstreams. Everything here is the Go standard library: no ACME
library, no Envoy.

## ACME (RFC 8555)

```
setura gateway run --config gw.json --acme-dir /var/lib/setura/acme --acme-email ops@example.com
```

An HTTPS listener with a `hostname` and **no `certificateRefs`** gets its certificate from an
ACME CA. A listener that has `certificateRefs` is untouched, so Secrets and ACME mix freely.
One certificate is ordered per listener hostname.

| Flag | Meaning |
| --- | --- |
| `--acme-dir DIR` | Enables ACME and stores the account key, account URL and certificates in `DIR` (directories 0700, files 0600, written atomically). |
| `--acme-directory URL` | Directory URL. **Default is Let's Encrypt staging**, whose certificates are not trusted by browsers, so a mistake cannot burn production rate limits. Plain `http://` is accepted only for loopback (tests). |
| `--acme-production` | Use the Let's Encrypt production directory. Explicit on purpose; cannot be combined with `--acme-directory`. |
| `--acme-email ADDR` | Account contact. |
| `--acme-challenge http-01\|tls-alpn-01` | Preferred challenge. Default: `http-01` when the gateway serves a plain HTTP listener, else `tls-alpn-01`; the other one is tried when the CA does not offer the preferred. |
| `--acme-dns-hook CMD` | Enables wildcards through DNS-01, see below. |

All `--acme-*` flags other than `--acme-dir` are refused without `--acme-dir`.

### Challenges

* **HTTP-01.** The gateway answers `/.well-known/acme-challenge/TOKEN` on every plain HTTP
  listener before routing, for tokens it currently holds. The CA connects to port 80 of the
  hostname, so the Gateway needs an HTTP listener that is reachable there (map it with
  `--port-offset` or `--port-map`; the CA must still reach it on 80, for example through a
  Service or load balancer).
* **TLS-ALPN-01.** HTTPS listeners offer the `acme-tls/1` protocol; a handshake that asks for
  it gets the validation certificate for the pending challenge (RFC 8737), nothing otherwise.
  Needs only port 443. Not available on TLS terminate listeners of TLSRoutes.
* **DNS-01 (wildcards only).** `--acme-dns-hook CMD` is run as
  `CMD present DOMAIN VALUE` before the CA validates and `CMD cleanup DOMAIN VALUE` after.
  `DOMAIN` is the name without `*.`; `VALUE` is the TXT value to publish at
  `_acme-challenge.DOMAIN`. The command is executed directly (no shell) and must return only once
  the record is visible. Without a hook a wildcard hostname cannot be issued: the listener is
  not served and its `ResolvedRefs` condition says
  `ACME cannot issue the wildcard *.example.com without the DNS-01 challenge: set --acme-dns-hook CMD or provide a Secret`.

### Lifecycle

* **Renewal** is scheduled at two thirds of each certificate's lifetime, minus a random jitter
  of up to one 24th of the lifetime (about 3.75 days for 90-day certificates), so a fleet does
  not renew in lockstep. Stored certificates are loaded at start; nothing is ordered while they
  are valid and not yet due.
* **Backoff.** A failed order is retried after 1 minute, doubling to 6 hours, with jitter. A
  `rateLimited` answer (or HTTP 429) waits at least its `Retry-After`, or an hour without one.
  While an order fails the previous certificate keeps being served.
* **Nonces.** Every request is signed (ES256) with a fresh `Replay-Nonce`; nonces come from the
  previous response, `badNonce` answers are retried with the nonce they carry, and an
  `accountDoesNotExist` answer re-registers the account.
* **Hot swap.** A new certificate is published by atomically replacing an entry the TLS
  handshake reads. New handshakes see it immediately, established connections are not touched,
  and no listener is rebound. OCSP stapling (`--ocsp-staple`) tracks ACME certificates as well.
* **Status.** The admin endpoint `/acme` lists every managed domain with its expiry, renewal
  time, failure count and last error.

Limits: one certificate per hostname (no SAN bundling), no external account binding, no ARI.
The tests use an in-process fake ACME server only; this code has not been run against a real CA
in this repository, so start with the default staging directory and check `/acme`.

## Reloading certificates

| Source | How a change is noticed |
| --- | --- |
| File mode, `secrets` certificate and key files | The file source remembers the size and modification time of the config file and of every certificate, key and CA file it read. A poll (`--interval`, default 1 s) is answered from memory while all of them are unchanged, so a quiet system reads nothing. Timestamps younger than 2 s at read time are not trusted (git's "racy" rule), so a rewrite inside the filesystem's timestamp granularity is still caught. No inotify. |
| File mode, `caCertificates` files and client CA bundles | Same, and their content now takes part in the configuration hash, so a rotated CA bundle reloads the gateway. |
| Kubernetes, Secrets and ConfigMaps | Every Secret or ConfigMap the last load fetched (listener certificates, client CA bundles, BackendTLSPolicy CAs, backend client certificates) gets a watch selected by `fieldSelector=metadata.name=NAME` in its namespace. A cert-manager renewal produces an event and a reload within a second or two. Watches follow the references: new ones start, dropped ones stop. `--resync` stays as a safety net. `--poll` disables watches. |
| ACME | The manager swaps certificates itself. |

In file mode, a certificate and key that were being served and stop matching within 2 seconds
of being written are treated as a rotation in progress: the previous pair keeps serving and
`/status` reports the reload as waiting. A pair still broken after that is applied, which leaves
its listener without a certificate. Writing both files and renaming them into place is still the
best way to rotate.

A reload builds a new routing table; listener sockets and established connections stay. TLS
certificates are looked up per handshake, so the next handshake after the swap uses the new
certificate. OCSP staples are keyed by certificate, so a reload that keeps a certificate keeps
its staple (the very next handshake has it) and a renewed certificate is fetched right after the
swap.

Kubernetes RBAC: watching needs `list` and `watch` on `secrets` and `configmaps` (the
generated `ClusterRole` has them, in addition to `get`). If you cannot grant cluster-wide list on
Secrets, give the controller a namespaced `Role` per certificate namespace with `resourceNames`;
the watches are name-selected, so that is enough. Without any, the resync is the only refresh.

## PROXY protocol

### Inbound

```
setura gateway run --config gw.json --proxy-protocol 8443=10.0.0.0/8,192.168.1.5 --proxy-protocol 80=10.0.0.0/8
```

`--proxy-protocol PORT=CIDR[,CIDR...]` (repeatable) enables PROXY protocol v1 and v2 on the
listener port `PORT` (a spec port; `--port-map` and `--port-offset` still apply). The sources are
mandatory:

* A connection from a **listed source** must start with a header; one that does not is closed.
* A connection from **any other address** is served as a plain connection. Its header, if it sends
  one, is not honoured (it is just bytes), so a stranger cannot forge a client address.
* v2 `LOCAL` commands (health checks of the load balancer) and v1 `UNKNOWN` keep the transport
  address.

The address in the header becomes the connection's remote address. Everything that looks at the
client therefore follows it: `--trusted-proxies` (the PROXY source is the peer; if it is itself
trusted, its `X-Forwarded-For` chain is believed and extended), rate limits keyed by IP, the access
log, `/connections` and the dashboard history. HTTP, HTTPS (the header precedes the TLS
handshake), TLS passthrough and TCPRoute listeners all work.

### Outbound

A backend option, in a config file:

```json
"backends": { "orders:80": { "endpoints": ["10.0.0.7:9001"], "proxyProtocol": "v2" } }
```

or, in Kubernetes mode, the Service annotation `setura.zyvor.dev/proxy-protocol: v1|v2`.
The header carries the client address the gateway saw (after any inbound header) and is written
first on every upstream connection: HTTP, gRPC, TLS passthrough (before the client's
ClientHello) and TCPRoute. Health checks and mirrored requests carry the "no client" form
(v2 `LOCAL`, v1 `UNKNOWN`).

A header names one client, so connections to such a backend are **not reused**: HTTP requests
use one upstream connection each. Terminate-mode `TLS` listeners forwarding to TCP backends do not
send it.

## HTTP/2 to upstreams

* `protocol: "h2c"` on a backend (or `appProtocol: kubernetes.io/h2c` on the Service port, or the
  annotation `setura.zyvor.dev/protocol: h2c`) speaks HTTP/2 with prior knowledge to plain
  `http://` endpoints, for ordinary HTTPRoutes as well as gRPC. It is refused for `https://`
  endpoints (the route's `ResolvedRefs` says so). It combines with `proxyProtocol`.
* `https://` upstreams need no option: the transport offers `h2` and `http/1.1` through ALPN and
  uses what the upstream picks, so an upstream without HTTP/2 is spoken to in HTTP/1.1. The
  connection record's `upstream_protocol` shows which was used.

## Alt-Svc

`--alt-svc VALUE` sets that `Alt-Svc` header on responses of HTTPS listeners (never on plain HTTP,
where clients ignore it). See [http3](http3.md): the gateway does not serve HTTP/3, the header only
helps when an HTTP/3-capable edge in front of it is also reachable on the advertised port.
