# HTTP/3

**The built-in gateway does not serve HTTP/3.** This page says why, what may change, and what to
do today.

## Why it is deferred

HTTP/3 runs over QUIC (RFC 9000) on UDP. The Go standard library has no QUIC implementation that
`net/http` can serve: `net/http` speaks HTTP/1.1 and HTTP/2 over TCP only, and `crypto/tls`
exposes a QUIC-specific API (`tls.QUICConn`, since Go 1.21) that is meant for a QUIC
implementation to build on, not a server by itself. The QUIC transport (packet protection,
loss recovery, congestion control, streams, connection migration, 0-RTT anti-replay), HTTP/3
framing and QPACK would all have to be written and then kept correct against a moving ecosystem.

Setura's constraint is a static binary with no dependencies beyond the standard library. Writing a
QUIC stack to satisfy it would be a large, security-critical project of its own, and a half-finished
one is worse than none: it would sit on the public edge parsing hostile UDP. So it is deliberately
not attempted.

## What could change this

* A QUIC server in the standard library, or HTTP/3 support in `net/http`. As far as this
  project can tell, neither exists today. A QUIC implementation lives in `golang.org/x/net/quic`,
  but it is outside the standard library, was developed as an experiment, and has no HTTP/3
  server on top; this repository could not check its current state offline, so treat that as
  unverified. When a Go release ships HTTP/3 in `net/http` (or an equivalent in the standard
  library), HTTP/3 can become an option on HTTPS listeners with the same routing table, since
  request handling is already independent of the wire protocol. That is the trigger to
  re-evaluate; nothing here promises a date.
* Until then this page is the whole story: the gateway's UDP support is for UDPRoute datagram
  proxying and has nothing to do with QUIC.

## What to do today

Put an HTTP/3-capable edge in front and let it speak HTTP/3 to clients and HTTP/1.1 or HTTP/2 to
the gateway: a CDN, a cloud load balancer with HTTP/3 enabled, or a reverse proxy such as Caddy,
nginx (with QUIC), HAProxy or Envoy. The gateway then sees ordinary requests. To keep client
addresses correct, send PROXY protocol from the edge when it supports it
(`--proxy-protocol`) or X-Forwarded-For (`--trusted-proxies`); see [certificates](certificates.md).

Clients learn that HTTP/3 exists from an `Alt-Svc` response header (RFC 7838). If the edge does not
add it, the gateway can:

```
setura gateway run --config gw.json --alt-svc 'h3=":443"; ma=86400'
```

`--alt-svc` sets the header on responses of HTTPS listeners only (clients ignore Alt-Svc received
over plain HTTP). **It advertises, it does not implement.** Setting it when nothing answers QUIC on
that port makes browsers try, fail and fall back to TCP after a delay; use it only when the
advertised endpoint is real. Use `--alt-svc clear` to tell clients to forget earlier
advertisements. A backend's own `Alt-Svc` header is not removed.
