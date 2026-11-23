# Traffic security in the built-in gateway

The built-in gateway can authenticate and restrict traffic per HTTPRoute rule, validate
client certificates on HTTPS listeners, staple OCSP responses, and protect its own admin
endpoint. Everything uses the Go standard library. Everything is off until you configure it,
and a policy that cannot be compiled makes its route invalid (not served), never open.

## Threat model

What the gateway defends against, and what it leaves to you.

| Threat | What happens |
| --- | --- |
| Unauthenticated client calls a protected route | 401 with `WWW-Authenticate`, or 403, and the backend is never called. |
| Client forges an identity header (`X-Setura-Auth-*`, `X-Setura-Client-*`, your claim headers) | The gateway removes them from every request on every route, then sets the values it verified itself. |
| Client forges `X-Forwarded-For` to dodge an address list | `X-Forwarded-For` is believed only from a peer in `--trusted-proxies`. |
| Token forged, replayed after expiry, issued for another service, or signed with the wrong algorithm | Rejected: see JWT below. |
| Algorithm confusion (`none`, or an RSA public key used as an HMAC secret) | `none` and every HS* algorithm are refused; an algorithm must match the type of the key it selects. |
| Slow or hostile JWKS endpoint, or a flood of tokens with random `kid` values | JWKS fetches have a 5 s timeout, a 1 MB limit, no redirects, and run at most once per `jwksMinRefresh`. |
| Secrets in dumps, logs and errors | Redacted, see "Secrets never leak". |
| Admin endpoint exposed on a network | Refused to start off loopback without `--admin-token`. |
| Timing attack on keys, passwords and tokens | Constant-time comparison; unknown users cost the same as known ones. |

Not in scope: a compromised gateway host or backend, a compromised identity provider (it
decides who gets tokens), denial of service by volume (use `--rate-limit`), and anything
past the first hop: the backend still decides what an authenticated caller may do.

## Where a policy goes

A rule carries an `setura.zyvor.dev/auth` block next to `matches` and `backendRefs`, exactly
like the shadow-diff block sits on a `RequestMirror`:

```json
"rules": [{
  "setura.zyvor.dev/auth": {
    "jwt": {"issuer": "https://idp.example", "audience": ["orders-api"],
            "jwksUri": "https://idp.example/.well-known/jwks.json",
            "requiredClaims": {"scope": ["orders:read"]},
            "claimHeaders": {"X-User": "sub", "X-Email": "email"}},
    "ipDeny": ["198.51.100.0/24"]
  },
  "backendRefs": [{"name": "orders", "port": 80}]
}]
```

In Kubernetes mode an HTTPRoute annotation does the same, with the JSON as a string:
`setura.zyvor.dev/auth` for every rule of the route, `setura.zyvor.dev/auth.rule-N`
(N counts from 1) for one rule; the rule-specific annotation wins, and an inline block
on the rule wins over both. `{"enabled": false}` switches a policy off for one rule (the
per-route switch). A snapshot taken from a cluster carries these annotations. GRPCRoutes take the same block and annotations;
rejections are Trailers-Only gRPC statuses (see [headers-and-logs](headers-and-logs.md)).

Checks run in this order and the first failure answers:

1. `ipAllow` / `ipDeny`: 403. The deny list wins; a non-empty allow list admits only its members.
2. `requireClientCert`: 403 unless a client certificate verified against the listener's CA bundle.
3. `csrf`: a state changing request from another origin is 403 (see [authorization.md](authorization.md)).
4. Credentials, when `jwt`, `apiKey`, `basic` or `oidc` is configured: any one valid credential admits.
   No credential or none valid is 401 with one `WWW-Authenticate` challenge per method (or, for a
   browser with `oidc`, a redirect to the identity provider, see [oidc.md](oidc.md)); a valid
   JWT that lacks a required claim is 403.
5. `authorization`: the first matching allow or deny rule decides, otherwise the default action
   (403, see [authorization.md](authorization.md)). `inject` then puts upstream credentials on the
   request that is proxied.

The client address is the TCP peer, or the `X-Forwarded-For` client when the peer is in
`--trusted-proxies` (the same address rate limits and access logs use).

## JWT

Algorithms: RS256, ES256 (P-256) and EdDSA (Ed25519). Keys come from a JWKS, inline (`jwks`)
or from `jwksUri`. RSA keys under 2048 bits and other curves are ignored.

| Field | Meaning |
| --- | --- |
| `issuer` | Exact match of `iss`. |
| `audience` | `aud` (string or array) must contain one of these. Always set it. Lint rule SET016 warns when it is missing. |
| `algorithms` | Restrict the accepted algorithms (default all three). |
| `clockSkew` | Tolerance for `exp` and `nbf`, default `60s`, at most `1h`. |
| `requiredClaims` | `{claim: [values]}`. An empty list means "must exist". Dotted names reach into objects (`realm_access.roles`). A string claim equals a value, an array contains one, a space separated string (`scope`) is split. |
| `claimHeaders` | `{header: claim}` copied to the backend request. Control characters are removed, arrays are comma joined. |
| `stripToken` | Remove `Authorization` from the request sent upstream (default: forwarded). |
| `jwksTtl` | How long fetched keys are trusted, default `10m`. |
| `jwksMinRefresh` | Shortest time between two JWKS fetches, default `30s`. |

Always required: a signature that verifies, an `exp` in the future (plus skew), `nbf` not in
the future (minus skew). Tokens over 16 KB, with a `crit` header, or without `exp` are refused.

Outcomes: a request with no token is `401` with `WWW-Authenticate: Bearer realm="..."` and no
`error` (RFC 6750: nothing was presented, so nothing was invalid). A token that is present but bad
(bad signature, expired, wrong issuer or audience) is `401` with
`WWW-Authenticate: Bearer realm="...", error="invalid_token", error_description="..."` (the
description never contains token content). Header names are case-insensitive; the gateway sends
`WWW-Authenticate` with exactly this spelling on HTTP/1. A valid token that fails `requiredClaims` is
`403` with `error="insufficient_scope"`. A JWKS that cannot be fetched and has nothing cached is
`503`; once keys are cached, a failing refresh keeps the old keys in service (stale on error)
and the failure is retried at most every `jwksMinRefresh`.

JWKS refresh: keys are fetched on first use and when older than `jwksTtl`. A token whose `kid`
is not in the cache triggers one refetch (key rotation), but never more often than
`jwksMinRefresh`, so random `kid` values cannot turn the gateway into a request amplifier. The
cache is shared by every route using the same URL and survives configuration reloads. Redirects
are not followed. Use an `https` URL (lint SET016 flags `http`).

## API keys and basic auth

```json
"apiKey": {"header": "X-API-Key", "query": "api_key",
           "keys": [{"name": "ci", "hash": "sha256$SALT$HEX"}]},
"basic":  {"realm": "files", "users": [{"name": "bob", "hash": "pbkdf2-sha256$600000$SALT$KEY"}]}
```

Create the stored values with `setura gateway hash --kind apikey|password`, which reads the
secret from stdin (never an argument). Stored formats:

* **API key**: `sha256$SALT$HEX`, SHA-256 of a random 16 byte salt followed by the key. This is
  salted SHA-256, not a slow hash, on purpose: API keys are long random strings, so slowing
  the hash buys nothing, and the gateway checks one on every request.
* **Password**: `pbkdf2-sha256$ITER$SALT$KEY`, PBKDF2-HMAC-SHA256 from `crypto/pbkdf2` (default
  600000 iterations, accepted range 1000 to 10000000). bcrypt and scrypt are not in the
  standard library. A recent successful check is cached in memory for 5 minutes as an HMAC
  under a per-process random key (never the password) so clients that send credentials on
  every request do not pay for PBKDF2 each time; wrong passwords always pay full price.

Comparisons are constant time and examine every stored key; an unknown user name does the same
work as a known one. `key` and `password` (clear text) exist for development; lint SET017
warns about them. Without `forward: true` the key header, query parameter or
`Authorization` header is removed from the request sent upstream.

## Headers the gateway owns

Removed from every inbound request, then set only from what the gateway verified:

* `X-Setura-Auth-*`: `Method` (`jwt`, `apikey`, `basic`) and `Subject` (JWT `sub`, key name,
  user name) when a credential was accepted.
* `X-Setura-Client-*`: `Verified`, `Subject`, `SAN`, `Serial`, `Fingerprint` (SHA-256, hex) for
  a client certificate. `SAN` lists `DNS:`, `URI:`, `IP:` and `email:` entries. For a
  certificate that did not verify (fallback mode) only `Verified: false` is set. Nothing is set
  for a client with no certificate.
* The `claimHeaders` names of the route's policy.

Backends may trust these headers only because the gateway removes client copies; keep
backends unreachable except through the gateway.

## Client certificates

Gateway API 1.5 frontend TLS validation, on HTTPS listeners:

```json
"gateways.gateway.networking.k8s.io/gw": {
  "listeners": [ ... ],
  "tls": {"frontend": {
    "default": {"validation": {"mode": "AllowValidOnly",
                "caCertificateRefs": [{"kind": "ConfigMap", "name": "clients-ca"}]}},
    "perPort": [{"port": 8443, "tls": {"validation": {"mode": "AllowInsecureFallback",
                "caCertificateRefs": [{"kind": "ConfigMap", "name": "clients-ca"}]}}}]}}
}
```

* `AllowValidOnly` (default): the handshake fails for a client without a certificate that
  chains to the CA bundle.
* `AllowInsecureFallback`: such clients are served, with no verified identity. Combine with
  `requireClientCert` on the routes that need one.

In a config file the CA bundle is an entry of the `secrets` section (`cert` or `certFile`, no
key); in Kubernetes mode it is the `ca.crt` key of the referenced ConfigMap or Secret (the
controller needs `get` on configmaps; `gateway install` grants it). Cross namespace references
need a ReferenceGrant. A reference that cannot be resolved makes the listener not serve
(`ResolvedRefs=False`, reason `InvalidCACertificateRef`): it never falls back to serving
without validation.

The certificate is also verified again per request against the CA bundle of the listener the
request's `Host` selects (client usage `clientAuth`), so reusing a connection negotiated for
another server name cannot skip validation: such a request gets 421. Not validated: revocation
of client certificates (no CRL or OCSP check of the client), and `TLS` terminate listeners.

## OCSP stapling

`--ocsp-staple` fetches an OCSP response for every listener certificate that has an issuer in
its chain and an OCSP responder URL, and staples it to the handshake. There is no OCSP package
in the standard library, so the gateway builds the request and parses the response itself
(SHA-1 CertID per RFC 6960). A response is used only if its signature verifies against the
issuer (or a delegated responder the issuer signed), it answers for that certificate, says
`good`, and is inside its validity window. Responses are refreshed at half their validity. A
responder that is down or misbehaving changes nothing: the old response keeps being stapled
until it expires, the failure is retried with backoff (1 minute doubling to 1 hour) and logged
without any URL parameters, and then the certificate is served without a staple. The first
fetch happens in the background after start, so the first handshakes may not carry a staple.

## Admin endpoint

`--admin-token TOKEN` (or `SETURA_ADMIN_TOKEN`) requires every admin request to carry
`Authorization: Bearer TOKEN` or the `setura_admin` session cookie, compared in constant time.
A GET with `?token=TOKEN` sets the cookie (`HttpOnly`, `SameSite=Strict`) and redirects without
the token in the URL. Without a token the endpoint answers only a loopback `Host` (blocks DNS
rebinding) and refuses to start on a non-loopback address, including `:PORT`.
`--admin-open-ready` leaves `/ready` open so kubelet probes work. The token is never logged,
printed or included in an error. `setura why --admin`, `connections`, `shadow` and
`gateway rollout` send `SETURA_ADMIN_TOKEN` when it is set in their environment.
`gateway install` generates a token Secret, sets `--admin-open-ready` and passes the token
through the environment. Use TLS in front of the admin port if it leaves the pod network.

## Secrets never leak

* `/config` shows policies with every hash, key and password replaced by `<redacted>` and JWKS
  URL credentials and query removed; the `secrets` section lists names only.
* Access logs, `/connections` and the dashboard show query strings only with `--log-query`, and
  then the values of `token`, `access_token`, `api_key`, `key`, `signature` and similar names
  and the query parameter of any API key policy are replaced by `<redacted>`.
* `setura why` and `/why` echo the request with `Authorization`, `Cookie`, `X-API-Key` and the
  policy's own key header and query parameter redacted, in the request and in the upstream
  request preview.
* Error messages, route status conditions and diagnostics print JWKS URLs without credentials
  or query, and describe a failed validation without token content.
* Not covered: backend response bodies, and headers you copy with your own
  `RequestHeaderModifier`.

## `setura why`

`setura why` shows the policy that applies, and whether the credentials given with
`--header` (and `--client-ip` for address lists) would pass, using the same evaluation as the
data path and the same identity headers in the upstream request preview. Three things it cannot
decide offline are reported as `undetermined`: a JWKS that is fetched from a URL (ask a running
gateway with `--admin`), address lists without `--client-ip`, and client certificates (they
live in the TLS handshake).

## Lint

| Rule | Severity | Meaning |
| --- | --- | --- |
| SET016 | warning | JWT policy without `audience`, or a `jwksUri` over plain http |
| SET017 | warning | API key or basic auth password stored in clear text |
| SET018 | error | auth block or annotation does not parse or compile, or names a rule that does not exist |

## Limits

HTTPRoute only for auth policies. Policies combine as "any credential"; there is no "all of".
No JWT encryption, no ES384/RS384/PS256, no introspection endpoint, no OIDC login, no
per-claim rate limits, no revocation lists. API key and password changes need a config reload.
Rate limiting runs before authentication, so a failed attempt costs a token like any request.
