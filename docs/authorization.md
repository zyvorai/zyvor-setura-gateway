# Authorization rules, CSRF and credential injection

Authentication says who the caller is. The `authorization` part of the
`setura.zyvor.dev/auth` block says what that caller may do. It runs after a credential was
accepted (`jwt`, `apiKey`, `basic`, `oidc`, or none at all), so the rules can use what the
gateway verified: claims, scopes, the API key's name, the client certificate, the client
address, and the request's method, path and headers. Everything is off until you configure it.

```json
"setura.zyvor.dev/auth": {
  "jwt": {"issuer": "https://keycloak.example/realms/haven", "audience": ["orders-api"],
          "jwksUri": "https://keycloak.example/realms/haven/protocol/openid-connect/certs"},
  "authorization": {
    "defaultAction": "deny",
    "rules": [
      {"name": "no-delete", "action": "deny", "operations": [{"methods": ["DELETE"]}]},
      {"name": "admins", "action": "allow",
       "principals": [{"claims": [{"name": "realm_access.roles", "exact": "admin"}]}]},
      {"name": "readers", "action": "allow",
       "principals": [{"scopes": ["orders:read"]}],
       "operations": [{"methods": ["GET", "HEAD"], "paths": [{"prefix": "/orders"}]}]}
    ]
  }
}
```

## How a decision is made

Rules are tried in order and **the first rule that matches decides**. A request that matches
no rule gets `defaultAction`, which is `deny` when it is not set. Put specific denials first.

A rule matches when **any** of its `principals` matches (no `principals`: any caller) **and**
**any** of its `operations` matches (no `operations`: any request). Inside one principal or one
operation every field that is set must match.

| Principal field | Matches when |
| --- | --- |
| `claims` | every listed claim matches. A claim is `{name, exact \| prefix \| in \| present}`; dotted names reach into objects (`realm_access.roles`); an array claim matches when any element does; a space separated string (`scope`) is split. |
| `scopes` | the caller has every one of them (the `scope` claim, space separated, and `scp`). |
| `apiKeys` | the caller authenticated with an API key of one of these names. |
| `clientCertSan` | the verified client certificate has one of these SANs (`DNS:host`, `URI:spiffe://...`, or the bare value). |
| `clientCertCn` | the verified client certificate's subject CN is one of these. |
| `cidrs` | the client address is in one of these networks (addresses or CIDRs, IPv4 and IPv6). |
| `authenticated` | `true`: any authenticated caller; `false`: only anonymous ones. |

| Operation field | Matches when |
| --- | --- |
| `methods` | the method is one of these. |
| `paths` | any entry matches the path: `{exact}`, `{prefix}` or `{regex}` (RE2, must match the whole path, at most 512 characters). |
| `headers` | every entry matches: `{name, exact \| prefix \| regex \| present}`. |

The client address is the TCP peer, or the `X-Forwarded-For` client when the peer is in
`--trusted-proxies`, the same address rate limits and access logs use. Claims come from the
token or session the gateway verified itself, never from a header.

A request that no credential admits stays `401` (or the login redirect): authorization only
ever sees authenticated callers. A denial is `403` with a JSON body that says which rule:

```json
{"error": "forbidden", "code": "authorization_denied", "rule": "no-delete",
 "message": "the request is not authorized: authorization rule no-delete denies the request"}
```

`rule` is the rule's `name`, `#N` for an unnamed rule (N from 1), or `default`. gRPC calls get
`PERMISSION_DENIED`.

## `setura why`

`setura why` runs the same evaluation and prints which rule decided:

```
auth: jwt issuer https://keycloak.example/realms/haven audience orders-api ...; authorization (3 rules, default deny)
    this request would be refused with 403 by jwt as alice
    authorization rule no-delete denies the request
    authorization: rule no-delete matched, action deny
```

The JSON form carries `authz_rule` and `authz_action`. A rule that depends on a client address
you did not give (`--client-ip`) or on a client certificate (which a TLS handshake provides, and
`why` cannot simulate) makes the result `unknown` rather than guessing.

## Metrics

`setura_gateway_authz_decisions_total{route,action,source}`: `action` is `allow` or `deny`,
`source` is `rule` or `default`. Rule names are not labels (they are unbounded); use `setura
why` or the access log to find the rule. Authorization denials also count in
`setura_gateway_auth_requests_total{reason="authz"}`.

## CSRF protection

A browser sends its cookies (the OIDC session) and cached basic-auth credentials on every
request to your site, also the ones another site makes for the user. `csrf` closes that for state changing methods:

```json
"csrf": {"allowedOrigins": ["https://admin.example"], "requireOrigin": false}
```

For `POST`, `PUT`, `PATCH`, `DELETE` and any other method not in `safeMethods` (default `GET`,
`HEAD`, `OPTIONS`, `TRACE`), the `Origin` header (or, without one, the `Referer`) must be the
origin the request is addressed to (scheme, host and port, default ports ignored) or one of
`allowedOrigins`. A mismatch, or `Origin: null`, is `403` with `{"code":"csrf_rejected"}`.

* A request with neither header is a non-browser client and passes, unless `requireOrigin` is
  true.
* A request with `Authorization: Bearer ...` is exempt: a browser does not add that header on
  its own, so another site cannot forge it.
* The scheme of the request is `https` when it arrived over TLS, or when a peer in
  `--trusted-proxies` says so in `X-Forwarded-Proto`. Behind a load balancer that terminates TLS
  without that, list the public origin in `allowedOrigins`.
* The check runs before authentication and also protects the OIDC logout.

Lint rule SET062 warns when a rule uses `oidc` without `csrf`.

## Credential injection

`inject` puts a secret into a header of the request sent to the backend, so the backend can
authenticate the gateway without the client ever holding the secret:

```json
"inject": [
  {"header": "Authorization", "scheme": "Bearer", "secret": {"env": "ORDERS_API_TOKEN"}},
  {"header": "X-Service-Auth", "scheme": "Basic", "username": "gateway",
   "secret": {"file": "/etc/setura/orders.password"}}
]
```

`scheme` is empty (the secret as is), `Bearer` (`Bearer SECRET`) or `Basic` (the base64 of
`USERNAME:SECRET`; without `username` the secret is taken to be `user:password` already). Any
value the client sent in that header is removed first, whatever the outcome of authentication,
so a client cannot pick the credential the backend sees. The secret sources and their
handling are those of [oidc.md](oidc.md#secrets): env, file (re-read when it changes) or
Kubernetes Secret, never a value in the route, never in a dump, `why`, log or metric (`why`
shows the header with a redacted value). Gateway-level header modifiers run before injection,
so injection has the last word.

Injection is independent of the authentication method: it also applies to a rule that has
only `inject` in its auth block. A rule that injects a credential and lets anyone in lets anyone
use the credential (lint SET065).

## `{claim:NAME}` header variables

A `RequestHeaderModifier` value can use `{claim:NAME}` next to `{client_ip}`, `{request_id}`,
`{host}`, `{scheme}` and `{listener}`:

```json
{"type": "RequestHeaderModifier", "requestHeaderModifier": {"set": [
  {"name": "X-Tenant", "value": "{claim:tenant.id}"},
  {"name": "X-Roles",  "value": "{claim:realm_access.roles}"}]}}
```

The claim is read from the JWT or OIDC session the gateway verified, dotted names reach into
objects, arrays are joined with commas, control characters are removed. When the claim is
missing or empty, or there is no verified identity, the header is **not sent, and a value the
client sent under that name is removed**. `setura why` and the replay tool apply the same
substitution, so what they show is what the proxy sends. Lint rule SET063 flags `{claim:NAME}`
on a rule without a `jwt` or `oidc` policy.

## TLS cipher suites and session resumption

For HTTPS and terminating TLS listeners, gateway wide or per listener:

| Flag | Listener option (`tls.options`) | Meaning |
| --- | --- | --- |
| `--tls-cipher-suites A,B` | `setura.zyvor.dev/tls-cipher-suites` | TLS 1.2 cipher suites accepted, as Go names them (`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`). Default: Go's secure set. |
| `--tls-session-resumption on\|off` | `setura.zyvor.dev/tls-session-resumption` | Session tickets. Default on. `off` also stops TLS 1.3 resumption. |

The suites Go lists as insecure (RC4, 3DES and the like) and the TLS 1.3 suites, which
Go does not let you choose, are refused. A listener's own options win over the flags. With a
list, HTTP/2 clients need `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` or
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` in it (RFC 9113); other clients are unaffected. An
invalid value makes the listener invalid; lint rule SET064 finds it in a snapshot.

## Order of checks

`ipAllow`/`ipDeny`, `requireClientCert`, `csrf`, credentials (`jwt`, `apiKey`, `basic`,
`oidc`), `authorization`. The OIDC callback and logout paths are answered before this chain
(logout applies `csrf`). The first failure answers.
