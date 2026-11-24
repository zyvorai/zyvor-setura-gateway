# OIDC login at the gateway

A route can log browsers in itself. A request without a session is sent to your identity
provider (Keycloak, Authentik, Entra ID, Okta, anything that speaks OpenID Connect), comes back
to the gateway, and carries an encrypted session cookie from then on. The backend receives the
user's claims as headers and never sees a login page, a token exchange or a cookie it did not
ask for. Everything uses the Go standard library, and a policy that cannot be compiled makes
the route invalid (not served), never open.

OIDC is one more method of the `setura.zyvor.dev/auth` block, next to `jwt`, `apiKey` and
`basic` (see [security.md](security.md)): one valid credential of any configured method admits
the request, so an API client with a bearer token and a browser with a session can share a route.

```json
"setura.zyvor.dev/auth": {
  "oidc": {
    "issuer": "https://keycloak.example/realms/haven",
    "clientId": "haven-app",
    "clientSecret": {"secret": {"name": "haven-oidc", "key": "client-secret"}},
    "redirectUrl": "https://app.example/oauth2/callback",
    "cookieKeys": [{"secret": {"name": "haven-oidc", "key": "cookie-key"}}],
    "claimHeaders": {"X-User": "preferred_username", "X-Email": "email",
                     "X-Roles": "realm_access.roles"},
    "accessTokenHeader": "Authorization", "accessTokenScheme": "Bearer"
  },
  "csrf": {}
}
```

The rule must match the callback path (`/oauth2/callback` above) and the logout path
(`/oauth2/logout`): a `PathPrefix: /` rule does. The gateway answers both itself; they never
reach the backend. Register the callback URL as a valid redirect URI of the client at the
provider.

## The flow

1. A browser navigation without a valid session is answered `302` to the provider's
   `authorization_endpoint` with `response_type=code`, your `scope`, a random `state` and
   `nonce`, and a PKCE `code_challenge` (always `S256`). The login state is kept in a short
   lived, encrypted cookie bound to that `state`, so two tabs can log in at once.
2. The provider sends the browser to the callback with a `code`. The gateway checks the
   `state` against the cookie, exchanges the code (with the PKCE verifier and the client
   secret) at the token endpoint, and validates the ID token: signature from the provider's
   JWKS (the same code as the `jwt` policy: RS256, ES256, EdDSA, no `none`, no HMAC), `iss`,
   `aud`, `azp`, `exp`, `nbf` and the `nonce`.
3. It sets the session cookie and redirects to the URL the user asked for (only a path on the
   same site: the return URL cannot be used as an open redirect).
4. Later requests carry the cookie. The gateway decrypts it, checks its lifetime, refreshes
   the tokens when they have expired, and proxies the request with the claim headers.

Discovery is read from `issuer/.well-known/openid-configuration` and cached for an hour. A
document whose `issuer` differs from your setting is refused. If the document lists
`code_challenge_methods_supported` without `S256` the login does not start; a document that
leaves the list out is accepted, because the gateway always sends `S256` and the provider
rejects it at the authorization endpoint if it cannot honour it. When the discovery document is unreachable the
login answers `503` and the check is retried at most every 10 seconds; with every endpoint
overridden (`authorizationEndpoint`, `tokenEndpoint`, `jwksUri`) discovery is not used.

## Fields

| Field | Meaning |
| --- | --- |
| `issuer` | Issuer URL, spelled exactly as in the provider's tokens. Keycloak: `https://HOST/realms/REALM`. Use https (lint SET060). |
| `clientId` | The client at the provider. |
| `clientSecret` | A secret source (below). Leave it out for a public client: PKCE alone protects the exchange (lint SET060). |
| `tokenAuthMethod` | `client_secret_basic` (default) or `client_secret_post`. |
| `redirectUrl` | The callback. An absolute URL is best; a path is completed with the request's `Host`. It needs a path of its own. |
| `scopes` | Scopes besides `openid` (default `profile`, `email`). Keycloak role claims need the `roles` scope or a mapper. |
| `cookieKeys` | One to four secret sources, at least 32 characters each. The first seals new cookies, all of them open (rotation, below). |
| `cookieMode` | `encrypted` (AES-256-GCM, default) or `signed` (HMAC-SHA256: the browser can read the session). |
| `cookie` | `name` (default `setura_session`), `domain`, `path` (default `/`), `sameSite` (`Lax` default, `Strict`, `None`), `secure` (default true, set false only for plain-http development). |
| `sessionTtl` | Longest a session lasts from login, default `8h`, from `1m` to `720h`. |
| `sessionClaims` | Keep only these claims in the session (default: all of the ID token's). |
| `logoutPath` | Default `/oauth2/logout`. |
| `postLogoutRedirectUrl` | Where the provider sends the browser after logout. |
| `denyRedirect` | `auto` (default), `always` or `never`, see below. |
| `authorizationEndpoint`, `tokenEndpoint`, `jwksUri`, `userinfoEndpoint`, `endSessionEndpoint` | Override what discovery says. |
| `userinfo` | Merge the userinfo response into the claims at login (its `sub` must match the ID token's). |
| `disableRefresh` | Keep the refresh token out of the session and never refresh. |
| `authParams` | Extra authorization parameters, such as Keycloak's `kc_idp_hint` or `prompt`. |
| `clockSkew` | Tolerance for the ID token's `exp` and `nbf`, default `60s`. |
| `claimHeaders` | `{header: claim}` sent upstream. Dotted names reach into objects (`realm_access.roles`, `resource_access.haven-app.roles`). |
| `accessTokenHeader`, `accessTokenScheme` | Forward the access token upstream, for example `Authorization` with scheme `Bearer`. |
| `idTokenHeader` | Forward the ID token upstream. |
| `forwardCookies` | Send the gateway's cookies upstream (default: removed; the browser's other cookies always pass). |

Whatever a client sends in a header the policy sets (`claimHeaders`, the token headers, the
`X-Setura-Auth-*` family) is removed first, so an identity cannot be forged.

## Secrets

The client secret, the cookie keys and every injected credential name a source, never a value:

```json
{"env": "OIDC_CLIENT_SECRET"}
{"file": "/etc/setura/cookie.key"}
{"secret": {"name": "haven-oidc", "namespace": "apps", "key": "cookie-key"}}
```

These are the same three sources as the AI provider keys. An environment variable is read when
the route is built. A file is re-read when it changes (checked every 5 seconds), so a rotation
needs no restart. A Kubernetes Secret is read by the Kubernetes source one Secret at a time
(RBAC needs only `get`), a Secret in another namespace needs a `ReferenceGrant`, and a snapshot
file takes `env` or `file`. A secret that cannot be read, or a cookie key shorter than 32
characters, makes the rule invalid with a message that names the source and never the value.
Generate a key with `openssl rand -base64 32`.

Secrets are not part of `/config`, snapshots, `setura why`, access logs, metrics or error
messages, and an error text from the provider is never passed to the browser (only its short
error code).

## The session cookie

The cookie holds the verified claims, the access token, the refresh token and the ID token (for
logout), compressed and sealed with AES-256-GCM under a key derived from the first cookie key,
bound to the cookie's name. A session too large for one cookie is split across
`setura_session`, `setura_session_1`, and so on, up to five; keep it small with `sessionClaims`
when a token carries a long group list. The cookie is `HttpOnly`, `Secure` and `SameSite=Lax`
unless you change it. `SameSite=Strict` makes the browser withhold the cookie from the request
that follows the provider's redirect, which sends the user back to the provider: prefer `Lax`.

**Rotation.** Put the new key first and keep the old one: `cookieKeys: [new, old]`. Sessions
sealed with `old` keep working and are re-sealed with `new` on their next request. Once they
have all expired or been renewed, remove `old`.

## Refresh and expiry

The tokens' lifetime comes from the provider (`expires_in`). Ten seconds before the access
token expires, the next request redeems the refresh token at the token endpoint, validates the
new ID token (the subject must not change) and sets a new cookie. Requests of one browser that
arrive together share one refresh, and a result is reused for 15 seconds, so a provider that
rotates refresh tokens (single use) is not asked twice. If the provider refuses the refresh
token (`invalid_grant`, session ended at the provider) the user is sent to log in again. If the
provider cannot be reached the answer is `503` and the cookie is kept, so an outage does not
log everyone out. Without a refresh token the session lasts until `sessionTtl`, unless the
access token is forwarded upstream, which then ends the session when it expires.
`sessionTtl` is absolute: it counts from login and a refresh does not extend it.

## Browsers and API calls

`denyRedirect` decides what an unauthenticated request gets:

| Mode | Behaviour |
| --- | --- |
| `auto` (default) | `302` to the provider for a browser navigation (`GET` or `HEAD` that accepts `text/html`). `401` with a small JSON body (`{"error":"unauthenticated","code":"login_required"}`) for everything else: XHR (`X-Requested-With: XMLHttpRequest`), `fetch` (`Sec-Fetch-Mode` other than `navigate`), requests that do not accept HTML, requests with an `Authorization` header, and non-`GET` methods. |
| `always` | Always redirect. |
| `never` | Always `401`. |

A single page application calls its API and, on `401`, navigates to a protected page to log in.

## Logout

`GET` or `POST` on `logoutPath` clears the cookies and, when the provider has an
`end_session_endpoint`, continues there with `client_id`, `id_token_hint` and (if configured)
`post_logout_redirect_uri`, which Keycloak requires to be registered on the client. Without an
end-session endpoint the browser goes to `postLogoutRedirectUrl` or `/`. A cross-site `POST` is
refused when the rule has a `csrf` block.

## Keycloak

Keycloak is the reference provider (Haven runs Keycloak with PostgreSQL). Create an OpenID
Connect client with "Client authentication" on, the standard flow on, and the callback as a
valid redirect URI. Use `https://HOST/realms/REALM` as the issuer. Realm roles arrive as
`realm_access.roles` and client roles as `resource_access.CLIENT.roles` in the ID token when
the client scope includes them; `kc_idp_hint` selects an identity provider and skips the
Keycloak login page. Keycloak's access token has an `aud` of `account`, which is fine: the
gateway checks the audience of the ID token, not of the access token.

## Observability and `setura why`

`setura_gateway_oidc_events_total{route,event}` counts `login_started`, `login_succeeded`,
`login_failed`, `refresh_succeeded`, `refresh_failed`, `session_invalid` and `logout`. Denials
appear in `setura_gateway_auth_requests_total` as `unauthenticated` (a redirect or `401`) or
`unavailable` (`503`). The labels are fixed sets, so the series stay bounded.

`setura why` shows the policy (`oidc login with CLIENT at ISSUER`), where the secrets come from
(never their values), and what a request would get: pass the browser's cookie with
`-H 'Cookie: setura_session=...'` to see the session's verdict and the headers the backend would
receive (the access token and cookies are redacted). Without a cookie it says the browser is
redirected to log in (302) or answered 401, following the headers you give (`Accept`,
`X-Requested-With`). A session that needs a refresh is reported as undetermined, since an offline
view does not call the provider.

## Limits

* HTTPRoutes only; a GRPCRoute with `oidc` is invalid (use `jwt` there).
* One policy per rule; the callback and logout paths belong to the rule that has the policy.
* The gateway keeps no session store. State lives in the cookie, so any replica serves any
  user, and a logout at the gateway cannot revoke a cookie someone has copied before it
  expires (it ends at the provider, and the cookie's own lifetime is `sessionTtl`).
* The login state and refresh de-duplication are per gateway process.
