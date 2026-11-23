# Direct responses

A rule can answer by itself with a fixed status, an optional body and
optional headers, without contacting a backend. This is Envoy's
`direct_response`: the usual way to block `/internal`, answer `/healthz`, or
return a static 403 for a path prefix.

Gateway API has no filter for this, so Setura expresses it the way it
expresses its other rule extensions (see `setura.zyvor.dev/auth` in
[security.md](security.md)): a field on the rule in a snapshot, or a route
annotation.

## Writing one

In a snapshot, as a field of the rule:

```json
{
  "matches": [{"path": {"type": "PathPrefix", "value": "/internal"}}],
  "setura.zyvor.dev/direct-response": {
    "status": 404,
    "body": "not found\n",
    "headers": {"Cache-Control": "no-store"}
  }
}
```

As an annotation on the HTTPRoute (works on a real cluster too, where the CRD
has no room for the field):

```yaml
metadata:
  annotations:
    setura.zyvor.dev/direct-response.rule-1: '{"status":404,"body":"not found\n"}'
```

`setura.zyvor.dev/direct-response` without a suffix applies to every rule of
the route (so every rule must then be a direct-response rule);
`setura.zyvor.dev/direct-response.rule-N` (N counts from 1) targets one rule
and wins. In a snapshot the annotations live under the route's
`"setura.zyvor.dev/annotations"` object, like the other Setura annotations.

| Field | Meaning |
|-------|---------|
| `status` | Required, 200 to 599. 204 and 304 cannot carry a body. |
| `body` | Optional string, up to 64 KiB, sent byte for byte. |
| `headers` | Optional map. `Content-Length`, `Transfer-Encoding`, `Connection`, `Host`, `Keep-Alive`, `Upgrade`, `Trailer` and `TE` are managed by the gateway and refused. |

When there is a body and no `Content-Type` header, the response is
`text/plain; charset=utf-8`. `HEAD` requests get the headers only.

## What it does and does not do

- Matching is unchanged: the rule wins or loses exactly like any other, so a
  longer prefix or an exact path beats a catch-all.
- The rule's `ResponseHeaderModifier` and `CORS` filters apply first, then
  the block's own headers (which win on a conflict). `X-Request-Id` is set.
- Authentication (`setura.zyvor.dev/auth`), the gateway-wide rate limit and a
  per-rule rate limit ([limits.md](limits.md)) run before the response, so a
  direct-response rule can be protected like any other.
- A direct-response rule must have no `backendRefs` and no `RequestRedirect`,
  `RequestMirror` or `ExternalAuth` filter. That is a conflict the gateway
  refuses instead of choosing silently: the route is reported not Accepted
  (`UnsupportedValue`) and lint reports SET030.
- A block that cannot be decoded makes the route invalid in the same way, so a
  typo never leaves a path unprotected.
- gRPC and TLS routes do not support it.

## Tooling

- `setura why GET http://a.test:8080/internal` reports the verdict
  `direct-response`, the status, headers and body the client would get, and
  exits 0. `--format json` has the same under `winner.direct_response`.
- `setura replay` classifies the outcome `direct-response` and reports a
  change of outcome or status between two configs.
- `setura lint`: SET030 covers invalid blocks, orphan `.rule-N` annotations
  and the conflicts above. SET003 (rule without backends) does not fire for a
  direct-response rule.
