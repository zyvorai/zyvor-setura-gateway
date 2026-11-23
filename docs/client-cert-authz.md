# Client certificate authorisation

Frontend TLS validation (`spec.tls.frontend`, see [mtls](mtls.md) and
[security](security.md)) proves that a client certificate chains to a CA bundle.
That is trust in the CA, not permission: every certificate the CA ever issued
is accepted. An **allow-list** narrows it to the identities you name, the
equivalent of Envoy's `match_typed_subject_alt_names`.

A certificate is accepted when it chains to the bundle **and** matches the
list. A certificate from a trusted CA that matches nothing is refused.

## The list

```json
{"san": ["*.corp.example", "dns:api.partner.example", "spiffe://td/ns/pay/sa/worker", "email:ops@corp.example"],
 "cn":  ["batch-runner"]}
```

| entry | matches |
| --- | --- |
| `name` | an exact DNS, URI or email SAN of the leaf, case-insensitive |
| `*.suffix` | any value that ends in `.suffix` with at least one character before it (`*.corp.example` matches `a.b.corp.example`, not `corp.example`, not `evilcorp.example`) |
| `dns:`, `uri:`, `email:` prefix | restricts the entry to that SAN type |
| `cn` entries | the subject common name, exact or `*.suffix` |

A certificate is accepted when **any** `san` entry or **any** `cn` entry
matches. An empty list allows every trusted certificate. Only a leading `*.` is
a wildcard; anything else (`a.*.test`, `*`) is rejected when the configuration
loads. Wildcard entries are plain suffix matches on the whole value, so prefer
exact entries for URI and email SANs.

## Where to put it

Three places, in this order of precedence for a listener:

1. **Snapshot field** on the validation block, `setura.zyvor.dev/client-allow`:

   ```json
   "tls": {"frontend": {"default": {"validation": {
     "caCertificateRefs": [{"kind": "ConfigMap", "name": "clients-ca"}],
     "setura.zyvor.dev/client-allow": {"san": ["*.corp.example"]}}}}}
   ```

2. **Gateway annotation** `setura.zyvor.dev/client-allow`, the same JSON as a
   string. It applies to every listener of that Gateway that has validation. A
   snapshot carries it under the Gateway's `setura.zyvor.dev/annotations`.

   ```yaml
   metadata:
     annotations:
       setura.zyvor.dev/client-allow: '{"san":["*.corp.example"]}'
   ```

3. **Flags**, the default for Gateways that declare neither:

   ```
   setura gateway run --config gw.json --client-allow-san '*.corp.example,spiffe://td/ns/pay/sa/worker' --client-allow-cn batch-runner
   ```

   Both flags are repeatable and take comma-separated lists. `--client-allow-san`
   defaults to the environment variable `SETURA_CLIENT_ALLOW_SAN` (comma
   separated), so a value that used to live in an Envoy-era variable such as
   `ZYVORA_CONNECTOR_ALLOWED_SAN` can be mapped across with
   `SETURA_CLIENT_ALLOW_SAN="$ZYVORA_CONNECTOR_ALLOWED_SAN"`.

A malformed list makes the listener not serve (it fails closed, like a bad CA
reference); it never falls back to "any trusted certificate".

## Where it is enforced

* `AllowValidOnly` (the default mode): in the TLS handshake. A refused client
  gets a TLS alert and never sends a request.
* `AllowInsecureFallback`: per request. The request is served, but the
  certificate counts as **not verified**: `X-Setura-Client-Verified: false`, no
  identity headers, and a route with `requireClientCert` answers 403.
* A connection negotiated for one server name and then used for a Host on a
  listener whose list it does not satisfy is refused with 421, as for a missing
  certificate.

## Rejections are logged and counted

Every refusal increments
`setura_gateway_client_cert_rejected_total{listener}` and writes a line to the
gateway's diagnostics (stderr):

```
client certificate refused on listener t/gw/web: subject "CN=alice" is not on the allow-list (SAN DNS:alice.other.test)
```

Request-level refusals (fallback mode, 421) also set the access log `error`
field. A handshake refusal has no request, so the metric and the diagnostic line
are the record.

## X-Forwarded-Client-Cert

Off by default. `--client-cert-xfcc` additionally writes the verified identity
in Envoy's format, next to the `X-Setura-Client-*` headers, which stay as they
are:

```
X-Forwarded-Client-Cert: By=spiffe://gw/edge;Hash=<sha256 hex>;Subject="CN=alice,O=Acme";URI=spiffe://corp/alice;DNS=alice.corp.example
```

* `By`: the first URI SAN of the listener's serving certificate (omitted when it
  has none).
* `Hash`: SHA-256 of the DER certificate, lower-case hex.
* `Subject`: the subject distinguished name, always quoted.
* `URI` and `DNS`: one field per SAN of that type.

Only a **verified** certificate (chain and allow-list) produces the header. A
client-supplied `X-Forwarded-Client-Cert`, like any `X-Setura-Client-*` and
`X-Setura-Auth-*` header, is **always** removed first, whether or not the flag is
set and whether or not the client presented a certificate. A trusted mesh proxy
in front of Setura that already sets XFCC therefore has it dropped: terminate
the client TLS on Setura, or carry the identity in a header Setura does not
reserve.
