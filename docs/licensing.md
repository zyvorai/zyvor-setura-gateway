# Licensing and licence keys

Zyvor Setura is source-available under the [Zyvor Production Licence v2.0](../LICENSE).
Setura keeps working without a key: no command is ever blocked or slowed
down by licence state. A key is the receipt for a paid Order, and
`setura licence` lets you (or your auditor) check it offline.

## Plans

These are the plans as published in the README; this page does not set prices.

| Plan | Price | For |
| --- | --- | --- |
| Evaluate | 30-day trial on request from sales@zyvor.dev (a paid evaluation Order at no charge) | Trying it out |
| Production | USD 101 / cluster / year, INR 9,999 incl. 18% GST in India | Each cluster you gate, probe and lint in production |
| Team | USD 505 / year for up to 10 clusters, INR 49,999 incl. 18% GST in India | Platform teams running several clusters |
| Enterprise | Custom | More than 10 clusters, supported releases, an SLA and a named contact |

INR includes 18% GST in India; US dollars are for customers outside India and
exclude tax. Buy or ask for a quote at <https://zyvor.dev/buy> or
sales@zyvor.dev.

## Commands

    setura licence verify KEY            # check a key given on the command line
    setura licence verify --file F       # key read from a file (- for stdin)
    setura licence show                  # check the configured key
    setura version --verbose             # adds an advisory "licence" line

Output is a status, tier, limit, product, edition, licensee, dates and key
id (`--format json` for scripts). The exit status is 0 for a valid key, 1 for
an invalid one and 2 for a usage error.

| Status | Meaning |
| --- | --- |
| `valid` | Signature checks out, product is `setura`, not expired |
| `expired` | Signature and product are right but `expires` has passed |
| `bad signature` | Not signed by an embedded Setura public key, or damaged |
| `wrong product` | Genuine Zyvor key for another product (or an unknown format version) |
| `bad format` | Not `ZYV1.<payload>.<signature>` |

`licence show` and `version --verbose` read the key from `SETURA_LICENCE_KEY`,
else from the file in `SETURA_LICENCE_FILE`, else from `setura/licence.key` in
the user config directory (`~/.config` on Linux, `~/Library/Application
Support` on macOS). Without one, `version --verbose` prints
`licence  unlicensed (trial)`. That line is advisory only.

## Key format

All Zyvor products share one format, produced by the private issuing tool
(not part of this repository):

    ZYV1.<base64url(payload JSON)>.<base64url(Ed25519 signature over the payload bytes)>

Base64 is URL-safe without padding on output; the verifier also accepts the
standard alphabet and padding. The signature covers the exact payload bytes
that appear in the key, so the JSON is never re-serialised before checking.

Payload (compact JSON, written in this order):

| Field | Meaning |
| --- | --- |
| `v` | format version, `1` |
| `product` | `setura` for this product |
| `edition` | `trial` (30 days) or `pro` (365 days by default) |
| `id` | random key id |
| `licensee`, `email` | who the Order is for |
| `macs` | licensed units; for Setura this is the cluster limit |
| `issued`, `expires` | Unix seconds; a key is expired when now >= `expires` |
| `seats` | optional, named users (some products) |

Checks run in the order: format, signature (against every embedded key for
the product, so keys can be rotated), then `v == 1` and `product`, then
expiry. There is no phoning home and a key cannot be revoked before it
expires.

The key carries no tier field, so the tier shown is derived from the
payload: `trial` for trial keys; for `pro` keys `per cluster` up to 9
clusters, `team` for 10 clusters (or when `seats` is set), `enterprise` above
10. If a key is issued differently from the published plans, the cluster
limit shown is authoritative, not the tier name.

## Embedded public keys

Public keys live in `internal/setura/licence_keys.txt` and are compiled in
with `go:embed`. Each line is `PRODUCT BASE64URL(32-byte Ed25519 public key)`;
`#` starts a comment. To publish a key: generate the pair with the private
tool (`zyvor_licence.py keygen --product setura`), then add the single line
from the resulting `public-keys/setura.pub` as `setura <that line>`. Never
add a private key here. At the time of writing no `setura` public key has been
generated, so the list is empty and every key reports `bad signature` until
one is added; Setura is unaffected.

## Tests

`internal/setura/licence_test.go` creates a throwaway Ed25519 keypair, builds
keys byte for byte the way the reference issuer does (compact JSON, field
order, UTF-8 not escaped, unpadded base64url) and covers valid, trial, team,
expired, wrong product, tampering, bad format and rotation. A cross-check
against a real key was not possible: the reference repository ships no fixed
sample key (its tests generate keys at run time) and has no `setura` public
key yet.
