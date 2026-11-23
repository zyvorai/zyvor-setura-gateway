# AI gateway

The built-in gateway can serve LLM traffic. A rule with a `setura.zyvor.dev/ai` block
becomes an **AI route**: it speaks the OpenAI-compatible and Anthropic request shapes,
holds the provider API keys so clients never see them, counts tokens, enforces token
budgets, fails over between providers, and can cache and redact prompts. It is the same
single binary, the same Gateway API objects and the same admin endpoint as everything else.
Everything is off until a rule carries the block.

What it is not: a billing system, a prompt-safety product or a model router that translates
between vendors. Read [Honest limits](#honest-limits) before you rely on it.

## Quick start

```json
{
  "schema": "setura.route-specs/v1",
  "namespace": "shop",
  "resources": {
    "gateways.gateway.networking.k8s.io/gw": {
      "gatewayClassName": "setura",
      "listeners": [{"name": "web", "protocol": "HTTP", "port": 8080}]
    },
    "httproutes.gateway.networking.k8s.io/llm": {
      "parentRefs": [{"name": "gw"}],
      "hostnames": ["llm.example.test"],
      "rules": [{
        "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
        "setura.zyvor.dev/auth": {"apiKey": {"keys": [{"name": "team-a", "hash": "sha256$...$..."}]}},
        "setura.zyvor.dev/ai": {
          "identity": "apikey",
          "providers": [
            {"name": "openai", "baseURL": "https://api.openai.com/v1", "weight": 3,
             "apiKey": {"env": "OPENAI_API_KEY"}},
            {"name": "azure-eu", "baseURL": "https://eu.example.com/openai/v1", "weight": 1,
             "apiKey": {"env": "AZURE_API_KEY"}},
            {"name": "backup", "baseURL": "https://llm.backup.example/v1", "priority": 1,
             "apiKey": {"file": "/var/run/secrets/ai/backup-key"}}
          ],
          "budget": {"default": {"tokensPerMinute": 60000, "monthlyTokens": 20000000}},
          "cache": {"enabled": true, "ttl": "10m"},
          "pii": {"mode": "redact"}
        }
      }]
    }
  }
}
```

```
setura gateway run --config llm.json --ai-prices prices.json
curl -s http://127.0.0.1:8080/v1/chat/completions -H 'Host: llm.example.test' \
  -H 'X-API-Key: team-a-secret' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
setura gateway ai-usage
setura why POST http://llm.example.test:8080/v1/chat/completions --config llm.json -H 'X-API-Key: team-a-secret'
```

An AI rule serves its providers, not `backendRefs`. It still matches on hostnames, paths,
headers and methods like any rule, takes the auth policy of the same rule (and its
`RequestHeaderModifier` and response filters), and is covered by `--rate-limit`.

In Kubernetes mode put the same JSON, as a string, in the HTTPRoute annotation
`setura.zyvor.dev/ai` (every rule of the route) or `setura.zyvor.dev/ai.rule-N` (rule N,
counting from 1); the rule-specific annotation wins and an inline block wins over both.
`{"enabled": false}` switches the policy off. A block that does not parse or validate makes
the route invalid (not served), never an open pass-through.

## APIs

The API is chosen from the end of the request path, so a route may match any prefix
(`/llm/v1/chat/completions`):

| Path ends in | Shape | Provider `type` | Usage read from |
| --- | --- | --- | --- |
| `/chat/completions` | OpenAI chat | `openai` | `usage.prompt_tokens`, `completion_tokens`; the last SSE chunk when streaming |
| `/completions` | OpenAI legacy completions | `openai` | same |
| `/embeddings` | OpenAI embeddings | `openai` | `usage.prompt_tokens` |
| `/messages` | Anthropic messages | `anthropic` | `usage.input_tokens` (plus cache creation and read tokens), `output_tokens`; `message_start` and `message_delta` events when streaming |

Only `POST` is accepted; anything else (`/v1/models`, images, audio, files, batches, the
OpenAI Responses API) answers 404 with a JSON error. A request needs a JSON object body
with a `model`. Errors use the shape the client's SDK parses: OpenAI's
`{"error": {"message", "type", "code", "param"}}` or, on `/messages`,
`{"type": "error", "error": {...}}`.

Every request is forwarded to `baseURL` plus the API path: `https://api.openai.com/v1` and
`/chat/completions` give `https://api.openai.com/v1/chat/completions`. A `baseURL` without a
path gets `/v1`. Put whatever prefix a vendor needs into the `baseURL`. Providers of one
route may mix types; a request only goes to providers of its own type. The gateway does not
translate between OpenAI and Anthropic.

## Providers

| Field | Meaning |
| --- | --- |
| `name` | Unique, shown in logs, metrics, `why` and `X-Setura-Provider`. |
| `type` | `openai` (default, any OpenAI-compatible server: vLLM, Ollama, Azure, Together...) or `anthropic`. |
| `baseURL` | API root, `http` or `https`, no credentials or query. |
| `weight` | Share within one priority tier (default 1). Weight 0 makes a standby of its tier. |
| `priority` | Tier, lowest first (default 0). A later tier is only used when the earlier ones fail or are ejected. |
| `apiKey` | Where the credential comes from: exactly one of `env`, `file`, `secret`. Optional for keyless servers. |
| `authHeader`, `authScheme` | Where the credential goes. Defaults: `Authorization` with `Bearer` for `openai`, `x-api-key` with no scheme for `anthropic`. Azure uses `"authHeader": "api-key"`. |
| `models` | Models this provider serves, exact or a trailing `*` prefix. Empty means all. |
| `modelMap` | Renames a model for this provider (`{"gpt-4o": "my-deployment"}`). |
| `timeout` | One attempt (default 120s). For a streamed response it ends when the response headers arrive. |
| `headers` | Extra static request headers. Credential headers are refused here. |

Route-level fields: `identity`, `budget`, `cache`, `pii`, `failover`, `allowedModels`
(trailing `*` prefixes), `defaultMaxTokens` (1024, used for the budget reservation),
`maxRequestBytes` (4 MiB), `injectStreamUsage` (default true) and `prices`.

## Secrets never reach clients

Provider keys are resolved when the route is compiled and are never part of the route, the
`/config` dump, the dashboard, `why`, the access log or a metric label:

* `{"env": "OPENAI_API_KEY"}` is read from the gateway's environment when a configuration
  is applied (restart or reload to change it).
* `{"file": "/var/run/secrets/ai/key"}` is read when applied and re-read within 5 seconds of
  the file changing, so a rotated Secret volume takes effect without a reload. An
  unreadable file keeps the last good key.
* `{"secret": {"name": "llm-keys", "key": "openai", "namespace": "ai"}}` is a Kubernetes
  Secret key, read by the Kubernetes source (`setura gateway run --kubernetes`). The
  controller needs `get` on the Secret (the install manifest already grants `get` on
  secrets for TLS certificates). A Secret in another namespace than the route needs a
  `ReferenceGrant`, as for listener certificates. A rotated Secret is picked up when the
  configuration is next read (the `--resync` interval, 1m by default, or any route change). A snapshot file cannot use `secret`; use `env` or `file`.

A key that cannot be resolved makes the route invalid with the reason in its status
condition: a route never serves without the key it was configured to use.

What the provider sees: the client's `Authorization`, `X-Api-Key`, `Cookie`, every
`X-Setura-*` header and everything else not on a short allow list is dropped. Only
`Accept`, `User-Agent`, `Anthropic-Version`, `Anthropic-Beta`, `OpenAI-Beta` and
`Idempotency-Key` are forwarded, with a trace header and the request id. The provider
credential is set last, **on every attempt**, so a request that fails over is signed for the
provider that receives it. If an upstream error body quotes the key, it is replaced with
`<redacted>` before it reaches the client or the log.

## Identity

Budgets, the per-key counters and the cache scope need to know who is calling. `identity`
selects it:

| `identity` | Value | Needs |
| --- | --- | --- |
| `subject` (default) | the verified subject of the credential (API key name, JWT `sub`, basic user) | an auth policy |
| `apikey` | the `name` of the API key that matched | an `apiKey` auth policy |
| `claim:NAME` | a claim of the verified JWT (dotted names reach into objects) | a `jwt` auth policy |
| `header:NAME` | a request header | nothing, but see below |

A header identity is exactly as trustworthy as whoever sets the header. Use it behind a
layer you control that overwrites it, never on a route clients reach directly: lint warns
(SET022). A route with a budget whose identity is missing answers 401 `identity_required`
(fail closed); it never pools unidentified callers.

## Token accounting

Tokens come from what the provider reports: the `usage` object of a JSON response, or the
final events of a stream. For streamed OpenAI-style requests the gateway sets
`stream_options.include_usage` so the provider sends a usage chunk, and removes that chunk
again from what the client receives if the client did not ask for it (disable with
`injectStreamUsage: false`). When a provider reports no usage, the gateway uses its own
estimate and flags it (`tokens_estimated: true` in the log).

Every request writes these fields to the access log (names and counts only, never prompts or
answers):

| Field | Meaning |
| --- | --- |
| `ai_key` | the identity (`anonymous` when none) |
| `provider`, `model` | the provider that answered and the model it reported (the requested one when none) |
| `tokens_in`, `tokens_out` | prompt (Anthropic: input plus cache tokens) and completion tokens |
| `tokens_estimated` | true when no usage was reported |
| `cache_hit` | present on routes with a cache: true for a hit, false for a miss |
| `cost_estimate` | tokens times the price table, in the table's currency |
| `pii_findings`, `pii_action` | number of PII matches in the prompt and what was done (`redacted`, `blocked`, `reported`) |

### Price table

`--ai-prices FILE` (re-read when the file changes) and the route's `prices` give the price
per **million** tokens:

```json
{"currency": "USD", "models": {"gpt-4o": {"input": 2.5, "output": 10}, "gpt-4o-mini": {"input": 0.15, "output": 0.6}, "*": {"input": 1, "output": 3}}}
```

A model name matches exactly, then by the longest table entry that is a prefix of it
(`gpt-4o` prices `gpt-4o-2024-08-06`), then `*`. A model with no price costs 0. The gateway
ships no prices: they change, and a stale default is worse than none.

## Token budgets

```json
"budget": {
  "default":   {"tokensPerMinute": 60000, "tokensPerDay": 2000000, "monthlyTokens": 20000000, "monthlyCost": 400},
  "overrides": {"team-b": {"tokensPerMinute": 200000}},
  "route":     {"tokensPerMinute": 1000000}
}
```

Limits are per identity (`default`, replaced as a whole by an entry of `overrides`) and
optionally for the whole route together (`route`). `0` means unlimited. The windows are the
UTC minute, the UTC day and the UTC calendar month (fixed windows, not sliding).

Enforcement is before forwarding, reconciled after:

1. The gateway estimates the request: the prompt text at about four characters per token plus
   4 per message, plus `max_tokens` (or `max_completion_tokens`, or `defaultMaxTokens`) for the completion.
2. If `used + estimate` would pass any limit, the request is refused and never forwarded.
3. Otherwise the estimate is **reserved** in every window.
4. When the response ends, the reservation is replaced by the real usage, so a request that
   asked for `max_tokens: 4000` and used 300 costs 300. A failed request costs 0.

A refusal is `429` with `Retry-After` (seconds to the end of the window that refused) and a
body that says which limit and what to do:

```json
{"error": {"message": "token budget exceeded: identity limit tokens_per_minute is 60000 with 58000 in use, and this request may need 3500 (prompt about 500 plus up to 3000 completion tokens); retry in 23 seconds",
           "type": "rate_limit_error", "code": "token_budget_exceeded", "param": null,
           "budget": {"limit": "tokens_per_minute", "max": 60000, "used": 58000, "requested": 3500,
                      "retry_after_seconds": 23, "scope": "identity"}}}
```

A request whose estimate alone is larger than a limit can never succeed: tell clients to
lower `max_tokens`. `monthlyCost` uses the price table; without prices it never fires
(lint SET026). Cache hits cost no tokens and spend no budget.

## Failover

For each request the gateway orders the providers that serve its API and model: providers
that can take traffic before ejected ones, tiers by `priority`, and within a tier by a
weighted random draw. It tries them in that order. A **transport error, a timeout, 429 or any
5xx** (`failover.statuses` replaces that status list; `failover.maxAttempts` bounds the tries)
moves the request to the next provider, before a byte reaches the client. Any other status,
including 400 and 401, is the client's and is returned. When the last provider also fails,
its answer is relayed (a 429 keeps its `Retry-After`); when every provider failed to answer at
all the client gets 502 or 504 with the list of attempts.

Failing providers are taken out of rotation by the outlier ejection the gateway already has
for every backend: a provider is one endpoint of a per-rule backend
`ai/NAMESPACE/NAME/N`, so `--outlier-failures`, `--outlier-base-ejection` and
`--outlier-max-ejection` apply (5 consecutive failures, then 30s doubling to 5m; the last
available provider is never ejected), state survives reloads and
`setura_gateway_ejections_total` counts them. For this purpose a 429 counts as a failure.
Active health checks are never run against providers: probing a paid API costs money.

Once a stream has started it cannot move to another provider.

## Prompt cache

Opt in per route:

```json
"cache": {"enabled": true, "ttl": "10m", "maxEntries": 1000, "maxEntryBytes": 262144, "maxBytes": 67108864,
          "scope": "identity", "stream": false, "ignoreFields": ["user"]}
```

The key is a SHA-256 of the route rule, the API, the identity (unless `scope` is `route`) and
the canonical request body (keys sorted, whitespace and `ignoreFields` removed): same model,
messages and parameters give the same key, and a different `temperature` does not. It is
exact match; there is no semantic similarity. The cache is a bounded LRU with a TTL, bounded
by entries and by bytes, in memory and per replica. Only `200` responses are stored.
Responses carry `X-Setura-Cache: HIT` or `MISS`. Streaming requests are skipped (no header)
unless `stream` is true, in which case the whole event stream is stored and replayed as one
burst. Prompts are redacted before the key is computed and the cache never holds an original.

The default scope is per identity so one client never receives another's answer. Scope
`route` shares answers across everyone who can reach the route: use it only when every
caller may see every answer (lint SET025 warns on an authenticated route). Caching a
non-deterministic model returns one earlier answer for a while; set `temperature: 0` for
requests you want deterministic.

## PII redaction

```json
"pii": {"mode": "redact", "rules": ["email", "phone", "card", "ssn"],
        "custom": [{"name": "employee-id", "pattern": "EMP-\\d{6}", "replacement": "[EMP]"}]}
```

| Mode | Effect |
| --- | --- |
| `redact` (default) | matches in the prompt are replaced by `[REDACTED:rule]` before anything else sees the request |
| `block` | the request is refused with 400 `pii_detected`; the body names the rules and counts, never the data |
| `report` | the request goes through unchanged; only counts are logged and counted |

Built-in rules (all four when `rules` is omitted, none with `"rules": []`): `email`; `phone`
(international `+` numbers and numbers with separators); `card` (13 to 19 digits that pass
the Luhn check, so order numbers are left alone); `ssn` (`NNN-NN-NNNN` in issued ranges).
Custom rules are Go regular expressions (RE2: linear time, no backtracking blow-ups).

Text is scanned in `messages` (strings and content parts), `prompt`, `input` and `system`.
Structure (`role`, `type`, ids, names, `url`, `data`) is not touched. The gateway never logs or
counts matched text, only `pii_findings`, `pii_action` and
`setura_ai_pii_findings_total{rule,action}`.

## Observing it

`setura gateway ai-usage [--admin ADDR] [--admin-token T] [--route R] [--key K] [--format table|json]`
reads the admin `/ai/usage` endpoint: per route the totals, cost estimate, cache hit rate, budget refusals,
PII findings, each provider's state (healthy or ejected), attempts, failures and tokens, and each
identity's tokens with every budget window as used, limit and time to reset. `--format json` prints the
document. Exit 0, 1 when the gateway cannot be read, 2 on a usage error.

`setura why POST URL --config FILE -H 'X-API-Key: ...'` shows an AI route: the provider the
request goes to first and why (tier, weights, percentages, ejections on a live `--admin`
gateway), the failover order, where each credential comes from (never the credential),
the identity, the limits and, live, how much is used, and the cache and PII policy. It sends no traffic.

Metrics (all on the admin `/metrics`, see [netra.md](netra.md) for the catalog):

| Metric | Labels |
| --- | --- |
| `setura_ai_requests_total` | `route`, `provider`, `model`, `outcome` (`ok`, `upstream_error`, `cache_hit`, `budget_denied`, `pii_blocked`, `rejected`) |
| `setura_ai_tokens_total` | `route`, `provider`, `model`, `direction` (`prompt`, `completion`) |
| `setura_ai_cost_estimate_total` | `route`, `provider`, `model` |
| `setura_ai_key_tokens_total`, `setura_ai_key_cost_estimate_total` | `route`, `key` (`direction`) |
| `setura_ai_cache_requests_total` | `route`, `result` (`hit`, `miss`) |
| `setura_ai_cache_evictions_total` | `route` |
| `setura_ai_budget_rejections_total` | `route`, `limit` |
| `setura_ai_provider_attempts_total` | `route`, `provider`, `result` (`ok`, `failover`, `error`) |
| `setura_ai_failovers_total` | `route`, `from`, `to` |
| `setura_ai_pii_findings_total` | `route`, `rule`, `action` |
| `setura_ai_provider_up` | `route`, `provider` |

`route` is `namespace/name/rule-number`. The `model` label is capped at 64 values per route and
the `key` label at `--ai-max-key-labels` (default 500) per route; the rest become `_other`.

## Lint

`setura lint` checks AI blocks offline, without reading any secret: SET020 (invalid block or
orphan annotation), SET021 (a budget whose identity the auth policy cannot provide),
SET022 (client-set header identity), SET023 (API key over plain `http` outside the cluster),
SET024 (AI route with no auth policy), SET025 (cache shared across authenticated clients),
SET026 (`monthlyCost` without prices), SET027 (`backendRefs` that are ignored). See
[lint-rules.md](lint-rules.md).

## Honest limits

* **No semantic cache.** The cache is exact match on the canonicalised request. Two prompts
  that mean the same but differ by a character are two entries.
* **Prompt token counts are estimates.** About four characters per token plus per-message
  overhead; real tokenizers differ, especially for code, non-Latin scripts and images. The
  estimate decides admission and the reservation; the provider's reported usage settles it.
  When a provider reports no usage, the estimate is what is accounted, and it is flagged.
* **Budgets are per gateway process.** They live in memory, reset on restart and are not
  shared between replicas; divide the limits by the replica count. Windows are fixed UTC
  windows, so a client can use a full minute's budget at the end of one minute and again at the
  start of the next. They are an abuse and cost guard, not an invoice. Cost is your price table
  times counted tokens: no discounts, cached-prompt tiers, batch pricing or taxes, and a
  model with no price costs 0.
* **No translation between vendors.** An OpenAI-shaped request cannot fail over to an
  Anthropic provider; failover is between providers of one API family.
* **Failover re-sends the request.** A provider that timed out may still have processed
  (and billed) it. A request that has started streaming cannot fail over. Retried requests are
  `POST`s: clients that need exactly-once should send `Idempotency-Key`, which is forwarded.
* **PII detection is pattern matching.** It catches the shapes it knows (emails, phone numbers,
  Luhn-valid card numbers, issued-range SSNs, your regexes) and misses names, addresses and
  anything else; it also has false positives (long digit groups). It scans prompts only, not
  responses, and not images or tool arguments. It is a safety net, not a compliance guarantee.
* **Only text APIs.** Chat completions, completions, embeddings and Anthropic messages. No
  model listing, Responses API, images, audio, files, batches or realtime.
* **Memory bound.** Request bodies are buffered (4 MiB by default) and non-streamed responses
  up to 32 MiB. When the gateway rewrites a request (redaction, `modelMap`, `stream_options`)
  the JSON is re-encoded and its key order may change.
* **Header identities can be forged** by whoever reaches the route unless a trusted layer sets them.
* **Secrets in environment variables** are read when a configuration is applied. Use `file` or
  a Kubernetes Secret for keys that rotate.
