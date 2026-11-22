# setura ai

`setura ai REPORT` extracts evidence from a saved JSON report. With `--model`
it also asks a model to interpret it; every finding must cite known evidence IDs.

## Providers

* `--provider ollama` (default): `/api/chat` on `http://127.0.0.1:PORT` (`--port`).
* `--provider openai-compatible --endpoint http://127.0.0.1:8080/v1`: posts to
  `ENDPOINT/chat/completions` (llama.cpp, LM Studio, vLLM). An optional bearer
  token is read from the `SETURA_AI_KEY` environment variable, never from arguments.

Endpoints must be loopback, `localhost` or RFC1918 addresses. Any other host
(including DNS names other than `localhost`) is refused unless `--allow-remote`
is given. Redirects are not followed.

## Flags

* `--redact`: before sending, IPs, hostnames, report namespaces and quoted
  header/identity values become stable placeholders (`ip-1`, `host-1`, `ns-1`,
  `value-1`). The mapping stays in memory and is used only to restore the
  model's answer and suggestions. The printed `evidence` is the local original.
* `--suggest`: asks for `suggested_commands`. Each is checked against an
  allowlist: `setura` read-only subcommands, and `kubectl get|describe|logs`
  (no secrets, no credential flags, no `-f`). Shell metacharacters, quotes and
  anything else are rejected. Output has `suggested_commands` and
  `rejected_suggestions`.
* `--max-evidence N`: sends at most N facts: failure/warning facts first, the
  rest in report order, IDs preserved. `evidence_omitted` reports the count.

Evidence covers the tls step fields (cipher, server certificate, expiry,
`client_cert`) and, generically, bench-like reports (`schema` starting with
`setura.bench`, or keys such as `p95_ms`).
