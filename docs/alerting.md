# Alerting and probe history

## Alerts from `setura watch`

    setura watch --file checks.json --alert-slack "$SLACK_WEBHOOK_URL"
    setura watch URL --alert-webhook "$HOOK_URL" --alert-cooldown 5m --alert-retries 3

| Flag | Meaning |
| --- | --- |
| `--alert-webhook URL` | POST generic JSON |
| `--alert-slack URL` | POST a Slack incoming-webhook message |
| `--alert-cooldown D` | minimum time between alerts for one target, default `1m` |
| `--alert-retries N` | delivery retries after the first attempt, default `3`, at most 10 |
| `--alert-after N` | consecutive failed probes before a `failure` is sent, default `1`, at most 1000 |
| `--alert-recover-after N` | consecutive passed probes before a `recovery` is sent, default `1` |

Both URLs may also come from `SETURA_ALERT_WEBHOOK` and `SETURA_ALERT_SLACK`, which keeps them out of the process list. Either, or both, can be set.

### Transitions only

Alerts are sent when a target goes from passing to failing (`failure`) and from failing back to passing (`recovery`). A target that keeps failing does not alert again. A target whose first probe passes sends nothing; one whose first probe fails sends a `failure`.

To ignore single blips, raise the streaks:

    setura watch --file checks.json --alert-slack "$URL" --alert-after 3 --alert-recover-after 2

With `--interval 10s` this reports a failure after about 30 seconds of failing probes. Any passed probe restarts the failure count, and any failed one restarts the recovery count. The generic JSON payload then carries `consecutive`, the streak that raised the alert. The streaks affect alerts only: the console, history, metrics and exit status still see every probe.

The cooldown spaces alerts per target. A transition inside the cooldown is held back and reconsidered on each later probe, so a flap that settles back to the state recipients already know about produces no message at all, and a real change goes out once the cooldown ends. Alerts are delivered in the background, so slow endpoints do not delay probing; `watch` waits for pending deliveries before it exits.

### Retries

Network errors, HTTP 429 and 5xx are retried with exponential backoff (500 ms, 1 s, 2 s, ...). Other 4xx responses are not retried. A delivery that still fails is logged to stderr and tried again on the next probe, because recipients have not been told about the change.

### Payloads

Generic JSON:

    {"source":"setura","event":"failure","target":"https://orders.example.com/","time":"2026-01-02T15:04:05Z",
     "elapsed_ms":3.2,"message":"https://orders.example.com/ is failing at http: expected HTTP 200, received 500",
     "stage":"http","reason":"expected HTTP 200, received 500"}

`event` is `failure` or `recovery`; `stage` and `reason` appear on failures only.

Slack: a `text` line with an icon plus an attachment (`danger` or `good`) with event, target and time fields. `&`, `<` and `>` are escaped as Slack requires.

### Secrets

Webhook and Slack URLs are secrets (a Slack URL is a bearer token). Setura never prints them: not in log lines, not in validation errors, not in `-h` output, and the request URL that Go's HTTP client normally embeds in transport errors is stripped. Logs name only the sink kind (`webhook` or `slack`) and the failure (`HTTP 404`, `connection refused`). Prefer the environment variables over flags in shared shells. Setura accepts only `http` and `https` URLs, and does not restrict hosts.

## History and `setura history`

`setura watch --history probes.jsonl` appends one JSON line per probe (the file is created with mode 0600); see [watch.md](watch.md).

    setura history probes.jsonl [--since 24h] [--route orders] [--format table|json]

For each route (target) it reports probes, uptime %, p50 and p95 latency (nearest rank, over all probes in the window) and the time and stage of the last failure. The window is the last `--since` (default 24h); it is compared with the window of equal length before it. A route is flagged as a regression when:

- uptime dropped by at least 1 percentage point, or
- p95 latency rose by at least 25% and at least 10 ms.

Routes with no data in the previous window show "no previous data" and are never flagged. `--route` keeps targets that equal or contain the text. Malformed lines are skipped and counted. The command exits 0 whether or not there are regressions; read the JSON (`regression`, `regression_reasons`) to gate on them. The file can also be passed as `--file`.
