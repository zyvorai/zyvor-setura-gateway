# SLOs and burn rates

`setura slo` (and `setura history --slo`) measure availability and latency
objectives and report how fast the error budget burns, using the multi-window,
multi-burn-rate method of the Google SRE Workbook.

    setura slo --history probes.jsonl                       # from setura watch --history
    setura slo --admin 127.0.0.1:19000 --state slo.jsonl    # from the gateway's own /metrics
    setura history probes.jsonl --slo --slo-config slo.json
    setura slo --history probes.jsonl --latency-ms 300      # add a latency SLO to the default availability one

Output is one verdict line, a short block per SLO and, when something needs
attention, a `Next:` hint:

      ! Budget is burning slowly  2 SLOs from probes probes.jsonl

      ✓ orders-availability  99.9% over 30d
        99.982% now  ·  budget left 82%
        burn 5m 0.0x  ·  30m 0.0x  ·  1h 0.3x  ·  6h 0.2x  ·  3d 0.1x

      ▲ orders-latency  99% under 300ms over 30d
        98.7% now  ·  budget left -30%  ·  data covers 40% of the window
        burn 5m 0.4x  ·  ...

      Next: See which route regressed with: setura history probes.jsonl --since 1h

`NO_COLOR`, `--color never` and `--ascii` are respected (`--ascii` swaps the
glyphs for `+ ! x`). `--format json` prints the full result.

## How it is computed

* The **error budget** of an objective of 99.9% is 0.1% of events.
* The **burn rate** over a window is the observed bad-event ratio divided by the
  budget ratio. A burn rate of 1 spends the budget exactly over the SLO window;
  14.4 spends 2% of a 30 day budget in one hour.
* A **burn rule** fires when the burn rate is at or above its factor over both its
  long and its short window. The short window makes the alert stop quickly once
  the problem is fixed.
* The built-in rules are the Workbook's: `1h/5m` at 14.4x (page), `6h/30m` at 6x
  (page), `3d/6h` at 1x (ticket).
* **Status** per SLO: `burning` (a page rule fires), `breached` (the budget over
  the SLO window is spent), `at_risk` (a ticket rule fires), `no_data`, `ok`. The
  verdict is the worst of them.
* A window is only believed when the data spans at least half of it; with less, its
  burn rate is shown as `no data` and the rule cannot fire. The compliance figure
  (`SLI`, budget left) is computed from whatever data there is and says how much of the
  window it covers.

Exit status: `--fail-on page` (default) exits 1 for `burning` and `breached`,
`ticket` also for `at_risk`, `never` always exits 0.

## Data sources

**Probe history** (`--history FILE`, written by `setura watch --history`).
Availability: a probe is good when it succeeded. Latency: among successful
probes, one is good when `elapsed_ms` is at or below `threshold_ms`.

**Gateway metrics** (`--admin ADDR`, the default). Availability uses
`setura_gateway_route_requests_total` (bad = `code="5xx"`); latency uses the
`setura_gateway_request_duration_seconds` histogram of all requests (bad = slower than
the threshold). A scrape holds lifetime counters, so burn rates need samples over
time: pass `--state FILE` and run the command on a schedule (every minute is fine).
Each run appends a sample per SLO and the burn rate over a window is the counter
growth between the oldest sample inside the window and the newest. A gateway restart
(counters going down) is detected and the new value counts as growth. Without
`--state` there is a single sample: the report says `no data` for burn rates. A
latency threshold that falls between histogram buckets is measured at the bucket
below it, and the report says so (`measured at the 250ms histogram bucket`). The
admin token is sent from `SETURA_ADMIN_TOKEN`, as for the other admin commands.

The state file is JSON Lines (`{"t":...,"slo":NAME,"total":N,"bad":N}`); samples older
than twice the longest window are dropped on each run.

## Config file

JSON (`--config slo.json`). Unknown fields are rejected.

```json
{
  "slos": [
    {"name": "orders-availability", "type": "availability", "objective": 99.9, "window": "30d", "route": "orders"},
    {"name": "orders-latency", "type": "latency", "objective": 99, "threshold_ms": 300, "window": "30d", "route": "orders"}
  ],
  "burn": [
    {"long": "1h", "short": "5m",  "factor": 14.4, "severity": "page"},
    {"long": "6h", "short": "30m", "factor": 6,    "severity": "page"},
    {"long": "3d", "short": "6h",  "factor": 1,    "severity": "ticket"}
  ]
}
```

| Field | Meaning |
|---|---|
| `slos[].name` | Unique name. |
| `slos[].type` | `availability` or `latency`. |
| `slos[].objective` | Percent of good events, above 0 and below 100, for example `99.9`. |
| `slos[].window` | Compliance window, `30d` by default. Durations accept `m`, `h`, `d`, `w`. |
| `slos[].route` | Only events of routes (or probe targets) equal to or containing this text. |
| `slos[].threshold_ms` | Latency SLOs: a request is good when it is at least this fast. Required for `latency`. |
| `burn` | Optional; defaults to the three rules above. `short` must be shorter than `long`; `severity` is `page` or `ticket`. |

Without `--config`, flags build one availability SLO (`--objective 99.9`,
`--window 30d`, `--route`) and optionally a latency SLO (`--latency-ms`,
`--latency-objective 99`).

## Prometheus alerts

The same ideas run continuously in Prometheus with the
[alerts](observability.md#prometheus-grafana-and-alertmanager) shipped in the Helm chart
and `setura gateway install --with-monitoring`; `setura slo` is for a quick answer from a
laptop, a CI gate (`--fail-on`) or a probe-only setup.
