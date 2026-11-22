# setura watch

Continuous monitoring: re-run probes on an interval and print only state changes.

    setura watch URL [URL...] [flags]
    setura watch --file checks.json [flags]

`--file` takes the same JSON format as `setura check` (see `examples/checks.json`). URLs and `--file` can be combined.

## Output

Each target prints one baseline line on the first probe, then a line only when its state changes:

    2026-01-02T15:04:05Z  http://127.0.0.1:8080/  ok
    2026-01-02T15:04:25Z  http://127.0.0.1:8080/  ok -> failed at http: expected HTTP 200, received 500
    2026-01-02T15:04:35Z  http://127.0.0.1:8080/  failed -> ok

Reported changes: ok to failed, failed to ok, a different stage failing while still failing, and a new backend identity (when `--backend` is set, so the identity is observable). On exit (count, duration or Ctrl-C) a per-target summary is printed.

## Flags

| Flag | Meaning |
| --- | --- |
| `--interval D` | time between rounds, Go duration, default `10s`, minimum `1s` |
| `--count N` | stop after N rounds (0 = until interrupted) |
| `--duration D` | stop after D (0 = until interrupted) |
| `--file FILE` | checks.json style cases |
| `--listen ADDR` | serve metrics, for example `127.0.0.1:9464` |
| `--allow-remote` | permit a non-loopback `--listen` address |
| `--history FILE` | append one JSON line per probe |
| `--backend --ca --address --status --timeout --header --body-contains --max-ms` | per-URL assertions, as in `setura explain` |

## Exit codes

0: last state of every target is ok (or the run was interrupted while all were ok). 1: the last state of any target is failing. 2: usage or setup error, including an invalid URL or a refused `--listen`.

## Metrics

`--listen` serves `/metrics` (Prometheus text format 0.0.4) and `/healthz`. Binding is refused unless the address is loopback (`127.0.0.1`, `::1`, `localhost`) or `--allow-remote` is given.

- `setura_probe_up{target}`: 1 if the last probe passed
- `setura_probe_duration_seconds{target}`: last probe duration
- `setura_probe_stage_ok{target,stage}`: 1/0 per stage; untested and unused stages are omitted
- `setura_probe_total{target,result}`: counters, `result` is `ok` or `failed`

## History

Each probe appends a line such as:

    {"time":"2026-01-02T15:04:05Z","target":"http://x/","ok":false,"failing_stage":"http","elapsed_ms":3.2}

`failing_stage` is empty when the probe passed. The file is created with mode 0600.

## Limits

Backend identity changes are only visible when `--backend` (or `backend` in the file) is set, because the probe records identity only for the asserted header. Changes in failure reason within the same stage are not reported.
