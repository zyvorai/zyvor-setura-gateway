# Guarded rollout for the built-in gateway

`setura gateway rollout` changes the configuration of a running
`setura gateway run --config live.json` safely: it lints the candidate, backs up
the live file, swaps it atomically, waits for the gateway to confirm the new
generation, then probes the gateway with your checks file. If anything looks
wrong it puts the previous config back and exits 1.

It uses only things the gateway already has: the file poller (hot reload) and the
admin `/status` document. Nothing is restarted and no cluster is touched.

```
setura gateway rollout --config live.json --new candidate.json --checks checks.json \
    [--admin 127.0.0.1:19000] [--observe 30s] [--steps 10,50,100 | --no-steps] \
    [--rollback-on-fail=true] [--max-error-rate 0] [--max-p95 0] \
    [--keep 10] [--lock-timeout 1m] [--force] [--format pretty|json]
setura gateway history  --config live.json [--format pretty|json]
setura gateway rollback --config live.json [--to ID] [--admin ADDR]
```

## What a rollout does

1. **Lint.** The candidate runs through the same lint rules as `setura lint`.
   Errors refuse the rollout (exit 1, nothing touched) unless `--force`. The
   running gateway applies its own lint gate too, so with `--force` a candidate
   with errors is still rejected by the gateway unless it was started with
   `--force`; that rejection is handled as a failed reload (step 3).
2. **Backup.** The live file is copied to `.setura-history/` next to it, with a
   sidecar `.meta.json` (time, admin generation, lint status, diff summary).
   Only the newest `--keep` backups are retained. A `lock` file in that directory
   stops two rollouts from racing (see "The lock" below); a rollout killed with
   SIGKILL does not leave it behind for good.
3. **Atomic replace.** The candidate is written to a temp file in the same
   directory, fsynced and renamed over the live file (mode preserved, symlinks
   followed). The gateway notices on its next poll (`--interval`, default 1s).
   The command waits up to `--apply-timeout` (15s) until `/status` reports the
   content hash of the new file as applied with `lastReload.ok` and every Gateway
   `Accepted` and `Programmed`. If `lastReload` reports an error instead (lint
   gate, parse error, bind failure), the reload counts as rejected.
4. **Observe.** Two sources are read across each stage's window and both are
   measured against the thresholds below:
   - the **probes**: the checks file (same format as `setura check`) runs
     repeatedly for `--observe` (default 30s), `--probe-interval` apart (default
     1s), at least once;
   - the **gateway's own counters**: `/stats` (requests and 5xx per route and
     backend) and `/metrics` (request duration histograms per route and
     backend `setura_gateway_request_duration_seconds` and
     `setura_gateway_backend_request_duration_seconds`) are read when the window
     opens and again after every probe round. The deltas are what the gateway
     served during the window, including traffic that is not yours, so real
     users count. Only the series the candidate touches are judged: the routes
     it adds or changes, the backends they reference, and the backends it adds
     or changes (every series when the candidate touches none of these, for
     example when only a Gateway changes). The report shows the window next to
     the cumulative error rate from before it.

   If the admin API cannot serve `/stats` or `/metrics` the rollout says so
   (`gatewayStats` in the JSON) and rests on the probes.
5. **Progressive weights.** When the candidate changes the weights of a canary
   rule it is applied in stages, `10,50,100` by default (see below); `--steps`
   chooses other percentages and `--no-steps` applies the candidate directly. A
   canary is a rule of the candidate with two or more `backendRefs` whose weights
   differ from the live file at the same resource and rule index. The ref whose
   weight grows most is the new backend; each step gives it that percentage and
   splits the remainder over the other refs in their candidate ratio. Every stage
   is applied with the same replace, wait and observe loop, and the candidate
   itself is applied last. When nothing changes weights, no stages are added
   and the candidate is applied directly; an explicit `--steps` then prints a
   note that it was ignored.
6. **Verdict.** Any of these triggers a restore:
   - a failed check or a gateway 5xx (default: `--max-error-rate 0`, no
     tolerated failures; with a value above 0 the rate over the stage is judged
     at the end of its window, per route and backend for the gateway source),
   - `--max-p95 DUR` exceeded by the probe latency 95th percentile, or by the
     95th percentile of a route or backend in the gateway's histogram delta
     (judged once the series has at least 5 requests in the window; the value is
     interpolated inside the histogram bucket, so it is an estimate),
   - the reload was rejected or not applied in time,
   - the checks could not run, or the command was interrupted (SIGINT/SIGTERM).

   The report says which source tripped: `trippedBy` is `probes`,
   `gateway /stats`, `gateway /metrics`, `apply` or `interrupt`, and the pretty
   output prints `tripped by: ...` with the evidence (the failing URL, or the
   route or backend and its counts).

   The previous config is written back atomically and the command waits for the
   gateway to confirm it. Exit 1 with the reason and evidence (failing URL, stage,
   reason). With `--rollback-on-fail=false` a failing config is left in place and
   the output says how to undo it (an interrupt always restores).

On success the exit code is 0 and the summary shows the generation before and
after, the stages with their probe counts, error rate and p95, and the gateway's
request count, 5xx rate and p95 for the window.

## Default stages

`--steps` is optional. If it is absent and the candidate changes the weights of
a canary rule, the rollout uses `10,50,100` and says so (`stepsNote` in the JSON
and a line on stderr). Pass `--no-steps` to apply such a candidate in one go, or
`--steps` for other stages. A candidate without a weight change is applied
directly either way. `--steps` together with `--no-steps` is a usage error.

## The lock

`.setura-history/lock` holds a JSON record: `pid`, `host`, `started`, a
`heartbeat` that the owner rewrites atomically every 5 seconds, and a random
token. A second rollout finds the lock and decides whether its owner is alive:

- same host: the process is checked (`kill -0`). If it is gone the lock is stale
  whatever the heartbeat says; if it is running the lock is never taken, however
  old its heartbeat is (a stopped but live process is still an owner);
- another host (a shared directory, for example): there is no process to check,
  so only the heartbeat counts. It is stale when older than `--lock-timeout`
  (default 1m, twelve heartbeats);
- a lock in the old format (just a pid) is judged by the pid on this host.

A stale lock is moved aside with an atomic rename (of two rollouts taking over
at once only one succeeds), verified to be the record that was judged, deleted,
and the rollout prints `took over a stale rollout lock (pid ..., host ..., last
heartbeat ...): <reason>`. A live owner is refused with its pid, host, start and
heartbeat age, exit 2. Release removes the lock only while the token is still
yours.

## Exit codes

| code | meaning |
|------|---------|
| 0 | rollout succeeded (or history/rollback succeeded) |
| 1 | refused by lint, or failed and was rolled back (or left in place) |
| 2 | usage or setup error: bad flags, unreadable files, admin API unreachable, lock held |

## History and rollback

`setura gateway history` lists backups newest first: ID, time, the admin
generation when it was taken, lint status of the backed up config and a diff
summary of what replaced it (`~` changed, `+` added, `-` removed resources and
backends). `setura gateway rollback` restores the newest backup, or `--to ID`
(a unique prefix is enough). The config being replaced is itself backed up first,
so a rollback can be rolled back. If the admin API is unreachable the file is
still restored and the output says the reload is unconfirmed.

## Notes

- The checks file must point at the gateway being changed (URL plus `address`).
  It should assert the behavior you want from the candidate, for example
  `body_contains` or `backend` identity. See `examples/checks.json`.
- Relative certificate paths (`secrets.*.certFile` and `keyFile`) in the
  candidate always resolve against the **candidate file's directory**, where you
  prepared them, and the rollout reports the directory (`certDir` in the JSON, a
  line on stderr). The gateway itself resolves relative paths against the
  directory of the file it serves, so when the two directories differ the
  installed config is written with absolute paths (the one case where the
  candidate is not applied byte for byte); when they are the same nothing is
  rewritten. A referenced file that does not exist in the candidate's
  directory refuses the rollout, naming it (and noting when it exists next to
  the live file instead); `--force` goes ahead anyway.
- The gateway only applies what it can parse and lint; the admin `/status` is the
  source of truth for "applied", not the file write.
- `--max-error-rate` is a fraction (`0.01` is 1%) and `--max-p95` a duration;
  both apply to the probes and to the gateway's own `/stats` and `/metrics`.
- The gateway source counts every request of the judged routes, not just your
  probes. With the default zero tolerance a single 5xx from real traffic during
  the window rolls the change back; set `--max-error-rate` for a noisy service.
- In CI, use `--format json` and read `outcome` (`success`, `rolled_back`,
  `failed_in_place`, `refused`, `interrupted`), `reason` and `evidence`. See
  [ci.md](ci.md) for the other gates.

## Limits

- The gateway source needs a gateway that publishes the duration histograms
  (this version and later). Against an older gateway the rollout falls back to
  probes and says so.
- The p95 from the gateway is a bucket-interpolated estimate (buckets from 5 ms
  to 10 s); latencies above 10 s are reported as 10 s.
- Counters reset when the gateway restarts; a window in which that happens has
  no gateway delta and is judged on the probes alone.
- The heartbeat protects against killed owners, not against a clock that is
  wrong by more than `--lock-timeout` on a shared directory between hosts.
