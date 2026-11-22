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
    [--admin 127.0.0.1:19000] [--observe 30s] [--steps 10,50,100] \
    [--rollback-on-fail=true] [--max-error-rate 0] [--max-p95 0] \
    [--keep 10] [--force] [--format pretty|json]
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
   stops two rollouts from racing; delete it if a rollout was killed with SIGKILL.
3. **Atomic replace.** The candidate is written to a temp file in the same
   directory, fsynced and renamed over the live file (mode preserved, symlinks
   followed). The gateway notices on its next poll (`--interval`, default 1s).
   The command waits up to `--apply-timeout` (15s) until `/status` reports the
   content hash of the new file as applied with `lastReload.ok` and every Gateway
   `Accepted` and `Programmed`. If `lastReload` reports an error instead (lint
   gate, parse error, bind failure), the reload counts as rejected.
4. **Observe.** The checks file (same format as `setura check`) runs repeatedly
   for `--observe` (default 30s), `--probe-interval` apart (default 1s), at
   least once. Failures are measured against the thresholds below.
5. **Progressive weights (optional).** With `--steps 10,50,100`, a candidate that
   changes backend weights is applied in stages. A canary is a rule of the
   candidate with two or more `backendRefs` whose weights differ from the live
   file at the same resource and rule index. The ref whose weight grows most is
   the new backend; each step gives it that percentage and splits the remainder
   over the other refs in their candidate ratio. Every stage is applied with the
   same replace, wait and observe loop, and the candidate itself is applied last,
   byte for byte. Without a weight change, `--steps` is ignored with a note.
6. **Verdict.** Any of these triggers a restore:
   - a failed check (default: `--max-error-rate 0`, no tolerated failures; with a
     value above 0 the rate over the stage is judged at the end of its window),
   - `--max-p95 DUR` exceeded by the probe latency 95th percentile,
   - the reload was rejected or not applied in time,
   - the checks could not run, or the command was interrupted (SIGINT/SIGTERM).

   The previous config is written back atomically and the command waits for the
   gateway to confirm it. Exit 1 with the reason and evidence (failing URL, stage,
   reason). With `--rollback-on-fail=false` a failing config is left in place and
   the output says how to undo it (an interrupt always restores).

On success the exit code is 0 and the summary shows the generation before and
after, the stages with their probe counts, error rate and p95.

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
- Relative file references in the candidate (certificates) resolve against the
  live file's directory, because that is where the content ends up.
- The gateway only applies what it can parse and lint; the admin `/status` is the
  source of truth for "applied", not the file write.
- `--max-error-rate` is a fraction (`0.01` is 1%).
- In CI, use `--format json` and read `outcome` (`success`, `rolled_back`,
  `failed_in_place`, `refused`, `interrupted`), `reason` and `evidence`. See
  [ci.md](ci.md) for the other gates.
