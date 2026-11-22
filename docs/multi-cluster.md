# Multiple kube contexts

`check`, `snapshot`, `gate` and `lint` can verify several clusters in one run.

    setura --context prod-eu,prod-us lint -n apps --format json
    setura snapshot --context prod-eu,prod-us -n apps
    setura --all-contexts gate orders https://orders.example.com/ --gateway edge --backend orders-v2 -n apps
    setura check checks.json --context prod-eu,prod-us

`--context` takes a comma separated list (duplicates are dropped). `--all-contexts` runs against every context from `kubectl config get-contexts -o name`; it cannot be combined with `--context`. Both flags work before or after the command. Any other command refuses a list, and a single context behaves exactly as before, with unchanged output.

Contexts run in parallel, each with its own kubectl `--context`. Setura only reads, as with a single context.

## Output

With more than one context the output is merged and every record carries a `context` field.

| Command | JSON shape |
| --- | --- |
| `check` | array of probe rows, each with `context` |
| `gate` | `{"ok", "contexts": [{"context", ...gate result}]}` |
| `lint` | `{"ok", "errors", "warnings", "findings": [{"context", ...}], "contexts": [{"context","ok","errors","warnings"}]}` |
| `snapshot` | `{"contexts": [{"context", "snapshot": {...}}]}` |

A context that fails to run (unreachable, bad credentials) appears as `{"context", "ok": false, "error": "..."}` and the others still run. The message is also written to stderr.

On a terminal, `check` and `gate` print a table with a CONTEXT column, and `lint --format text` (the default) prefixes each finding with its context. `--format json` forces JSON anywhere. `sarif`, `github`, `--junit`, `--sarif`, `--snapshot` and `--write-baseline` are rejected with several contexts (exit 2) because they describe a single source.

## Exit codes

Unchanged: 0 all contexts passed, 1 at least one check, gate or lint failed, 2 usage or input error, including any context that could not be queried. The highest code wins.

## `check` and the `{context}` placeholder

`check` does not read the cluster, so running the same file for each context would be redundant. Setura therefore replaces `{context}` in the check file (JSON-escaped) before each run, for example:

    [{"url": "https://orders.{context}.example.com/health", "backend": "orders-v2"}]

Use it in `url`, `address` or any other string field. Without the placeholder the same cases run once per context.

## Limits

- The snapshot produced by a multi-context run is not itself a `lint --snapshot` input; take per-context snapshots with a single `--context` for that.
- Contexts are not named in kubectl errors beyond the `context` field.
