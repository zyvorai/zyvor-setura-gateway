# CI integrations

## GitHub Action

```yaml
jobs:
  gateway-lint:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: zyvorai/zyvor-setura-gateway@v0
        with:
          version: latest          # or a release such as 0.5.0
          command: lint
          args: --snapshot snapshot.json --manifest-dir k8s --format sarif --baseline .setura-baseline.json > setura.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: setura.sarif
```

The action downloads the release archive for the runner OS and architecture
(Linux and macOS, amd64 and arm64), verifies it against `checksums.txt` with
SHA-256, caches it under `$RUNNER_TOOL_CACHE`, and runs `setura COMMAND ARGS`.
With no `command` it only installs setura onto `PATH`.

## Output formats

| Command | Flag | Result |
| --- | --- | --- |
| `lint` | `--format sarif` | SARIF 2.1.0 on stdout: rules table, results with logical locations such as `HTTPRoute/ns/name` |
| `lint` | `--format github` | `::error title=SET002::...` / `::warning ...` workflow commands |
| `check` | `--sarif OUT` | writes SARIF; each failed probe stage is a result (`SETCHK-DNS` ... `SETCHK-ASSERT`) |
| `check` | `--format github` | annotations instead of JSON on stdout |

Messages are escaped for workflow commands (`%`, CR and LF; properties also
escape `:` and `,`).

Snapshots carry no file positions. Pass `--manifest-dir DIR` to `lint` and the
findings for a Gateway or HTTPRoute found in YAML or JSON manifests below DIR
(matched on `kind` and `metadata.name`, plus `namespace` when present) carry
`file` and `line` in SARIF and annotations. The YAML scan is a small
line-based reader of `kind` and `metadata.name`/`namespace` only.

## Adopting lint on an existing cluster

```sh
setura lint --snapshot snapshot.json --write-baseline .setura-baseline.json   # record today's findings
setura lint --snapshot snapshot.json --baseline .setura-baseline.json         # CI: only new findings fail
setura lint --snapshot snapshot.json --disable SET004,SET009 --severity-override SET006=error
```

A fingerprint is `RULE:resource:sha256(message)[:12]`; severity is not part of
it. `--write-baseline` writes every finding left after `--disable` and
`--severity-override`, then reports clean. Baselined findings are counted as
`suppressed` in JSON and text output. Unknown rule IDs or severities exit 2.

## pre-commit

```yaml
repos:
  - repo: https://github.com/zyvorai/zyvor-setura-gateway
    rev: v0.5.0
    hooks:
      - id: setura-lint
```

The hook runs `setura lint --snapshot FILE` for files named `*snapshot*.json`.
