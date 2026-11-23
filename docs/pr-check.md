# PR traffic-impact check

`setura pr-check` answers "what would merging this pull request do to our real
traffic?" It reads a recording of real requests, decides for every one which
route, rule, backends, filters and status the base config serves it with and
which the head config would, with the gateway's own match code and no network,
and reports the difference. It is built on the same ingestion and decision path
as [`setura replay`](replay.md) and [`setura why`](why.md): same log formats,
same precedence rules, same limits.

```
setura pr-check --base CONFIG_OR_DIR --head CONFIG_OR_DIR --traffic RECORDING
                [--format auto|table|json|markdown] [--fail-if-changed-over PCT]
                [--limit N] [--default-host HOST]
                [--base-rate-limit SPEC] [--head-rate-limit SPEC]
```

| Flag | Meaning |
|------|---------|
| `--base`, `--head` | A gateway snapshot file, or a directory holding one: `setura.json`, `gateway.json`, `snapshot.json`, `routes.json` or `config.json`, or the only `*.json` file with schema `setura.route-specs/v1`. Required. |
| `--traffic` | The recording: the built-in gateway's JSON or text access log or a Common/Combined Log Format file (Apache, nginx, load balancers). `-` is stdin; gzip is detected. Required. |
| `--format` | `auto` is a table on a terminal and JSON when piped. `markdown` (alias `md`) is GitHub-flavoured Markdown for a pull-request comment. |
| `--fail-if-changed-over PCT` | Exit 1 when more than PCT percent of the replayed requests are routed differently. `0` fails on any change. |
| `--limit N` | Examples per class (default 3). The route table shows at least 10 rows. |
| `--default-host` | The Host to replay Common Log Format lines with; that format records none. |
| `--base-rate-limit`, `--head-rate-limit` | The gateway's `--rate-limit` before and after, as `100/s[,burst=N][,key=ip\|route\|header:NAME]`. Rate limits are a gateway process flag, so the configs do not carry them. |

Exit status: `0` fine (or no limit asked for), `1` over `--fail-if-changed-over`,
`2` usage or input error (no replayable requests counts as one).

## What it reports

**The headline** is the share of recorded requests that are routed
differently: a different route, different backends, a new 404 or 500, a
newly served request, a redirect or a rewrite changed. That percentage is
what `--fail-if-changed-over` gates on.

**Impact classes**, each with its request count, share and representative
examples (the request shapes with the most traffic, each with its decision
under base and head):

| Class | Counts toward the headline | Meaning |
|-------|----------------------------|---------|
| `route` | yes | Served by a different route (a route that stops matching counts as no route). |
| `backend` | yes | Both serve it from backends, but not the same set. |
| `to404` | yes | Would turn into 404: no listener serves the host or no route matches. |
| `to500` | yes | Would turn into 500: the route matches but has no usable backend. |
| `served` | yes | Was 404 or 500 and is now served. |
| `redirect` | yes | A redirect added, removed, or with another status or target. |
| `rewrite` | yes | The URL rewrite (host, path) applied to the request differs; the example shows `path /v1/x -> /v2/x`. |
| `auth` | no | The rule's auth policy changed (`jwt`, `apiKey`, `basic`, `ipAllow`, `ipDeny`, `clientCert`, `externalAuth`). A new gate can answer 401 or 403. |
| `ratelimit` | no | The two `--*-rate-limit` policies differ. A tighter limit can answer 429; the title says when it is not tighter. |
| `filters` | no | Other filters changed: header modifiers, CORS, external auth. |
| `weights` | no | Same backends, different split. |
| `unknown` | no | A rule needing request headers could also match; the recording has none, so it is flagged, not guessed. |

**Per-route traffic share**, base against head, in percent of the recording and
in points of change, with a pseudo-route for requests that get no route
(`(404 no route)`, `(404 no listener)`, `(no-backend)`).

**New and removed routes**: routes attached in one config and not the other,
with how many recorded requests land on them (head) or used to (base).

## What it cannot know

* **403 and 429 are flagged, not simulated.** Whether a request is refused by an
  auth policy depends on credentials and client addresses the recording does not
  carry, and a rate limit depends on timing and per-client state. `pr-check`
  reports that a gate was added or a limit tightened and how many requests it
  covers; it does not claim they would be refused. Likewise per-request headers
  (the `unknown` class), retries and mirrors: see [replay.md](replay.md#what-replay-still-cannot-know).
* **The recording decides.** A request shape that is not in it is not checked.
  Use a recent, representative recording (a day of an access log is better than a
  smoke test), and treat 0% as "no recorded traffic changes", not "nothing changes".
* Weighted splits are deterministic in the comparison (the percentages), not
  sampled per request.

## Output

`--format json` is `setura.pr-check/v1`: `input` counters, `changed_requests`,
`changed_percent`, `classes` (with `examples`), `routes`, `new_routes`,
`removed_routes`, `rate_limit`, `fail_if_changed_over` and `failed`.
`--format markdown` starts with the hidden marker `<!-- setura-pr-check -->`
(so a workflow can update one sticky comment), then the verdict, an impact
table, new and removed routes, and collapsed `<details>` blocks with the route
table and the examples.

## CI

### GitHub Actions

Copy this to `.github/workflows/traffic-impact.yml`. It checks out the base and
the pull request, replays a recording kept in the repository, posts (and on
later pushes updates) one comment, and fails the check when more than 10% of the
traffic is routed differently.

```yaml
name: traffic-impact
on:
  pull_request:
    paths: ["gateway/**"]

permissions:
  contents: read
  pull-requests: write

jobs:
  pr-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: base
      - uses: actions/checkout@v4
        with:
          path: head
      - id: check
        uses: zyvorai/zyvor-setura-gateway@v0
        with:
          command: pr-check
          args: >-
            --base base/gateway --head head/gateway
            --traffic head/traffic/recording.jsonl.gz
            --format markdown --fail-if-changed-over 10
            > pr-comment.md
      - name: Comment on the pull request
        if: always()
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          test -s pr-comment.md || exit 0
          gh pr comment "${{ github.event.pull_request.number }}" --repo "$GITHUB_REPOSITORY" \
            --body-file pr-comment.md --edit-last --create-if-none
```

The comment step runs even when the check step fails, so the reviewer sees why.
`--edit-last --create-if-none` needs a recent `gh` (2.62 or later; the runner
image ships one); on older versions use a sticky-comment action keyed on the
`<!-- setura-pr-check -->` marker. Keep the recording in the repository
(a few MB of gzipped access log is enough), or download it from your log store in
an earlier step: `--traffic` takes any path or `-`. For pull requests from forks
`GITHUB_TOKEN` is read-only; use `pull_request_target` with care, or drop the
comment step and read the check output instead.

### GitLab CI

```yaml
traffic-impact:
  stage: test
  image: alpine:3.20
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes: ["gateway/**/*"]
  variables:
    GIT_DEPTH: "0"
  script:
    - apk add --no-cache curl git
    - curl -fsSL https://raw.githubusercontent.com/zyvorai/zyvor-setura-gateway/main/install.sh | sh -s -- --prefix /usr/local
    - mkdir base
    - git archive "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" gateway | tar -x -C base
    - rc=0
    - setura pr-check --base base/gateway --head gateway --traffic traffic/recording.jsonl.gz --format markdown --fail-if-changed-over 10 > pr-comment.md || rc=$?
    - 'test -s pr-comment.md && curl -fsS --request POST --header "PRIVATE-TOKEN: $GITLAB_TOKEN" --data-urlencode "body@pr-comment.md" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" > /dev/null || true'
    - exit $rc
  artifacts:
    when: always
    paths: [pr-comment.md]
```

`GITLAB_TOKEN` is a project access token with the `api` scope, stored as a masked
CI/CD variable. Without it the Markdown is still kept as a job artifact. Each run
adds a new note; delete the old one in a follow-up step if you prefer a single
note. Pin the install to a release (`install.sh --version X.Y.Z`) for
reproducible builds.

### Any other CI

```
setura pr-check --base base/ --head head/ --traffic recording.jsonl.gz \
    --format json --fail-if-changed-over 5 > pr-check.json
```

The exit status gates the job, and `pr-check.json` is the machine-readable report.
