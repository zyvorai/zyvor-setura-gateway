# Terminal experience

Human output is calm and typographic: one aligned row per item, a single
verdict line, and a `Next:` hint on failure. JSON output is never affected.

## Color and symbols

| Control | Effect |
| --- | --- |
| `--color auto` (default) | Color only when stdout is a terminal, `NO_COLOR` is unset and `TERM` is not `dumb` |
| `--color always` / `never` | Force on or off (an explicit flag overrides `NO_COLOR`) |
| `--ascii` | Use `+ x ! - .` instead of `✓ ✗ ▲ – ·` (also implied by `TERM=dumb`) |

`--color` and `--ascii` are global and may appear anywhere on the command line.
Palette: blue `#2997ff`, green `#30d158`, red `#ff453a`, amber `#ffd60a`, gray
`#86868b`. 24-bit color is used when `COLORTERM` is `truecolor` or `24bit`,
otherwise 256-color.

## Which commands print what

| Command | Terminal | Piped / redirected |
| --- | --- | --- |
| `explain` | stage rows and verdict (`--json` for JSON) | same text, no escapes |
| `lint` | grouped by resource (`--format json` for JSON) | same text, no escapes |
| `check` | table of cases | **JSON** |
| `doctor` | checklist | **JSON** |
| `gate`, `compare` | attempt / target summary | **JSON** |

`check`, `doctor`, `gate` and `compare` accept `--format auto|pretty|json`.
`auto` (the default) picks pretty on a terminal and JSON otherwise, so existing
scripts and CI keep receiving the same JSON. Use `--format json` to force JSON
on a terminal. `gate` and `compare` render their summary when the run finishes.

## Help and errors

`setura --help` shows commands grouped as Verify, Inspect, Analyze, Publish and
Utilities. `setura COMMAND -h` shows flags and an example. Unknown commands
suggest the nearest name; missing arguments print an example. Usage errors
exit 2, failed verification exits 1, success exits 0.

`setura version --verbose` adds Go version, platform and VCS build info.
