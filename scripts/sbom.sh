#!/bin/sh
# Emit a simple JSON inventory (main module, build settings, dependencies)
# from `go version -m BINARY`. No external tools.
set -eu
bin=${1:?usage: sbom.sh BINARY}
go version -m "$bin" | awk '
function q(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return "\"" s "\"" }
BEGIN { printf "{\n  \"components\": [" ; n = 0 }
NR == 1 { goversion = $2 }
$1 == "path" { path = $2 }
$1 == "mod" { printf "%s\n    {\"type\": \"main\", \"name\": %s, \"version\": %s}", (n++ ? "," : ""), q($2), q($3) }
$1 == "dep" { printf "%s\n    {\"type\": \"library\", \"name\": %s, \"version\": %s, \"hash\": %s}", (n++ ? "," : ""), q($2), q($3), q($4) }
$1 == "build" { split($2, kv, "="); if (kv[1] == "GOOS" || kv[1] == "GOARCH" || kv[1] == "vcs.revision") b = b (b ? "," : "") "\n    " q(kv[1]) ": " q(substr($2, length(kv[1]) + 2)) }
END { printf "\n  ],\n  \"go\": %s,\n  \"build\": {%s\n  }\n}\n", q(goversion), b }'
