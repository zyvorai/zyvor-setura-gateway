#!/bin/sh
# Print the CHANGELOG.md section for a version (the text under "## X.Y.Z" up
# to the next "## " heading). Used for the GitHub release body.
# Usage: scripts/release-notes.sh VERSION [CHANGELOG]   (VERSION with or without "v")
# Exits 1 when the section is missing or empty so a release cannot ship without notes.
set -eu
version=${1:?usage: release-notes.sh VERSION [CHANGELOG]}
version=${version#v}
file=${2:-$(cd "$(dirname "$0")/.." && pwd)/CHANGELOG.md}
[ -f "$file" ] || { echo "release-notes: $file not found" >&2; exit 1; }

notes=$(awk -v v="$version" '
	/^## / {
		h = $0; sub(/^## +/, "", h); sub(/^\[/, "", h); sub(/^v/, "", h)
		split(h, w, /[] ]/)
		on = (w[1] == v)
		next
	}
	on { print }
' "$file")
# Trim leading and trailing blank lines.
notes=$(printf '%s\n' "$notes" | awk 'NF { p = 1 } p { print }' | awk '{ l[NR] = $0 } END { n = NR; while (n > 0 && l[n] == "") n--; for (i = 1; i <= n; i++) print l[i] }')
[ -n "$notes" ] || { echo "release-notes: no CHANGELOG section for $version in $file" >&2; exit 1; }
printf '%s\n' "$notes"
