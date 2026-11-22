#!/bin/sh
# Write one SBOM (scripts/sbom.sh JSON inventory) per release archive in DIR,
# named like the archive with .sbom.json instead of .tar.gz. No external tools.
# Usage: scripts/sbom-dist.sh [DIR]   (default dist)
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:-dist}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
found=0
for a in "$dir"/setura_*.tar.gz; do
	[ -f "$a" ] || continue
	found=1
	name=$(basename "$a" .tar.gz)
	tar -xzf "$a" -C "$tmp" "$name/setura"
	sh "$root/scripts/sbom.sh" "$tmp/$name/setura" > "$dir/$name.sbom.json"
	rm -rf "${tmp:?}/$name"
	echo "wrote $dir/$name.sbom.json"
done
[ "$found" -eq 1 ] || { echo "sbom-dist: no archives in $dir (run make dist)" >&2; exit 1; }
