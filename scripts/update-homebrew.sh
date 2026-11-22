#!/bin/sh
# Render packaging/homebrew/Formula/setura.rb for a version from dist/checksums.txt.
# Usage: scripts/update-homebrew.sh VERSION [CHECKSUMS_FILE]   (VERSION without "v")
set -eu

version=${1:?usage: update-homebrew.sh VERSION [CHECKSUMS_FILE]}
version=${version#v}
sums=${2:-dist/checksums.txt}
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/packaging/homebrew/Formula/setura.rb

[ -f "$sums" ] || { echo "update-homebrew: $sums not found (run make dist)" >&2; exit 1; }

sha() {
	s=$(awk -v f="setura_${version}_$1.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$sums")
	[ -n "$s" ] || { echo "update-homebrew: no checksum for $1 in $sums" >&2; exit 1; }
	printf '%s' "$s"
}

da=$(sha darwin_arm64)
dx=$(sha darwin_amd64)
la=$(sha linux_arm64)
lx=$(sha linux_amd64)

mkdir -p "$(dirname "$out")"
sed -e "s/@VERSION@/$version/g" \
	-e "s/@SHA_DARWIN_ARM64@/$da/" \
	-e "s/@SHA_DARWIN_AMD64@/$dx/" \
	-e "s/@SHA_LINUX_ARM64@/$la/" \
	-e "s/@SHA_LINUX_AMD64@/$lx/" \
	"$root/packaging/homebrew/setura.rb" > "$out"
echo "wrote $out"
