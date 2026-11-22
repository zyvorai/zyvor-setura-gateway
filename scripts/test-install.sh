#!/bin/sh
# Test install.sh against a local fake release (file:// via SETURA_BASE_URL).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in x86_64 | amd64) arch=amd64 ;; *) arch=arm64 ;; esac
v=9.9.9
name=setura_${v}_${os}_${arch}
rel=$tmp/rel/v$v
mkdir -p "$rel" "$tmp/pkg/$name/man"
printf '#!/bin/sh\necho setura %s\n' "$v" > "$tmp/pkg/$name/setura"
chmod 755 "$tmp/pkg/$name/setura"
echo '.TH SETURA 1' > "$tmp/pkg/$name/man/setura.1"
tar -C "$tmp/pkg" -czf "$rel/$name.tar.gz" "$name"
if command -v sha256sum >/dev/null 2>&1; then
	(cd "$rel" && sha256sum "$name.tar.gz" > checksums.txt)
else
	(cd "$rel" && shasum -a 256 "$name.tar.gz" > checksums.txt)
fi
export SETURA_BASE_URL="file://$tmp/rel"

# dry run changes nothing
sh "$root/install.sh" --version $v --prefix "$tmp/dry" --dry-run > "$tmp/out"
grep -q 'dry run' "$tmp/out" || fail "dry-run output"
[ ! -e "$tmp/dry" ] || fail "dry-run created files"

# real install
sh "$root/install.sh" --version "v$v" --prefix "$tmp/ok" > /dev/null
[ "$("$tmp/ok/bin/setura")" = "setura $v" ] || fail "installed binary"
[ -f "$tmp/ok/share/man/man1/setura.1" ] || fail "man page"

# tampered archive is rejected and nothing is installed
echo tamper >> "$rel/$name.tar.gz"
if sh "$root/install.sh" --version $v --prefix "$tmp/bad" > /dev/null 2> "$tmp/err"; then
	fail "tampered archive accepted"
fi
grep -q 'checksum mismatch' "$tmp/err" || fail "expected checksum mismatch"
[ ! -e "$tmp/bad/bin/setura" ] || fail "tampered binary installed"

# missing version with override is a usage error
if sh "$root/install.sh" --prefix "$tmp/x" > /dev/null 2>&1; then fail "no version accepted"; fi
echo "install.sh tests passed"
