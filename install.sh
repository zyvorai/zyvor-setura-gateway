#!/bin/sh
# Zyvor Setura installer. Downloads a release archive, verifies its sha256
# against checksums.txt and installs the binary (and man page).
#
# Usage: install.sh [--version X.Y.Z] [--prefix DIR] [--dry-run] [--help]
#   --version X.Y.Z  release to install (default: latest)
#   --prefix DIR     install into DIR/bin (default: ~/.local, or /usr/local as root)
#   --dry-run        print what would happen and change nothing
# Environment: SETURA_BASE_URL overrides the release download base (testing).
set -eu

REPO=zyvorai/zyvor-setura-gateway
BASE=${SETURA_BASE_URL:-https://github.com/$REPO/releases/download}

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

version=
prefix=
dry=0
while [ $# -gt 0 ]; do
	case $1 in
	--version) [ $# -ge 2 ] || die "--version needs a value"; version=$2; shift 2 ;;
	--version=*) version=${1#--version=}; shift ;;
	--prefix) [ $# -ge 2 ] || die "--prefix needs a value"; prefix=$2; shift 2 ;;
	--prefix=*) prefix=${1#--prefix=}; shift ;;
	--dry-run) dry=1; shift ;;
	-h | --help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "unknown argument: $1 (try --help)" ;;
	esac
done

case $(uname -s) in
Darwin) os=darwin ;;
Linux) os=linux ;;
*) die "unsupported OS: $(uname -s)" ;;
esac
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac

if [ -z "$prefix" ]; then
	if [ "$(id -u)" -eq 0 ]; then prefix=/usr/local; else prefix=$HOME/.local; fi
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "curl or wget is required"
fi
if command -v sha256sum >/dev/null 2>&1; then
	hash256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	hash256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	die "sha256sum or shasum is required"
fi

if [ -z "$version" ]; then
	if [ -n "${SETURA_BASE_URL:-}" ]; then die "set --version when using SETURA_BASE_URL"; fi
	if [ "$dry" -eq 1 ]; then
		version=latest
	else
		# Follow the /releases/latest redirect to learn the tag; no API token needed.
		command -v curl >/dev/null 2>&1 || die "curl is needed to resolve the latest version; pass --version"
		url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null || true)
		tag=${url##*/}
		case $tag in v[0-9]*) version=${tag#v} ;; *) die "could not determine the latest version; pass --version" ;; esac
	fi
fi
version=${version#v}
tag=v$version
archive=setura_${version}_${os}_${arch}.tar.gz

say "Setura $version for $os/$arch"
say "  download: $BASE/$tag/$archive"
say "  verify:   sha256 against $BASE/$tag/checksums.txt"
say "  install:  $prefix/bin/setura and $prefix/share/man/man1/setura.1"
if [ "$dry" -eq 1 ]; then say "dry run: nothing changed"; exit 0; fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
fetch "$BASE/$tag/$archive" "$tmp/$archive" || die "download failed: $archive"
fetch "$BASE/$tag/checksums.txt" "$tmp/checksums.txt" || die "download failed: checksums.txt"

want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || die "no checksum listed for $archive"
got=$(hash256 "$tmp/$archive")
[ "$want" = "$got" ] || die "checksum mismatch for $archive (expected $want, got $got)"
say "checksum ok"

tar -xzf "$tmp/$archive" -C "$tmp"
src=$tmp/setura_${version}_${os}_${arch}
[ -f "$src/setura" ] || die "archive does not contain setura"

mkdir -p "$prefix/bin"
cp "$src/setura" "$prefix/bin/setura.new"
chmod 755 "$prefix/bin/setura.new"
mv -f "$prefix/bin/setura.new" "$prefix/bin/setura"
if [ -f "$src/man/setura.1" ]; then
	mkdir -p "$prefix/share/man/man1"
	cp "$src/man/setura.1" "$prefix/share/man/man1/setura.1"
fi
say "installed $prefix/bin/setura"
case ":$PATH:" in *":$prefix/bin:"*) ;; *) say "note: add $prefix/bin to your PATH" ;; esac
