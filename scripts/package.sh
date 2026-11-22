#!/bin/sh
# Build .deb and .rpm packages for linux/amd64 and linux/arm64 from the release
# archives in dist/ (run `make dist` first). Hand-built with tools/mkpkg (Go
# standard library only): no dpkg, rpm, fpm or nfpm.
#
# Usage: scripts/package.sh VERSION [DIST_DIR]      (VERSION without "v")
# Output: DIST/setura_VERSION_ARCH.deb and DIST/setura-VERSION-1.ARCH.rpm
#         (deb ARCH amd64|arm64, rpm ARCH x86_64|aarch64)
# Reproducible: timestamps come from SOURCE_DATE_EPOCH, else the last commit.
# Installed: /usr/bin/setura, man page, bash/zsh/fish completions, and under
# /usr/share/doc/setura the licence files and the systemd unit examples. Nothing
# is enabled or started.
set -eu

version=${1:?usage: package.sh VERSION [DIST_DIR]}
version=${version#v}
dist=${2:-dist}
root=$(cd "$(dirname "$0")/.." && pwd)

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
	SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)
fi
export SOURCE_DATE_EPOCH

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

(cd "$root" && go build -o "$tmp/mkpkg" ./tools/mkpkg)
comp=$tmp/completions
mkdir -p "$comp"
# Completion scripts do not depend on the architecture; generate them on the host.
(cd "$root" && go run ./cmd/setura completion bash > "$comp/bash" && go run ./cmd/setura completion zsh > "$comp/zsh" && go run ./cmd/setura completion fish > "$comp/fish")

built=0
for arch in amd64 arm64; do
	name=setura_${version}_linux_${arch}
	archive=$dist/$name.tar.gz
	[ -f "$archive" ] || { echo "package: $archive not found (run make dist VERSION=$version)" >&2; exit 1; }
	src=$tmp/src/$arch
	mkdir -p "$src"
	tar -xzf "$archive" -C "$src"
	src=$src/$name
	[ -f "$src/setura" ] || { echo "package: $archive has no setura binary" >&2; exit 1; }

	for fmt in deb rpm; do
		st=$tmp/stage/$arch.$fmt
		rm -rf "$st"
		mkdir -p "$st/usr/bin" "$st/usr/share/man/man1" "$st/usr/share/bash-completion/completions" \
			"$st/usr/share/fish/vendor_completions.d" "$st/usr/share/doc/setura/examples/systemd"
		install -m 755 "$src/setura" "$st/usr/bin/setura"
		gzip -9n -c "$src/man/setura.1" > "$st/usr/share/man/man1/setura.1.gz"
		install -m 644 "$comp/bash" "$st/usr/share/bash-completion/completions/setura"
		install -m 644 "$comp/fish" "$st/usr/share/fish/vendor_completions.d/setura.fish"
		if [ "$fmt" = deb ]; then zsh=usr/share/zsh/vendor-completions; else zsh=usr/share/zsh/site-functions; fi
		mkdir -p "$st/$zsh"
		install -m 644 "$comp/zsh" "$st/$zsh/_setura"
		for f in LICENSE NOTICE README.md; do install -m 644 "$src/$f" "$st/usr/share/doc/setura/$f"; done
		cp -R "$root/packaging/systemd/system" "$root/packaging/systemd/user" "$st/usr/share/doc/setura/examples/systemd/"
		install -m 644 "$root/packaging/systemd/README.md" "$st/usr/share/doc/setura/examples/systemd/README.md"
		find "$st" -type f ! -name setura -exec chmod 644 {} +
		chmod 755 "$st/usr/bin/setura"

		if [ "$fmt" = deb ]; then
			out=$dist/setura_${version}_${arch}.deb
			"$tmp/mkpkg" -format deb -root "$st" -out "$out" -version "$version" -arch "$arch" -mtime "$SOURCE_DATE_EPOCH"
		else
			case $arch in amd64) rarch=x86_64 ;; *) rarch=aarch64 ;; esac
			out=$dist/setura-${version}-1.${rarch}.rpm
			"$tmp/mkpkg" -format rpm -root "$st" -out "$out" -version "$version" -arch "$arch" -mtime "$SOURCE_DATE_EPOCH"
		fi
		built=$((built + 1))
	done
done
echo "built $built packages in $dist"
