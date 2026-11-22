#!/bin/sh
# Test install.sh against a local fake release (file:// via SETURA_BASE_URL).
# cosign is faked (SETURA_COSIGN) so signature handling is tested without network.
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

# A fake cosign that records its arguments and passes or fails on demand.
cat > "$tmp/cosign-ok" <<'EOF'
#!/bin/sh
echo "$@" >> "$COSIGN_LOG"
[ "$1" = verify-blob ] || exit 3
EOF
cat > "$tmp/cosign-bad" <<'EOF'
#!/bin/sh
echo "Error: none of the expected identities matched" >&2
exit 1
EOF
chmod 755 "$tmp/cosign-ok" "$tmp/cosign-bad"
export COSIGN_LOG="$tmp/cosign.log"
export SETURA_COSIGN="$tmp/no-such-cosign" # default: no cosign

# --help prints the usage block
sh "$root/install.sh" --help | grep -q -- '--uninstall' || fail "--help"

# dry run changes nothing
sh "$root/install.sh" --version $v --prefix "$tmp/dry" --dry-run > "$tmp/out"
grep -q 'dry run' "$tmp/out" || fail "dry-run output"
grep -q 'checksum only' "$tmp/out" || fail "dry-run should mention missing cosign"
[ ! -e "$tmp/dry" ] || fail "dry-run created files"

# real install (no cosign: checksum only, with a note)
sh "$root/install.sh" --version "v$v" --prefix "$tmp/ok" > "$tmp/out"
grep -q 'only the checksum is verified' "$tmp/out" || fail "missing no-cosign note"
[ "$("$tmp/ok/bin/setura")" = "setura $v" ] || fail "installed binary"
[ -f "$tmp/ok/share/man/man1/setura.1" ] || fail "man page"

# uninstall: dry run keeps files, real run removes them, a second run is harmless
sh "$root/install.sh" --uninstall --prefix "$tmp/ok" --dry-run > "$tmp/out"
grep -q 'would remove' "$tmp/out" || fail "uninstall dry-run output"
[ -x "$tmp/ok/bin/setura" ] || fail "uninstall --dry-run removed the binary"
sh "$root/install.sh" --uninstall --prefix "$tmp/ok" > /dev/null
[ ! -e "$tmp/ok/bin/setura" ] || fail "binary not uninstalled"
[ ! -e "$tmp/ok/share/man/man1/setura.1" ] || fail "man page not uninstalled"
sh "$root/install.sh" --uninstall --prefix "$tmp/ok" > /dev/null || fail "second uninstall"
if sh "$root/install.sh" --uninstall --version $v --prefix "$tmp/ok" > /dev/null 2>&1; then fail "--uninstall --version accepted"; fi

# signature: valid signature installs and passes the right identity and issuer
printf '{}' > "$rel/checksums.txt.sigstore.json"
SETURA_COSIGN=$tmp/cosign-ok sh "$root/install.sh" --version $v --prefix "$tmp/sig" > "$tmp/out"
grep -q 'signature ok' "$tmp/out" || fail "signature ok not reported"
grep -q 'verify-blob --bundle' "$tmp/cosign.log" || fail "cosign not called"
grep -q 'certificate-oidc-issuer https://token.actions.githubusercontent.com' "$tmp/cosign.log" || fail "issuer not pinned"
grep -q 'workflows/release' "$tmp/cosign.log" || fail "identity not pinned to the release workflow"
[ -x "$tmp/sig/bin/setura" ] || fail "signed install"

# signature: a failing verification aborts before anything is installed
if SETURA_COSIGN=$tmp/cosign-bad sh "$root/install.sh" --version $v --prefix "$tmp/badsig" > /dev/null 2> "$tmp/err"; then
	fail "bad signature accepted"
fi
grep -q 'signature verification failed' "$tmp/err" || fail "expected signature failure"
[ ! -e "$tmp/badsig/bin/setura" ] || fail "binary installed despite bad signature"
# ... unless the check is explicitly skipped
SETURA_COSIGN=$tmp/cosign-bad sh "$root/install.sh" --version $v --prefix "$tmp/skip" --no-signature-check > /dev/null
[ -x "$tmp/skip/bin/setura" ] || fail "--no-signature-check install"

# signature: a missing bundle is an error when cosign exists
rm "$rel/checksums.txt.sigstore.json"
if SETURA_COSIGN=$tmp/cosign-ok sh "$root/install.sh" --version $v --prefix "$tmp/nobundle" > /dev/null 2> "$tmp/err"; then
	fail "missing bundle accepted"
fi
grep -q 'signature bundle missing' "$tmp/err" || fail "expected missing bundle error"

# --require-signature without cosign fails
if sh "$root/install.sh" --version $v --prefix "$tmp/req" --require-signature > /dev/null 2> "$tmp/err"; then
	fail "--require-signature without cosign accepted"
fi
grep -q 'needs cosign' "$tmp/err" || fail "expected cosign requirement error"

# tampered archive is rejected and nothing is installed
echo tamper >> "$rel/$name.tar.gz"
if sh "$root/install.sh" --version $v --prefix "$tmp/bad" > /dev/null 2> "$tmp/err"; then
	fail "tampered archive accepted"
fi
grep -q 'checksum mismatch' "$tmp/err" || fail "expected checksum mismatch"
[ ! -e "$tmp/bad/bin/setura" ] || fail "tampered binary installed"

# missing version with override is a usage error
if sh "$root/install.sh" --prefix "$tmp/x" > /dev/null 2>&1; then fail "no version accepted"; fi
if sh "$root/install.sh" --bogus > /dev/null 2>&1; then fail "unknown flag accepted"; fi
echo "install.sh tests passed"
