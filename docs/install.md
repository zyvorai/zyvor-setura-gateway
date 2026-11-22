# Installing Zyvor Setura

Release archives are named `setura_VERSION_OS_ARCH.tar.gz` (darwin and linux,
amd64 and arm64) and contain `setura`, `man/setura.1`, `LICENSE`, `NOTICE` and
`README.md`. Each release also publishes `checksums.txt`.

## Homebrew

A formula template lives in `packaging/homebrew/setura.rb`. After
`make dist VERSION=X.Y.Z`, render it with:

    scripts/update-homebrew.sh X.Y.Z

which writes `packaging/homebrew/Formula/setura.rb` with the sha256 values
from `dist/checksums.txt`. Publishing that file to a tap is a manual step.
The formula installs the man page and bash, zsh and fish completions.

## install.sh

    sh install.sh                      # latest release into ~/.local/bin
    sh install.sh --version 0.4.0      # a specific release
    sh install.sh --prefix /usr/local  # system-wide (needs write access)
    sh install.sh --dry-run            # print the plan, change nothing

The script prints what it will do, downloads the archive and
`checksums.txt`, verifies the sha256 and aborts on a mismatch before
anything is installed. It never uses sudo. `SETURA_BASE_URL` overrides the
download base for mirrors and tests (`--version` is then required);
`sh scripts/test-install.sh` exercises it against a local fake release.

## Docker

    docker run --rm ghcr.io/zyvorai/zyvor-setura-gateway:latest version

Multi-arch images (linux/amd64, linux/arm64) are built by
`.github/workflows/image.yml` on version tags. Build locally with
`docker build --build-arg VERSION=dev -t setura:local .`.

## go install

    go install github.com/zyvorai/zyvor-setura-gateway/cmd/setura@latest

This build reports the source default version, not the release tag.

## Verifying downloads

    sha256sum -c --ignore-missing checksums.txt        # Linux
    shasum -a 256 -c --ignore-missing checksums.txt    # macOS

## Manual page

`setura man` prints the roff page; `make man` regenerates `man/setura.1`.

## SBOM and provenance

`make sbom` writes `bin/sbom.json`, a simple JSON inventory built from
`go version -m bin/setura` (main module, dependencies, GOOS/GOARCH, revision).

Signing and attestation are not wired into the workflows. Options, for
documentation only: sign release assets or the image with
`cosign sign-blob` / `cosign sign` (keyless via GitHub OIDC), and publish
build provenance with `actions/attest-build-provenance`, verifiable using
`gh attestation verify FILE --repo zyvorai/zyvor-setura-gateway`.
